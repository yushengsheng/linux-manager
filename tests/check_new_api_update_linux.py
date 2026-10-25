"""Opt-in root integration check using an isolated systemd service and Nginx."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid


def check(updater_file):
    spec = importlib.util.spec_from_file_location('isolated_new_api_updater', updater_file)
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    directory = Path(tempfile.mkdtemp(prefix='newapi-update-fixture-'))
    unit_name = 'new-api-update-fixture-' + uuid.uuid4().hex[:8] + '.service'
    unit_file = Path('/run/systemd/system') / unit_name
    nginx = None
    def run(args):
        return updater.command(args, timeout=45)
    def port():
        with socket.socket() as connection:
            connection.bind(('127.0.0.1', 0))
            return connection.getsockname()[1]
    try:
        backend_port, frontend_port = port(), port()
        data = directory / 'data'
        state = directory / 'state'
        data.mkdir(); state.mkdir()
        database = data / 'new-api.db'
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            connection.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, quota INTEGER)')
            connection.execute('INSERT INTO users VALUES (1, 123456)')
            connection.execute('CREATE TABLE options (key TEXT PRIMARY KEY, value TEXT)')
            connection.execute("INSERT INTO options VALUES ('test-price', 'half-price')")
        def server(version, broken=False):
            migration = ''
            if broken:
                migration = 'c=sqlite3.connect(' + repr(str(database)) + ');c.execute("UPDATE users SET quota=0");c.commit();c.close();raise SystemExit(23)\n'
            return ('#!/usr/bin/python3\nimport json, sqlite3\nfrom http.server import BaseHTTPRequestHandler,HTTPServer\n' + migration +
                    'class Handler(BaseHTTPRequestHandler):\n'
                    ' def do_GET(self):\n'
                    '  body=json.dumps({"success":True,"data":{"version":' + repr(version) + '}}).encode()\n'
                    '  self.send_response(200);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)\n'
                    ' def log_message(self,*args):pass\n'
                    'HTTPServer(("127.0.0.1",' + str(backend_port) + '),Handler).serve_forever()\n')
        binary = directory / 'server'
        binary.write_text(server('v1.0.0-rc.46')); binary.chmod(0o755)
        bad = directory / 'bad'; bad.write_text(server('v1.0.0-rc.47', True))
        good = directory / 'good'; good.write_text(server('v1.0.0-rc.47'))
        unit_file.write_text('[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=exec\nExecStart=' + str(binary) + '\nRestart=no\n')
        run(['systemctl', 'daemon-reload']); run(['systemctl', 'start', unit_name])
        cert, key = directory / 'certificate.pem', directory / 'key.pem'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', str(key), '-out', str(cert)])
        marker = directory / 'maintenance'
        nginx_conf = directory / 'nginx.conf'
        nginx_conf.write_text('user root;\ndaemon off;\npid ' + str(directory / 'nginx.pid') + ';\nerror_log ' + str(directory / 'error.log') + ';\nevents { worker_connections 32; }\nhttp { access_log off; server { listen 127.0.0.1:' + str(frontend_port) + ' ssl; ssl_certificate ' + str(cert) + '; ssl_certificate_key ' + str(key) + '; if (-f ' + str(marker) + ') { return 503; } location / { proxy_pass http://127.0.0.1:' + str(backend_port) + '; } } }\n')
        nginx = subprocess.Popen([shutil.which('nginx'), '-p', str(directory), '-c', str(nginx_conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = dict(unit=unit_name, binary=str(binary), data_dir=str(data), database=str(database), port=backend_port,
                      health_url='http://127.0.0.1:' + str(backend_port) + '/api/status', ingress_url='https://127.0.0.1:' + str(frontend_port) + '/api/status', maintenance_marker=str(marker))
        real_wait = updater.wait_healthy
        updater.wait_healthy = lambda cfg, expected: real_wait(cfg, expected, timeout=8)
        updater.wait_healthy(config, 'v1.0.0-rc.46')
        for _ in range(30):
            try:
                if updater.ingress_status(config) == 200:
                    break
            except Exception:
                pass
            time.sleep(.1)
        assert updater.ingress_status(config) == 200, 'fixture_ingress_failed'
        original = updater.database_signatures(database)
        failed = updater.Updater(config, state)
        try:
            failed.apply({'tag': 'v1.0.0-rc.47', 'sha256': hashlib.sha256(bad.read_bytes()).hexdigest()}, bad, 'v1.0.0-rc.46')
        except RuntimeError:
            pass
        else:
            raise AssertionError('broken_release_not_rejected')
        assert updater.status(config) == 'v1.0.0-rc.46'
        assert updater.database_signatures(database) == original
        assert updater.ingress_status(config) == 200
        succeeded = updater.Updater(config, state)
        succeeded.apply({'tag': 'v1.0.0-rc.47', 'sha256': hashlib.sha256(good.read_bytes()).hexdigest()}, good, 'v1.0.0-rc.46')
        assert updater.status(config) == 'v1.0.0-rc.47'
        assert updater.database_signatures(database) == original
        assert updater.ingress_status(config) == 200
        return dict(real_systemd=True, real_nginx_gate=True, failed_upgrade_restored_database=True,
                    successful_upgrade=True, production_service_untouched=True)
    finally:
        subprocess.run(['systemctl', 'stop', unit_name], capture_output=True, timeout=30)
        unit_file.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
        if nginx is not None:
            nginx.terminate()
            try:
                nginx.wait(timeout=10)
            except subprocess.TimeoutExpired:
                nginx.kill(); nginx.wait(timeout=5)
        shutil.rmtree(directory)
