#!/usr/bin/env python3
"""Install against the existing standard SQLite/systemd/Nginx deployment."""
import json
import os
from pathlib import Path
import re
import subprocess


def run(args):
    process = subprocess.run(args, capture_output=True, timeout=45)
    if process.returncode:
        raise RuntimeError('installation_command_failed')
    return process.stdout.decode()


def install(updater_source):
    if os.geteuid() != 0:
        raise PermissionError('root_required')
    os.umask(0o077)
    state = Path('/var/lib/new-api-updater')
    gate = Path('/var/lib/new-api-update-gate')
    unit = 'new-api.service'
    props = dict(row.split('=', 1) for row in run(['systemctl', 'show', unit, '--property=ExecStart,WorkingDirectory,MainPID']).splitlines() if '=' in row)
    directory = Path(props['WorkingDirectory']).resolve()
    binary = Path(re.search(r'path=([^ ;]+)', props['ExecStart']).group(1))
    if not binary.is_file() or binary.is_symlink() or directory in (Path('/'), Path('/var'), Path('/var/lib'), binary.parent):
        raise ValueError('unsupported_deployment_layout')
    pid = props['MainPID']
    env = dict(entry.split('=', 1) for entry in Path('/proc/' + pid + '/environ').read_text().split('\0') if '=' in entry)
    if env.get('SQL_DSN') or env.get('REDIS_CONN_STRING'):
        raise ValueError('external_database_or_redis_requires_separate_backup')
    database = Path(env.get('SQLITE_PATH') or str(directory / 'new-api.db'))
    if not database.is_absolute():
        database = directory / database
    database = database.resolve()
    if database.parent != directory or not database.is_file():
        raise ValueError('unsupported_sqlite_layout')
    args = Path('/proc/' + pid + '/cmdline').read_text().split('\0')
    port = int(args[args.index('--port') + 1]) if '--port' in args else int(next((x.split('=', 1)[1] for x in args if x.startswith('--port=')), env.get('PORT', '3000')))
    candidates = []
    for site in list(Path('/etc/nginx/conf.d').glob('*.conf')) + list(Path('/etc/nginx/sites-enabled').glob('*')):
        if site.is_file() and re.search(r'listen\s+(?:[^;\s]*:)?2026(?:\s|;)', site.read_text()):
            candidates.append(site.resolve())
    if len(set(candidates)) != 1:
        raise ValueError('ingress_not_unique')
    site = candidates[0]
    original = site.read_text()
    if len(re.findall(r'(?m)^\s*server\s*\{', original)) != 1 or 'proxy_pass http://127.0.0.1:' + str(port) not in original:
        raise ValueError('unsupported_ingress_layout')
    for folder, mode in ((state, 0o700), (gate, 0o755)):
        folder.mkdir(mode=mode, exist_ok=True)
        os.chmod(folder, mode)
    backup = state / 'ingress-before-install.conf'
    if not backup.exists():
        backup.write_text(original)
        os.chmod(backup, 0o600)
    marker = gate / 'maintenance'
    directive = 'if (-f ' + str(marker) + ') { return 503; }'
    if directive not in original:
        updated = re.sub(r'(?m)^(\s*server\s*\{)', lambda m: m.group(1) + '\n    ' + directive, original, count=1)
        site.write_text(updated)
        try:
            run(['nginx', '-t'])
            run(['systemctl', 'reload', 'nginx'])
        except BaseException:
            site.write_text(original)
            run(['nginx', '-t'])
            run(['systemctl', 'reload', 'nginx'])
            raise
    target = Path('/usr/local/sbin/new-api-auto-update')
    target.write_text(updater_source)
    os.chmod(target, 0o755)
    config = dict(unit=unit, binary=str(binary), data_dir=str(directory), database=str(database), port=port,
                  health_url='http://127.0.0.1:' + str(port) + '/api/status', ingress_url='https://127.0.0.1:2026/api/status',
                  pricing_url='http://127.0.0.1:' + str(port) + '/api/pricing', maintenance_marker=str(marker), keep_backups=7)
    path = Path('/etc/new-api-auto-update.json')
    path.write_text(json.dumps(config))
    os.chmod(path, 0o600)
    writable = ' '.join(json.dumps(str(p)) for p in (state, gate, binary.parent, directory))
    service = '''[Unit]
Description=New API official release update with database backup and rollback
Wants=network-online.target
After=network-online.target nginx.service new-api.service

[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=/usr/local/sbin/new-api-auto-update
ExecStopPost=/usr/local/sbin/new-api-auto-update --recover
TimeoutStartSec=1200
TimeoutStopSec=300
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=''' + writable + '''
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=true
'''
    timer = '''[Unit]
Description=Daily New API official release check (Asia/Shanghai)

[Timer]
OnBootSec=2min
OnCalendar=*-*-* 04:30:00 Asia/Shanghai
RandomizedDelaySec=10min
Persistent=true
Unit=new-api-auto-update.service

[Install]
WantedBy=timers.target
'''
    for name, source in (('new-api-auto-update.service', service), ('new-api-auto-update.timer', timer)):
        path = Path('/etc/systemd/system') / name
        path.write_text(source)
        os.chmod(path, 0o644)
    run(['systemd-analyze', 'verify', '/etc/systemd/system/new-api-auto-update.service', '/etc/systemd/system/new-api-auto-update.timer'])
    run(['systemctl', 'daemon-reload'])
    return dict(installed=True, timer_enabled=False, database='sqlite', maintenance_gate_installed=True,
                schedule='04:30-04:40 Asia/Shanghai', backups=7)
