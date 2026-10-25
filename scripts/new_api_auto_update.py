#!/usr/bin/env python3
"""Update the official New API Linux binary, with a maintenance gate and rollback."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

STATE = Path('/var/lib/new-api-updater')
CONFIG = Path('/etc/new-api-auto-update.json')
API = 'https://api.github.com/repos/QuantumNous/new-api/releases/latest'


def emit(event, **fields):
    # Never log subprocess output, configuration contents, or exception messages.
    print(json.dumps(dict(event=event, **fields), ensure_ascii=False), flush=True)


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.tmp')
    with temp.open('w') as stream:
        os.chmod(temp, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    fsync_dir(path.parent)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def command(args, timeout=90):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError('subprocess_failed')
    return p.stdout


def version(value):
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)[.-]?(\d+))?', value)
    if not match:
        raise ValueError('unsupported_version_format')
    major, minor, patch, stage, serial = match.groups()
    return int(major), int(minor), int(patch), {None: 3, 'rc': 2, 'beta': 1, 'alpha': 0}[stage], int(serial or 0)


def get_json(url, maximum=4 * 1024 * 1024):
    req = urllib.request.Request(url, headers={'User-Agent': 'new-api-systemd-updater', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('response_too_large')
    return json.loads(raw)


def select_release(data, current, arch=None):
    if data.get('draft') or data.get('prerelease'):
        return None
    tag = data['tag_name']
    if version(tag) <= version(current):
        return None
    arch = arch or platform.machine()
    prefix = {'x86_64': 'new-api-', 'aarch64': 'new-api-arm64-', 'arm64': 'new-api-arm64-'}.get(arch)
    if not prefix:
        raise ValueError('unsupported_architecture')
    matches = [a for a in data.get('assets', []) if a['name'] == prefix + tag]
    if len(matches) != 1:
        raise ValueError('official_asset_missing')
    asset = matches[0]
    url = urllib.parse.urlparse(asset['browser_download_url'])
    if url.scheme != 'https' or url.hostname != 'github.com' or not url.path.startswith('/QuantumNous/new-api/releases/download/' + tag + '/'):
        raise ValueError('untrusted_asset_url')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or ''):
        raise ValueError('official_sha256_missing')
    if not 1024 * 1024 <= asset['size'] <= 1024 * 1024 * 1024:
        raise ValueError('invalid_asset_size')
    return dict(tag=tag, url=asset['browser_download_url'], sha256=asset['digest'][7:], size=asset['size'])


def download(release, target):
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(urllib.request.Request(release['url'], headers={'User-Agent': 'new-api-systemd-updater'}), timeout=90) as response, target.open('wb') as out:
        if urllib.parse.urlparse(response.url).scheme != 'https':
            raise ValueError('insecure_download_redirect')
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > release['size']:
                raise ValueError('download_too_large')
            out.write(chunk)
            digest.update(chunk)
        out.flush()
        os.fsync(out.fileno())
    if count != release['size'] or digest.hexdigest() != release['sha256']:
        raise ValueError('download_sha256_mismatch')
    with target.open('rb') as stream:
        header = stream.read(20)
    machine = {'x86_64': 62, 'aarch64': 183, 'arm64': 183}[platform.machine()]
    if header[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', header[18:20])[0] != machine:
        raise ValueError('wrong_elf_architecture')


def status(config):
    data = get_json(config['health_url'])
    if data.get('success') is not True:
        raise RuntimeError('unhealthy_status')
    return data['data']['version']


def wait_healthy(config, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if status(config) == expected:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError('health_check_failed')


def copy_file(source, destination):
    source, destination = Path(source), Path(destination)
    if source.is_symlink():
        raise ValueError('symlink_not_supported')
    shutil.copy2(source, destination)
    info = source.stat()
    if os.geteuid() == 0:
        os.chown(destination, info.st_uid, info.st_gid)
    with destination.open('rb') as stream:
        os.fsync(stream.fileno())
    return str(destination)


def copy_tree(source, destination):
    source, destination = Path(source), Path(destination)
    if any(p.is_symlink() for p in source.rglob('*')):
        raise ValueError('symlink_not_supported')
    shutil.copytree(source, destination, copy_function=copy_file)
    for directory in [source] + [p for p in source.rglob('*') if p.is_dir()]:
        target = destination / directory.relative_to(source)
        if os.geteuid() == 0:
            info = directory.stat()
            os.chown(target, info.st_uid, info.st_gid)
        fsync_dir(target)


def quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def database_signatures(database, specs=None):
    signatures = {}
    with contextlib.closing(sqlite3.connect(Path(database).as_uri() + '?mode=ro', uri=True)) as connection:
        if connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('sqlite_integrity_failed')
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        # Instance heartbeats are regenerated on startup; Casbin IDs are recreated
        # while the permission rule contents remain authoritative.
        for table in sorted(t for t in tables if not t.startswith('sqlite_') and t != 'system_instances') if specs is None else specs:
            if table not in tables:
                if specs is not None:
                    raise RuntimeError('business_table_missing')
                continue
            columns = [r[1] for r in connection.execute('PRAGMA table_info(' + quote(table) + ')')] if specs is None else specs[table]['columns']
            if table == 'casbin_rule' and specs is None:
                columns = [column for column in columns if column != 'id']
            # Compare all original columns; added migration columns are allowed.
            rows = connection.execute('SELECT ' + ','.join(map(quote, columns)) + ' FROM ' + quote(table))
            hashes = sorted(hashlib.sha256(repr(row).encode()).digest() for row in rows)
            signatures[table] = dict(columns=columns, count=len(hashes), digest=hashlib.sha256(b''.join(hashes)).hexdigest())
    return signatures


def ingress_status(config):
    # This probe sends no credentials and connects only to the local TLS listener.
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(config['ingress_url'], timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def effective_pricing(config):
    if 'pricing_url' not in config:
        return None
    data = get_json(config['pricing_url'])
    if data.get('success') is not True or not isinstance(data.get('data'), list):
        raise RuntimeError('effective_pricing_unavailable')
    rows = []
    for row in data['data']:
        rows.append({key: value for key, value in row.items() if key in ('model_name', 'quota_type', 'enable_groups')
                     or (any(part in key for part in ('ratio', 'price', 'billing')) and key != 'pricing_version')})
    value = dict(models=sorted(rows, key=lambda row: row['model_name']),
                 groups={key: data.get(key) for key in ('group_ratio', 'usable_group', 'auto_groups')})
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def wait_drained(config, timeout=300):
    port = int(config['port'])
    deadline = time.monotonic() + timeout
    quiet = 0
    while time.monotonic() < deadline:
        busy = 0
        for name in ('tcp', 'tcp6'):
            for row in Path('/proc/net/' + name).read_text().splitlines()[1:]:
                columns = row.split()
                if int(columns[1].rsplit(':', 1)[1], 16) == port and columns[3] == '01':
                    busy += 1
        quiet = quiet + 1 if busy == 0 else 0
        if quiet >= 2:
            return
        time.sleep(1)
    raise RuntimeError('inflight_requests_did_not_finish')


class Updater:
    def __init__(self, config, state=STATE):
        self.config = config
        self.state = Path(state)
        self.pending = self.state / 'pending.json'
        self.marker = Path(config['maintenance_marker'])
        self.installed_attempt = False

    def control(self, action):
        command(['systemctl', action, self.config['unit']], timeout=150)

    def maintain(self):
        self.marker.touch(mode=0o644)
        with self.marker.open('rb') as stream:
            os.fsync(stream.fileno())
        fsync_dir(self.marker.parent)
        if ingress_status(self.config) != 503:
            raise RuntimeError('maintenance_gate_failed')

    def reopen(self):
        self.marker.unlink(missing_ok=True)
        fsync_dir(self.marker.parent)

    def recover(self):
        if not self.pending.exists():
            self.reopen()
            return False
        record = json.loads(self.pending.read_text())
        if record.get('installed_attempt') or record['phase'] == 'installed':
            atomic_json(self.state / 'last-failure.json', dict(version=record['new_version'],
                        sha256=record.get('sha256'), error_type='InterruptedUpdate'))
        if record['phase'] in ('backed_up', 'installed'):
            # A recreated gate cannot prove that no usage arrived while it was absent.
            if not self.marker.is_file():
                record['maintenance_lost'] = True
                atomic_json(self.pending, record)
            try:
                self.maintain()
            except Exception:
                record['maintenance_lost'] = True
                atomic_json(self.pending, record)
                raise
            if record.get('maintenance_lost'):
                raise RuntimeError('rollback_requires_manual_review')
            wait_drained(self.config)
            self.control('stop')
            backup = self.state / record['backup']
            if backup.parent != self.state or not (backup / 'manifest.json').is_file():
                raise RuntimeError('backup_manifest_missing')
            manifest = json.loads((backup / 'manifest.json').read_text())
            backup_db = backup / 'data' / Path(self.config['database']).relative_to(self.config['data_dir'])
            if database_signatures(backup_db, manifest['signatures']) != manifest['signatures']:
                raise RuntimeError('backup_database_invalid')
            if hashlib.sha256((backup / 'binary').read_bytes()).hexdigest() != manifest['binary_sha256']:
                raise RuntimeError('backup_binary_invalid')
            data = Path(self.config['data_dir'])
            for item in data.iterdir():
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            for item in (backup / 'data').iterdir():
                if item.is_dir():
                    copy_tree(item, data / item.name)
                else:
                    copy_file(item, data / item.name)
            if database_signatures(self.config['database'], manifest['signatures']) != manifest['signatures']:
                raise RuntimeError('restored_database_invalid')
            binary = Path(self.config['binary'])
            staged = binary.with_name(binary.name + '.restore')
            copy_file(backup / 'binary', staged)
            os.replace(staged, binary)
            fsync_dir(binary.parent)
        self.control('start')
        wait_healthy(self.config, record['old_version'])
        self.pending.unlink()
        fsync_dir(self.state)
        self.reopen()
        if record['phase'] == 'prepared':
            partial = self.state / record['backup']
            if partial.parent == self.state and partial.name.startswith('backup-') and partial.is_dir():
                shutil.rmtree(partial)
        emit('rollback_completed', version=record['old_version'])
        return True

    def apply(self, release, candidate, current):
        backup = self.state / ('backup-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
        backup.mkdir(mode=0o700)
        record = dict(phase='prepared', backup=backup.name, old_version=current, new_version=release['tag'],
                      sha256=release['sha256'])
        atomic_json(self.pending, record)
        try:
            self.maintain()
            wait_drained(self.config)
            pricing_before = effective_pricing(self.config)
            self.control('stop')
            copy_tree(self.config['data_dir'], backup / 'data')
            copy_file(self.config['binary'], backup / 'binary')
            backup_db = backup / 'data' / Path(self.config['database']).relative_to(self.config['data_dir'])
            signatures = database_signatures(backup_db)
            manifest = dict(format=1, old_version=current, new_version=release['tag'], signatures=signatures,
                            binary_sha256=hashlib.sha256((backup / 'binary').read_bytes()).hexdigest())
            atomic_json(backup / 'manifest.json', manifest)
            record['phase'] = 'backed_up'
            atomic_json(self.pending, record)
            binary = Path(self.config['binary'])
            staged = binary.with_name(binary.name + '.update')
            copy_file(candidate, staged)
            info = binary.stat()
            os.chmod(staged, info.st_mode & 0o777)
            os.chown(staged, info.st_uid, info.st_gid)
            record['installed_attempt'] = True
            atomic_json(self.pending, record)
            self.installed_attempt = True
            os.replace(staged, binary)
            fsync_dir(binary.parent)
            record['phase'] = 'installed'
            atomic_json(self.pending, record)
            self.control('start')
            wait_healthy(self.config, release['tag'])
            checked = database_signatures(self.config['database'], signatures)
            if checked != signatures:
                emit('business_data_mismatch', tables=[table for table in signatures if checked.get(table) != signatures[table]])
                raise RuntimeError('business_data_changed_during_migration')
            if effective_pricing(self.config) != pricing_before:
                raise RuntimeError('effective_model_prices_changed')
            if not self.marker.is_file() or ingress_status(self.config) != 503:
                record['maintenance_lost'] = True
                atomic_json(self.pending, record)
                raise RuntimeError('maintenance_gate_lost')
            # Commit before reopening traffic: subsequent rollback must never erase new usage.
            self.pending.unlink()
            fsync_dir(self.state)
            self.reopen()
            atomic_json(self.state / 'last-success.json', dict(version=release['tag'], previous=current, backup=backup.name,
                        completed=dt.datetime.now(dt.timezone.utc).isoformat(), business_data_verified=True, effective_pricing_verified=True))
            emit('update_completed', previous=current, version=release['tag'], business_data_verified=True, effective_pricing_verified=True)
            if ingress_status(self.config) != 200:
                emit('post_update_ingress_unhealthy', version=release['tag'])
        except BaseException:
            if self.pending.exists():
                self.recover()
            raise

    def prune(self):
        backups = sorted((p for p in self.state.glob('backup-*') if p.is_dir() and (p / 'manifest.json').is_file()), reverse=True)
        for old in backups[int(self.config.get('keep_backups', 7)):]:
            shutil.rmtree(old)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--retry-failed', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError('root_required')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            emit('already_running')
            return
        config = json.loads(CONFIG.read_text())
        updater = Updater(config)
        updater.recover()
        if args.recover:
            return
        current = status(config)
        release = select_release(get_json(API), current)
        if not release:
            emit('already_current', version=current)
            return
        emit('update_available', current=current, version=release['tag'])
        if args.check:
            return
        failed = STATE / 'last-failure.json'
        if failed.exists() and not args.retry_failed:
            failure = json.loads(failed.read_text())
            if (failure.get('sha256') == release['sha256'] or
                    (not failure.get('sha256') and failure.get('version') == release['tag'])):
                emit('previously_failed_release_skipped', version=release['tag'])
                return
        size = sum(p.stat().st_size for p in Path(config['data_dir']).rglob('*') if p.is_file())
        for path in (STATE, Path(config['binary']).parent, Path(config['data_dir'])):
            if shutil.disk_usage(path).free < max(512 * 1024 * 1024, release['size'] * 3 + size * 3):
                raise RuntimeError('insufficient_disk_space')
        with tempfile.TemporaryDirectory(prefix='download-', dir=STATE) as temp:
            candidate = Path(temp) / 'new-api'
            download(release, candidate)
            try:
                updater.apply(release, candidate, current)
            except BaseException as error:
                if updater.installed_attempt:
                    atomic_json(failed, dict(version=release['tag'], sha256=release['sha256'], error_type=type(error).__name__))
                raise
        updater.prune()


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        known = {'subprocess_failed', 'unhealthy_status', 'health_check_failed', 'sqlite_integrity_failed', 'business_table_missing',
                 'effective_pricing_unavailable', 'inflight_requests_did_not_finish', 'backup_manifest_missing', 'backup_database_invalid',
                 'backup_binary_invalid', 'restored_database_invalid', 'maintenance_gate_failed', 'business_data_changed_during_migration',
                  'effective_model_prices_changed', 'maintenance_gate_lost', 'insufficient_disk_space', 'rollback_requires_manual_review'}
        emit('update_failed', error_type=type(error).__name__, error_code=str(error) if str(error) in known else 'unclassified')
        sys.exit(1)
