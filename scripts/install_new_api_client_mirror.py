"""Publish a verified component mirror through the existing New API TLS site."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PUBLIC = Path('/var/lib/new-api-client-mirror/public')
BEGIN = '    # BEGIN managed New API client mirror\n'
END = '    # END managed New API client mirror\n'
BLOCK = BEGIN + '''    location ^~ /client-setup/ {
        alias /var/lib/new-api-client-mirror/public/;
        autoindex off;
        types { text/plain sh ps1 py txt md; application/json json; }
        default_type application/octet-stream;
        charset utf-8;
        add_header X-Content-Type-Options nosniff always;
        add_header Cache-Control "no-cache" always;
        limit_except GET HEAD { deny all; }
    }
''' + END


def run(args):
    if subprocess.run(args, capture_output=True, timeout=40).returncode:
        raise RuntimeError('mirror_ingress_command_failed')


def install(root):
    if os.geteuid() != 0:
        raise PermissionError('root_required')
    root = root.resolve()
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    for asset in manifest['assets']:
        path = root / asset['path']
        if not path.resolve().is_relative_to(root) or path.is_symlink() or path.stat().st_size != asset['size']:
            raise RuntimeError('invalid_mirror_asset')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != asset['sha256']:
            raise RuntimeError('mirror_checksum_mismatch')
    source = root / 'releases' / manifest['setup_sha256'] / 'new_api_setup.py'
    if hashlib.sha256(source.read_bytes()).hexdigest() != manifest['setup_sha256']:
        raise RuntimeError('mirror_source_checksum_mismatch')
    for suffix in ('sh', 'ps1'):
        if '__SETUP_SHA256__' in (root / ('install.' + suffix)).read_text(encoding='utf-8'):
            raise RuntimeError('unrendered_mirror_installer')
    sites = set()
    for path in list(Path('/etc/nginx/conf.d').glob('*.conf')) + list(Path('/etc/nginx/sites-enabled').glob('*')):
        if path.is_file() and re.search(r'listen\s+(?:[^;\s]*:)?2026(?:\s|;)', path.read_text()):
            sites.add(path.resolve())
    if len(sites) != 1:
        raise RuntimeError('mirror_ingress_not_unique')
    site = sites.pop()
    original = site.read_text()
    if BEGIN in original:
        updated = re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END), lambda _: BLOCK, original, count=1, flags=re.S)
    elif '# Managed New API client component mirror.' in original:
        pattern = r'    # Managed New API client component mirror\.\n    location \^~ /client-setup/ \{\n.*?\n    \}\n'
        updated = re.sub(pattern, lambda _: BLOCK, original, count=1, flags=re.S)
        if updated == original:
            raise RuntimeError('unknown_existing_mirror_layout')
    else:
        if '/client-setup/' in original:
            raise RuntimeError('existing_mirror_requires_review')
        updated = re.sub(r'(?m)^(\s*server\s*\{)', lambda m: m.group(1) + '\n' + BLOCK, original, count=1)
    if PUBLIC.is_symlink() or PUBLIC.exists():
        if PUBLIC.resolve() != root:
            raise RuntimeError('existing_public_mirror_requires_review')
    else:
        PUBLIC.parent.mkdir(parents=True, exist_ok=True)
        PUBLIC.symlink_to(root, target_is_directory=True)
    for path in [root] + list(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('mirror_symlinks_not_supported')
        path.chmod(0o755 if path.is_dir() else 0o644)
    backup = PUBLIC.parent / 'nginx-before-mirror.conf'
    if not backup.exists():
        backup.write_text(original)
        backup.chmod(0o600)
    if updated != original:
        site.write_text(updated)
        try:
            run(['nginx', '-t'])
            run(['systemctl', 'reload', 'nginx'])
        except BaseException:
            site.write_text(original)
            run(['nginx', '-t'])
            run(['systemctl', 'reload', 'nginx'])
            raise
    return dict(mirror_installed=True, verified_assets=len(manifest['assets']), utf8_scripts=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    try:
        print(json.dumps(install(parser.parse_args().root)))
    except Exception as error:
        print(json.dumps({'mirror_installed': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
