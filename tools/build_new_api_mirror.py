"""Prepare a verified static mirror; only the administrator needs GitHub access."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def build(destination, download=True, current_platform=False):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'tools/new_api_mirror_assets.json').read_text())
    if current_platform:
        architecture = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'amd64': 'x86_64', 'x86_64': 'x86_64'}[platform.machine().lower()]
        system = 'apple-darwin' if sys.platform == 'darwin' else 'pc-windows-msvc' if os.name == 'nt' else 'unknown-linux-'
        manifest['assets'] = [asset for asset in manifest['assets'] if architecture + '-' + system in asset['path']]
    context = ssl.create_default_context()
    if Path('/etc/ssl/cert.pem').is_file():
        context.load_verify_locations('/etc/ssl/cert.pem')

    def prepare(asset):
        target = destination / asset['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file() and target.stat().st_size == asset['size'] and sha256(target) == asset['sha256']:
            return
        if not download:
            raise RuntimeError('mirror_asset_missing_or_invalid')
        temporary = target.with_name(target.name + '.partial')
        try:
            request = urllib.request.Request(asset['url'], headers={'User-Agent': 'newapi-static-mirror'})
            with urllib.request.urlopen(request, context=context, timeout=180) as response, temporary.open('wb') as output:
                total = 0
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > asset['size']:
                        raise RuntimeError('mirror_asset_too_large')
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if total != asset['size'] or sha256(temporary) != asset['sha256']:
                raise RuntimeError('mirror_asset_checksum_mismatch')
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(prepare, manifest['assets']))
    source = (ROOT / 'tools/new_api_setup.py').read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    release = destination / 'releases' / digest
    release.mkdir(parents=True, exist_ok=True)
    (release / 'new_api_setup.py').write_bytes(source)
    for suffix in ('sh', 'ps1'):
        template = (ROOT / ('tools/new_api_bootstrap.' + suffix)).read_text()
        (destination / ('install.' + suffix)).write_text(template.replace('__SETUP_SHA256__', digest), encoding='utf-8')
    public = dict(manifest, setup_sha256=digest)
    (destination / 'manifest.json').write_text(json.dumps(public, indent=2) + '\n')
    (destination / 'SHA256SUMS').write_text(''.join(
        asset['sha256'] + '  ' + asset['path'] + '\n' for asset in manifest['assets']) +
        digest + '  releases/' + digest + '/new_api_setup.py\n')
    for name in ('install.sh', 'install.ps1', 'manifest.json', 'SHA256SUMS'):
        (destination / name).chmod(0o644)
    (release / 'new_api_setup.py').chmod(0o644)
    print(json.dumps({'mirror_ready': True, 'verified_assets': len(manifest['assets']), 'setup_sha256': digest}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--current-platform', action='store_true', help='Prepare only this test machine platform')
    options = parser.parse_args()
    try:
        build(options.destination, download=not options.verify_only, current_platform=options.current_platform)
    except Exception as error:
        print(json.dumps({'mirror_ready': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
