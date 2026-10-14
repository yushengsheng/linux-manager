"""Discover supported Mac apps; installation and user configuration are independent."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import plistlib
import subprocess
import tempfile

from .models import ManagerError


BUNDLE_CLIENTS = {'com.openai.codex': 'codex', 'ai.opencode.desktop': 'opencode'}


@dataclass(frozen=True)
class ClientApplication:
    path: Path
    name: str
    client: str
    icon: bytes | None = None


def _info(application):
    file = application / 'Contents/Info.plist'
    if not application.is_dir() or application.suffix.lower() != '.app' or file.stat().st_size > 65536:
        raise ValueError('invalid application bundle')
    info = plistlib.loads(file.read_bytes())
    if not isinstance(info, dict) or not isinstance(info.get('CFBundleIdentifier'), str) or info['CFBundleIdentifier'] not in BUNDLE_CLIENTS:
        raise ValueError('unsupported application')
    return info


def resolve_application(path):
    try:
        application = Path(path).expanduser().resolve(strict=True)
        info = _info(application)
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ManagerError('无法识别所选应用；请刷新列表并选择支持配置的 GPT / Codex 或 OpenCode 桌面客户端。') from None
    name = info.get('CFBundleDisplayName') or info.get('CFBundleName') or application.stem
    if not isinstance(name, str): name = application.stem
    return ClientApplication(application, name, BUNDLE_CLIENTS[info['CFBundleIdentifier']])


def _icon(application, info):
    name = info.get('CFBundleIconFile')
    if not isinstance(name, str) or not name or Path(name).name != name:
        return None
    file = application / 'Contents/Resources' / name
    if not file.suffix: file = file.with_suffix('.icns')
    try:
        if not file.is_file() or file.stat().st_size > 16 * 1024 * 1024: return None
        with tempfile.TemporaryDirectory(prefix='lm-client-icon-') as folder:
            target = Path(folder) / 'icon.png'
            subprocess.run(['/usr/bin/sips', '-s', 'format', 'png', '-z', '56', '56', str(file), '--out', str(target)],
                           capture_output=True, timeout=3, check=True)
            return target.read_bytes()
    except (OSError, subprocess.SubprocessError):
        return None


def installed_applications(home=None, roots=None):
    home = Path(home or Path.home())
    folders = list(roots) if roots is not None else [Path('/Applications'), home / 'Applications']
    candidates = []
    for folder in folders:
        try:
            for entry in Path(folder).iterdir():
                if entry.suffix.lower() == '.app':
                    candidates.append(entry)
                elif entry.is_dir() and not entry.name.startswith('.') and not entry.is_symlink():
                    candidates.extend(entry.glob('*.app'))
        except OSError:
            continue
    # Exact metadata query also finds supported apps moved outside Applications.
    query = ' || '.join('kMDItemCFBundleIdentifier == "' + identifier + '"' for identifier in BUNDLE_CLIENTS)
    try:
        result = subprocess.run(['/usr/bin/mdfind', query], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            candidates.extend(Path(line) for line in result.stdout.splitlines()[:128] if line.endswith('.app'))
    except (OSError, subprocess.SubprocessError):
        pass
    found = {}
    for candidate in candidates:
        try:
            application = resolve_application(candidate)
            if application.path in found: continue
            info = _info(application.path)
            found[application.path] = ClientApplication(application.path, application.name, application.client,
                                                         _icon(application.path, info))
        except (ManagerError, OSError, ValueError):
            continue
    return sorted(found.values(), key=lambda item: (item.name.casefold(), str(item.path)))
