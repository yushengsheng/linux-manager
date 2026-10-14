"""Create a standard UTF-8 ZIP, preserving Mac executable permissions and links."""
from pathlib import Path
import hashlib
import os
import sys
import tempfile
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager import VERSION
from tools.final_release_audit import audit_archive


def package_release(release, archive):
    release = release.resolve(); archive = archive.absolute()
    if archive.resolve().is_relative_to(release):
        raise ValueError('安装包输出不能放在待打包目录内。')
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.lm-package-', dir=archive.parent) as folder:
        candidate = Path(folder) / archive.name
        with zipfile.ZipFile(candidate, 'w', zipfile.ZIP_DEFLATED, compresslevel=6, strict_timestamps=False) as package:
            for path in sorted(release.rglob('*')):
                name = release.name + '/' + path.relative_to(release).as_posix()
                if path.is_symlink():
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = path.lstat().st_mode << 16
                    package.writestr(info, os.readlink(path).encode('utf-8'))
                else:
                    package.write(path, name)
        with candidate.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        checksum = candidate.with_suffix('.sha256')
        checksum.write_text(digest + '  ' + archive.name + '\n', encoding='utf-8')
        audit_archive(release, candidate, checksum)
        os.chmod(candidate, 0o644); os.chmod(checksum, 0o644)
        os.replace(candidate, archive)
        os.replace(checksum, archive.with_suffix('.sha256'))
    return digest


def main():
    release = BASE / ('新版v' + VERSION + '-Mac通用')
    archive = BASE / ('linux-server-manager-macOS-universal2-v' + VERSION + '.zip')
    print('安装包已生成并核对内容，SHA-256：' + package_release(release, archive))


if __name__ == '__main__':
    main()
