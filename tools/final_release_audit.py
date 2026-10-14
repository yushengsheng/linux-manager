"""Read-only audit of a local universal Mac release; never loads user profiles."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager import APP_NAME, VERSION
from tools.build_desktop import source_hashes

FORBIDDEN = {'profiles.json', 'history.json', 'current.json', 'test-connection.json', 'known_hosts',
             'askpass.sock', 'session.sock', '.git', '.env', 'client-config-backups', 'client-config-directories.json',
             'auth.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', '.DS_Store', '__pycache__'}
MACHO = {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
         b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, '程序或系统工具检查失败：' + Path(arguments[0]).name)
    return result.stdout


def audit_archive(release, archive, checksum):
    expected = checksum.read_text().strip().split()
    require(len(expected) == 2 and expected[1].lstrip('*') == archive.name, '校验文件名不匹配。')
    with archive.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected[0], '安装包 SHA-256 不匹配。')
    local = {str(path.relative_to(release)): path for path in release.rglob('*') if path.is_file() or path.is_symlink()}
    require(local and not any(set(Path(name).parts) & FORBIDDEN for name in local), '交付目录包含本机数据或缓存。')
    with zipfile.ZipFile(archive) as package:
        require(package.testzip() is None, 'ZIP CRC 检查失败。')
        found = set()
        for entry in package.infolist():
            parts = PurePosixPath(entry.filename).parts
            require(parts and not entry.filename.startswith('/') and '..' not in parts, 'ZIP 包含无效路径。')
            if parts[0] == '__MACOSX':
                continue  # ditto stores macOS resource forks here.
            require(parts[0] == release.name and not set(parts) & FORBIDDEN, 'ZIP 包含非交付文件或本机数据。')
            if entry.is_dir():
                continue
            name = str(PurePosixPath(*parts[1:]))
            require(name in local and name not in found, 'ZIP 与交付目录的文件列表不一致。')
            path = local[name]
            symlink = stat.S_ISLNK(entry.external_attr >> 16)
            require(symlink == path.is_symlink(), 'ZIP 中的链接类型与交付目录不一致。')
            if symlink:
                require(package.read(entry) == os.readlink(path).encode(), 'ZIP 中的链接目标不一致。')
                require(path.resolve().is_relative_to(release.resolve()), '交付包链接依赖外部目录。')
            else:
                require(stat.S_IMODE(entry.external_attr >> 16) == stat.S_IMODE(path.stat().st_mode), 'ZIP 没有保留交付文件的权限。')
                with package.open(entry) as stream, path.open('rb') as original:
                    require(hashlib.file_digest(stream, 'sha256').digest() == hashlib.file_digest(original, 'sha256').digest(), 'ZIP 文件与交付目录内容不一致。')
            found.add(name)
        require(found == set(local), 'ZIP 缺少交付文件。')


def audit(release, archive, checksum):
    require(sys.platform == 'darwin', '原生程序验收需要 macOS。')
    main = release / 'linux服务器管理.app'
    launcher = release / '启动linux服务器管理.app'
    manifest = json.loads((main / 'Contents/Resources/build-manifest.json').read_text())
    require(manifest == {'version': VERSION, 'sources': source_hashes(BASE)}, '安装包源码清单与当前源码不一致，请重新构建。')
    binaries = {}
    for bundle in [main, launcher]:
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        require(info.get('CFBundleShortVersionString') == VERSION and info.get('CFBundleVersion') == VERSION,
                '应用版本与源码不一致。')
        require(info.get('LSMinimumSystemVersion') == '11.0', '应用的最低 macOS 版本不一致。')
        binary = bundle / 'Contents/MacOS' / info['CFBundleExecutable']
        require(binary.is_file() and os.access(binary, os.X_OK), '应用启动文件缺失或无法执行。')
        binaries[bundle] = binary
        run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(bundle)])
    count = 0
    for path in release.rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic not in MACHO:
            continue
        require({'arm64', 'x86_64'}.issubset(run(['/usr/bin/lipo', '-archs', str(path)]).split()), '应用包含单架构运行文件。')
        for line in run(['/usr/bin/otool', '-L', str(path)]).splitlines():
            if line.startswith('\t'):
                dependency = line.strip().split(' (', 1)[0]
                require(dependency.startswith(('@', '/System/Library/', '/usr/lib/')), '运行库依赖构建电脑的目录。')
        count += 1
    require(count > 0, '没有找到原生运行文件。')
    for path in (main / 'Contents/Resources/linux_manager').glob('*.py'):
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sources'].get('linux_manager/' + path.name),
                '嵌入的服务器代码与源码清单不一致。')
    for architecture in ['arm64', 'x86_64']:
        output = run(['/usr/bin/arch', '-' + architecture, str(binaries[main]), '--self-check'])
        require((APP_NAME + '：环境检查通过。') in output, '图形运行环境自检未确认。')
    audit_archive(release, archive, checksum)
    return {'release_audit_passed': True, 'version': VERSION, 'source_matches': True,
            'universal_macho_files': count, 'signatures_valid': True, 'external_build_paths_absent': True,
            'self_check_architectures': ['arm64', 'x86_64'], 'archive_matches_delivery': True, 'sha256_valid': True}


def main():
    parser = argparse.ArgumentParser(description='只读检查本地 Mac 通用安装包，不读取连接档案或操作服务器')
    parser.add_argument('--release-dir', type=Path, default=BASE / ('新版v' + VERSION + '-Mac通用'))
    parser.add_argument('--archive', type=Path, default=BASE / ('linux-server-manager-macOS-universal2-v' + VERSION + '.zip'))
    parser.add_argument('--checksum', type=Path)
    args = parser.parse_args()
    checksum = args.checksum or args.archive.with_suffix('.sha256')
    print(json.dumps(audit(args.release_dir, args.archive, checksum), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'release_audit_passed': False, 'reason': str(error)}, ensure_ascii=False))
        raise SystemExit(1)
