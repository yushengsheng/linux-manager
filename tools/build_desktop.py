"""Build an isolated macOS app; local profiles and credentials are never copied."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
WORK = Path("/private/tmp/linux-manager-build")
sys.path.insert(0, str(BASE))
from linux_manager import VERSION


def run(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, text=True, **kwargs)
    if result.returncode:
        text = (result.stderr or result.stdout)[-5000:]
        text = text.replace(str(BASE), "[项目目录]")
        text = re.sub(r"(?:\d{1,3}\.){3}\d{1,3}", "[地址]", text)
        print(text)
        raise SystemExit("桌面程序构建失败。")


def source_hashes(root):
    files = [root / 'linux服务器管理.py', *(root / 'linux_manager').rglob('*')]
    return {str(file.relative_to(root)): hashlib.sha256(file.read_bytes()).hexdigest()
            for file in sorted(files) if file.is_file() and '__pycache__' not in file.parts and file.suffix not in {'.pyc', '.pyo'}}


def prepare_source(source):
    # A reused build must not retain modules removed from the current project.
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True)
    shutil.copytree(BASE / 'linux_manager', source / 'linux_manager', ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
    shutil.copy2(BASE / 'linux服务器管理.py', source)


def configure_bundle(bundle, source=BASE):
    path = bundle / "Contents/Info.plist"
    metadata = plistlib.loads(path.read_bytes())
    metadata.update(CFBundleShortVersionString=VERSION, CFBundleVersion=VERSION, LSMinimumSystemVersion="11.0",
                    NSAppleEventsUsageDescription="用于打开服务器命令行及读取属于本次登录的浏览器授权回调。")
    path.write_bytes(plistlib.dumps(metadata))
    manifest = bundle / 'Contents/Resources/build-manifest.json'
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({'version': VERSION, 'sources': source_hashes(source)}, ensure_ascii=False, sort_keys=True), encoding='utf-8')
    # Updating Info.plist invalidates the root bundle's ad-hoc signature.
    run(["codesign", "--force", "--sign", "-", str(bundle)], timeout=60)
    run(["codesign", "--verify", "--deep", "--strict", str(bundle)], timeout=60)


def main():
    global WORK
    parser = argparse.ArgumentParser(description="构建自带运行环境的 Mac 程序")
    parser.add_argument('--target-arch', choices=['arm64', 'x86_64', 'universal2'])
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("此构建入口用于 macOS。")
    if args.target_arch:
        architectures = subprocess.run(['lipo', '-archs', sys.executable], capture_output=True, text=True, timeout=10)
        required = {'arm64', 'x86_64'} if args.target_arch == 'universal2' else {args.target_arch}
        if architectures.returncode or not required.issubset(architectures.stdout.split()):
            raise SystemExit("构建所选架构需要匹配的 Python 运行环境；通用包需要 universal2 Python 及 Tk。")
        WORK = WORK.with_name(WORK.name + '-' + args.target_arch)
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = WORK / "source"
    prepare_source(source)
    environment = WORK / "environment"
    if not (environment / "bin/python").exists():
        run([sys.executable, "-m", "venv", str(environment)])
    python = str(environment / "bin/python")
    run([python, "-m", "pip", "install", "--disable-pip-version-check", "pyinstaller==6.22.0", "truststore==0.10.4", "segno==1.6.6"])
    print("隔离构建环境已准备。", flush=True)
    architecture_options = ['--target-arch', args.target_arch] if args.target_arch else []
    run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", *architecture_options, "--name", "linux服务器管理", "--osx-bundle-identifier", "local.linuxservermanager.desktop", "--add-data", "linux_manager/remote_agent.py:linux_manager", "--add-data", "linux_manager/server_downloads.py:linux_manager", "--add-data", "linux_manager/redeployment.py:linux_manager", "--add-data", "linux_manager/reality.py:linux_manager", "--add-data", "linux_manager/uninstallation.py:linux_manager", "--add-data", "linux_manager/cliproxyapi.py:linux_manager", "--add-data", "linux_manager/cliproxy_oauth.py:linux_manager", "--add-data", "linux_manager/oauth_contract.py:linux_manager", "--add-data", "linux_manager/external_projects.py:linux_manager", "--add-data", "linux_manager/resources:linux_manager/resources", "--distpath", str(WORK / "dist"), "--workpath", str(WORK / "build"), "linux服务器管理.py"], cwd=source)
    bundle = WORK / "dist/linux服务器管理.app"
    # A release must never contain local connection profiles or private keys.
    forbidden = {"profiles.json", "history.json", "current.json", "test-connection.json", "known_hosts", "askpass.sock",
                 "project-cache", "external-projects.json", "window-state.json", "ui-check.json",
                 "ui-error.json", "transport-error.json", "application.lock", "vault.lock"}
    if any(path.name in forbidden for path in bundle.rglob("*")):
        raise SystemExit("发现本地数据进入构建，已停止交付。")
    configure_bundle(bundle, source)
    run([str(bundle / "Contents/MacOS/linux服务器管理"), "--self-check"], timeout=30)
    print("桌面程序构建完成；独立运行环境检查通过。", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
        file = WORK / "build-error.txt"
        file.write_text(traceback.format_exc()); file.chmod(0o600)
        print("桌面程序构建失败，原始诊断已保留在本机。", flush=True)
        raise SystemExit(1)
