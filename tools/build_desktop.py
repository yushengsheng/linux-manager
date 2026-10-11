"""Build an isolated macOS app; local profiles and credentials are never copied."""
from pathlib import Path
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


def configure_bundle(bundle):
    path = bundle / "Contents/Info.plist"
    metadata = plistlib.loads(path.read_bytes())
    metadata.update(CFBundleShortVersionString=VERSION, CFBundleVersion=VERSION, LSMinimumSystemVersion="11.0",
                    NSAppleEventsUsageDescription="用于打开当前服务器的命令行窗口。")
    path.write_bytes(plistlib.dumps(metadata))
    # Updating Info.plist invalidates the root bundle's ad-hoc signature.
    run(["codesign", "--force", "--sign", "-", str(bundle)], timeout=60)
    run(["codesign", "--verify", "--deep", "--strict", str(bundle)], timeout=60)


def main():
    if platform.system() != "Darwin":
        raise SystemExit("此构建入口用于 macOS。")
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = WORK / "source"
    source.mkdir(exist_ok=True)
    shutil.copytree(BASE / "linux_manager", source / "linux_manager", dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(BASE / "linux服务器管理.py", source)
    environment = WORK / "environment"
    if not (environment / "bin/python").exists():
        run([sys.executable, "-m", "venv", str(environment)])
    python = str(environment / "bin/python")
    run([python, "-m", "pip", "install", "--disable-pip-version-check", "pyinstaller==6.22.0", "truststore==0.10.4"])
    print("隔离构建环境已准备。", flush=True)
    run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--name", "linux服务器管理", "--osx-bundle-identifier", "local.linuxservermanager.desktop", "--add-data", "linux_manager/remote_agent.py:linux_manager", "--add-data", "linux_manager/redeployment.py:linux_manager", "--add-data", "linux_manager/uninstallation.py:linux_manager", "--add-data", "linux_manager/resources:linux_manager/resources", "--distpath", str(WORK / "dist"), "--workpath", str(WORK / "build"), "linux服务器管理.py"], cwd=source)
    bundle = WORK / "dist/linux服务器管理.app"
    # A release must never contain local connection profiles or private keys.
    forbidden = {"profiles.json", "history.json", "current.json", "test-connection.json", "known_hosts", "askpass.sock"}
    if any(path.name in forbidden for path in bundle.rglob("*")):
        raise SystemExit("发现本地数据进入构建，已停止交付。")
    configure_bundle(bundle)
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
