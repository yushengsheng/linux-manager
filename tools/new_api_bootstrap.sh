#!/bin/sh
# Download the pinned, checked setup payload and prepare user-owned dependencies.
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" != 0 ] || fail '请使用日常桌面账号运行，不要 sudo 或 root。'
command -v curl >/dev/null 2>&1 || fail '系统没有 curl，无法联网准备；请让系统管理员安装网络下载组件。'
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target=aarch64-apple-darwin; digest=743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73 ;;
  Darwin:x86_64) target=x86_64-apple-darwin; digest=b0f52b0e3945b4107d89024ea38e625683011fbfc05a0d98f9fa2d6dcee28c66 ;;
  Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl; digest=7906c79adb21c81abd559841ba76bb1d9af9d791acac7a041b2972e03ae16538 ;;
  Linux:x86_64) target=x86_64-unknown-linux-musl; digest=57ef9d9ccb01fb1bd998df995b0dd221b52f7d7841fbea93f2d4463bf61fb7a9 ;;
  *) fail '当前系统或处理器不在已支持的 64 位平台中。' ;;
esac
runtime=${CODEX_HOME:-"$HOME/.codex"}/newapi-runtime
[ ! -L "$runtime" ] || fail '运行目录是符号链接，已停止。'
mkdir -p "$runtime" || fail '无法写入当前用户目录；请修复权限，不要用 sudo 重跑。'
runtime=$(cd "$runtime" && pwd -P)
work=$(mktemp -d "$runtime/prepare.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
download() { curl --proto '=https' --tlsv1.2 -fLsS --retry 2 --connect-timeout 20 --max-time 180 "$1" -o "$2"; }
verify() {
  if command -v shasum >/dev/null 2>&1; then got=$(shasum -a 256 "$1");
  elif command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$1");
  else fail '系统缺少 SHA-256 校验工具，已停止。'; fi
  [ "${got%% *}" = "$2" ] || fail '下载校验失败，未执行下载内容。'
}
printf '%s\n' '正在自动检查并准备运行环境，首次可能需要下载，请稍候…'
download 'https://raw.githubusercontent.com/yushengsheng/linux-manager/17271fb01259c4c13fb1aba346a63cfce6a99ae1/tools/new_api_setup.py' "$work/setup.py"
verify "$work/setup.py" 'a2ef8212851b29eead645a878248989e6562cd21323e88816eb60931ac930d54'
download "https://github.com/astral-sh/uv/releases/download/0.13.5/uv-$target.tar.gz" "$work/uv.tar.gz"
verify "$work/uv.tar.gz" "$digest"
tar -xzf "$work/uv.tar.gz" -C "$work" "uv-$target/uv"
uv="$work/uv-$target/uv"
chmod 700 "$uv"
export UV_CACHE_DIR="$runtime/cache"
export UV_PYTHON_INSTALL_DIR="$runtime/python"
# Managed Python avoids depending on Command Line Tools/Homebrew/system Python.
if [ -t 0 ]; then
  "$uv" run --no-project --no-config --managed-python --python 3.13 "$work/setup.py" --auto-prepare "$@"
elif [ -r /dev/tty ] && [ "${1:-}" != --prepare-only ]; then
  "$uv" run --no-project --no-config --managed-python --python 3.13 "$work/setup.py" --auto-prepare "$@" < /dev/tty
else
  "$uv" run --no-project --no-config --managed-python --python 3.13 "$work/setup.py" --auto-prepare "$@"
fi
