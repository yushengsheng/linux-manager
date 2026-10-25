#!/bin/sh
# Published by build_new_api_mirror.py after all mirrored assets are verified.
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" != 0 ] || fail '请使用日常桌面账号运行，不要 sudo 或 root。'
command -v curl >/dev/null 2>&1 || fail '系统没有 curl，无法联网准备；请让系统管理员安装网络下载组件。'
origin=${NEWAPI_SETUP_ORIGIN:-}
origin=${origin%/}; origin=${origin%/v1}
case "$origin" in https://*) ;; *) fail '请先输入有效的 New API HTTPS 根地址。' ;; esac
case "$origin" in *'@'*|*'?'*|*'#'*|*' '*|*'
'*) fail '地址不能包含账号、查询参数或空白。' ;; esac
NEWAPI_SETUP_ORIGIN=$origin
NEWAPI_DOWNLOAD_BASE=$origin/client-setup
export NEWAPI_SETUP_ORIGIN NEWAPI_DOWNLOAD_BASE
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
download() {
  code=$(curl --proto '=https' --tlsv1.2 -fsS --retry 2 --connect-timeout 20 --max-time 300 --write-out '%{http_code}' "$1" -o "$2" 2>"$work/network-error") || fail '服务器组件下载失败，请检查网络和 HTTPS 证书。'
  [ "$code" = 200 ] || fail '服务器组件未正常返回；不会转到其他下载站。'
}
verify() {
  if command -v shasum >/dev/null 2>&1; then got=$(shasum -a 256 "$1");
  elif command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$1");
  else fail '系统缺少 SHA-256 校验工具，已停止。'; fi
  [ "${got%% *}" = "$2" ] || fail '下载校验失败，未执行下载内容。'
}
printf '%s\n' '正在从服务器检查并准备运行环境，首次可能需要下载，请稍候…'
setup_digest=__SETUP_SHA256__
download "$NEWAPI_DOWNLOAD_BASE/releases/$setup_digest/new_api_setup.py" "$work/setup.py"
verify "$work/setup.py" "$setup_digest"
download "$NEWAPI_DOWNLOAD_BASE/uv/0.13.5/uv-$target.tar.gz" "$work/uv.tar.gz"
verify "$work/uv.tar.gz" "$digest"
tar -xzf "$work/uv.tar.gz" -C "$work" "uv-$target/uv"
uv="$work/uv-$target/uv"
chmod 700 "$uv"
export UV_CACHE_DIR="$runtime/cache"
export UV_PYTHON_INSTALL_DIR="$runtime/python"
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1
unset UV_PYTHON_DOWNLOADS_JSON_URL
"$uv" python install 3.13.17 --mirror "$NEWAPI_DOWNLOAD_BASE/python" --no-bin --no-registry --no-config --system-certs >"$work/python-log" 2>&1 || fail '无法从服务器准备 Python；未修改连接配置。'
# Python is already installed; uv cannot contact a package/download site here.
if [ -t 0 ]; then
  "$uv" run --offline --no-project --no-config --managed-python --python 3.13.17 "$work/setup.py" --auto-prepare "$@"
elif [ -r /dev/tty ] && [ "${1:-}" != --prepare-only ]; then
  "$uv" run --offline --no-project --no-config --managed-python --python 3.13.17 "$work/setup.py" --auto-prepare "$@" < /dev/tty
else
  "$uv" run --offline --no-project --no-config --managed-python --python 3.13.17 "$work/setup.py" --auto-prepare "$@"
fi
