#!/bin/sh
# Source launcher only. Standalone desktop packages include their own runtime.
probe='import sys, signal; signal.alarm(8); assert sys.version_info >= (3, 11); import tkinter, tomllib, segno; root=tkinter.Tk(); root.withdraw(); root.destroy()'
for candidate in \
    "${LINUX_MANAGER_PYTHON:-}" \
    "${1:-}/.venv/bin/python3" \
    "$HOME"/.local/share/uv/python/*/bin/python3 \
    "$HOME"/.local/share/uv/python/*/bin/python3.* \
    /opt/homebrew/bin/python3 /usr/local/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.*/bin/python3 \
    "$(command -v python3 2>/dev/null)"
do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    if "$candidate" -c "$probe" >/dev/null 2>&1; then
        printf '%s\n' "$candidate"
        exit 0
    fi
done
exit 1
