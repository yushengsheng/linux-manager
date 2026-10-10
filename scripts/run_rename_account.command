#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
exec /usr/bin/env python3 "$SCRIPT_DIR/rename_account_gui.py"
