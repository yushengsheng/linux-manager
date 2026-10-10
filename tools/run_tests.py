"""Run local tests and redact paths/connection values before returning output."""
from pathlib import Path
import json
import re
import subprocess
import sys

base = Path(__file__).resolve().parents[1]
values = [str(base)]
for path in [base / "scripts/.rename_account_gui_state.json", Path("/private/tmp/linux-manager-development/current.json")]:
    if path.is_file():
        data = json.loads(path.read_text())
        values.extend(v for v in data.values() if isinstance(v, str) and v)
result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=base, capture_output=True, text=True)
output = result.stdout + result.stderr
for value in sorted(values, key=len, reverse=True):
    output = output.replace(value, "[local-value]")
output = re.sub(r"(?:\d{1,3}\.){3}\d{1,3}", "[address]", output)
print(output[-8000:] if result.returncode else "\n".join(output.strip().splitlines()[-5:]))
raise SystemExit(result.returncode)
