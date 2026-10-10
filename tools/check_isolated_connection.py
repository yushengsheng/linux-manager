"""Read-only check using local aliases; never accepts a changed host identity."""
from pathlib import Path
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    from linux_manager.models import Connection, atomic_private
    from linux_manager.transport import SSH
    private = Path("/private/tmp/linux-manager-development")
    approved = json.loads((private / "test-connection.json").read_text())
    old = Path("scripts/.rename_account_gui_state.json")
    if not approved.get("test_only") or (old.exists() and json.loads(old.read_text()).get("host") == approved["host"]):
        raise RuntimeError("target rejected")
    current = json.loads((private / "current.json").read_text())
    if current.get("host") != approved["host"]: raise RuntimeError("target changed")
    tracked = json.loads((private / "bundle-process.json").read_text())
    data = Path(tracked["data"])
    records = json.loads((data / "profiles.json").read_text())
    native = next((p for p in records if p.get("host") == approved["host"] and p.get("username") == current.get("username")), None)
    known = data / "ssh" / (native or current)["identifier"] / "known_hosts"
    # Work under our private test folder: the native application's data is read only.
    connection = Connection(**current)
    transport = SSH(connection, private / "readonly-identity-check")
    if not known.exists():
        print(json.dumps({"target": "isolated-test", "state": "identity_confirmation_required"})); return
    result = subprocess.run(["ssh-keygen", "-lf", str(known)], capture_output=True, text=True, timeout=5)
    saved = {line.split()[1] for line in result.stdout.splitlines() if len(line.split()) > 1}
    fingerprints, keys = transport.fingerprint()
    if not set(fingerprints.splitlines()) <= saved:
        print(json.dumps({"target": "isolated-test", "state": "changed_identity_requires_local_confirmation"})); return
    atomic_private(transport.known_hosts, known.read_bytes())
    report = transport.call({"action": "snapshot"})
    atomic_private(private / "snapshot.json", json.dumps(report, ensure_ascii=False))
    print(json.dumps({"target": "isolated-test", "state": "connected_readonly", "supported": report["supported"], "accounts": len(report["accounts"]), "installed_projects": sum(any(u.get("LoadState") == "loaded" for u in units) for units in report["services"].values())}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"target": "isolated-test", "state": "check_failed", "detail": "原始连接诊断不向外输出"}, ensure_ascii=False))
        raise SystemExit(1)
