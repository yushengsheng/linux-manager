"""Explicitly isolated development harness; never uses the original server profile."""
from pathlib import Path
import json
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager.models import Connection, Store, Redactor, atomic_private
from linux_manager.controller import Controller


def main():
    private = Path("/private/tmp/linux-manager-development")
    value = json.loads((private / "test-connection.json").read_text())
    old = Path(__file__).resolve().parents[1] / "scripts/.rename_account_gui_state.json"
    if old.exists() and json.loads(old.read_text()).get("host") == value["host"]:
        raise SystemExit("Development target rejected: original server is protected.")
    if not value.pop("test_only", False):
        raise SystemExit("Development target must be explicitly isolated.")
    state = private / "current.json"
    if state.exists():
        current = json.loads(state.read_text())
        if current.get("host") != value["host"]:
            raise SystemExit("Development target changed; isolated test connection required.")
        value = current
    conn = Connection(**value)
    if not state.exists():
        # Persist a stable identity before the first connection, even if it fails.
        atomic_private(state, json.dumps(conn.__dict__, ensure_ascii=False))
    redactor = Redactor(conn.host, conn.username, conn.password, conn.sudo_password, conn.key_path)
    controller = Controller(Store(Path.cwd() / "data/linux-manager"))
    ssh = controller.transport(conn)
    conn.validate()
    if not ssh.trusted():
        _, keys = ssh.fingerprint()
        ssh.trust(keys)
        print("Test server identity recorded locally.", flush=True)
    mode = sys.argv[1] if len(sys.argv) > 1 else "inspect"
    if mode == "inspect":
        report = controller.inspect(conn)
        atomic_private(private / "snapshot.json", json.dumps(report, ensure_ascii=False))
        print(json.dumps({"target": "isolated-test-server", "os": report["os"], "architecture": report["architecture"], "supported": report["supported"], "login_accounts": len(report["accounts"]), "disk_free_gib": round(report["disk_free"] / 1024 ** 3, 1), "memory_gib": round(report["memory"].get("MemTotal", 0) / 1024 ** 3, 1), "services": {k: [u.get("ActiveState") for u in v] for k, v in report["services"].items()}, "ssh_password_enabled": report["ssh"].get("passwordauthentication"), "firewall_active": report["firewall"]["active"]}, ensure_ascii=False), flush=True)
    else:
        params = json.loads((private / "operation.json").read_text())
        redactor.add(*(v for v in params.values() if isinstance(v, str)))
        last = None
        def progress(status):
            nonlocal last
            current = (status.get("state"), status.get("message"))
            if current != last:
                print(redactor.text(status.get("message", "")), flush=True)
                last = current
        status, updated = controller.execute(conn, params, progress)
        atomic_private(state, json.dumps(updated.__dict__, ensure_ascii=False))
        safe_result = {k: v for k, v in status.get("result", {}).items() if k in {"service", "version", "port", "verified", "enabled", "automatic_reboot", "restored"}}
        print("TEST_OPERATION_RESULT", json.dumps(safe_result, ensure_ascii=False), flush=True)
    controller.store.save([conn])
    atomic_private(state, json.dumps(conn.__dict__, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No traceback or raw subprocess exception can expose a credential.
        print("TEST_FAILURE", str(error) if error.__class__.__name__ == "ManagerError" else error.__class__.__name__, flush=True)
        raise SystemExit(1)
