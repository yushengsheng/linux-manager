"""Read-only real SSH lifecycle regression against the disposable-server alias."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time

BASE = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BASE))
from linux_manager.controller import Controller
from linux_manager.models import Connection, Store, atomic_private
from linux_manager.transport import Askpass

PRIVATE = Path("/private/tmp/linux-manager-development")


def peer(ssh):
    c = ssh.connection
    with tempfile.TemporaryDirectory(prefix="peer-", dir=PRIVATE) as directory:
        folder = Path(directory)
        with Askpass(folder, c.password if c.auth == "password" else c.key_passphrase) as environment:
            config = ssh._config(folder)
            result = subprocess.run(["ssh", "-F", str(config), "-T", "linux-manager-server", 'printf "%s" "$SSH_CONNECTION"'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25, env=os.environ | environment, start_new_session=True)
        assert result.returncode == 0 and len(result.stdout.split()) == 4
        return result.stdout


def passed(name):
    print(json.dumps({"check": name, "result": "passed"}), flush=True)


def main():
    state = json.loads((PRIVATE / "bundle-process.json").read_text())
    store = Store(Path(state["data"]))
    legacy = json.loads((BASE / "scripts/.rename_account_gui_state.json").read_text())
    profiles = [p for p in store.profiles() if p.host != legacy["host"]]
    assert len(profiles) == 1 and not store.last_warning
    c = profiles[0]; controller = Controller(store)
    try:
        controller.keep_connection(c)
        master = controller.connections.sessions[c.identifier]
        initial = master.process.pid
        first = peer(controller.transport(c)); second = peer(controller.transport(c))
        assert first == second
        assert peer(controller.transport(c, fresh=True)) != first
        passed("authenticated_master_reused_and_security_verification_fresh")
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            assert master.process.poll() is None and master.process.pid == initial
            time.sleep(1)
        assert peer(controller.transport(c)) == first
        passed("idle_connection_retained_across_multiple_keepalive_intervals")
        master.process.terminate()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if master.process and master.process.pid != initial and controller.connection_status(c)["state"] == "connected":
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("automatic_reconnection_not_observed")
        assert controller.transport(c).call({"action": "ping"})["root_access"] is True
        passed("interrupted_transport_automatically_reconnected_without_replaying_tasks")
        other = c.changed(identifier=Connection().identifier)
        candidate = controller.transport(other, fresh=True)
        atomic_private(candidate.known_hosts, controller.transport(c).known_hosts.read_bytes())
        controller.keep_connection(other)
        second_master = controller.connections.sessions[other.identifier]
        controller.disconnect_connection(c.identifier); master.thread.join(3)
        assert not master.thread.is_alive() and controller.connection_status(c)["state"] == "disconnected"
        assert controller.transport(other).call({"action": "ping"})["root_access"] is True
        assert second_master.process.poll() is None
        passed("manual_disconnect_stops_retry_and_preserves_other_connection")
        controller.close_connections(); second_master.thread.join(3)
        assert second_master.process.poll() is not None and not second_master.thread.is_alive()
        assert not master.control_path.parent.exists() and not second_master.control_path.parent.exists()
        passed("application_shutdown_reaps_owned_masters_and_removes_local_sockets")
        atomic_private(PRIVATE / "connection-regression-result.json", json.dumps({"persistent_connection_tests_passed": True}))
    finally:
        controller.close_connections()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        atomic_private(PRIVATE / "connection-regression-error.txt", type(error).__name__ + ": " + str(error))
        print(json.dumps({"connection_regression": "failed", "failure_type": type(error).__name__}), flush=True)
        raise SystemExit(1)
