"""Read-only final checks; return no connection parameters or credentials."""
from pathlib import Path
import json
import pwd
import subprocess


def output(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=20).stdout.strip()


groups = {
    "exchange": ["xiaojun-exchange-web.service", "xiaojun-exchange-worker.service", "xiaojun-exchange-nginx.service"],
    "hysteria2": ["sing-box.service"],
    "xui": ["x-ui.service"],
    "nginx": ["nginx.service"],
}
policy = {}
for line in output(["/usr/sbin/sshd", "-T"]).splitlines():
    field, _, value = line.partition(" ")
    if field in {"port", "passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin"}:
        policy.setdefault(field, []).append(value)
pending = 0
completed_operations = {}
for file in Path("/var/lib/linux-server-manager/tasks").glob("*/status.json"):
    item = json.loads(file.read_text())
    pending += item.get("state") in {"queued", "running", "awaiting_verification", "recovery_failed"}
    if item.get("state") == "succeeded":
        operation = item.get("operation")
        completed_operations[operation] = completed_operations.get(operation, 0) + 1
result = {
    "services_active": {kind: all(output(["systemctl", "is-active", unit]) == "active" for unit in units) for kind, units in groups.items()},
    "services_enabled": {kind: all(output(["systemctl", "is-enabled", unit]) == "enabled" for unit in units) for kind, units in groups.items()},
    "certificate_renewal_timer_active": output(["systemctl", "is-active", "linux-manager-cert-renew.timer"]) == "active",
    "certificate_renewal_timer_enabled": output(["systemctl", "is-enabled", "linux-manager-cert-renew.timer"]) == "enabled",
    "ssh_original_port_restored": policy.get("port") == ["22"],
    "ssh_password_disabled": policy.get("passwordauthentication") == ["no"],
    "ssh_interactive_password_disabled": policy.get("kbdinteractiveauthentication") == ["no"],
    "ssh_root_disabled": policy.get("permitrootlogin") == ["no"],
    "temporary_test_accounts_removed": not any(row.pw_name.startswith("lmcheck_") for row in pwd.getpwall()),
    "unfinished_tasks": pending,
    "completed_operation_counts": completed_operations,
}
print(json.dumps(result))
