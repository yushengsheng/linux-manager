"""Root-side, allowlisted operations. Sent over SSH stdin; no arbitrary-command UI."""
from __future__ import annotations

import base64
import contextlib
import configparser
import datetime
import fcntl
import fnmatch
import grp
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path("/var/lib/linux-server-manager")
UNITS = {
    "exchange": ["xiaojun-exchange-web.service", "xiaojun-exchange-worker.service", "xiaojun-exchange-nginx.service"],
    "hysteria2": ["sing-box.service"],
    "reality": ["linux-manager-xray.service"],
    "xui": ["x-ui.service"],
    "nginx": ["nginx.service"],
}
JOB_ACTIONS = {"deploy", "uninstall", "create_admin", "rename_user", "password", "ssh", "firewall", "updates", "backup", "restore", "service", "account_access", "delete_user", "ssh_hardening", "fail2ban", "prepare_key", "login_policy", "retire_key"}
TASK = None
SECRETS = set()
APT_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
UPDATE_CONFIG = "/etc/apt/apt.conf.d/90-linux-manager-updates"
CERTIFICATE_CONFIG = "/etc/linux-server-manager/letsencrypt"
CERTIFICATE_WEBROOT = "/var/lib/linux-manager-acme-webroot"
NGINX_MANAGED_SITE = "/etc/nginx/conf.d/linux-manager-default.conf"
NGINX_ACME_SITE = "/etc/nginx/conf.d/linux-manager-acme.conf"


def update_configuration_paths():
    return [UPDATE_CONFIG, *(f"/etc/systemd/system/{unit}.d/90-linux-manager-updates.conf" for unit in APT_TIMERS)]
#LM_BUNDLED_CERTBOT#


class OperationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise OperationError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def private_write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2))


def clean(value):
    text = str(value)
    for secret in sorted(SECRETS, key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", "[服务器地址]", text)
    text = re.sub(r"(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*)[^\s,;]+", r"\1[已隐藏]", text)
    text = re.sub(r"(?:hysteria2|hy2|ss|vmess|vless|trojan)://\S+", "[连接信息已隐藏]", text)
    return text


def register_secrets(params):
    for key, value in params.items():
        if isinstance(value, str) and (re.search(r"password|secret|token|key|host|user|account", key, re.I)):
            SECRETS.add(value)


def command(args, *, input=None, timeout=45, check=True, env=None):
    try:
        result = subprocess.run(args, input=input, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=os.environ | (env or {}))
    except subprocess.TimeoutExpired:
        raise OperationError("执行超时，已保留任务记录。请先检查状态再重试。") from None
    except FileNotFoundError:
        raise OperationError("服务器缺少所需的系统工具，请先安装相关服务或依赖。") from None
    if check and result.returncode:
        details = clean((result.stderr or result.stdout).strip())[-1500:]
        raise OperationError("执行失败：" + (details or "系统工具返回错误，请查看任务记录。"))
    return result


def step(message, percent=None):
    if TASK:
        status = json.loads((TASK / "status.json").read_text())
        status["message"] = clean(message)
        if percent is not None:
            status["progress"] = percent
        status["updated"] = now()
        status.setdefault("events", []).append({"time": now(), "message": clean(message)})
        status["events"] = status["events"][-120:]
        write_json(TASK / "status.json", status)


def username(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value), "账号名格式不正确。")
    return value


def port(value):
    require(not isinstance(value, bool), "端口格式不正确。")
    try:
        value = int(value)
    except (ValueError, TypeError):
        raise OperationError("端口必须为整数。") from None
    require(1 <= value <= 65535, "端口必须在 1 至 65535 之间。")
    return value


def password(value):
    require(isinstance(value, str) and 12 <= len(value) <= 256 and not any(x in value for x in "\n\r\x00"), "新密码至少 12 位，且不能包含换行。")
    SECRETS.add(value)
    return value


def host(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value), "访问地址必须是 IPv4 或域名。")
    SECRETS.add(value)
    return value


def unit_info(unit):
    data = {}
    result = command(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,Description,FragmentPath,DropInPaths"], check=False)
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value
    return data


def listeners():
    result = command(["ss", "-lntupH"], check=False)
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        address, _, number = fields[4].rpartition(":")
        if number.isdigit():
            rows.append({"protocol": fields[0], "port": int(number), "local_only": address.strip("[]") in {"127.0.0.1", "::1"} or address.startswith("127."), "processes": sorted(set(re.findall(r'\("([^"\n]+)"', line)))})
    return rows


def ensure_port_available(number, protocol="tcp"):
    number = port(number)
    require(not any(x["port"] == number and x["protocol"] == protocol for x in listeners()), "所选端口已经被使用，请选择其他端口。")


def account_snapshot():
    rows = []
    shadows = {line.split(":")[0]: line.split(":")[1] for line in Path("/etc/shadow").read_text().splitlines() if ":" in line}
    blocked = managed_accounts()
    denied = " ".join(ssh_configuration().get("denyusers", [])).split()
    for user in pwd.getpwall():
        groups = [g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem or g.gr_gid == user.pw_gid]
        keyfile = Path(user.pw_dir) / ".ssh/authorized_keys"
        count = 0
        if keyfile.is_file():
            count = sum(bool(re.search(r"\b(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+", line)) for line in keyfile.read_text().splitlines() if not line.lstrip().startswith("#"))
        value = shadows.get(user.pw_name)
        state = "unknown" if value is None else "locked" if value.startswith(("!", "*")) else "set" if value else "empty"
        rows.append({"username": user.pw_name, "uid": user.pw_uid, "gid": user.pw_gid, "groups": groups, "home": user.pw_dir, "shell": user.pw_shell, "system": user.pw_uid != 0 and not 1000 <= user.pw_uid < 65534, "admin": user.pw_uid == 0 or "sudo" in groups, "key_count": count, "password_state": state, "managed_blocked": user.pw_name in blocked, "ssh_denied": any(fnmatch.fnmatchcase(user.pw_name, item) for item in denied if "@" not in item)})
    return rows


def ssh_configuration(context=None):
    result = command(["/usr/sbin/sshd", "-T"] + (["-C", context] if context else []), check=False)
    fields = {"port", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods", "allowusers", "denyusers", "allowgroups", "denygroups", "authorizedkeysfile", "maxauthtries", "x11forwarding", "allowagentforwarding", "allowtcpforwarding", "logingracetime", "clientaliveinterval", "clientalivecountmax", "permitemptypasswords", "loglevel"}
    values = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in fields:
            values.setdefault(key, []).append(value)
    values["valid"] = command(["/usr/sbin/sshd", "-t"], check=False).returncode == 0
    values["query_valid"] = result.returncode == 0
    return values


def account_details(request):
    account = username(request.get("username"))
    row = next((u for u in account_snapshot() if u["username"] == account), None)
    require(row is not None, "所选账号已不存在，请刷新用户列表。")
    parts = globals().get("SSH_CONTEXT", "").split()
    context = "user=" + account
    if len(parts) == 4:
        context += ",addr=" + parts[0] + ",host=" + parts[0] + ",laddr=" + parts[2] + ",lport=" + parts[3]
    policy = ssh_configuration(context)
    require(policy.get("query_valid"), "按账号查询 SSH 策略失败，请先检查服务器配置。")
    row.update(ssh=policy, context_available=len(parts) == 4, policy_scope="当前连接地址；涉及主机名的条件仍需核对" if len(parts) == 4 else "按账号查询；当前来源地址不可用，地址条件需核对")
    keyfile = Path(row["home"]) / ".ssh/authorized_keys"
    row["public_key_fingerprints"] = []
    if keyfile.is_file():
        output = command(["ssh-keygen", "-lf", str(keyfile)], check=False).stdout
        row["public_key_fingerprints"] = [line.split()[1] for line in output.splitlines() if len(line.split()) > 1 and line.split()[1].startswith("SHA256:")]
    shadow = next((line.split(":") for line in Path("/etc/shadow").read_text().splitlines() if line.split(":", 1)[0] == account), [])
    row["account_expiry"] = shadow[7] if len(shadow) > 7 and shadow[7] else "未设定"
    row["password_expiry_days"] = shadow[4] if len(shadow) > 4 and shadow[4] else "未设定"
    sudo = command(["sudo", "-n", "-l", "-U", account], check=False)
    row["sudo_policy"] = "含免密码 sudo 规则" if "NOPASSWD:" in sudo.stdout else "有 sudo 规则，通常需要系统密码" if sudo.returncode == 0 else "未发现可用 sudo 规则"
    return row


def firewall_snapshot():
    if not shutil.which("ufw"):
        return {"installed": False, "active": False, "rules": ""}
    result = command(["ufw", "status", "verbose"], check=False)
    return {"installed": True, "active": "Status: active" in result.stdout, "rules": clean(result.stdout)}


def update_timer_states():
    timers = {}
    for unit in APT_TIMERS:
        result = command(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState,NextElapseUSecRealtime,Persistent"], check=False)
        timers[unit] = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line) if result.returncode == 0 else {}
    return timers


def automatic_updates_snapshot():
    installed = bool(shutil.which("unattended-upgrade"))
    result = command(["apt-config", "dump"], check=False) if shutil.which("apt-config") else None
    valid = result is not None and result.returncode == 0
    values = dict(re.findall(r'^\s*(APT::Periodic::(?:Enable|Update-Package-Lists|Unattended-Upgrade)|Unattended-Upgrade::Automatic-Reboot)\s+"([^"\n]*)";', result.stdout, re.M)) if valid else {}
    origins = bool(valid and re.search(r'^\s*Unattended-Upgrade::(?:Allowed-Origins|Origins-Pattern)::\s+"[^"\n]+";', result.stdout, re.M))
    periodic = values.get("APT::Periodic::Enable", "1").lower() not in {"0", "false", "no"}
    lists = values.get("APT::Periodic::Update-Package-Lists", "0")
    upgrades = values.get("APT::Periodic::Unattended-Upgrade", "0")
    def interval_enabled(value):
        return value == "always" or (value.isdigit() and int(value) > 0)
    timers = update_timer_states()
    def scheduled(unit, state):
        if state.get("LoadState") != "loaded" or state.get("UnitFileState") != "enabled" or state.get("ActiveState") != "active":
            return False
        next_run = state.get("NextElapseUSecRealtime", "")
        if state.get("SubState") == "waiting" and next_run not in {"", "n/a", "0", "infinity"}:
            return True
        # A timer can temporarily have no next deadline while its job is executing.
        return state.get("SubState") == "running" and unit_info(unit.replace(".timer", ".service")).get("ActiveState") in {"active", "activating"}
    active = installed and valid and periodic and origins and interval_enabled(lists) and interval_enabled(upgrades) and all(scheduled(unit, state) for unit, state in timers.items())
    return {"active": active, "installed": installed, "config_valid": valid, "periodic_enabled": periodic if valid else False, "package_lists_interval": lists, "upgrade_interval": upgrades, "origins_configured": origins, "automatic_reboot": values.get("Unattended-Upgrade::Automatic-Reboot", "false").lower() not in {"false", "no", "0"} if valid else None, "timers": timers}


def restore_update_timers(timers):
    command(["systemctl", "daemon-reload"])
    current = update_timer_states()
    for unit in APT_TIMERS:
        previous = timers[unit]
        if current[unit].get("UnitFileState") != previous.get("UnitFileState"):
            require(previous.get("UnitFileState") in {"enabled", "disabled"}, "原更新定时器使用自定义启动方式，不能自动恢复；请查看任务记录。")
            command(["systemctl", "enable" if previous["UnitFileState"] == "enabled" else "disable", unit])
        if (current[unit].get("ActiveState") == "active") != (previous.get("ActiveState") == "active"):
            command(["systemctl", "start" if previous.get("ActiveState") == "active" else "stop", unit])
    current = update_timer_states()
    require(all(current[unit].get("UnitFileState") == timers[unit].get("UnitFileState") and (current[unit].get("ActiveState") == "active") == (timers[unit].get("ActiveState") == "active") for unit in APT_TIMERS), "更新定时器原状态恢复未通过，请查看任务记录。")


def snapshot(include_projects=False, address=""):
    release = platform.freedesktop_os_release()
    disk = shutil.disk_usage("/")
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(value.strip().split()[0]) * 1024
    services = {key: [{"unit": unit, **unit_info(unit)} for unit in units] for key, units in UNITS.items()}
    supported = (release.get("ID"), release.get("VERSION_ID")) in {("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}
    protection = unit_info("fail2ban.service")
    jail = command(["fail2ban-client", "status", "linux-manager-sshd"], check=False) if shutil.which("fail2ban-client") else None
    updates = automatic_updates_snapshot()
    result = {"os": release.get("PRETTY_NAME", "Linux"), "architecture": platform.machine(), "supported": supported, "disk_total": disk.total, "disk_free": disk.free, "memory": memory, "load": list(os.getloadavg()), "accounts": account_snapshot(), "ssh": ssh_configuration(), "firewall": firewall_snapshot(), "services": services, "listeners": listeners(), "automatic_updates": updates["active"], "update_status": updates, "fail2ban": {"installed": protection.get("LoadState") == "loaded", "active": bool(jail and jail.returncode == 0)}, "tasks": task_list()}
    if include_projects:
        result["project_details"] = {}
        for kind in UNITS:
            try:result["project_details"][kind]=connection_details({"service":kind,"host":address})
            except Exception:result["project_details"][kind]={"service":kind,"installed":any(unit.get("LoadState")=="loaded" for unit in services[kind]),"units":[{"unit":unit["unit"],**unit} for unit in services[kind]],"information_error":"部分配置信息未能读取，请刷新项目详情。"}
    return result


def validate_task_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{24}", value), "任务编号无效。")
    return value


def task_list():
    rows = []
    if (ROOT / "tasks").exists():
        for path in sorted((ROOT / "tasks").glob("*/status.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
            with contextlib.suppress(OSError, ValueError):
                rows.append(json.loads(path.read_text()))
    return rows


@contextlib.contextmanager
def state_lock(folder):
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (folder / "state.lock").open("a") as stream:
        os.chmod(folder / "state.lock", 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def start_task(params, identifier=None):
    action = params.get("operation")
    require(action in JOB_ACTIONS, "不支持此操作。")
    if identifier is not None:
        validate_task_id(identifier)
    with state_lock(ROOT / "submission"):
        return submit_task(params, identifier)


def submission_digest(params, key):
    # A keyed receipt survives deletion of the secret request without exposing
    # an unkeyed password hash in the public task status.
    encoded = json.dumps(params, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hmac.new(bytes.fromhex(key), encoded, hashlib.sha256).hexdigest()


def submit_task(params, identifier=None):
    action = params["operation"]
    root = ROOT / "tasks"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    identifier = identifier or secrets.token_hex(12)
    directory = root / identifier
    if directory.exists():
        receipt = directory / "submission.json"
        require(receipt.is_file() and (directory / "status.json").is_file(), "任务提交记录不完整，请检查操作记录；不会重复执行。")
        saved = json.loads(receipt.read_text())
        require(hmac.compare_digest(saved["digest"], submission_digest(params, saved["key"])), "任务编号已经用于其他请求，未执行重复提交。")
        return {"task_id": identifier}
    # Changes waiting for independent SSH verification must finish first.
    require(not any(s["state"] in {"queued", "running", "awaiting_verification", "recovery_failed"} for s in task_list()), "另一个任务尚未完成，请先查看操作记录并完成验证或恢复。")
    key = secrets.token_hex(32)
    receipt = {"key": key, "digest": submission_digest(params, key)}
    params = dict(params)
    archive = params.pop("release_archive", None)
    content = None
    if action == "deploy" and archive is not None:
        require(isinstance(params.get("version"), str) and re.fullmatch(r"v\d+\.\d+\.\d+", params["version"]), "请先确认具体发行版本。")
        require(isinstance(archive, str) and len(archive) <= 140 * 1024 * 1024, "请从本地程序传送已校验的发行包。")
        try:
            content = base64.b64decode(archive, validate=True)
        except (ValueError, TypeError):
            raise OperationError("发行包传送格式无效。") from None
        require(0 < len(content) <= 100 * 1024 * 1024 and hashlib.sha256(content).hexdigest() == params.get("release_sha256"), "发行包传送校验失败，未提交安装。")
    directory.mkdir(mode=0o700)
    write_json(directory / "submission.json", receipt)
    if content is not None:
        private_write(directory / "release.tar.gz", content)
    write_json(directory / "request.json", params)
    write_json(directory / "status.json", {"id": identifier, "operation": action, "state": "queued", "progress": 0, "created": now(), "updated": now(), "message": "任务已提交，等待执行。", "events": []})
    private_write(directory / "runner.py", globals().get("AGENT_SOURCE", Path(__file__).read_text() if "__file__" in globals() else ""))
    try:
        command(["systemd-run", "--quiet", "--collect", "--unit=linux-manager-task-" + identifier, "--property=TimeoutStartSec=infinity", "/usr/bin/python3", str(directory / "runner.py"), "run", identifier])
    except Exception:
        (directory / "request.json").unlink(missing_ok=True)
        (directory / "release.tar.gz").unlink(missing_ok=True)
        status = json.loads((directory / "status.json").read_text())
        status.update(state="failed", message="后台任务启动失败。")
        write_json(directory / "status.json", status)
        raise
    return {"task_id": identifier}


def status_task(identifier):
    path = ROOT / "tasks" / validate_task_id(identifier) / "status.json"
    require(path.is_file(), "没有找到该任务。")
    return json.loads(path.read_text())


def snapshot_panel_database(source, destination):
    # Copy committed WAL contents into a standalone, closed database. WAL/SHM
    # files belong to the running process and must not enter restore metadata.
    mode = source.stat().st_mode & 0o777
    for suffix in ["", "-wal", "-shm"]:
        Path(str(destination) + suffix).unlink(missing_ok=True)
    with contextlib.closing(sqlite3.connect("file:" + str(source) + "?mode=ro", uri=True)) as original, contextlib.closing(sqlite3.connect(destination)) as saved:
        original.backup(saved)
        saved.execute("PRAGMA journal_mode=DELETE")
    destination.chmod(mode)


def backup_files(paths, extra=None):
    require(TASK is not None, "配置备份需要后台任务。")
    target = TASK / "backup"
    target.mkdir(mode=0o700, exist_ok=True)
    inventory = []
    for name in paths:
        source = Path(name)
        relative = str(source).lstrip("/")
        row = {"path": str(source), "exists": source.exists() or source.is_symlink(), "directory": source.is_dir(), "symlink": source.is_symlink()}
        if row["exists"]:
            stat = source.lstat()
            row.update(mode=stat.st_mode & 0o777, uid=stat.st_uid, gid=stat.st_gid)
        if source.is_symlink():
            row["link_target"] = os.readlink(source)
        elif source.exists():
            destination = target / "files" / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if source.is_dir():
                panel = str(name) == "/etc/x-ui" and (source / "x-ui.db").is_file()
                def ignore(directory, names):
                    return set(names) & {"x-ui.db", "x-ui.db-wal", "x-ui.db-shm"} if panel and Path(directory) == source else set()
                shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True, ignore=ignore)
                if panel:
                    snapshot_panel_database(source / "x-ui.db", destination / "x-ui.db")
                row["ownership"] = [{"name":str(p.relative_to(source)), "uid":p.lstat().st_uid, "gid":p.lstat().st_gid} for p in source.rglob("*") if not (panel and p.parent == source and p.name in {"x-ui.db-wal", "x-ui.db-shm"})]
            else:
                shutil.copy2(source, destination, follow_symlinks=False)
        inventory.append(row)
    write_json(target / "manifest.json", {"paths": inventory, "extra": extra or {}})
    return target


def restore_files(task):
    target = ROOT / "tasks" / validate_task_id(task) / "backup"
    require((target / "manifest.json").is_file(), "该任务没有可恢复的配置备份。")
    manifest = json.loads((target / "manifest.json").read_text())
    extra = manifest.get("extra", {})
    for row in manifest["paths"]:
        destination = Path(row["path"])
        # Restore only the affected login in account databases. Other users may
        # have been created by an independent package manager in the meantime.
        if destination.name in {"passwd", "shadow", "group", "gshadow", "subuid", "subgid"} and destination.parent == Path("/etc") and extra.get("account_users"):
            source = target / "files" / str(destination).lstrip("/")
            if row["exists"]:
                merged = merge_accounts(destination.name, destination.read_text() if destination.exists() else "", source.read_text(), extra)
                private_write(destination, merged, row.get("mode", 0o600))
                os.chown(destination, row.get("uid", 0), row.get("gid", 0))
            continue
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        if row["exists"]:
            source = target / "files" / str(destination).lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if row.get("symlink"):
                destination.symlink_to(row["link_target"])
            elif row["directory"]:
                shutil.copytree(source, destination, symlinks=True)
            else:
                shutil.copy2(source, destination, follow_symlinks=False)
            if not destination.is_symlink():
                os.chown(destination, row.get("uid", 0), row.get("gid", 0))
            for item in row.get("ownership", []):
                os.chown(destination / item["name"], item["uid"], item["gid"], follow_symlinks=False)
    if extra.get("old_home") and extra.get("new_home"):
        old = Path(extra["old_home"]); new = Path(extra["new_home"])
        if new.exists() and not old.exists():
            shutil.move(str(new), str(old))
    if extra.get("created_home"):
        home = Path(extra["created_home"])
        if home.parent == Path("/home") and home.is_dir():
            shutil.rmtree(home)
    if extra.get("service") == "security":
        # General configuration restore must not undo individual account actions.
        write_account_denials(managed_accounts())
    if "update_timers" in extra:
        restore_update_timers(extra["update_timers"])
    if extra.get("operation") == "updates":
        # Update rollback must not reload SSH or alter firewall/account settings.
        return
    command(["systemctl", "daemon-reload"], check=False)
    if extra.get("deployment"):
        return
    if shutil.which("ufw"):
        if extra.get("firewall_active"):
            command(["ufw", "--force", "enable"], check=False)
        elif "firewall_active" in extra:
            command(["ufw", "--force", "disable"], check=False)
    if command(["systemctl", "is-active", "ssh.socket"], check=False).returncode == 0:
        command(["systemctl", "restart", "ssh.socket"], check=False)
    command(["systemctl", "reload-or-restart", "ssh.service"], check=False)
    if "fail2ban_active" in extra:
        command(["systemctl", "enable" if extra.get("fail2ban_enabled") else "disable", "fail2ban.service"], check=False)
        command(["systemctl", "restart" if extra["fail2ban_active"] else "stop", "fail2ban.service"], check=False)


def merge_accounts(kind, current, previous, extra):
    names = set(extra["account_users"])
    old, new = extra.get("renamed_from"), extra.get("renamed_to")
    original = [line for line in previous.splitlines() if line.split(":", 1)[0] in names]
    if extra.get("deleted_user") and kind in {"passwd", "group"}:
        saved_ids = {line.split(":")[2] for line in original if len(line.split(":")) > 2}
        require(not any(line.split(":", 1)[0] not in names and len(line.split(":")) > 2 and line.split(":")[2] in saved_ids for line in current.splitlines()), "原账号或组编号已被其他账号使用，不能自动恢复；请从云平台检查，程序不会覆盖新账号。")
    result = []
    for line in current.splitlines():
        fields = line.split(":")
        if fields[0] in names:
            continue
        if kind in {"group", "gshadow"}:
            for index in ([3] if kind == "group" else [2, 3]):
                if len(fields) <= index:
                    continue
                members = fields[index].split(",") if fields[index] else []
                if old and new:
                    members = [old if name == new else name for name in members]
                elif extra.get("created_home"):
                    members = [name for name in members if name not in names]
                elif extra.get("deleted_user"):
                    saved = next((row.split(":") for row in previous.splitlines() if row.split(":", 1)[0] == fields[0]), [])
                    if len(saved) > index:
                        members += [name for name in saved[index].split(",") if name in names]
                fields[index] = ",".join(dict.fromkeys(members))
            line = ":".join(fields)
        result.append(line)
    return "\n".join(result + original) + "\n"


def arm_recovery(seconds=180):
    identifier = TASK.name
    command(["systemd-run", "--quiet", "--unit=linux-manager-recover-" + identifier, "--on-active=" + str(seconds) + "s", "/usr/bin/python3", str(TASK / "runner.py"), "recover", identifier])


def recover(identifier):
    folder = ROOT / "tasks" / validate_task_id(identifier)
    require((folder / "status.json").is_file(), "没有找到该任务。")
    # Wait until the runner has finished writing its configuration, then
    # serialize recovery against connection confirmation.
    with (ROOT / "operation.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        with state_lock(folder):
            status = status_task(identifier)
            if status["state"] not in {"awaiting_verification", "running", "recovery_failed"}:
                return
            try:
                operation = status.get("operation")
                if operation == "uninstall":
                    restore_uninstall(identifier)
                elif operation == "deploy":
                    restore_deployment(identifier)
                else:
                    restore_files(identifier)
                message = "卸载未完成，已恢复项目文件和原服务状态。" if operation == "uninstall" else "部署未完成，已恢复原项目和服务状态。" if operation == "deploy" else "新连接未在时限内验证，已恢复原配置。"
                status.update(state="rolled_back", progress=100, updated=now(), message=message)
            except Exception as error:
                status.update(state="recovery_failed", progress=100, updated=now(), message="配置恢复未完成，请通过云平台控制台检查；修复后可再次恢复。", diagnostic=clean(str(error)))
            write_json(folder / "status.json", status)


def confirm_task(identifier):
    identifier = validate_task_id(identifier)
    require(status_task(identifier)["state"] in {"awaiting_verification", "succeeded"}, "此任务没有等待连接验证。")
    with state_lock(ROOT / "tasks" / identifier):
        status = status_task(identifier)
        require(status["state"] in {"awaiting_verification", "succeeded"}, "此任务已经恢复，请重新检查连接。")
        if status["state"] == "awaiting_verification":
            status.update(state="succeeded", progress=100, message="新连接及管理员权限验证成功，配置已生效。", updated=now())
            write_json(ROOT / "tasks" / identifier / "status.json", status)
    # Persist confirmation before stopping the timer, so an already-started
    # watchdog sees the committed state and cannot undo a verified change.
    command(["systemctl", "stop", "linux-manager-recover-" + identifier + ".timer"], check=False)
    return status


def apt(packages):
    step("准备系统依赖…")
    command(["apt-get", "update", "-q"], timeout=300)
    command(["apt-get", "install", "-y", "--no-install-recommends", *packages], timeout=900, env={"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"})


def allow_port(number, protocol="tcp"):
    if shutil.which("ufw"):
        command(["ufw", "allow", str(port(number)) + "/" + protocol])


def system_password(params):
    account = username(params.get("username"))
    require(any(x.pw_name == account for x in pwd.getpwall()), "账号不存在。")
    value = password(params.get("new_password"))
    blocked = managed_accounts()
    backup_files(["/etc/shadow", str(ROOT / "blocked-accounts.json")], {"account_users": [account]})
    arm_recovery()
    command(["chpasswd"], input=account + ":" + value + "\n")
    if account in blocked:
        command(["usermod", "--lock", account])
        shadows = {line.split(":")[0]: line.split(":")[1] for line in Path("/etc/shadow").read_text().splitlines() if ":" in line}
        blocked[account] = {"unlock_on_restore": True, "locked_value": shadows[account]}
        write_json(ROOT / "blocked-accounts.json", blocked)
    return {"verification": {"username": account, "password_changed": True}, "requires_verification": True}


def create_admin(params):
    account = username(params.get("username"))
    require(account != "root", "请为普通管理员选择独立的账号名。")
    require(not any(x.pw_name == account for x in pwd.getpwall()), "账号已经存在，请使用修改密码或账号改名功能。")
    value = password(params.get("new_password"))
    public = params.get("public_key", "").strip()
    require(not public or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?", public), "仅接受有效的 Ed25519 公钥。")
    backup_files(["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"], {"created_home": "/home/" + account, "account_users": [account]})
    arm_recovery()
    command(["useradd", "--create-home", "--shell", "/bin/bash", "--groups", "sudo", account])
    command(["chpasswd"], input=account + ":" + value + "\n")
    user = pwd.getpwnam(account)
    if public:
        folder = Path(user.pw_dir) / ".ssh"
        folder.mkdir(mode=0o700)
        os.chown(folder, user.pw_uid, user.pw_gid)
        private_write(folder / "authorized_keys", public + "\n")
        os.chown(folder / "authorized_keys", user.pw_uid, user.pw_gid)
    policy = Path("/etc/sudoers.d/90-linux-manager-" + account)
    # A new account uses password-authenticated sudo unless explicitly requested.
    private_write(policy, account + " ALL=(ALL:ALL) " + ("NOPASSWD: " if params.get("passwordless_sudo") else "") + "ALL\n", 0o440)
    command(["visudo", "-c"])
    for source in [Path("/etc/ssh/sshd_config"), *Path("/etc/ssh/sshd_config.d").glob("*.conf")]:
        if source.is_file():
            text = source.read_text()
            changed = re.sub(r"(?im)^(\s*AllowUsers\s+)([^\n]+)$", lambda m: m.group(0) if account in m.group(2).split() else m.group(0) + " " + account, text)
            if changed != text:
                private_write(source, changed, source.stat().st_mode & 0o777)
    command(["/usr/sbin/sshd", "-t"])
    command(["systemctl", "reload", "ssh.service"])
    return {"requires_verification": True, "verification": {"username": account, "created": True}}


def rename_user(params):
    old = username(params.get("old_username")); new = username(params.get("new_username"))
    require(old != "root" and new != "root" and old != new, "超级管理员账号不能改名；新旧账号名必须不同。")
    require(not any(x.pw_name == new for x in pwd.getpwall()), "新账号名已存在。")
    user = pwd.getpwnam(old)
    require(1000 <= user.pw_uid < 65534, "不能改名系统服务账号。")
    services = command(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"]).stdout
    for line in services.splitlines():
        unit = line.split()[0]
        owner = command(["systemctl", "show", unit, "--property=User", "--value"], check=False).stdout.strip()
        require(owner != old or unit.startswith("user@"), "该账号正在运行后台服务，请先安排维护；程序不会终止业务进程。")
    allowed = {"sshd", "sshd-session", "bash", "sh", "zsh", "systemd", "(sd-pam)", "dbus-daemon", "dbus-broker"}
    owned = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid == user.pw_uid:
                name = (path / "comm").read_text().strip()
                require(name in allowed, "该账号还有业务进程，请先停止自己的任务后再改名。")
                owned.append(int(path.name))
        except OSError:
            pass
    old_home = Path(user.pw_dir); new_home = old_home.parent / new
    require(old_home.parent == Path("/home") and not new_home.exists(), "只支持标准家目录的普通账号，目标家目录必须不存在。")
    paths = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/cloud/cloud.cfg"]
    backup_files(paths, {"old_home": str(old_home), "new_home": str(new_home), "account_users": [old, new], "renamed_from": old, "renamed_to": new})
    arm_recovery()
    step("正在切换账号，原账号的登录会话将关闭…", 35)
    time.sleep(3)
    for pid in owned:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, 15)
    time.sleep(2)
    # Refuse new processes rather than killing an unverified business process.
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            with contextlib.suppress(OSError):
                if path.stat().st_uid == user.pw_uid:
                    require((path / "comm").read_text().strip() in allowed, "出现新的业务进程，已取消改名并恢复配置。")
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(path.name), 9)
    command(["usermod", "-l", new, old])
    if grp.getgrgid(user.pw_gid).gr_name == old:
        command(["groupmod", "-n", new, old])
    command(["usermod", "-d", str(new_home), "-m", new])
    for source in [Path("/etc/ssh/sshd_config"), *Path("/etc/ssh/sshd_config.d").glob("*.conf"), *Path("/etc/sudoers.d").glob("*"), Path("/etc/cloud/cloud.cfg")]:
        if source.is_file():
            original = source.read_text()
            changed = re.sub(r"(?<![\w-])" + re.escape(old) + r"(?![\w-])", new, original)
            if changed != original:
                private_write(source, changed, source.stat().st_mode & 0o777)
    command(["visudo", "-c"])
    command(["/usr/sbin/sshd", "-t"])
    command(["systemctl", "reload", "ssh.service"])
    return {"requires_verification": True, "verification": {"username": new, "renamed": True}}


def managed_accounts():
    path = ROOT / "blocked-accounts.json"
    return json.loads(path.read_text()) if path.exists() else {}


def ssh_files_without_match():
    files = [Path("/etc/ssh/sshd_config"), *Path("/etc/ssh/sshd_config.d").glob("*.conf")]
    require(not any(re.search(r"^\s*Match\s", file.read_text(), re.M | re.I) for file in files if file.is_file()), "检测到条件式 SSH 配置，无法安全自动修改；请保留现有设置。")
    return files


def security_preflight(request):
    target = username(request.get("username")); current = username(request.get("current_username"))
    release = platform.freedesktop_os_release()
    require((release.get("ID"), release.get("VERSION_ID")) in {("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}, "当前系统尚未支持一键方案；可以先使用只读检查。")
    files = ssh_files_without_match()
    text = Path("/etc/ssh/sshd_config").read_text()
    require(re.search(r"(?im)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*(?:#.*)?$", text), "SSH 配置未使用标准配置目录，无法安全自动应用；请保留当前配置。")
    for file in files:
        for line in file.read_text().splitlines():
            require(not re.match(r"(?i)^\s*Include\s+", line) or re.match(r"(?i)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*(?:#.*)?$", line), "检测到自定义 SSH 配置来源，暂不自动改写。")
    config = ssh_configuration()
    require(config.get("valid") and config.get("query_valid"), "SSH 配置检查失败，请先处理当前配置。")
    require(config.get("pubkeyauthentication") == ["yes"] and config.get("authenticationmethods", ["any"]) in [["any"], ["publickey"]], "当前认证要求包含额外限制，暂不自动替换；请逐项配置。")
    require(config.get("authorizedkeysfile", [".ssh/authorized_keys"])[0].split()[0] == ".ssh/authorized_keys", "当前公钥位置不是标准目录，暂不自动改写。")
    names = {u.pw_name for u in pwd.getpwall()}
    require(target != "root", "请选择普通管理员的账号名。")
    if request.get("mode") == "create":
        require(target not in names, "新账号名已存在，请改名或选择修改现有账号。")
    else:
        user = pwd.getpwnam(current)
        require(1000 <= user.pw_uid < 65534 and "sudo" in [g.gr_name for g in grp.getgrall() if current in g.gr_mem or g.gr_gid == user.pw_gid], "修改模式需要先连接普通管理员；超级管理员请选择新增模式。")
        require(target == current or target not in names, "改名后的账号已存在。")
        if target != current:
            require(Path(user.pw_dir).parent == Path("/home") and not (Path("/home") / target).exists(), "账号家目录不标准或目标目录已存在，不能自动改名。")
    return {"compatible": True}


def prepare_key(params):
    account = username(params.get("username"))
    user = pwd.getpwnam(account)
    public = params.get("public_key", "").strip()
    require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?", public), "公钥格式不正确。")
    keyfile = Path(user.pw_dir) / ".ssh/authorized_keys"
    require(not keyfile.is_symlink() and not keyfile.parent.is_symlink(), "密钥目录使用链接，暂不自动修改。")
    backup_files([str(keyfile)])
    arm_recovery()
    keyfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    keyfile.parent.chmod(0o700); os.chown(keyfile.parent, user.pw_uid, user.pw_gid)
    previous = keyfile.read_text() if keyfile.exists() else ""
    if public not in previous.splitlines():
        private_write(keyfile, previous.rstrip() + "\n" + public + "\n")
    os.chown(keyfile, user.pw_uid, user.pw_gid)
    return {"requires_verification": True, "verification": {"username": account}}


def login_policy(params):
    account = username(params.get("username")); user = pwd.getpwnam(account)
    require(1000 <= user.pw_uid < 65534 and grp.getgrnam("sudo").gr_gid in os.getgrouplist(account, user.pw_gid), "需要已验证的普通管理员，不能锁住唯一超级管理员入口。")
    require((Path(user.pw_dir) / ".ssh/authorized_keys").is_file(), "请先安装并验证密钥。")
    files = ssh_files_without_match()
    previous = ssh_configuration()
    values = {"PermitRootLogin": "no", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "PubkeyAuthentication": "yes", "AuthenticationMethods": "publickey", "PermitEmptyPasswords": "no", "MaxAuthTries": str(min(3, int(previous.get("maxauthtries", ["3"])[0]))), "LoginGraceTime": str(min(60, int(previous.get("logingracetime", ["60"])[0])) or 60), "LogLevel": "VERBOSE", "X11Forwarding": "no", "AllowAgentForwarding": "no"}
    backup_files(["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"])
    arm_recovery()
    fields = {key.lower() for key in values}
    for source in files:
        text = "".join("# linux服务器管理已接管此项: " + line if line.strip() and line.split()[0].lower() in fields else line for line in source.read_text().splitlines(keepends=True))
        private_write(source, text, source.stat().st_mode & 0o777)
    private_write("/etc/ssh/sshd_config.d/00-linux-manager-login.conf", "".join(f"{key} {value}\n" for key, value in values.items()), 0o644)
    command(["/usr/sbin/sshd", "-t"])
    effective = ssh_configuration()
    require(all(effective.get(key.lower()) == [value] for key, value in values.items()), "服务器没有加载完整登录策略，已停止并尝试恢复。")
    command(["systemctl", "reload", "ssh.service"])
    # Deliberately no port, firewall, source-address or TCP forwarding changes.
    return {"requires_verification": True}


def retire_key(params):
    account = username(params.get("username")); user = pwd.getpwnam(account)
    old = params.get("old_public_key", "").split(); new = params.get("public_key", "").split()
    require(len(old) >= 2 and len(new) >= 2 and old[:2] != new[:2], "新旧公钥无效或相同。")
    keyfile = Path(user.pw_dir) / ".ssh/authorized_keys"
    require(keyfile.is_file() and not keyfile.is_symlink() and not keyfile.parent.is_symlink(), "未找到可安全修改的公钥文件。")
    lines = keyfile.read_text().splitlines(keepends=True)
    def identity(line):
        # Quoted command options must not be mistaken for another key's identity.
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            return []
        for i, token in enumerate(tokens[:-1]):
            if token in {"ssh-ed25519", "ssh-rsa"} or token.startswith("ecdsa-sha2-"):
                return [token, tokens[i + 1]]
        return []
    require(any(identity(line) == new[:2] for line in lines), "新公钥尚未安装，不撤销旧钥匙。")
    backup_files([str(keyfile)])
    arm_recovery()
    kept = [line for line in lines if identity(line) != old[:2]]
    private_write(keyfile, "".join(kept)); os.chown(keyfile, user.pw_uid, user.pw_gid)
    return {"requires_verification": True, "removed_keys": len(lines) - len(kept)}


def guarded_account(params):
    account = username(params.get("username"))
    verified = username(params.get("verified_username"))
    require(account != verified and account != "root" and verified != "root", "请先切换到另一个普通管理员；不能禁用或删除当前账号及超级管理员。")
    try:
        user = pwd.getpwnam(account)
        admin = pwd.getpwnam(verified)
    except KeyError:
        raise OperationError("所选账号或备用管理员不存在。") from None
    require(1000 <= user.pw_uid < 65534 and 1000 <= admin.pw_uid < 65534, "系统服务账号不能使用此功能。")
    require(grp.getgrnam("sudo").gr_gid in os.getgrouplist(verified, admin.pw_gid), "备用账号需要属于 sudo 管理员组。")
    return user, verified


def write_account_denials(accounts):
    path = Path("/etc/ssh/sshd_config.d/02-linux-manager-accounts.conf")
    private_write(path, "# Managed SSH login restrictions\n" + ("DenyUsers " + " ".join(sorted(accounts)) + "\n" if accounts else ""), 0o644)
    command(["/usr/sbin/sshd", "-t"])
    effective = " ".join(ssh_configuration().get("denyusers", [])).split()
    require(all(account in effective for account in accounts), "服务器未加载登录禁用配置，已取消变更。")
    command(["systemctl", "reload", "ssh.service"])


def account_access(params):
    user, verified = guarded_account(params)
    ssh_files_without_match()
    records = managed_accounts()
    blocked = params.get("blocked")
    require(isinstance(blocked, bool), "请选择禁止或恢复登录。")
    require(blocked or user.pw_name in records, "这个账号没有被本程序禁用；不会改写其他人的限制。")
    require(not blocked or user.pw_name not in records, "这个账号已经被本程序禁用。")
    paths = ["/etc/shadow", "/etc/ssh/sshd_config.d/02-linux-manager-accounts.conf", str(ROOT / "blocked-accounts.json")]
    backup_files(paths, {"account_users": [user.pw_name]})
    arm_recovery()
    shadows = {line.split(":")[0]: line.split(":")[1] for line in Path("/etc/shadow").read_text().splitlines() if ":" in line}
    original = shadows.get(user.pw_name, "")
    if blocked:
        records[user.pw_name] = {"unlock_on_restore": bool(original and not original.startswith(("!", "*"))), "locked_value": "!" + original if original and not original.startswith("!") else original}
        command(["usermod", "--lock", user.pw_name])
    else:
        saved = records.pop(user.pw_name)
        # An independent password change must never be undone by this button.
        if saved.get("unlock_on_restore") and original == saved.get("locked_value"):
            command(["usermod", "--unlock", user.pw_name])
    write_json(ROOT / "blocked-accounts.json", records)
    write_account_denials(records)
    return {"requires_verification": True, "verification": {"username": verified}, "blocked": blocked}


def require_unused_account(user):
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            try:
                require(path.stat().st_uid != user.pw_uid, "账号还有运行进程，不能删除；请先自行安排维护。")
            except OSError:
                pass
    units = command(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain"]).stdout
    for line in units.splitlines():
        if not line.strip():
            continue
        unit = line.split()[0]
        owner = command(["systemctl", "show", unit, "--property=User", "--value"], check=False).stdout.strip()
        require(owner not in {user.pw_name, str(user.pw_uid)}, "账号被系统服务使用，不能删除；请先处理对应服务。")
    require(not any(path.exists() for path in [Path("/var/spool/cron/crontabs") / user.pw_name, Path("/var/spool/cron") / user.pw_name]), "账号仍有定时任务，不能删除。")
    for path in [Path("/etc/crontab"), *Path("/etc/cron.d").glob("*")]:
        if path.is_file():
            for line in path.read_text().splitlines():
                fields = line.split()
                if not fields or fields[0].startswith("#"):
                    continue
                index = 1 if fields[0].startswith("@") else 5
                require(len(fields) <= index or fields[index] != user.pw_name, "账号仍有系统定时任务，不能删除。")


def delete_user(params):
    user, verified = guarded_account(params)
    ssh_files_without_match()
    require_unused_account(user)
    expression = re.compile(r"(?<![\w-])" + re.escape(user.pw_name) + r"(?![\w-])")
    sudoers = Path("/etc/sudoers")
    require(not sudoers.exists() or not any(expression.search(line) for line in sudoers.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")), "主 sudo 配置仍引用这个账号，请先处理该配置后再删除。")
    paths = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid", "/etc/sudoers.d", "/etc/ssh/sshd_config.d/02-linux-manager-accounts.conf", str(ROOT / "blocked-accounts.json")]
    backup_files(paths, {"account_users": [user.pw_name], "deleted_user": user.pw_name})
    arm_recovery()
    # No --remove and no --force: leave the home directory and owned files intact.
    command(["userdel", user.pw_name])
    for path in Path("/etc/sudoers.d").glob("*"):
        if path.is_file():
            text = path.read_text()
            changed = "".join("# linux服务器管理：已删除账号的规则 " + line if expression.search(line) and not line.lstrip().startswith("#") else line for line in text.splitlines(keepends=True))
            if text != changed:
                private_write(path, changed, path.stat().st_mode & 0o777)
    command(["visudo", "-c"])
    records = managed_accounts()
    records.pop(user.pw_name, None)
    write_json(ROOT / "blocked-accounts.json", records)
    write_account_denials(records)
    return {"requires_verification": True, "verification": {"username": verified}, "files_retained": True}


def bounded_number(value, minimum, maximum, label):
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise OperationError(label + "必须是整数。") from None
    require(not isinstance(value, bool) and minimum <= number <= maximum, label + f"需在 {minimum} 至 {maximum} 之间。")
    return number


def ssh_hardening(params):
    values = {
        "MaxAuthTries": str(bounded_number(params.get("max_auth_tries"), 2, 20, "认证尝试次数")),
        "LoginGraceTime": str(bounded_number(params.get("login_grace"), 15, 600, "登录等待秒数")),
        "ClientAliveInterval": str(bounded_number(params.get("alive_interval"), 0, 3600, "断线检查秒数")),
        "ClientAliveCountMax": "2", "PermitEmptyPasswords": "no", "LogLevel": "VERBOSE",
    }
    for field, directive in [("tcp_forwarding", "AllowTcpForwarding"), ("x11_forwarding", "X11Forwarding"), ("agent_forwarding", "AllowAgentForwarding")]:
        setting = params.get(field)
        require(isinstance(setting, bool) or (field == "tcp_forwarding" and setting in {"local", "remote"}), "转发设置格式不正确。")
        values[directive] = setting if isinstance(setting, str) else "yes" if setting else "no"
    files = ssh_files_without_match()
    backup_files(["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"])
    arm_recovery()
    fields = {key.lower() for key in values}
    for source in files:
        if source.is_file():
            text = "".join("# linux服务器管理已接管此项: " + line if line.strip() and line.split()[0].lower() in fields else line for line in source.read_text().splitlines(keepends=True))
            private_write(source, text, source.stat().st_mode & 0o777)
    private_write("/etc/ssh/sshd_config.d/01-linux-manager-protection.conf", "".join(f"{key} {value}\n" for key, value in values.items()), 0o644)
    command(["/usr/sbin/sshd", "-t"])
    effective = ssh_configuration()
    require(all(effective.get(key.lower()) == [value] for key, value in values.items()), "服务器没有完整加载所选防护设置，已取消变更。")
    command(["systemctl", "reload", "ssh.service"])
    return {"requires_verification": True}


def fail2ban_settings(params):
    enabled = params.get("enabled")
    require(isinstance(enabled, bool), "请选择开启或关闭防猜密码保护。")
    target = Path("/etc/fail2ban/jail.d/99-linux-manager.local")
    attempts = bounded_number(params.get("attempts", 5), 3, 20, "失败次数")
    window = bounded_number(params.get("window_minutes", 10), 1, 1440, "统计分钟数")
    duration = bounded_number(params.get("ban_minutes", 60), 1, 10080, "封禁分钟数")
    previous = unit_info("fail2ban.service")
    extra = {"fail2ban_active": previous.get("ActiveState") == "active", "fail2ban_enabled": previous.get("UnitFileState") == "enabled"}
    if not enabled:
        require(target.is_file(), "本程序尚未启用防猜密码保护。")
    backup_files([str(target)], extra)
    if enabled and not shutil.which("fail2ban-client"):
        apt(["fail2ban"])
    arm_recovery()
    ports = sorted({port(value) for value in ssh_configuration().get("port", [])} | {port(params.get("ssh_port", 22))})
    content = "[linux-manager-sshd]\nfilter = sshd\nbackend = systemd\nenabled = " + ("true" if enabled else "false") + "\nport = " + ",".join(map(str, ports)) + f"\nmaxretry = {attempts}\nfindtime = {window * 60}\nbantime = {duration * 60}\n"
    private_write(target, content, 0o644)
    command(["fail2ban-client", "-t"], timeout=60)
    if enabled:
        command(["systemctl", "enable", "--now", "fail2ban.service"])
    if extra["fail2ban_active"] or enabled:
        command(["systemctl", "restart", "fail2ban.service"])
    if enabled:
        # systemctl can finish before Fail2ban has created its control socket.
        for _ in range(30):
            ready = command(["fail2ban-client", "status", "linux-manager-sshd"], check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise OperationError("防猜密码服务未能在等待时间内就绪，已停止并尝试恢复原设置。")
    return {"requires_verification": True, "enabled": enabled}


def ssh_settings(params):
    new_port = port(params.get("port"))
    old_port = port(params.get("old_port", 22))
    config = ssh_configuration()
    public = params.get("public_key", "").strip()
    account = username(params.get("username"))
    require(not public or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?", public), "公钥格式不正确。")
    user = pwd.getpwnam(account)
    if not params.get("allow_password"):
        require(public or (Path(user.pw_dir) / ".ssh/authorized_keys").is_file(), "禁用密码登录前，请先为验证账号配置密钥。")
    if not params.get("allow_root"):
        require(account != "root" and "sudo" in [g.gr_name for g in grp.getgrall() if account in g.gr_mem], "禁用超级管理员登录前，需要选择能够使用 sudo 的普通管理员并验证登录。")
    # Match blocks and account allowlists must not be silently overridden.
    ssh_files = [Path("/etc/ssh/sshd_config"), *Path("/etc/ssh/sshd_config.d").glob("*.conf")]
    require(not any(re.search(r"^\s*Match\s", f.read_text(), re.M | re.I) for f in ssh_files if f.is_file()), "检测到条件式 SSH 配置，第一版不自动改写，请保留现有设置。")
    if new_port != old_port:
        ensure_port_available(new_port)
    keyfile = Path(user.pw_dir) / ".ssh/authorized_keys"
    backup_files(["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/systemd/system/ssh.socket.d", "/etc/ufw", "/etc/fail2ban/jail.d/99-linux-manager.local", str(keyfile)], {"firewall_active": firewall_snapshot()["active"]})
    arm_recovery()
    if public:
        keyfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(keyfile.parent, user.pw_uid, user.pw_gid)
        previous = keyfile.read_text() if keyfile.exists() else ""
        if public not in previous.splitlines():
            private_write(keyfile, previous.rstrip() + "\n" + public + "\n")
        os.chown(keyfile, user.pw_uid, user.pw_gid)
    values = {
        "PermitRootLogin": "yes" if params.get("allow_root") else "no",
        "PasswordAuthentication": "yes" if params.get("allow_password") else "no",
        "KbdInteractiveAuthentication": "no", "PubkeyAuthentication": "yes",
        "AuthenticationMethods": "any" if params.get("allow_password") else "publickey",
        "PermitEmptyPasswords": "no", "MaxAuthTries": "3", "X11Forwarding": "no", "AllowAgentForwarding": "no",
    }
    if Path("/etc/ssh/sshd_config.d/01-linux-manager-protection.conf").exists():
        for key in ["PermitEmptyPasswords", "MaxAuthTries", "X11Forwarding", "AllowAgentForwarding"]:
            values.pop(key, None)
    # OpenSSH uses the first value. Remove only directives managed by this operation.
    for source in ssh_files:
        if source.is_file():
            lines = source.read_text().splitlines(keepends=True)
            changed = "".join("# linux服务器管理已接管此项: " + line if line.strip() and line.split()[0].lower() in {k.lower() for k in values} | {"port"} else line for line in lines)
            private_write(source, changed, source.stat().st_mode & 0o777)
    managed = Path("/etc/ssh/sshd_config.d/00-linux-manager.conf")
    lines = [f"Port {new_port}"] + ([f"Port {old_port}"] if old_port != new_port else [])
    lines += [key + " " + value for key, value in values.items()]
    private_write(managed, "\n".join(lines) + "\n", 0o644)
    # Account allowlist stays intact, with the explicitly selected verification login added.
    for source in ssh_files:
        if source.is_file():
            changed = re.sub(r"(?im)^(\s*AllowUsers\s+)([^\n]+)$", lambda m: m.group(0) if account in m.group(2).split() else m.group(0) + " " + account, source.read_text())
            private_write(source, changed, source.stat().st_mode & 0o777)
    command(["/usr/sbin/sshd", "-t"])
    allow_port(new_port)
    if command(["systemctl", "is-active", "ssh.socket"], check=False).returncode == 0:
        private_write("/etc/systemd/system/ssh.socket.d/99-linux-manager.conf", "[Socket]\nListenStream=\n" + "".join(f"ListenStream={p}\n" for p in sorted({old_port, new_port})), 0o644)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "restart", "ssh.socket"])
        command(["systemctl", "restart", "ssh.service"])
    else:
        command(["systemctl", "reload-or-restart", "ssh.service"])
    protection = Path("/etc/fail2ban/jail.d/99-linux-manager.local")
    if protection.is_file():
        text = re.sub(r"(?m)^port\s*=.*$", "port = " + ",".join(map(str, sorted({old_port, new_port}))), protection.read_text())
        private_write(protection, text, 0o644)
        if command(["systemctl", "is-active", "fail2ban.service"], check=False).returncode == 0:
            command(["fail2ban-client", "reload"])
    return {"requires_verification": True, "verification": {"username": account, "port": new_port, "key_required": not params.get("allow_password")}, "old_port_retained": old_port != new_port}


def firewall_settings(params):
    if not shutil.which("ufw"):
        apt(["ufw"])
    backup_files(["/etc/ufw"], {"firewall_active": firewall_snapshot()["active"]})
    arm_recovery()
    allow_port(port(params.get("ssh_port", 22)))
    for item in params.get("ports", []):
        require(item.get("protocol") in {"tcp", "udp"}, "防火墙协议无效。")
        allow_port(item["port"], item["protocol"])
    # Preserve all existing rules; no reset/delete of unmanaged service rules.
    command(["ufw", "default", "deny", "incoming"])
    command(["ufw", "default", "allow", "outgoing"])
    command(["ufw", "--force", "enable"])
    return {"requires_verification": True, "verification": {"port": port(params.get("ssh_port", 22))}}


def update_settings(params):
    enabled = params.get("enabled", True)
    require(isinstance(enabled, bool), "请选择开启或关闭自动安全更新。")
    previous = update_timer_states()
    require(all(state.get("LoadState") == "loaded" and state.get("UnitFileState") in {"enabled", "disabled"} for state in previous.values()), "APT 定时器缺失、被屏蔽或使用自定义启动方式，未改动更新配置；请先检查系统。")
    backup_files(update_configuration_paths(), {"operation": "updates", "update_timers": previous})
    if enabled and not shutil.which("unattended-upgrade"):
        apt(["unattended-upgrades"])
    private_write(UPDATE_CONFIG, 'APT::Periodic::Enable "1";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "' + ("1" if enabled else "0") + '";\nUnattended-Upgrade::Automatic-Reboot "false";\n', 0o644)
    configured = automatic_updates_snapshot()
    require(configured["config_valid"] and configured["automatic_reboot"] is False and configured["periodic_enabled"] and configured["package_lists_interval"] == "1" and configured["upgrade_interval"] == ("1" if enabled else "0"), "自动更新配置被其他设置覆盖或无效，已停止并尝试恢复原设置。")
    if enabled:
        require(configured["installed"] and configured["origins_configured"], "缺少可用的安全更新工具或软件源策略，已停止并尝试恢复原设置。")
        for path in update_configuration_paths()[1:]:
            # Keep the distribution's calendar/random delay, but do not immediately
            # catch up missed upgrades when enabling a previously disabled timer.
            private_write(path, "[Timer]\nPersistent=false\n", 0o644)
        step("启用 APT 定时调度并核验下一次执行时间…", 80)
        command(["systemctl", "daemon-reload"])
        require(all(state.get("Persistent") == "no" for state in update_timer_states().values()), "更新定时器配置被其他设置覆盖，无法避免立即补跑；已停止并尝试恢复原设置。")
        command(["systemctl", "enable", "--now", *APT_TIMERS])
        command(["systemctl", "restart", *APT_TIMERS])
        configured = automatic_updates_snapshot()
        require(configured["active"] and configured["automatic_reboot"] is False, "自动更新定时调度未通过验证，已停止并尝试恢复原设置。")
    # Disabling upgrades leaves the shared package-list refresh timers alone.
    return {"enabled": enabled, "automatic_reboot": False, "update_status": configured}


def github_release(repo, version):
    require(repo in {"SagerNet/sing-box", "MHSanaei/3x-ui", "yushengsheng/xiaojun-bn"}, "安装来源不在允许列表中。")
    require(re.fullmatch(r"v\d+\.\d+\.\d+", version), "发行版本号格式不正确。")
    url = "https://api.github.com/repos/" + repo + "/releases/tags/" + version
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "linux-server-manager/0.1", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=45) as response:
            release = json.load(response)
    except (urllib.error.URLError, ValueError):
        raise OperationError("无法获取官方安装包。请检查服务器访问 GitHub 的网络，稍后重试。") from None
    require(isinstance(release, dict) and release.get("tag_name") == version and release.get("prerelease") is False and release.get("draft") is False, "官方版本与已确认版本不一致或属于测试版，已停止安装。")
    return release


def download_verified(repo, version, filename, destination):
    release = github_release(repo, version)
    asset = next((a for a in release.get("assets", []) if a["name"] == filename), None)
    require(asset is not None, "官方发行版缺少当前架构的安装包。")
    url = asset["browser_download_url"]
    require(url.startswith("https://github.com/" + repo + "/releases/download/"), "安装包下载地址不符合官方来源。")
    expected = str(asset.get("digest") or "").removeprefix("sha256:")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        candidates = [a for a in release.get("assets", []) if a["name"] in {filename + ".sha256", "SHA256SUMS", "checksums.txt", "sing-box-" + version[1:] + "-checksums.txt"}]
        for checksum in candidates:
            with urllib.request.urlopen(checksum["browser_download_url"], timeout=45) as response:
                text = response.read(1024 * 1024).decode()
            for line in text.splitlines():
                match = re.match(r"([a-fA-F0-9]{64})\s+\*?(.+)", line)
                if match and Path(match.group(2)).name == filename:
                    expected = match.group(1)
                elif checksum["name"] == filename + ".sha256" and re.fullmatch(r"[a-fA-F0-9]{64}", line.strip()):
                    expected = line.strip()
    require(re.fullmatch(r"[a-fA-F0-9]{64}", expected), "官方安装包缺少可验证的 SHA-256，已停止安装。")
    digest = hashlib.sha256()
    destination = Path(destination)
    with urllib.request.urlopen(url, timeout=120) as response, destination.open("wb") as stream:
        count = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            require(count <= 600 * 1024 * 1024, "安装包超过允许大小。")
            stream.write(block)
            digest.update(block)
    require(digest.hexdigest().lower() == expected.lower(), "安装包校验失败，文件未被执行。")
    return destination


def unpack(archive, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(archive) as package:
        members = package.getmembers()
        require(sum(m.size for m in members) < 1024 ** 3, "安装包展开后过大。")
        for member in members:
            name = Path(member.name)
            require(not name.is_absolute() and ".." not in name.parts and (member.isfile() or member.isdir()), "安装包包含不安全的路径或链接。")
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, target.open("wb") as stream:
                    shutil.copyfileobj(source, stream)
                target.chmod(member.mode & 0o755)


def cert_hook():
    # Certificate hooks affect only proxy services installed by this program.
    managed = ROOT / "installed.json"
    script = "#!/bin/sh\n"
    installed = json.loads(managed.read_text()) if managed.exists() else {}
    if installed.get("exchange", {}).get("certificate_source") == "manager" and not installed["exchange"].get("uninstalled"):
        lineage = installed["exchange"].get("certificate_lineage", "/etc/linux-server-manager/letsencrypt/live/manager")
        script += 'if [ "$RENEWED_LINEAGE" = ' + shlex.quote(lineage) + ' ]; then\n'
        script += '  install -m 600 "$RENEWED_LINEAGE/fullchain.pem" /etc/xiaojun-exchange/tls/fullchain.pem && install -m 600 "$RENEWED_LINEAGE/privkey.pem" /etc/xiaojun-exchange/tls/privkey.pem && nginx -t -c /etc/xiaojun-exchange/nginx.conf && systemctl reload xiaojun-exchange-nginx.service || exit 1\nfi\n'
    for service in ["hysteria2", "xui"]:
        if service in installed and not installed[service].get("uninstalled"):
            lineage = proxy_certificate_lineage(service)
            if lineage:
                script += 'if [ "$RENEWED_LINEAGE" = ' + shlex.quote(lineage) + ' ]; then\n'
            script += "systemctl try-restart " + UNITS[service][0] + " || true\n"
            if lineage: script += "fi\n"
    for base in [Path("/etc/xiaojun-exchange/letsencrypt"), Path("/etc/linux-server-manager/letsencrypt")]:
        if base.exists():
            private_write(base / "renewal-hooks/deploy/linux-manager-proxies", script, 0o700)


def proxy_certificate_lineage(service):
    try:
        if service == "hysteria2":
            data = json.loads(Path("/etc/sing-box/config.json").read_text())
            inbound = next(item for item in data["inbounds"] if item.get("type") == "hysteria2")
            certificate_file = inbound["tls"]["certificate_path"]
        else:
            with contextlib.closing(sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)) as db:
                certificate_file = db.execute("SELECT value FROM settings WHERE key='webCertFile'").fetchone()[0]
        lineage = str(Path(certificate_file).parent)
        return lineage if lineage.startswith(("/etc/linux-server-manager/letsencrypt/live/", "/etc/xiaojun-exchange/letsencrypt/live/")) else None
    except (OSError, ValueError, KeyError, TypeError, StopIteration, sqlite3.DatabaseError):
        return None


def certificate_name(address, legacy_exists, identity_matches):
    return "manager" if not legacy_exists or identity_matches else "manager-" + hashlib.sha256(address.encode()).hexdigest()[:12]


def certificate_renewals():
    result = []
    for file in sorted(Path(CERTIFICATE_CONFIG + "/renewal").glob("*.conf")):
        require(not file.is_symlink(), "证书续期配置是自定义链接，不能自动迁移。")
        config = configparser.RawConfigParser()
        try:
            # Certbot's ConfigObj files have top-level values before sections.
            config.read_string("[DEFAULT]\n" + file.read_text())
            authenticator = config.get("renewalparams", "authenticator")
            webroot = config.get("renewalparams", "webroot_path", fallback="").strip().rstrip(",").strip()
        except (OSError, configparser.Error):
            raise OperationError("证书续期配置无法读取，已保留原配置。") from None
        require(authenticator in {"standalone", "webroot"}, "证书使用自定义验证方式，不能自动迁移。")
        require(re.fullmatch(r"[A-Za-z0-9._-]+", file.stem), "证书续期名称无法识别。")
        result.append((file, authenticator, webroot))
    return result


def certificate_webroot_needed():
    renewals = certificate_renewals()
    if not renewals:
        return False
    site = Path(NGINX_MANAGED_SITE)
    if not site.is_file() or not Path(NGINX_ACME_SITE).is_file():
        return True
    match = re.search(r"listen\s+(\d+)", site.read_text())
    if not match or int(match.group(1)) == 80 and nginx_acme_location() not in site.read_text():
        return True
    timer = unit_info("linux-manager-cert-renew.timer")
    hook = Path(CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies")
    if not hook.is_file():
        return True
    records = ROOT / "installed.json"
    exchange = json.loads(records.read_text()).get("exchange", {}) if records.is_file() else {}
    if exchange.get("certificate_source") == "manager" and not exchange.get("uninstalled"):
        if exchange.get("certificate_lineage", CERTIFICATE_CONFIG + "/live/manager") not in hook.read_text() or "reload xiaojun-exchange-nginx.service" not in hook.read_text():
            return True
    return any(auth != "webroot" or root != CERTIFICATE_WEBROOT for _, auth, root in renewals) or timer.get("ActiveState") != "active" or timer.get("UnitFileState") != "enabled"


def certificate_renewal_addresses():
    addresses = set()
    for file, _, _ in certificate_renewals():
        certificate = Path(CERTIFICATE_CONFIG + "/live") / file.stem / "fullchain.pem"
        result = command(["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"])
        names = re.findall(r"(?:DNS:|IP Address:)([^,\s]+)", result.stdout)
        require(names, "已有证书缺少可识别的访问地址，不能自动迁移续期。")
        addresses.update(host(name) for name in names)
    return addresses


def nginx_acme_location():
    return " location ^~ /.well-known/acme-challenge/ {\n  root " + CERTIFICATE_WEBROOT + ";\n  default_type text/plain;\n  try_files $uri =404;\n }\n"


def verify_certificate_webroot(addresses):
    challenge = Path(CERTIFICATE_WEBROOT + "/.well-known/acme-challenge")
    require(challenge.resolve() == challenge.absolute(), "证书验证目录含自定义链接，不能自动写入。")
    for folder in [challenge.parent, challenge]:
        folder.mkdir(mode=0o755, parents=True, exist_ok=True)
        folder.chmod(0o755)
    token = secrets.token_hex(24)
    file = challenge / token
    private_write(file, token, 0o644)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        for address in sorted(addresses):
            request = urllib.request.Request("http://127.0.0.1/.well-known/acme-challenge/" + token, headers={"Host": address})
            for attempt in range(10):
                try:
                    with opener.open(request, timeout=5) as response:
                        require(response.status == 200 and response.read(len(token) + 1) == token.encode(), "证书验证路径被其他网页配置拦截，已保留原入口。")
                    break
                except (OSError, urllib.error.URLError):
                    if attempt == 9:
                        raise OperationError("Nginx 证书验证路径不可访问，已保留原入口。") from None
                    time.sleep(0.2)
    finally:
        file.unlink(missing_ok=True)


def prepare_certificate_webroot(addresses):
    site = Path(NGINX_MANAGED_SITE)
    require(not site.is_symlink() and site.is_file() and site.read_text().startswith("# Managed by linux-server-manager\n"), "TCP 80 的网页入口不属于本程序，不能自动修改证书验证配置。")
    text = site.read_text()
    match = re.search(r"listen\s+(\d+)", text)
    require(match is not None, "本程序的 Nginx 入口端口无法识别。")
    names = set(addresses)
    location = nginx_acme_location()
    if int(match.group(1)) == 80:
        if location not in text:
            require("/.well-known/acme-challenge/" not in text and text.rstrip().endswith("}"), "发现自定义证书验证路径，已保留原配置。")
            text = text.rstrip()[:-1] + location + "}\n"
        name = re.search(r"server_name\s+([^;]+);", text)
        if name:
            names.difference_update(name.group(1).split())
    acme = Path(NGINX_ACME_SITE)
    require(not acme.is_symlink() and (not acme.exists() or acme.read_text().startswith("# Managed by linux-server-manager\n")), "证书验证站点存在自定义配置，不能覆盖。")
    configuration = "# Managed by linux-server-manager\nserver {\n listen 80;\n listen [::]:80;\n server_name " + " ".join(sorted(names) or ["_"]) + ";\n access_log off;\n" + location + " location / { return 404; }\n}\n"
    originals = [(file, file.read_bytes() if file.exists() else None, file.stat().st_mode & 0o777 if file.exists() else 0o644) for file in [site, acme]]
    webroot = Path(CERTIFICATE_WEBROOT)
    require(webroot.resolve() == webroot.absolute(), "证书验证目录是自定义链接，不能自动写入。")
    webroot.mkdir(mode=0o755, parents=True, exist_ok=True)
    webroot.chmod(0o755)
    try:
        private_write(site, text, 0o644)
        private_write(acme, configuration, 0o644)
        command(["nginx", "-t"])
        command(["systemctl", "reload", "nginx.service"])
        verify_certificate_webroot(addresses)
    except Exception:
        for file, content, mode in originals:
            if content is None:
                file.unlink(missing_ok=True)
            else:
                private_write(file, content, mode)
        command(["nginx", "-t"])
        command(["systemctl", "reload", "nginx.service"])
        raise


def ensure_certbot():
    environment = Path("/opt/linux-server-manager/certbot")
    if not (environment / "bin/certbot").is_file():
        apt(["python3-venv", "ca-certificates", "openssl"])
        command(["python3", "-m", "venv", str(environment)], timeout=90)
        require(TASK is not None, "证书工具修复需要后台安装任务。")
        lock = TASK / "certbot-requirements.txt"
        private_write(lock, globals().get("CERTBOT_LOCK", ""))
        require(lock.stat().st_size > 100, "证书依赖清单缺失，不能自动申请证书。")
        command([str(environment / "bin/python"), "-m", "pip", "install", "--require-hashes", "--no-cache-dir", "-r", str(lock)], timeout=600)
    return str(environment / "bin/certbot")


def certbot_arguments(verb):
    return [ensure_certbot(), verb, "--non-interactive", "--config-dir", CERTIFICATE_CONFIG, "--work-dir", "/var/lib/linux-server-manager/acme", "--logs-dir", "/var/log/linux-server-manager-acme"]


def pause_certificate_renewal():
    require(unit_info("linux-manager-cert-renew.service").get("ActiveState") not in {"active", "activating"}, "证书正在续期，请等待完成后再安装 Nginx。")
    command(["systemctl", "stop", "linux-manager-cert-renew.timer"])
    require(unit_info("linux-manager-cert-renew.service").get("ActiveState") not in {"active", "activating"}, "证书正在续期，请等待完成后再安装 Nginx。")


def migrate_certificate_renewals():
    renewals = certificate_renewals()
    if all(auth == "webroot" and root == CERTIFICATE_WEBROOT for _, auth, root in renewals):
        return
    timer = unit_info("linux-manager-cert-renew.timer")
    originals = [(file, file.read_bytes(), file.stat().st_mode & 0o777) for file, _, _ in renewals]
    try:
        pause_certificate_renewal()
        for file, authenticator, webroot in renewals:
            if authenticator != "webroot" or webroot != CERTIFICATE_WEBROOT:
                try:
                    command(certbot_arguments("reconfigure") + ["--cert-name", file.stem, "--webroot", "--webroot-path", CERTIFICATE_WEBROOT], timeout=300)
                except OperationError as error:
                    raise OperationError("证书续期验证未通过。请确认云平台 TCP 80 已放行且访问地址指向本机；原续期配置会恢复。" + str(error)) from None
        require(all(auth == "webroot" and root == CERTIFICATE_WEBROOT for _, auth, root in certificate_renewals()), "证书续期方式迁移未生效，已保留原配置。")
    except Exception:
        for file, content, mode in originals:
            private_write(file, content, mode)
        raise
    finally:
        if timer.get("ActiveState") == "active":
            command(["systemctl", "start", "linux-manager-cert-renew.timer"])


def ensure_certificate_renewal():
    executable = ensure_certbot()
    private_write("/etc/systemd/system/linux-manager-cert-renew.service", "[Unit]\nDescription=Renew Linux manager certificates\n[Service]\nType=oneshot\nExecStart=" + executable + " renew --quiet --config-dir " + CERTIFICATE_CONFIG + " --work-dir /var/lib/linux-server-manager/acme --logs-dir /var/log/linux-server-manager-acme\n", 0o644)
    private_write("/etc/systemd/system/linux-manager-cert-renew.timer", "[Unit]\nDescription=Check Linux manager certificates\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=12h\nPersistent=true\n[Install]\nWantedBy=timers.target\n", 0o644)
    cert_hook()
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "linux-manager-cert-renew.timer"])


def ensure_certificate(address):
    import ipaddress
    try:
        ipaddress.IPv4Address(address)
        check_argument = "-checkip"
    except ValueError:
        check_argument = "-checkhost"
    def matches(path):
        return path.is_file() and command(["openssl", "x509", "-in", str(path), "-noout", check_argument, address], check=False).returncode == 0 and command(["openssl", "x509", "-in", str(path), "-noout", "-checkend", "86400"], check=False).returncode == 0
    exchange_base = Path("/etc/xiaojun-exchange/letsencrypt/live/exchange-ip")
    if matches(exchange_base / "fullchain.pem") and (exchange_base / "privkey.pem").is_file():
        return str(exchange_base / "fullchain.pem"), str(exchange_base / "privkey.pem")
    own_base = Path("/etc/linux-server-manager/letsencrypt/live/manager")
    site = Path(NGINX_MANAGED_SITE)
    webroot = site.is_file() and unit_info("nginx.service").get("ActiveState") == "active"
    if webroot:
        prepare_certificate_webroot(certificate_renewal_addresses() | {address})
        migrate_certificate_renewals()
    if matches(own_base / "fullchain.pem") and (own_base / "privkey.pem").is_file():
        require((Path(CERTIFICATE_CONFIG + "/renewal") / (own_base.name + ".conf")).is_file(), "已有证书的续期资料缺失，不能保证自动续期；请先恢复证书续期配置。")
        ensure_certificate_renewal()
        return str(own_base / "fullchain.pem"), str(own_base / "privkey.pem")
    legacy = own_base / "fullchain.pem"
    same_identity = legacy.is_file() and command(["openssl", "x509", "-in", str(legacy), "-noout", check_argument, address], check=False).returncode == 0
    name = certificate_name(address, legacy.is_file(), same_identity)
    own_base = own_base.parent / name
    if matches(own_base / "fullchain.pem") and (own_base / "privkey.pem").is_file():
        require((Path(CERTIFICATE_CONFIG + "/renewal") / (own_base.name + ".conf")).is_file(), "已有证书的续期资料缺失，不能保证自动续期；请先恢复证书续期配置。")
        ensure_certificate_renewal()
        return str(own_base / "fullchain.pem"), str(own_base / "privkey.pem")
    if not webroot:
        require(not any(x["port"] == 80 and x["protocol"] == "tcp" for x in listeners()), "申请证书需要可用的 TCP 80。请通过本程序部署 Nginx 网页入口以自动兼容证书验证；其他网页服务不会被覆盖。")
    allow_port(80)
    args = certbot_arguments("certonly") + ["--agree-tos", "--register-unsafely-without-email", "--cert-name", name]
    args += ["--webroot", "--webroot-path", CERTIFICATE_WEBROOT] if webroot else ["--standalone"]
    import ipaddress
    try:
        ipaddress.IPv4Address(address)
        args += ["--ip-address", address, "--preferred-profile", "shortlived"]
    except ValueError:
        args += ["-d", address]
    try:
        command(args, timeout=240)
    except OperationError as error:
        message = str(error).lower()
        if any(word in message for word in ["timeout during connect", "connection refused", "unauthorized", "challenge failed", "challenges have failed"]):
            raise OperationError("证书验证未通过。请在云平台安全组放行 TCP 80，确认访问地址指向本机后重试；项目尚未安装，不会覆盖已有数据。") from None
        raise
    ensure_certificate_renewal()
    return str(own_base / "fullchain.pem"), str(own_base / "privkey.pem")


def certificate(params):
    custom_cert = params.get("tls_cert", "")
    custom_key = params.get("tls_key", "")
    require(bool(custom_cert) == bool(custom_key), "证书和私钥必须同时提供。")
    if custom_cert:
        folder = Path("/etc/linux-server-manager/tls") / (TASK.name if TASK else secrets.token_hex(12))
        private_write(folder / "fullchain.pem", custom_cert)
        private_write(folder / "privkey.pem", custom_key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(folder / "fullchain.pem", folder / "privkey.pem")
        except ssl.SSLError:
            raise OperationError("提供的证书与私钥不匹配。") from None
        return str(folder / "fullchain.pem"), str(folder / "privkey.pem")
    return ensure_certificate(host(params.get("host")))


def mark_installed(service, details):
    path = ROOT / "installed.json"
    previous = json.loads(path.read_text()) if path.exists() else {}
    previous[service] = details | {"installed": now()}
    write_json(path, previous)
    cert_hook()


def exchange_retry_allowed(params):
    root = Path("/opt/xiaojun-exchange"); configuration = Path("/etc/xiaojun-exchange"); data = Path("/var/lib/xiaojun-exchange")
    marker = root / ".install-incomplete.json"
    if any(p.is_symlink() for p in [root,configuration,data,marker]) or not marker.is_file():return False
    try:
        saved = json.loads(marker.read_text())
        expected = dict(version=params.get("version"),host=params.get("host"),port=port(params.get("port")),backend_port=port(params.get("backend_port",18880)),phase="bootstrap")
        return saved == expected and not any(Path("/etc/systemd/system").glob("xiaojun-exchange-*")) and (not data.exists() or all(p.name=="setup-token" for p in data.iterdir()))
    except (OSError,ValueError,OperationError):return False


def deployment_preflight(params):
    kind = params.get("service")
    require(kind in {"exchange", "hysteria2", "xui"}, "部署项目无效。")
    address = host(params.get("host")); number = port(params.get("port"))
    release = platform.freedesktop_os_release()
    require((release.get("ID"), release.get("VERSION_ID")) in {("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}, "当前系统尚未支持自动部署。")
    require(shutil.disk_usage("/").free >= 1024 ** 3, "磁盘可用空间不足 1 GiB。")
    architecture = platform.machine()
    require(architecture in {"x86_64", "aarch64"} and (kind != "exchange" or architecture == "x86_64"), "当前服务器架构尚未支持此项目。")
    if kind == "exchange":
        require(not any(Path(p).exists() for p in ["/opt/xiaojun-exchange", "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange"]) or exchange_retry_allowed(params), "检测到已有或未完成的交易系统安装，已保留现场。请查看安装记录，不能覆盖运行数据。")
        backend = port(params.get("backend_port", 18880))
        require(number != backend, "访问端口和内部端口不能相同。")
        ensure_port_available(backend)
    elif kind == "hysteria2":
        require(not Path("/etc/sing-box/config.json").exists() and unit_info("sing-box.service").get("LoadState") == "not-found", "代理已经安装，已保留原配置。")
    else:
        require(not Path("/etc/x-ui/x-ui.db").exists() and not Path("/usr/local/x-ui").exists(), "代理管理面板已经安装，已保留原配置。")
    ensure_port_available(number, "udp" if kind == "hysteria2" else "tcp")
    return {"architecture": architecture, "service": kind, "preflight": "passed", "retry_incomplete":kind == "exchange" and exchange_retry_allowed(params)}


def project_archive(params, repository, version, name, destination):
    archive = TASK / "release.tar.gz"
    if archive.is_file():
        with archive.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == params.get("release_sha256"), "传送的安装包校验失败，未执行安装。")
        return archive
    return download_verified(repository, version, name, destination)


def verify_local_https(address, number, path="/", certificate_data=None):
    """Keep TLS hostname/trust checks while avoiding a cloud public-IP hairpin."""
    context = ssl.create_default_context(cadata=certificate_data) if certificate_data else ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1",number),timeout=20) as connection:
            with context.wrap_socket(connection,server_hostname=address) as secured:
                secured.sendall(("GET "+path+" HTTP/1.1\r\nHost: "+address+":"+str(number)+"\r\nConnection: close\r\n\r\n").encode())
                response=http.client.HTTPResponse(secured);response.begin()
                require(response.status==200,"项目 HTTPS 检查未通过，请查看任务记录。")
    except (OSError,ssl.SSLError,http.client.HTTPException):
        raise OperationError("项目已安装，但本机 HTTPS 检查未通过；请查看服务日志，不要重复覆盖安装。") from None


def deploy_hysteria(params):
    number = port(params.get("port", 51752))
    value = password(params.get("proxy_password"))
    require(not Path("/etc/sing-box/config.json").exists() and unit_info("sing-box.service").get("LoadState") == "not-found", "已存在 sing-box 配置，已保留原服务。请使用管理功能查看，不能重复覆盖安装。")
    ensure_port_available(number, "udp")
    step("准备代理证书…", 15)
    cert, key = certificate(params)
    version = params.get("version", "v1.14.2")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    require(architecture is not None, "当前服务器架构尚未支持自动安装。")
    step("下载并验证 Hysteria2 服务内核…", 35)
    name = "sing-box-" + version[1:] + "-linux-" + architecture + ".tar.gz"
    package = project_archive(params, "SagerNet/sing-box", version, name, TASK / "sing-box.tar.gz")
    unpack(package, TASK / "unpacked")
    binaries = list((TASK / "unpacked").rglob("sing-box"))
    require(len(binaries) == 1, "代理安装包结构不符合预期。")
    target = Path("/usr/local/bin/sing-box")
    shutil.copy2(binaries[0], target); target.chmod(0o755)
    config = {"log": {"level": "warn", "timestamp": True}, "inbounds": [{"type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": number, "users": [{"name": "client", "password": value}], "tls": {"enabled": True, "certificate_path": cert, "key_path": key}}], "outbounds": [{"type": "direct", "tag": "direct"}]}
    private_write("/etc/sing-box/config.json", json.dumps(config, indent=2))
    command([str(target), "check", "-c", "/etc/sing-box/config.json"])
    private_write("/etc/systemd/system/sing-box.service", "[Unit]\nDescription=sing-box Hysteria2 proxy\nAfter=network-online.target\nWants=network-online.target\n[Service]\nExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n", 0o644)
    step("启动服务并检查监听端口…", 80)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "sing-box.service"])
    allow_port(number, "udp")
    time.sleep(2)
    require(unit_info("sing-box.service").get("ActiveState") == "active" and any(x["port"] == number and x["protocol"] == "udp" for x in listeners()), "代理服务未正常监听，请查看任务记录。")
    details = {"version": version, "port": number, "host": params["host"]}
    mark_installed("hysteria2", details)
    return {"service": "hysteria2", "version": version, "port": number, "verified": "service-and-udp-listener"}


def deploy_xui(params):
    number = port(params.get("port", 2053))
    account = username(params.get("panel_username", "manager")); value = password(params.get("panel_password"))
    require(not Path("/etc/x-ui/x-ui.db").exists() and not Path("/usr/local/x-ui").exists(), "已经存在代理管理面板，不能覆盖安装。")
    ensure_port_available(number)
    step("准备管理面板证书…", 15)
    cert, key = certificate(params)
    apt(["python3-bcrypt", "ca-certificates"])
    version = params.get("version", "v3.9.0")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    require(architecture is not None, "当前服务器架构尚未支持自动安装。")
    step("下载并校验代理管理面板…", 35)
    package = project_archive(params, "MHSanaei/3x-ui", version, "x-ui-linux-" + architecture + ".tar.gz", TASK / "x-ui.tar.gz")
    unpack(package, TASK / "unpacked")
    candidates = [p for p in (TASK / "unpacked").rglob("x-ui") if p.is_file()]
    require(len(candidates) == 1, "面板安装包结构不符合预期。")
    folder = Path("/usr/local/x-ui")
    shutil.copytree(candidates[0].parent, folder)
    executable = folder / "x-ui"; executable.chmod(0o755)
    command([str(executable), "migrate"], timeout=90)
    import bcrypt
    database = Path("/etc/x-ui/x-ui.db")
    require(database.is_file(), "面板数据库初始化失败。")
    path = "/" + secrets.token_urlsafe(18) + "/"
    with sqlite3.connect(database) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        require({"username", "password"} <= columns, "面板数据库版本尚未适配，未开放访问端口。")
        hashed = bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()
        if db.execute("SELECT count(*) FROM users").fetchone()[0]:
            db.execute("UPDATE users SET username=?,password=?", (account, hashed))
        else:
            db.execute("INSERT INTO users(username,password) VALUES(?,?)", (account, hashed))
        for setting, data in {"webPort": str(number), "webListen": "", "webBasePath": path, "webCertFile": cert, "webKeyFile": key}.items():
            db.execute("DELETE FROM settings WHERE key=?", (setting,))
            db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (setting, data))
    database.chmod(0o600)
    private_write("/etc/systemd/system/x-ui.service", "[Unit]\nDescription=x-ui proxy management\nAfter=network-online.target\nWants=network-online.target\n[Service]\nWorkingDirectory=/usr/local/x-ui\nExecStart=/usr/local/x-ui/x-ui\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n", 0o644)
    step("启动管理面板并检查 HTTPS…", 80)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "x-ui.service"])
    time.sleep(3)
    require(unit_info("x-ui.service").get("ActiveState") == "active", "管理面板启动失败，访问端口尚未放行。")
    verify_local_https(host(params["host"]),number,path,params.get("tls_cert"))
    allow_port(number)
    details = {"version": version, "port": number, "host": params["host"], "path": path}
    mark_installed("xui", details)
    return {"service": "xui", "version": version, "port": number, "verified": "https", "path": path}


def deploy_exchange(params):
    version = params.get("version", "")
    require(isinstance(version, str) and re.fullmatch(r"v\d+\.\d+\.\d+", version), "请先在本地确认具体发行版本，再提交部署。")
    address = host(params.get("host")); number = port(params.get("port", 26483)); backend = port(params.get("backend_port", 18880))
    require(platform.machine() == "x86_64", "小军交易系统首次安装仅支持 x86_64。")
    retry = exchange_retry_allowed(params)
    require(not any(Path(p).exists() for p in ["/opt/xiaojun-exchange", "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange"]) or retry, "检测到已有交易系统，已保留配置和数据。首次安装不能用于升级。")
    require(number != backend, "面板端口和内部端口不能相同。")
    ensure_port_available(number); ensure_port_available(backend)
    step("再次校验已传送的小军交易系统发行包…", 15)
    archive = TASK / "release.tar.gz"
    require(archive.is_file(), "没有找到本机传送的发行包。")
    with archive.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == params.get("release_sha256"), "发行包校验失败，文件未被执行。")
    source = TASK / "exchange-source"
    unpack(archive, source)
    installer = source / "linux_exchange/install.py"
    require(installer.is_file(), "官方发行包缺少安装入口。")
    step("先准备 HTTPS 证书；验证端口不通时停在安装之前…", 22)
    cert, key = certificate(params)
    arguments = ["python3", str(installer), "--source", str(source), "--host", address, "--port", str(number), "--backend-port", str(backend), "--tls-cert",cert,"--tls-key",key]
    if retry:
        arguments += ["--retry-incomplete"]
    else:
        command(arguments + ["--check"], timeout=120)
    allow_port(number)
    step("安装交易系统、运行环境和证书。这一步可能需要数分钟…", 35)
    command(arguments, timeout=1800, env={"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"})
    step("验证网页和执行服务…", 85)
    for unit in UNITS["exchange"]:
        require(unit_info(unit).get("ActiveState") == "active", "交易系统服务没有全部启动，请查看任务记录。")
    verify_local_https(address,number,certificate_data=params.get("tls_cert"))
    mark_installed("exchange", {"version": version, "port": number, "host": address, "certificate_source":"manager" if cert.startswith("/etc/linux-server-manager/letsencrypt/") else "custom", "certificate_lineage":str(Path(cert).parent)})
    return {"service": "exchange", "version": version, "port": number, "verified": "https-and-services", "initialization_available": Path("/var/lib/xiaojun-exchange/setup-token").is_file()}


def deploy_nginx(params):
    require(not any(x["port"] == 80 and x["protocol"] == "tcp" for x in listeners()), "TCP 80 已有服务，已保留现有网页入口。交易系统会自动安装自己的 Nginx。")
    require(unit_info("nginx.service").get("LoadState") == "not-found", "已经安装 Nginx，请使用服务管理。")
    apt(["nginx"])
    command(["nginx", "-t"])
    command(["systemctl", "enable", "--now", "nginx.service"])
    allow_port(80)
    mark_installed("nginx", {"port": 80, "version": "system-package"})
    return {"service": "nginx", "verified": "configuration-and-service", "port": 80}


def deploy(params):
    kind = params.get("service")
    require(kind in UNITS, "不支持的服务类型。")
    release = platform.freedesktop_os_release()
    require((release.get("ID"), release.get("VERSION_ID")) in {("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}, "第一版自动部署支持 Ubuntu 24.04、Debian 12/13。")
    require(shutil.disk_usage("/").free >= 1024 ** 3, "磁盘可用空间不足 1 GiB，请先释放空间。")
    return {"exchange": deploy_exchange, "hysteria2": deploy_hysteria, "xui": deploy_xui, "nginx": deploy_nginx}[kind](params)


def manage_service(params):
    kind = params.get("service"); operation = params.get("action")
    require(kind in UNITS and operation in {"start", "stop", "restart", "enable", "disable"}, "服务管理操作无效。")
    selected = [u for u in UNITS[kind] if unit_info(u).get("LoadState") == "loaded"]
    require(selected, "服务尚未安装。")
    if kind == "exchange" and operation in {"stop", "restart"}:
        require(params.get("maintenance_confirmed") is True, "请先确认交易任务已经停止并完成清理，再进行维护。")
    step("正在管理所选服务…", 40)
    command(["systemctl", operation, *selected], timeout=360)
    return {"services": [{"unit": unit, **unit_info(unit)} for unit in selected]}


def configuration_backup(params):
    kind = params.get("service")
    paths = {
        "security": ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/ufw", "/etc/sudoers.d", "/etc/systemd/system/ssh.socket.d", "/etc/fail2ban/jail.d/99-linux-manager.local", *update_configuration_paths()],
        "hysteria2": ["/etc/sing-box", "/etc/systemd/system/sing-box.service"],
        "reality": ["/etc/linux-manager-xray", "/etc/systemd/system/linux-manager-xray.service"],
        "xui": ["/etc/x-ui", "/etc/systemd/system/x-ui.service"],
        "nginx": ["/etc/nginx"],
    }
    require(kind in paths, "交易数据备份需使用业务系统的备份机制；本程序只提供已支持的配置备份。")
    step("正在备份配置…", 40)
    # backup_files snapshots the panel database consistently while it runs.
    extra = {"service": kind, "firewall_active": firewall_snapshot()["active"]}
    if kind == "security":
        protection = unit_info("fail2ban.service")
        extra.update(fail2ban_active=protection.get("ActiveState") == "active", fail2ban_enabled=protection.get("UnitFileState") == "enabled", update_timers=update_timer_states())
    directory = backup_files(paths[kind], extra)
    return {"backup_id": TASK.name, "service": kind}


def configuration_restore(params):
    identifier = validate_task_id(params.get("backup_id"))
    status = status_task(identifier)
    require(status["state"] in {"succeeded", "failed", "rolled_back"}, "该备份对应的操作尚未结束。")
    manifest_path = ROOT / "tasks" / identifier / "backup/manifest.json"
    require(manifest_path.exists(), "所选任务没有备份。")
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get("extra", {}).get("service") in {"security", "hysteria2", "reality", "xui", "nginx"}, "账号数据库仅允许由原任务的恢复机制处理，不能覆盖其他账号变更。")
    current_paths = [row["path"] for row in manifest["paths"]]
    kind = manifest["extra"]["service"]
    extra = {"firewall_active": firewall_snapshot()["active"], "service": kind}
    if kind == "security":
        protection = unit_info("fail2ban.service")
        extra.update(fail2ban_active=protection.get("ActiveState") == "active", fail2ban_enabled=protection.get("UnitFileState") == "enabled")
        if "update_timers" in manifest["extra"]:
            extra["update_timers"] = update_timer_states()
    backup_files(current_paths, extra)
    arm_recovery()
    restore_files(identifier)
    kind = manifest["extra"]["service"]
    for unit in UNITS.get(kind, []):
        if unit_info(unit).get("LoadState") == "loaded":
            command(["systemctl", "restart", unit])
    return {"requires_verification": True, "verification": {}, "restored": kind}


def run_task(identifier):
    global TASK
    TASK = ROOT / "tasks" / validate_task_id(identifier)
    params = json.loads((TASK / "request.json").read_text())
    register_secrets(params)
    status = json.loads((TASK / "status.json").read_text())
    lock = ROOT / "operation.lock"
    with lock.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            status.update(state="running", message="开始执行。", updated=now())
            write_json(TASK / "status.json", status)
            handlers = {"deploy": deploy, "uninstall": uninstall_project, "create_admin": create_admin, "rename_user": rename_user, "password": system_password, "ssh": ssh_settings, "firewall": firewall_settings, "updates": update_settings, "backup": configuration_backup, "restore": configuration_restore, "service": manage_service, "account_access": account_access, "delete_user": delete_user, "ssh_hardening": ssh_hardening, "fail2ban": fail2ban_settings, "prepare_key": prepare_key, "login_policy": login_policy, "retire_key": retire_key}
            data = handlers[params["operation"]](params)
            state = "awaiting_verification" if data.get("requires_verification") else "succeeded"
            status = json.loads((TASK / "status.json").read_text())
            status.update(state=state, progress=90 if state == "awaiting_verification" else 100, result=data, updated=now(), message="等待本地程序通过新连接验证；超时自动恢复。" if state == "awaiting_verification" else "操作完成，验证已通过。")
            write_json(TASK / "status.json", status)
        except Exception as error:
            recovery_failed = False
            recovery_diagnostic = ""
            if params["operation"] == "uninstall" and (TASK / "uninstall/manifest.json").exists():
                try:
                    restore_uninstall(identifier)
                except Exception as recovery_error:
                    recovery_failed = True
                    recovery_diagnostic = clean(type(recovery_error).__name__ + ": " + str(recovery_error))
            elif (TASK / "backup/manifest.json").exists() and params["operation"] in {"deploy", "ssh", "rename_user", "password", "firewall", "restore", "create_admin", "account_access", "delete_user", "ssh_hardening", "fail2ban", "prepare_key", "login_policy", "retire_key", "updates"}:
                try:
                    if params["operation"] == "deploy":
                        restore_deployment(identifier)
                    else:
                        restore_files(identifier)
                except Exception as recovery_error:
                    recovery_failed = True
                    recovery_diagnostic = clean(type(recovery_error).__name__ + ": " + str(recovery_error))
            command(["systemctl", "stop", "linux-manager-recover-" + identifier + ".timer"], check=False)
            status = json.loads((TASK / "status.json").read_text())
            status.update(state="recovery_failed" if recovery_failed else "failed", progress=100, updated=now(), message="操作失败且配置恢复未完成，请通过云平台控制台检查。" if recovery_failed else ("卸载未完成，已恢复项目文件和原服务状态。" if params["operation"] == "uninstall" and (TASK / "uninstall/manifest.json").exists() else "部署未完成，已恢复原项目。" if params["operation"] == "deploy" and (TASK / "backup/manifest.json").exists() else "") + (clean(error) if isinstance(error, OperationError) else "执行出现异常，已保留任务记录。请查看脱敏诊断。"))
            status["diagnostic"] = clean(type(error).__name__ + ": " + str(error))
            if recovery_diagnostic:
                status["recovery_diagnostic"] = recovery_diagnostic
            write_json(TASK / "status.json", status)
        finally:
            (TASK / "request.json").unlink(missing_ok=True)
            (TASK / "release.tar.gz").unlink(missing_ok=True)


def certificate_expiry(data, certificate_file):
    if certificate_file and Path(certificate_file).is_file():
        result = command(["openssl","x509","-in",str(certificate_file),"-noout","-enddate"],check=False)
        if result.returncode == 0 and result.stdout.startswith("notAfter="):
            data["certificate_expiry"] = result.stdout.partition("=")[2].strip()
    return data


def connection_details(params):
    kind = params.get("service")
    require(kind in UNITS, "项目类型无效。")
    manifest = ROOT / "installed.json"
    installed = json.loads(manifest.read_text()) if manifest.exists() else {}
    units = [{"unit":name, **unit_info(name)} for name in UNITS[kind]]
    loaded = any(unit.get("LoadState") == "loaded" for unit in units)
    data = {"service":kind, "installed":loaded, "units":units, **installed.get(kind,{})}
    if kind == "exchange":
        token = Path("/var/lib/xiaojun-exchange/setup-token")
        data["initialization_code"] = token.read_text().strip() if token.exists() else ""
        env = Path("/etc/xiaojun-exchange/server.env")
        if env.is_file():
            origin = next((line.partition("=")[2].strip().strip('\"') for line in env.read_text().splitlines() if line.startswith("XIAOJUN_PUBLIC_ORIGIN=")), "")
            if origin:
                parsed = urllib.parse.urlsplit(origin)
                if parsed.scheme in {"http","https"} and parsed.hostname:
                    data.update(host=parsed.hostname,port=parsed.port or 443,scheme=parsed.scheme,path="/")
        config = command(["systemctl","show","xiaojun-exchange-web.service","--property=ExecStart","--value"],check=False).stdout
        match = re.search(r"--port\s+(\d+)",config)
        if match:data["backend_port"]=int(match.group(1))
        elif data.get("uninstalled"):
            retained = Path("/etc/xiaojun-exchange/nginx.conf")
            if retained.is_file():
                match = re.search(r"127\.0\.0\.1:(\d+)", retained.read_text())
                if match:data["backend_port"]=int(match.group(1))
        data.setdefault("port",26483)
        certificate_file = next((p for p in ["/etc/xiaojun-exchange/tls/fullchain.pem", "/etc/xiaojun-exchange/letsencrypt/live/exchange-ip/fullchain.pem"] if Path(p).is_file()),"")
        return certificate_expiry(data,certificate_file)
    if kind == "reality":
        return reality_details(data)
    if kind == "hysteria2":
        path = Path("/etc/sing-box/config.json")
        if not path.is_file():return data
        config = json.loads(path.read_text())
        inbound = next((x for x in config.get("inbounds", []) if x.get("type") == "hysteria2"), None)
        if not inbound or not inbound.get("users"):return data
        data.update(installed=True,port=inbound["listen_port"],proxy_password=inbound["users"][0]["password"],sni=(inbound.get("tls") or {}).get("server_name", ""))
        return certificate_expiry(data,(inbound.get("tls") or {}).get("certificate_path"))
    if kind == "xui":
        path = Path("/etc/x-ui/x-ui.db")
        if not path.is_file():return data
        with sqlite3.connect("file:"+str(path)+"?mode=ro",uri=True,timeout=5) as db:
            db.row_factory=sqlite3.Row
            tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            settings={str(row["key"]):str(row["value"]) for row in db.execute("SELECT key,value FROM settings")} if "settings" in tables else {}
            data.update(installed=True,port=int(settings.get("webPort") or data.get("port") or 2053),path=settings.get("webBasePath") or data.get("path") or "/",scheme="https" if settings.get("webCertFile") else "http",inbounds=[])
            if "users" in tables:
                row=db.execute("SELECT username FROM users LIMIT 1").fetchone()
                if row:data["panel_username"]=row[0]
            if "inbounds" in tables:
                for row in db.execute("SELECT * FROM inbounds LIMIT 1000"):
                    row=dict(row);item={key:row[key] for key in ["port","protocol","remark","enable"] if key in row}
                    for key in ["settings","stream_settings"]:
                        try:item[key]=json.loads(row.get(key) or "{}")
                        except (ValueError,TypeError):item[key]={};item["port_protocol_error"]=True
                    data["inbounds"].append(item)
            if settings.get("subEnable", "true").lower()=="true":
                data["subscription_port"] = port(settings.get("subPort") or 2096)
                data["subscription_local_only"] = settings.get("subListen", "").strip("[]") in {"127.0.0.1", "::1", "localhost"} or settings.get("subListen", "").startswith("127.")
                custom=settings.get("subURI", "")
                if custom.startswith(("https://","http://")):
                    data["subscription_base"]=custom
                else:
                    address=data.get("host") or params.get("host", "")
                    if address:
                        scheme="https" if settings.get("subCertFile") else "http"
                        authority="["+address+"]" if ":" in address else address
                        data["subscription_base"]=scheme+"://"+authority+":"+str(settings.get("subPort") or 2096)+(settings.get("subPath") or "/sub/")
        return certificate_expiry(data,settings.get("webCertFile"))
    data["frontend_listeners"] = [{"port":row["port"], "protocol":row["protocol"]} for row in listeners() if "nginx" in row.get("processes",[]) and not row["local_only"]]
    data["frontend_ports"] = sorted({row["port"] for row in data["frontend_listeners"]})
    if 80 in data["frontend_ports"]:
        data.setdefault("port",80);data.setdefault("scheme","http")
    elif data["frontend_ports"]:
        data.setdefault("port",data["frontend_ports"][0]);data.setdefault("scheme","https")
    return data


def dispatch(request):
    require(os.geteuid() == 0, "此功能需要服务器管理员权限。")
    operation = request.get("action")
    if operation == "ping":
        return {"root_access": True, "time": now()}
    if operation == "verify_password":
        import ctypes
        import ctypes.util
        account = username(request.get("username"))
        encoded = next((line.split(":")[1] for line in Path("/etc/shadow").read_text().splitlines() if line.split(":", 1)[0] == account), "")
        if account in managed_accounts() and encoded.startswith("!"):
            encoded = encoded[1:]
        require(encoded and not encoded.startswith(("!", "*")), "账号密码未启用，无法验证。")
        library = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
        library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        library.crypt.restype = ctypes.c_char_p
        checked = library.crypt(request.get("password", "").encode(), encoded.encode())
        return {"verified": bool(checked) and secrets.compare_digest(checked.decode(), encoded)}
    if operation == "verify_project_password":
        register_secrets(request)
        require(request.get("service") == "xui", "项目凭据验证类型无效。")
        import bcrypt
        with sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True) as db:
            row = db.execute("SELECT password FROM users WHERE username=? LIMIT 1", (request.get("username"),)).fetchone()
        return {"verified": bool(row) and bcrypt.checkpw(request.get("password", "").encode(), row[0].encode())}
    if operation == "snapshot":
        return snapshot(request.get("include_projects", False), request.get("host", ""))
    if operation == "deployment_preflight":
        register_secrets(request.get("params", {}))
        return deployment_preflight(request.get("params", {}))
    if operation == "uninstall_preflight":
        return uninstall_preflight(request.get("params", {}))
    if operation == "account_details":
        return account_details(request)
    if operation == "security_preflight":
        return security_preflight(request)
    if operation == "start":
        return start_task(request.get("params", {}), request.get("task_id"))
    if operation == "task_lookup":
        identifier = validate_task_id(request.get("task_id"))
        with state_lock(ROOT / "submission"):
            directory = ROOT / "tasks" / identifier
            if not directory.exists():
                return {"task": None}
            return {"task": status_task(identifier)}
    if operation == "task":
        return status_task(request.get("task_id"))
    if operation == "tasks":
        return {"tasks": task_list()}
    if operation == "confirm":
        return confirm_task(request.get("task_id"))
    if operation == "recover":
        recover(request.get("task_id"))
        return status_task(request.get("task_id"))
    if operation == "details":
        return connection_details(request)
    if operation == "logs":
        kind = request.get("service")
        require(kind in UNITS, "服务类型无效。")
        args = ["journalctl", "--no-pager", "-n", "120", "--output=short"]
        for unit in UNITS[kind]:
            args += ["-u", unit]
        # Journals may contain third-party credentials. Only report lifecycle lines.
        output = command(args, check=False).stdout
        lines = [line for line in output.splitlines() if re.search(r"(?:Started|Stopped|Starting|Stopping|Failed|Main process exited|Deactivated)", line)]
        return {"logs": clean("\n".join(lines)) or "没有可显示的服务生命周期日志。业务日志请在对应管理网页中查看。"}
    raise OperationError("不支持此操作。")


def rpc():
    try:
        data = dispatch(REQUEST)
        result = {"ok": True, "data": data}
    except Exception as error:
        result = {"ok": False, "message": clean(error) if isinstance(error, OperationError) else "服务器检查失败，请确认系统和管理员权限。"}
    print("LM_RESULT:" + json.dumps(result, ensure_ascii=False))


#LM_BUNDLED_REALITY#
if globals().get("LM_REALITY_SOURCE"):
    exec(compile(LM_REALITY_SOURCE, "<linux-manager-reality>", "exec"), globals())
elif "__file__" in globals() and Path(__file__).with_name("reality.py").is_file():
    exec(compile(Path(__file__).with_name("reality.py").read_text(), "<linux-manager-reality>", "exec"), globals())

#LM_BUNDLED_REDEPLOYMENT#
if globals().get("LM_REDEPLOYMENT_SOURCE"):
    exec(compile(LM_REDEPLOYMENT_SOURCE, "<linux-manager-deployment>", "exec"), globals())
elif "__file__" in globals() and Path(__file__).with_name("redeployment.py").is_file():
    exec(compile(Path(__file__).with_name("redeployment.py").read_text(), "<linux-manager-deployment>", "exec"), globals())

#LM_BUNDLED_UNINSTALLATION#
if globals().get("LM_UNINSTALLATION_SOURCE"):
    exec(compile(LM_UNINSTALLATION_SOURCE, "<linux-manager-uninstallation>", "exec"), globals())
elif "__file__" in globals() and Path(__file__).with_name("uninstallation.py").is_file():
    exec(compile(Path(__file__).with_name("uninstallation.py").read_text(), "<linux-manager-uninstallation>", "exec"), globals())

if __name__ == "linux_manager_remote":
    rpc()
elif __name__ == "__main__" and len(sys.argv) == 3:
    if sys.argv[1] == "run":
        run_task(sys.argv[2])
    elif sys.argv[1] == "recover":
        recover(sys.argv[2])

