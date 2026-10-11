"""Native OpenSSH transport. Secrets travel through stdin and a private askpass socket."""
from __future__ import annotations

import base64
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

from .models import Connection, ManagerError, Redactor, atomic_private

class ConnectionInterrupted(ManagerError):
    """Only retry reads or requests carrying an idempotent task identifier."""


class AuthenticationFailed(ManagerError):
    """Permanent authentication failure; never retry the same credentials."""

BOOTSTRAP = "import sys,json,base64; lines=sys.stdin.read().splitlines(); packet=next(x[10:] for x in lines if x.startswith('LMREQUEST:')); e=json.loads(base64.b64decode(packet)); scope={'__name__':'linux_manager_remote','REQUEST':e['request'],'AGENT_SOURCE':e['agent'],'SSH_CONTEXT':sys.argv[1] if len(sys.argv)>1 else ''}; exec(compile(e['agent'],'<linux-manager-agent>','exec'),scope)"


class Askpass:
    def __init__(self, directory: Path, secret: str):
        self.directory = directory
        self.secret = secret
        self.server = None
        self.thread = None

    def __enter__(self) -> dict:
        self.socket_directory = tempfile.TemporaryDirectory(prefix="lm-ask-", dir="/tmp")
        endpoint = Path(self.socket_directory.name) / "askpass.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(endpoint))
        endpoint.chmod(0o600)
        self.server.listen(4)
        self.server.settimeout(0.25)
        self.stop = threading.Event()

        def serve():
            while not self.stop.is_set():
                try:
                    client, _ = self.server.accept()
                    with client:
                        client.sendall(self.secret.encode() + b"\n")
                except socket.timeout:
                    continue
                except OSError:
                    break

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        helper = self.directory / "askpass"
        code = "import os,socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ns.connect(os.environ['LM_ASKPASS_SOCKET'])\nb=b''\nwhile True:\n c=s.recv(4096)\n if not c: break\n b+=c\nsys.stdout.buffer.write(b)\n"
        # A shell launcher handles interpreter paths containing spaces.
        script = self.directory / "askpass.py"
        atomic_private(script, code)
        arguments = [sys.executable, "--askpass"] if getattr(sys, "frozen", False) else [sys.executable, str(script)]
        atomic_private(helper, "#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in arguments) + "\n")
        helper.chmod(0o700)
        return {"SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "linux-manager", "LM_ASKPASS_SOCKET": str(endpoint)}

    def __exit__(self, *args):
        self.stop.set()
        if self.server:
            self.server.close()
        if self.thread:
            self.thread.join(timeout=1)
        self.socket_directory.cleanup()
        self.secret = ""


class SSH:
    def __init__(self, connection: Connection, directory: Path, control_path=None):
        self.connection = connection
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.known_hosts = directory / "known_hosts"
        self.control_path = control_path
        self.redactor = Redactor(connection.host, connection.username, connection.key_path, connection.password, connection.key_passphrase, connection.sudo_password)
        if not shutil.which("ssh"):
            raise ManagerError("本机缺少 OpenSSH 客户端，请安装系统的 OpenSSH 客户端后重试。")

    def fingerprint(self) -> tuple[str, str]:
        c = self.connection
        try:
            result = subprocess.run(["ssh-keyscan", "-T", "8", "-p", str(c.port), "-t", "ed25519", c.host], capture_output=True, timeout=15)
            if not result.stdout.strip():
                raise ManagerError("无法获取服务器身份，请检查服务器地址、SSH 端口和云平台安全组。")
            checked = subprocess.run(["ssh-keygen", "-lf", "-"], input=result.stdout, capture_output=True, timeout=5)
            if checked.returncode:
                raise ManagerError("服务器身份信息无效。")
            fingerprints = sorted(set(line.split()[1] for line in checked.stdout.decode().splitlines() if len(line.split()) > 1))
            if not fingerprints:
                raise ManagerError("服务器未提供有效的身份指纹。")
            return "\n".join(fingerprints), result.stdout.decode()
        except subprocess.TimeoutExpired:
            raise ManagerError("获取服务器身份超时，请检查网络。") from None

    def trusted(self) -> bool:
        if not self.known_hosts.exists():
            return False
        endpoint = self.connection.host if self.connection.port == 22 else f"[{self.connection.host}]:{self.connection.port}"
        result = subprocess.run(["ssh-keygen", "-F", endpoint, "-f", str(self.known_hosts)], capture_output=True, timeout=5)
        return result.returncode == 0

    def trust(self, keys: str) -> None:
        existing = self.known_hosts.read_text() if self.known_hosts.exists() else ""
        atomic_private(self.known_hosts, existing + keys)

    def replace_trust(self, keys: str) -> None:
        """Called only after the user confirms a server rebuild in the local UI."""
        if self.known_hosts.exists():
            atomic_private(self.known_hosts.with_suffix(".previous"), self.known_hosts.read_bytes())
            endpoint = self.connection.host if self.connection.port == 22 else f"[{self.connection.host}]:{self.connection.port}"
            result = subprocess.run(["ssh-keygen", "-R", endpoint, "-f", str(self.known_hosts)], capture_output=True, timeout=5)
            if result.returncode:
                raise ManagerError("无法更新服务器身份记录，原记录已保留。")
        self.trust(keys)

    def _config(self, directory: Path) -> Path:
        c = self.connection

        def quoted(value):
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

        lines = ["Host linux-manager-server", f" HostName {c.host}", f" User {c.username}", f" Port {c.port}", " ConnectTimeout 12", " ServerAliveInterval 15", " ServerAliveCountMax 3", " StrictHostKeyChecking yes", " LogLevel ERROR", " NumberOfPasswordPrompts 1", " IdentitiesOnly yes", f" UserKnownHostsFile {quoted(self.known_hosts)}"]
        # Never borrow a master created outside this program. Critical login
        # verification has no ControlPath and always authenticates afresh.
        lines += [" ControlMaster no", " ControlPersist no", " ControlPath " + (quoted(self.control_path) if self.control_path else "none")]
        if c.auth == "key":
            lines += [f" IdentityFile {quoted(Path(c.key_path).expanduser())}", " PreferredAuthentications publickey"]
        else:
            lines += [" PubkeyAuthentication no", " PreferredAuthentications password,keyboard-interactive"]
        config = directory / "connection.conf"
        atomic_private(config, "\n".join(lines) + "\n")
        return config

    def _failure(self, request, reason, returncode=None):
        # Keep fixed categories only: never persist stderr, stdout, the request,
        # addresses, account names, paths, keys or credentials.
        actions = {"ping", "start", "task", "task_lookup", "confirm", "recover", "tasks", "snapshot", "security_preflight", "deployment_preflight", "uninstall_preflight", "verify_password"}
        data = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "action": request.get("action") if request.get("action") in actions else "other", "reason": reason, "returncode": returncode}
        identifier = request.get("task_id")
        if isinstance(identifier, str) and re.fullmatch(r"[a-f0-9]{24}", identifier):
            data["task_id"] = identifier
        try:
            atomic_private(self.directory / "transport-error.json", json.dumps(data, ensure_ascii=False))
        except OSError:
            return "（连接诊断未能保存到本机。）"
        return "（脱敏连接诊断已保存在本机。）"

    def call(self, request: dict, timeout: int = 60) -> dict:
        self.connection.validate()
        if not self.trusted():
            raise ManagerError("请先确认服务器身份指纹，再建立连接。")
        source = Path(__file__).with_name("remote_agent.py").read_text()
        lock = Path(__file__).with_name("resources") / "requirements-certbot.lock"
        source = source.replace("#LM_BUNDLED_CERTBOT#", "CERTBOT_LOCK = " + repr(lock.read_text()))
        source = source.replace("#LM_BUNDLED_REDEPLOYMENT#", "LM_REDEPLOYMENT_SOURCE = " + repr(Path(__file__).with_name("redeployment.py").read_text()))
        source = source.replace("#LM_BUNDLED_UNINSTALLATION#", "LM_UNINSTALLATION_SOURCE = " + repr(Path(__file__).with_name("uninstallation.py").read_text()))
        envelope = json.dumps({"agent": source, "request": request}, ensure_ascii=False).encode()
        # Passwords and the complete request are never command-line arguments.
        payload = (self.connection.sudo_password or self.connection.password) + "\nLMREQUEST:" + base64.b64encode(envelope).decode() + "\n"
        command = "if [ \"$(id -u)\" = 0 ]; then python3 -c " + shlex.quote(BOOTSTRAP) + ' "$SSH_CONNECTION"; else sudo -S -p \'\' python3 -c ' + shlex.quote(BOOTSTRAP) + ' "$SSH_CONNECTION"; fi'
        secret = self.connection.password if self.connection.auth == "password" else self.connection.key_passphrase
        with tempfile.TemporaryDirectory(prefix="lm-", dir=self.directory) as temporary:
            folder = Path(temporary)
            with Askpass(folder, secret) as environment:
                config = self._config(folder)
                try:
                    result = subprocess.run(["ssh", "-F", str(config), "-T", "linux-manager-server", command], input=payload, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=os.environ | environment, start_new_session=True)
                except subprocess.TimeoutExpired:
                    note = self._failure(request, "timeout")
                    raise ConnectionInterrupted("连接超时。已提交的后台任务可能仍在运行，请重新连接并查看操作记录，不要重复部署。" + note) from None
        for line in reversed(result.stdout.splitlines()):
            if line.startswith("LM_RESULT:"):
                try:
                    response = json.loads(line[len("LM_RESULT:"):])
                except ValueError:
                    continue
                if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
                    continue
                if not response["ok"]:
                    raise ManagerError(self.redactor.text(response.get("message", "服务器操作失败。")))
                if not isinstance(response.get("data"), dict):
                    continue
                return response["data"]
        diagnostics = result.stderr.lower()
        if "host key verification failed" in diagnostics or "remote host identification has changed" in diagnostics:
            note = self._failure(request, "identity_changed", result.returncode)
            raise ManagerError("服务器身份与已保存的指纹不一致。\n请先在云平台确认地址仍对应你的服务器；如已重装或核实身份，回到“连接服务器”点击“重新确认服务器身份”，确认后重新连接。" + note)
        if any(value in diagnostics for value in ("permission denied", "authentication failed", "no supported authentication", "incorrect passphrase", "bad permissions", "load key")):
            note = self._failure(request, "authentication_failed", result.returncode)
            raise AuthenticationFailed("登录失败，请检查账号、密码、密钥及服务器允许的登录方式。" + note)
        if "sudo" in diagnostics or "password is required" in diagnostics:
            note = self._failure(request, "sudo_failed", result.returncode)
            raise ManagerError("需要管理员权限。请填写管理员密码；当前账号必须允许使用 sudo。" + note)
        if "python3" in diagnostics and "not found" in diagnostics:
            note = self._failure(request, "missing_python", result.returncode)
            raise ManagerError("服务器缺少 Python 3，请使用支持的 Ubuntu 24.04 或 Debian 12/13 镜像。" + note)
        if "traceback (most recent call last)" in diagnostics:
            note = self._failure(request, "remote_bootstrap_failed", result.returncode)
            raise ManagerError("服务器检查程序未能正常启动，已停止自动重试。" + note)
        reason = next((category for token, category in [("connection reset", "connection_reset"), ("connection timed out", "timeout"), ("connection refused", "connection_refused"), ("connection closed", "connection_closed"), ("broken pipe", "broken_pipe"), ("no route to host", "unreachable"), ("could not resolve", "name_resolution_failed")] if token in diagnostics), "invalid_response" if result.stdout.strip() else "empty_response")
        note = self._failure(request, reason, result.returncode)
        raise ConnectionInterrupted("服务器未返回有效结果，请检查网络、SSH 端口和云平台安全组。" + note)

