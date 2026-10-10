"""App-owned OpenSSH masters; no credentials are written to session files."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import uuid

from .models import ManagerError
from .transport import Askpass


def connection_key(connection):
    return tuple(getattr(connection, name) for name in (
        "host", "username", "port", "auth", "key_path", "password", "key_passphrase", "sudo_password"
    ))


MESSAGES = {
    "connecting": "正在建立持续连接…",
    "connected": "连接保持中。短暂掉线后会自动重连。",
    "reconnecting": "连接暂时中断，正在自动重连；已提交的任务不会重复执行。",
    "identity_changed": "服务器身份核验失败，已停止自动重连。请核实身份后重新确认。",
    "authentication_failed": "登录认证失败，已停止自动重连。请检查登录信息后重新连接。",
    "failed": "连接未能建立，请检查网络和 SSH 设置后重试。",
    "disconnected": "已手动断开，不会自动重连。",
}


class ManagedConnection:
    STARTUP_TIMEOUT = 20
    CHECK_INTERVAL = 0.25
    RETRY_DELAY = 2
    BACKOFF_LIMIT = 30

    def __init__(self, ssh, notify):
        self.ssh = ssh
        self.key = connection_key(ssh.connection)
        self.notify = notify
        self.token = uuid.uuid4().hex
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.state = "connecting"
        self.process = None
        self.folder = tempfile.TemporaryDirectory(prefix="lm-session-", dir="/tmp")
        self.control_path = Path(self.folder.name) / "control.sock"
        self.thread = threading.Thread(target=self._run, daemon=True, name="linux-manager-connection")

    def start(self):
        self.thread.start()

    def status(self):
        with self.lock:
            state = self.state
        return {"identifier": self.ssh.connection.identifier, "token": self.token,
                "state": state, "message": MESSAGES[state]}

    def _state(self, state):
        with self.lock:
            if self.stop_event.is_set() and state != "disconnected":
                return
            self.state = state
            if state in {"connecting", "reconnecting"}:
                self.ready.clear()
            else:
                self.ready.set()
        self.notify(self.status())

    def wait_connected(self, timeout=25):
        if not self.ready.wait(timeout) or self.status()["state"] != "connected":
            raise ManagerError(self.status()["message"])

    def stop(self):
        self.stop_event.set()
        self._state("disconnected")
        with self.lock:
            process = self.process
        if process and process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass

    @staticmethod
    def failure_state(diagnostic):
        text = diagnostic.lower()
        if "host key verification failed" in text or "remote host identification has changed" in text:
            return "identity_changed"
        if any(value in text for value in ("permission denied", "authentication failed", "no supported authentication", "incorrect passphrase", "bad permissions", "load key")):
            return "authentication_failed"
        return "failed"

    def _attempt(self, config):
        self.control_path.unlink(missing_ok=True)
        c = self.ssh.connection
        secret = c.password if c.auth == "password" else c.key_passphrase
        with Askpass(Path(self.folder.name), secret) as environment:
            with self.lock:
                if self.stop_event.is_set():
                    return "disconnected"
                self.process = subprocess.Popen([
                    "ssh", "-F", str(config), "-M", "-S", str(self.control_path),
                    "-o", "ControlMaster=yes", "-o", "ControlPersist=no", "-N", "-T", "linux-manager-server"
                ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    env=os.environ | environment, start_new_session=True)
                process = self.process
            deadline = time.monotonic() + self.STARTUP_TIMEOUT
            while not self.stop_event.is_set() and process.poll() is None and time.monotonic() < deadline:
                if self.control_path.exists():
                    try:
                        checked = subprocess.run([
                            "ssh", "-F", str(config), "-S", str(self.control_path), "-O", "check", "linux-manager-server"
                        ], stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
                    except subprocess.TimeoutExpired:
                        continue
                    if checked.returncode == 0:
                        break
                self.stop_event.wait(self.CHECK_INTERVAL)
            else:
                if process.poll() is None:
                    process.terminate()
                diagnostic = process.communicate(timeout=5)[1].decode(errors="replace")
                return "disconnected" if self.stop_event.is_set() else self.failure_state(diagnostic)
        # The askpass socket is removed as soon as authentication completes.
        self._state("connected")
        while process.poll() is None and not self.stop_event.wait(self.CHECK_INTERVAL):
            pass
        if self.stop_event.is_set() and process.poll() is None:
            process.terminate()
        diagnostic = process.communicate(timeout=5)[1].decode(errors="replace")
        return "disconnected" if self.stop_event.is_set() else self.failure_state(diagnostic)

    def _run(self):
        connected_once = False
        backoff = self.RETRY_DELAY
        try:
            config = self.ssh._config(Path(self.folder.name))
            while not self.stop_event.is_set():
                outcome = self._attempt(config)
                connected_once = connected_once or self.status()["state"] == "connected"
                if outcome == "disconnected":
                    break
                if outcome in {"identity_changed", "authentication_failed"} or not connected_once:
                    self._state(outcome)
                    return
                self._state("reconnecting")
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, self.BACKOFF_LIMIT)
        except Exception:
            self._state("failed")
        finally:
            with self.lock:
                process = self.process
            if process:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.communicate()
            self.folder.cleanup()


class PersistentConnections:
    def __init__(self, listener=lambda state: None):
        self.listener = listener
        self.lock = threading.Lock()
        self.sessions = {}
        self.closed = False

    def _notify(self, value):
        # UI notifications contain an opaque id and fixed messages only.
        self.listener(value)

    def connect(self, ssh):
        ssh.connection.validate()
        if not ssh.trusted():
            raise ManagerError("请先确认服务器身份指纹，再建立连接。")
        identifier = ssh.connection.identifier
        with self.lock:
            if self.closed:
                raise ManagerError("程序正在关闭，不再建立连接。")
            previous = self.sessions.get(identifier)
            if previous and previous.key == connection_key(ssh.connection) and previous.status()["state"] in {"connecting", "connected", "reconnecting"}:
                session = previous
            else:
                if previous:
                    previous.stop()
                session = ManagedConnection(ssh, self._notify)
                self.sessions[identifier] = session
                session.start()
        session.wait_connected()
        return session

    def status(self, connection):
        with self.lock:
            session = self.sessions.get(connection.identifier)
        if session and session.key == connection_key(connection):
            return session.status()
        return {"identifier": connection.identifier, "state": "disconnected", "token": "", "message": MESSAGES["disconnected"]}

    def control_path(self, connection):
        with self.lock:
            session = self.sessions.get(connection.identifier)
        if session and session.key == connection_key(connection) and session.status()["state"] == "connected":
            return session.control_path
        return None

    def disconnect(self, identifier):
        with self.lock:
            session = self.sessions.pop(identifier, None)
        if session:
            session.stop()

    def close(self):
        with self.lock:
            self.closed = True
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.stop()
        for session in sessions:
            session.thread.join(timeout=2)
