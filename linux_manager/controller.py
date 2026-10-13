from __future__ import annotations

import datetime
import base64
import json
from pathlib import Path
import subprocess
import time
import tempfile
import os
import secrets
import threading

from .models import Connection, ManagerError, Store, atomic_private, validate_password, validate_user
from .transport import SSH, Askpass, ConnectionInterrupted, AuthenticationFailed
from .releases import download_exchange
from .official_packages import download_project
from .project_info import credential_alias, information_rows, server_key
from .vault import LocalVault, vault_alias


class Controller:
    CONNECTION_ATTEMPTS = 4

    def __init__(self, store: Store):
        self.store = store
        self.connections = None
        self.connection_listener = lambda state: None
        self._connection_lock = threading.Lock()
        self._connections_closed = False

    def transport(self, connection: Connection, fresh=False) -> SSH:
        control = self.connections.control_path(connection) if self.connections and not fresh else None
        return SSH(connection, self.store.directory / "ssh" / connection.identifier, control_path=control)

    def keep_connection(self, connection):
        with self._connection_lock:
            if self._connections_closed:
                raise ManagerError("程序正在关闭，不再建立连接。")
            if self.connections is None:
                from .connections import PersistentConnections
                self.connections = PersistentConnections(self.connection_listener)
            manager = self.connections
        manager.connect(self.transport(connection, fresh=True))

    def connection_status(self, connection):
        return self.connections.status(connection) if self.connections else {"state": "disconnected", "token": ""}

    def disconnect_connection(self, identifier):
        if self.connections:
            self.connections.disconnect(identifier)

    def close_connections(self):
        with self._connection_lock:
            self._connections_closed = True
            manager = self.connections
        if manager:
            manager.close()

    def open_terminal(self, connection):
        from .terminal import open_terminal
        return open_terminal(self.transport(connection))

    def inspect(self, connection: Connection) -> dict:
        report = self.transport(connection).call({"action": "snapshot", "include_projects": True, "host": connection.host})
        report["project_information"] = {kind:self._project_information(connection, kind, data) for kind,data in report.get("project_details",{}).items()}
        self.observe_tasks(connection, report.get("tasks", []))
        return report

    def observe_tasks(self, connection, tasks):
        latest = {row["task_id"]:row for row in self.store.history() if row.get("server_id") == connection.identifier}
        redactor = self.transport(connection).redactor
        for task in tasks:
            previous = latest.get(task.get("id"))
            if previous and task.get("state") in {"succeeded", "failed", "rolled_back", "recovery_failed"} and previous.get("state") != task["state"]:
                self.store.record(previous | {"state":task["state"], "message":redactor.text(task.get("message", ""))})

    def tasks(self, connection):
        data = self.retry_call(connection, {"action": "tasks"})
        self.observe_tasks(connection, data["tasks"])
        seen = {task["id"] for task in data["tasks"]}
        latest = {row["task_id"]: row for row in self.store.history() if row.get("server_id") == connection.identifier}
        for identifier, row in latest.items():
            if identifier not in seen and row.get("state") == "submission_unknown":
                data["tasks"].append({"id": identifier, "operation": row["operation"], "state": "submission_unknown", "message": "本机已保存提交编号；服务器列表尚未显示此任务，请核对后再操作，不要重跑整个方案。", "events": []})
        return data

    def saved_password_tasks(self, connection):
        latest = {row["task_id"]: row for row in self.store.history() if row.get("operation") in {"create_admin", "password"} and isinstance(row.get("task_id"), str)}
        tasks = []
        for identifier, row in reversed(list(latest.items())):
            saved = self.store.vault.get(vault_alias("task-password", identifier))
            if saved.get("host") == connection.host and saved.get("password"):
                tasks.append({"id": identifier, "operation": row["operation"], "state": row["state"], "message": row.get("message", "本机口令副本；请核对任务结果。")})
        return {"tasks": tasks}

    def _project_information(self, connection, service, data):
        values = self.store.vault.get(credential_alias(connection,service)) if service in {"exchange","hysteria2","xui"} else {}
        if service in {"hysteria2", "xui"}:
            alias = vault_alias("service-pending", credential_alias(connection, service))
            pending = self.store.vault.get(alias)
            verified = bool(pending.get("proxy_password") and pending["proxy_password"] == data.get("proxy_password")) if service == "hysteria2" else False
            if service == "xui" and pending.get("panel_password") and data.get("panel_username"):
                try:
                    verified = self.transport(connection).call({"action":"verify_project_password", "service":"xui", "username":pending.get("panel_username") or data["panel_username"], "password":pending["panel_password"]}).get("verified", False)
                except ManagerError:
                    # An incomplete installation must not hide the other
                    # projects or replace the last known working password.
                    verified = False
            if verified:
                self.store.vault.put(credential_alias(connection, service), pending)
                self.store.vault.delete(alias)
                values = pending
        return {"server_key":server_key(connection),"service":service,"data":data,"rows":information_rows(data,connection,values)}

    def project_information(self, connection, service):
        data = self.transport(connection).call({"action":"details","service":service,"host":connection.host})
        return self._project_information(connection,service,data)

    def deployment_preview(self, connection, params):
        return self.transport(connection).call({"action":"deployment_preflight", "params":params})

    def uninstall_preview(self, connection, params):
        return self.retry_call(connection, {"action": "uninstall_preflight", "params": params})

    def generate_key(self, connection: Connection, passphrase: str) -> tuple[str, str]:
        if len(passphrase) < 16 or any(c in passphrase for c in "\n\r\x00"):
            raise ManagerError("私钥口令至少 16 位，不能包含换行。")
        folder = self.store.directory / "keys" / connection.identifier
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = folder / ("manager-" + str(time.time_ns()))
        with tempfile.TemporaryDirectory(prefix="key-", dir=folder) as temporary:
            with Askpass(Path(temporary), passphrase) as environment:
                result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-a", "64", "-C", "linux-server-manager", "-f", str(key)], stdin=subprocess.DEVNULL, capture_output=True, env=os.environ | environment, start_new_session=True, timeout=30)
        if result.returncode:
            raise ManagerError("无法生成本机密钥，请确认 OpenSSH 工具可用。")
        key.chmod(0o600)
        # Escrow the encryption password before sending any public key to Linux.
        try:
            alias = vault_alias("generated-key", connection.identifier + "/" + key.name)
            self.store.vault.put(alias, {"key_passphrase": passphrase})
            if self.store.vault.get(alias).get("key_passphrase") != passphrase:
                raise ManagerError("本机钥匙串验证失败。")
            atomic_private(folder / (key.name + ".json"), json.dumps({"key_path": str(key), "vault_alias": alias}))
        except ManagerError:
            key.unlink(missing_ok=True)
            key.with_suffix(".pub").unlink(missing_ok=True)
            raise ManagerError("私钥口令无法安全保存到本机钥匙串，已停止；服务器尚未修改。") from None
        return str(key), key.with_suffix(".pub").read_text().strip()

    def public_key(self, connection):
        with tempfile.TemporaryDirectory(prefix="public-", dir=self.store.directory) as temporary:
            with Askpass(Path(temporary), connection.key_passphrase) as environment:
                result = subprocess.run(["ssh-keygen", "-y", "-f", connection.key_path], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=os.environ | environment, start_new_session=True, timeout=30)
        if result.returncode:
            raise ManagerError("无法读取原私钥的公钥，不能自动撤销旧钥匙。")
        return result.stdout.strip()

    def trust_same_server(self, original: SSH, candidate: SSH) -> None:
        if candidate.trusted():
            return
        _, keys = candidate.fingerprint()
        old_keys = {tuple(line.split()[1:3]) for line in original.known_hosts.read_text().splitlines() if len(line.split()) >= 3}
        new_keys = {tuple(line.split()[1:3]) for line in keys.splitlines() if len(line.split()) >= 3}
        if not new_keys or not new_keys <= old_keys:
            raise ManagerError("新端口的服务器身份不一致，已停止验证，配置将在超时后恢复。")
        candidate.trust(keys)

    def candidate(self, connection: Connection, params: dict, result: dict) -> Connection:
        operation = params["operation"]
        changes = {}
        verify = result.get("verification", {})
        if operation in {"create_admin", "rename_user", "ssh"}:
            changes["username"] = verify.get("username", connection.username)
        if operation in {"ssh", "firewall"} and "port" in verify:
            changes["port"] = verify["port"]
        if operation == "create_admin":
            changes.update(password=params["new_password"], sudo_password=params["new_password"])
            if params.get("local_key_path"):
                changes.update(auth="key", key_path=params["local_key_path"], key_passphrase=params.get("local_key_passphrase", ""))
            else:
                changes["auth"] = "password"
        if operation in {"ssh", "prepare_key"} and params.get("local_key_path"):
            changes.update(auth="key", key_path=params["local_key_path"], key_passphrase=params.get("local_key_passphrase", ""))
        if operation == "password" and params.get("username") == connection.username:
            changes.update(password=params["new_password"], sudo_password=params["new_password"])
        return connection.changed(**changes)

    def retry_call(self, connection, request, *, timeout=30, progress=lambda status: None, fallback=None, connected=lambda connection: None):
        # Only safe reads and idempotent confirmation use this helper. Task
        # submission separately confirms the receipt before a repeat send.
        original = connection
        last = None
        for attempt in range(self.CONNECTION_ATTEMPTS):
            ssh = self.transport(connection, fresh=True)
            if connection != original:
                self.trust_same_server(self.transport(original), ssh)
            try:
                data = ssh.call(request, timeout=timeout)
                connected(connection)
                return data
            except AuthenticationFailed:
                if fallback is None or connection == fallback:
                    raise
                connection = fallback
            except ConnectionInterrupted as error:
                last = error
            if attempt + 1 < self.CONNECTION_ATTEMPTS:
                progress({"task_id": request.get("task_id"), "state": "running", "progress": 0, "message": "连接暂时中断，正在重新连接并读取原任务；不会重复执行。"})
                time.sleep(2)
        raise ConnectionInterrupted("多次重连仍未取得有效结果。请重新连接后查看操作记录，不要重跑整个方案。" + (" " + str(last) if last else ""))

    def _task_fallback(self, connection, params):
        if params["operation"] not in {"ssh", "rename_user", "password", "login_policy", "retire_key", "prepare_key", "create_admin"}:
            return None
        preliminary = {"verification": {"username": params.get("new_username", params.get("username", connection.username)), "port": params.get("port", connection.port)}}
        candidate = self.candidate(connection, params, preliminary)
        return candidate if candidate != connection else None

    def _submit_task(self, connection, wire, identifier, params, progress, timeout):
        request = {"action": "start", "task_id": identifier, "params": wire}
        for attempt in range(self.CONNECTION_ATTEMPTS):
            try:
                started = self.transport(connection, fresh=True).call(request, timeout=timeout)
                if started.get("task_id") != identifier:
                    raise ManagerError("服务器返回的任务编号不一致，已停止；请查看操作记录，不要重复提交。")
                return connection
            except ConnectionInterrupted:
                progress({"task_id": identifier, "state": "running", "progress": 0, "message": "提交响应中断，正在确认原任务是否已收到；不会重跑已执行步骤。"})
                observed = []
                found = self.retry_call(connection, {"action": "task_lookup", "task_id": identifier}, progress=progress, fallback=self._task_fallback(connection, params), connected=observed.append)
                if found.get("task") is not None:
                    task = found["task"]
                    if not isinstance(task, dict) or task.get("id") != identifier or task.get("operation") != params["operation"]:
                        raise ManagerError("服务器任务回执不一致，已停止；请查看操作记录。")
                    return observed[-1]
                if attempt + 1 < self.CONNECTION_ATTEMPTS:
                    time.sleep(2)
        raise ConnectionInterrupted("提交未能确认，任务编号已保存在操作记录中；请重新连接检查，不要重跑整个方案。")

    def verify_task(self, connection: Connection, identifier: str, params: dict, status: dict, progress=lambda status: None) -> Connection:
        candidate = self.candidate(connection, params, status.get("result", {}))
        self.trust_same_server(self.transport(connection), self.transport(candidate, fresh=True))
        try:
            self.retry_call(candidate, {"action": "ping"}, timeout=25, progress=progress)
            if params["operation"] == "password":
                checked = self.retry_call(candidate, {"action": "verify_password", "username": params["username"], "password": params["new_password"]}, progress=progress)
                if not checked["verified"]:
                    raise ManagerError("新密码的服务器端验证失败，未确认变更。")
            try:
                confirmed = self.retry_call(candidate, {"action": "confirm", "task_id": identifier}, progress=progress)
            except ConnectionInterrupted:
                # All confirmation replies may be lost even though the server
                # committed success. Read that state instead of reporting a
                # verified login as an unverified change.
                confirmed = self.retry_call(candidate, {"action": "task", "task_id": identifier}, progress=progress)
            if confirmed.get("state") != "succeeded" or confirmed.get("id") != identifier:
                raise ManagerError("任务确认结果不一致，已停止；请查看操作记录。")
            status.clear()
            status.update(confirmed)
        except ManagerError as error:
            raise ManagerError("新连接或任务确认未完成。请勿重复提交；服务器只会恢复仍未确认的变更，已确认结果请在操作记录中核对。 " + str(error)) from None
        return candidate

    def execute(self, connection: Connection, params: dict, progress=lambda status: None) -> tuple[dict, Connection]:
        original = connection
        ssh = self.transport(connection, fresh=True)
        ssh.redactor.add(*(v for k, v in params.items() if isinstance(v, str) and any(x in k for x in ["password", "username", "key", "host"])))
        wire = {k: v for k, v in params.items() if not k.startswith("local_")}
        if params.get("operation") in {"account_access", "delete_user"}:
            if params.get("username") == connection.username or connection.username == "root":
                raise ManagerError("请先使用另一个普通管理员连接，再禁用或删除账号。")
            # A new SSH session verifies the spare admin immediately before mutation.
            ssh.call({"action": "ping"})
            wire["verified_username"] = connection.username
        identifier = secrets.token_hex(12)
        created = datetime.datetime.now(datetime.timezone.utc).isoformat()
        poll_connection = connection
        def submit(timeout=60):
            nonlocal poll_connection
            if params["operation"] in {"rename_user", "password", "ssh", "prepare_key", "login_policy", "retire_key"}:
                # Stop only our own master before credentials change; its
                # watcher must not reconnect with an obsolete account/key.
                self.disconnect_connection(connection.identifier)
            self.store.record({"task_id": identifier, "server_id": connection.identifier, "operation": params["operation"], "state": "submission_unknown", "created": created, "message": "正在提交；尚未确认服务器是否收到，勿重复执行。"})
            poll_connection = self._submit_task(connection, wire, identifier, params, progress, timeout)
        deployment = params.get("operation") == "deploy" and params.get("service") in {"exchange", "hysteria2", "reality", "xui", "nginx"}
        pending_values = None
        if deployment:
            preflight = self.retry_call(connection, {"action": "deployment_preflight", "params": wire}, progress=progress)
            if params.get("deployment_fingerprint") and params["deployment_fingerprint"] != preflight["fingerprint"]:
                raise ManagerError("项目配置在预览后发生变化，未执行改动。请重新预览。")
            kind = params["service"]
            wire["version"] = preflight["version"]
            wire["deployment_fingerprint"] = preflight["fingerprint"]
            if kind in {"hysteria2", "xui"}:
                pending_values = self.store.vault.get(credential_alias(connection, kind)) | {key:params[key] for key in ["proxy_password", "panel_username", "panel_password"] if params.get(key)}
                # Escrow proposed values locally without replacing a working
                # panel password before the server change has been verified.
                self.store.vault.put(vault_alias("service-pending", credential_alias(connection, kind)), pending_values)
            if preflight["requires_archive"]:
                progress({"state": "preparing", "progress": 5, "message": "在本机下载并校验已确认版本的官方发行包…"})
                with tempfile.TemporaryDirectory(prefix="lm-release-", dir=self.store.directory) as directory:
                    archive = Path(directory) / "release.tar.gz"
                    wire["release_sha256"] = download_exchange(preflight["version"], archive) if kind == "exchange" else download_project(kind, preflight["version"], preflight["architecture"], archive)
                    wire["release_archive"] = base64.b64encode(archive.read_bytes()).decode()
                    progress({"state": "preparing", "progress": 10, "message": "通过 SSH 传送已校验的发行包…"})
                    submit(timeout=180)
                wire.pop("release_archive", None)
            else:
                submit()
        else:
            if params["operation"] == "uninstall":
                preflight = self.uninstall_preview(connection, wire)
                if params.get("uninstall_fingerprint") != preflight["fingerprint"]:
                    raise ManagerError("卸载范围在预览后发生变化，未执行改动。请重新预览。")
                wire["uninstall_fingerprint"] = preflight["fingerprint"]
                if params.get("service") == "exchange" and params.get("maintenance_confirmed") is not True:
                    raise ManagerError("请先在交易网页停止交易并完成撤单、清理，再卸载交易系统。")
            if params["operation"] in {"create_admin", "password"}:
                values = {"host": connection.host, "username": validate_user(params["username"]), "password": validate_password(params["new_password"])}
                alias = vault_alias("task-password", identifier)
                # Keep a per-task copy even for an account without a saved
                # login profile; never replace the verified login in advance.
                try:
                    self.store.vault.put(alias, values)
                    if isinstance(self.store.vault, LocalVault):
                        self.store.vault.cache.pop(alias, None)
                    if self.store.vault.get(alias) != values:
                        raise ManagerError("本机钥匙串回读验证失败。")
                except (ManagerError, ValueError, TypeError):
                    raise ManagerError("新密码无法安全保存并验证，已停止；服务器密码尚未修改。请允许访问本机钥匙串后重试。") from None
            submit()
        self.store.record({"task_id": identifier, "server_id": connection.identifier, "operation": params["operation"], "state": "submitted", "created": created, "message": "任务已提交。"})
        progress({"task_id": identifier, "state": "queued", "progress": 0, "message": "任务已提交。"})
        status = {}
        fallback = self._task_fallback(connection, params)
        def observed(current):
            nonlocal poll_connection
            poll_connection = current
        for _ in range(1200):
            status = self.retry_call(poll_connection, {"action": "task", "task_id": identifier}, progress=progress, fallback=fallback if fallback != poll_connection else None, connected=observed)
            progress(status)
            if status["state"] in {"succeeded", "failed", "rolled_back", "awaiting_verification", "recovery_failed"}:
                break
            time.sleep(2)
        else:
            raise ManagerError("任务仍未结束，请在操作记录中查看后台任务，勿重复执行。")
        if status["state"] == "awaiting_verification":
            progress(status | {"message": "正在使用新连接验证账号和管理员权限…"})
            connection = self.verify_task(connection, identifier, params, status, progress)
            # Confirmation is durable; persist the verified login before any
            # further result read can fail and leave the profile outdated.
            profiles, identifiers = self.synchronize_profiles(self.store.profiles(), original, connection, params)
            self.store.save(profiles, update_identifiers=identifiers)
            if connection != original:
                self.disconnect_connection(original.identifier)
            # verify_task supplied the authoritative, idempotent confirmation
            # result; do not add an unnecessary post-confirmation SSH round-trip.
        self.store.record({"task_id": identifier, "server_id": connection.identifier, "operation": params["operation"], "state": status["state"], "created": created, "message": ssh.redactor.text(status["message"])})
        if status["state"] != "succeeded":
            if deployment and pending_values is not None and preflight["installed"] and status["state"] in {"failed", "rolled_back"}:
                self.store.vault.delete(vault_alias("service-pending", credential_alias(connection, params["service"])))
            raise ManagerError(ssh.redactor.text(status["message"]))
        if deployment and pending_values is not None:
            self.store.vault.put(credential_alias(connection, params["service"]), pending_values)
            self.store.vault.delete(vault_alias("service-pending", credential_alias(connection, params["service"])))
        if params["operation"] == "ssh" and original.port != connection.port:
            for kind in ["exchange", "hysteria2", "xui"]:
                values = self.store.vault.get(credential_alias(original,kind))
                if values:
                    self.store.vault.put(credential_alias(connection,kind),values)
        profiles, identifiers = self.synchronize_profiles(self.store.profiles(), original, connection, params)
        self.store.save(profiles, update_identifiers=identifiers)
        if params["operation"] == "delete_user":
            for profile in profiles:
                if profile.host == original.host and profile.username == params["username"]:
                    self.store.vault.delete(vault_alias("security-recovery", profile.identifier))
        if params["operation"] in {"delete_user", "rename_user"}:
            target = params["old_username"] if params["operation"] == "rename_user" else params["username"]
            aliases = {vault_alias("task-password", row["task_id"]) for row in self.store.history() if row.get("operation") in {"create_admin", "password"} and isinstance(row.get("task_id"), str)}
            for alias in aliases:
                saved = self.store.vault.get(alias)
                if saved.get("host") == original.host and saved.get("username") == target:
                    if params["operation"] == "delete_user":
                        self.store.vault.delete(alias)
                    else:
                        self.store.vault.put(alias, saved | {"username": params["new_username"]})
        return status, connection

    def synchronize_profiles(self, profiles, original, updated, params):
        result, identifiers = [], set()
        operation = params["operation"]
        for profile in profiles:
            changes = {}
            if profile.identifier == updated.identifier:
                profile = updated
                identifiers.add(profile.identifier)
            elif profile.host == original.host:
                target = params.get("old_username") if operation == "rename_user" else params.get("username")
                if profile.username == target:
                    if operation == "password":
                        changes.update(password=params["new_password"], sudo_password=params["new_password"])
                    elif operation == "rename_user":
                        changes["username"] = params["new_username"]
                    elif operation == "delete_user":
                        changes.update(password="", sudo_password="", key_passphrase="", remember=False)
                if operation == "ssh" and profile.port == original.port:
                    changes["port"] = updated.port
                if operation in {"ssh", "prepare_key"} and profile.username == original.username and updated.auth == "key":
                    changes.update(auth="key", key_path=updated.key_path, key_passphrase=updated.key_passphrase)
                if changes:
                    profile = profile.changed(**changes)
                    identifiers.add(profile.identifier)
            result.append(profile)
        return result, identifiers

    def account_details(self, connection, account):
        from .key_info import encrypted_key
        result = self.transport(connection).call({"action": "account_details", "username": account})
        paths = []
        for profile in self.store.profiles():
            if profile.host == connection.host and profile.username == account and profile.auth == "key" and profile.key_path:
                paths.append(profile.key_path)
        result["local_private_keys"] = list(dict.fromkeys(paths))
        result["local_key_encryption"] = {path: encrypted_key(path) for path in result["local_private_keys"]}
        return result

    def security_plan(self, connection, options, progress=lambda status: None):
        from .security_plan import apply_plan
        return apply_plan(self, connection, options, progress)

