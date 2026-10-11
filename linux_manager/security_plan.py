"""A sequential, locally journalled login migration; each SSH step is verified."""
from __future__ import annotations

import json
import secrets
from pathlib import Path

from .models import Connection, ManagerError, atomic_private, validate_user, validate_password
from .vault import vault_alias


def apply_plan(controller, original, options, progress):
    mode = options.get("mode")
    if mode not in {"rename", "create"}:
        raise ManagerError("请选择修改现有账号或新增管理员。")
    target = validate_user(options.get("username", ""))
    if target == "root" or (mode == "rename" and original.username == "root"):
        raise ManagerError("超级管理员不能改名；请选新增普通管理员。")
    new_password = options.get("new_password", "")
    if mode == "create" and not new_password:
        new_password = secrets.token_urlsafe(30)
    if new_password:
        validate_password(new_password)
    phrase = options.get("key_passphrase") or secrets.token_urlsafe(36)
    if len(phrase) < 16 or any(c in phrase for c in "\r\n\x00"):
        raise ManagerError("私钥口令至少 16 位；留空可以安全自动生成。")
    # Check compatibility and conflicts before generating keys or changing Linux.
    controller.retry_call(original, {"action": "security_preflight", "mode": mode, "username": target, "current_username": original.username}, progress=progress)
    old_public = controller.public_key(original) if mode == "rename" and options.get("retire_old_key") and original.auth == "key" else ""
    updated = original.changed(remember=True)
    if mode == "create":
        updated = updated.changed(identifier=Connection().identifier, label=original.label + " · 新管理员")
        controller.trust_same_server(controller.transport(original), controller.transport(updated))
    key, public = controller.generate_key(updated, phrase)
    journal = controller.store.directory / "security-plans" / (updated.identifier + "-" + secrets.token_hex(8) + ".json")
    stages = []
    def record(state, message=""):
        atomic_private(journal, json.dumps({"server_id": updated.identifier, "mode": mode, "state": state, "stages": stages, "message": message}, ensure_ascii=False))
    def save(profile):
        profiles = controller.store.profiles()
        profiles = [p for p in profiles if p.identifier != profile.identifier] + [profile]
        controller.store.save(profiles, {profile.identifier})
        if controller.store.last_warning:
            raise ManagerError("本机登录信息未能安全保存，已停止后续步骤。")
        restored = next((p for p in controller.store.profiles() if p.identifier == profile.identifier), None)
        if not restored or (restored.key_passphrase, restored.sudo_password, restored.password) != (profile.key_passphrase, profile.sudo_password, profile.password):
            raise ManagerError("本机登录信息回读验证失败，已停止后续步骤。")
    # Persist a separate recovery entry before remote account/key migration.
    recovery = updated.changed(key_path=key, key_passphrase=phrase)
    if mode == "create":
        recovery = recovery.changed(username=target, auth="key", password=new_password, sudo_password=new_password)
    controller.store.vault.put(vault_alias("security-recovery", updated.identifier), {"key_passphrase": phrase, "password": new_password or original.password, "sudo_password": new_password or original.sudo_password})
    atomic_private(journal.with_suffix(".recovery.json"), json.dumps(recovery.public_record(), ensure_ascii=False))
    record("running")
    def run(title, params):
        nonlocal updated
        progress({"state": "running", "progress": 0, "message": title})
        status, updated = controller.execute(updated, params, lambda s: progress(s | {"message": title + "：" + s.get("message", "")}))
        stages.append({"step": title, "task_id": status.get("id", status.get("task_id")), "state": "succeeded"})
        record("running")
        save(updated)
    try:
        # Verify persistence while the original login still works.
        save(original.changed(remember=True))
        if mode == "create":
            save(updated)
            run("创建并验证新管理员", {"operation": "create_admin", "username": target, "new_password": new_password, "public_key": public, "local_key_path": key, "local_key_passphrase": phrase})
        else:
            run("安装并验证加密密钥", {"operation": "prepare_key", "username": updated.username, "public_key": public, "local_key_path": key, "local_key_passphrase": phrase})
            if target != updated.username:
                run("修改并验证用户名", {"operation": "rename_user", "old_username": updated.username, "new_username": target})
            if new_password:
                run("修改并验证系统密码", {"operation": "password", "username": updated.username, "new_password": new_password})
        run("启用仅密钥登录与基础防护", {"operation": "login_policy", "username": updated.username})
        if old_public:
            run("撤销原档案的旧钥匙", {"operation": "retire_key", "username": updated.username, "old_public_key": old_public, "public_key": public})
        if options.get("fail2ban", True):
            run("启用防猜密码保护", {"operation": "fail2ban", "enabled": True, "ssh_port": updated.port})
        if options.get("updates", True):
            run("启用安全更新（不自动重启）", {"operation": "updates", "enabled": True})
        if mode == "create" and options.get("block_original", True) and original.username != "root":
            run("禁止原账号 SSH 登录", {"operation": "account_access", "username": original.username, "blocked": True})
    except ManagerError as error:
        # Keep the last independently verified account after a later step fails.
        message = str(error)
        record("incomplete", message)
        return {"complete": False, "connection": updated, "stages": stages, "message": "方案未全部完成；已成功的步骤保留。" + message}
    record("succeeded")
    return {"complete": True, "connection": updated, "stages": stages, "message": "安全方案已完成，每次连接切换均已验证。"}
