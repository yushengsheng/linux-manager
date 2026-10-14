"""Live validation restricted to the explicitly approved, empty test server."""
from pathlib import Path
import json
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    from linux_manager.models import Connection, ManagerError, Store, atomic_private
    from linux_manager.controller import Controller
    private = Path("/private/tmp/linux-manager-development")
    approved = json.loads((private / "test-connection.json").read_text())
    current = json.loads((private / "current.json").read_text())
    old = Path("scripts/.rename_account_gui_state.json")
    if not approved.get("test_only") or current.get("host") != approved["host"] or (old.exists() and json.loads(old.read_text()).get("host") == approved["host"]):
        raise ManagerError("测试目标未通过隔离检查。")
    folder = private / "security-integration"
    store = Store(folder)
    controller = Controller(store)
    original = Connection(**current)
    trusted = private / "readonly-identity-check/known_hosts"
    if not trusted.exists(): raise ManagerError("尚未完成只读身份核对。")
    atomic_private(controller.transport(original).known_hosts, trusted.read_bytes())
    report = controller.inspect(original)
    if any(any(u.get("LoadState") == "loaded" for u in units) for units in report["services"].values()):
        raise ManagerError("测试服务器已有项目，已停止自动测试。")
    if original.username == "root": raise ManagerError("本次测试需要普通管理员。")
    if list(folder.glob("live-test-*.json")):
        raise ManagerError("发现上次实机测试记录，先核对状态，不重复执行。")
    record = folder / ("live-test-" + secrets.token_hex(8) + ".json")
    names = {"created": "lmt_" + secrets.token_hex(5), "renamed": "lmt_" + secrets.token_hex(5)}
    atomic_private(record, json.dumps({"state": "started", **names}))
    store.save([original])
    if store.last_warning: raise ManagerError("本机钥匙串不可用，停止测试。")
    print("ISOLATED_TEST: 验证并保存原管理员的加密密钥", flush=True)
    phrase = secrets.token_urlsafe(36)
    key, public = controller.generate_key(original, phrase)
    _, original = controller.execute(original, {"operation": "prepare_key", "username": original.username, "public_key": public, "local_key_path": key, "local_key_passphrase": phrase})
    atomic_private(private / "current.json", json.dumps(original.__dict__, ensure_ascii=False))
    def progress(status):
        state = status.get("state")
        if state in {"awaiting_verification", "preparing"}:
            print("ISOLATED_TEST: " + state, flush=True)
    print("ISOLATED_TEST: 新增管理员一键方案（仅新账号策略）", flush=True)
    result = controller.security_plan(original, {"mode": "create", "username": names["created"]}, progress)
    if not result["complete"]: raise ManagerError("新增方案未全部完成，请在本机记录核对已完成步骤。")
    created = result["connection"]
    atomic_private(record, json.dumps({"state": "created", **names, "profile_id": created.identifier}))
    controller.transport(created).call({"action": "ping"})
    before = controller.account_details(created, created.username)
    print("ISOLATED_TEST: 改名并轮换密钥一键方案", flush=True)
    result = controller.security_plan(created, {"mode": "rename", "username": names["renamed"], "retire_old_key": True}, progress)
    if not result["complete"]: raise ManagerError("改名方案未全部完成，请在本机记录核对已完成步骤。")
    renamed = result["connection"]
    after = controller.account_details(renamed, renamed.username)
    if before["uid"] != after["uid"] or before["public_key_fingerprints"][0] in after["public_key_fingerprints"]:
        raise ManagerError("用户编号或旧密钥撤销检查未通过。")
    controller.transport(original).call({"action": "ping"})
    atomic_private(record, json.dumps({"state": "renamed", **names, "profile_id": renamed.identifier}))
    print("ISOLATED_TEST: 使用原管理员删除测试账号，保留文件", flush=True)
    time.sleep(2)
    controller.execute(original, {"operation": "delete_user", "username": renamed.username})
    final = controller.inspect(original)
    if any(row["username"] in names.values() for row in final["accounts"]): raise ManagerError("测试账号删除检查未通过。")
    if final["ssh"].get("passwordauthentication") != ["no"] or final["ssh"].get("permitrootlogin") != ["no"] or not final["fail2ban"]["active"]:
        raise ManagerError("最终登录策略或防猜密码检查未通过。")
    atomic_private(record, json.dumps({"state": "succeeded", **names, "profile_id": renamed.identifier}))
    atomic_private(private / "snapshot.json", json.dumps(final, ensure_ascii=False))
    print("ISOLATED_TEST: 新增、改名、密钥撤销、删除、管理员备用连接、仅密钥策略均通过", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        from linux_manager.models import Redactor, atomic_private
        private = Path("/private/tmp/linux-manager-development")
        values = [str(Path.cwd())]
        for file in [private / "current.json", private / "test-connection.json", *list((private / "security-integration").glob("*.json"))]:
            try:
                def collect(value):
                    if isinstance(value, dict):
                        for item in value.values(): collect(item)
                    elif isinstance(value, list):
                        for item in value: collect(item)
                    elif isinstance(value, str) and value: values.append(value)
                collect(json.loads(file.read_text()))
            except Exception:
                pass
        diagnostic = Redactor(*values).text(str(error))
        atomic_private(private / "security-integration-error.json", json.dumps({"error_type": type(error).__name__, "message": diagnostic}, ensure_ascii=False))
        print("ISOLATED_TEST_FAILED: 诊断和连接信息仅留本机；不自动重复提交操作。", flush=True)
        raise SystemExit(1)
