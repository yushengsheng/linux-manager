"""Continue this task's recorded test fixture; never create an untracked account."""
from pathlib import Path
import json
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
    if not approved.get("test_only") or current["host"] != approved["host"] or (old.exists() and json.loads(old.read_text()).get("host") == approved["host"]):
        raise ManagerError("隔离检查失败。")
    folder = private / "security-integration"
    files = list(folder.glob("live-test-*.json"))
    if len(files) != 1: raise ManagerError("需要本次唯一测试记录。")
    record = files[0]; names = json.loads(record.read_text())
    if names.get("state") != "started": raise ManagerError("测试状态已改变，不重复执行。")
    controller = Controller(Store(folder)); original = Connection(**current)
    controller.transport(original).call({"action": "ping"})
    candidates = [p for p in controller.store.profiles() if p.host == original.host and p.username == names["created"] and p.auth == "key"]
    if len(candidates) != 1: raise ManagerError("已验证的新管理员记录不唯一。")
    created = candidates[0]
    controller.transport(created).call({"action": "ping"})
    report = controller.inspect(original)
    if any(any(u.get("LoadState") == "loaded" for u in units) for units in report["services"].values()): raise ManagerError("测试服务器出现项目，停止。")
    if any(t["state"] in {"queued", "running", "awaiting_verification", "recovery_failed"} for t in report["tasks"]): raise ManagerError("存在未完成任务，停止。")
    print("ISOLATED_TEST: 按已验证新账号完成密钥轮换、防猜密码和安全更新", flush=True)
    result = controller.security_plan(created, {"mode": "rename", "username": created.username, "retire_old_key": True})
    if not result["complete"]: raise ManagerError(result["message"])
    created = result["connection"]
    atomic_private(record, json.dumps(names | {"state": "created", "profile_id": created.identifier}))
    before = controller.account_details(created, created.username)
    print("ISOLATED_TEST: 改用户名并再次更换密钥", flush=True)
    result = controller.security_plan(created, {"mode": "rename", "username": names["renamed"], "retire_old_key": True, "fail2ban": False, "updates": False})
    if not result["complete"]: raise ManagerError(result["message"])
    renamed = result["connection"]
    after = controller.account_details(renamed, renamed.username)
    if before["uid"] != after["uid"] or any(f in after["public_key_fingerprints"] for f in before["public_key_fingerprints"]): raise ManagerError("用户编号或旧密钥撤销检查失败。")
    atomic_private(record, json.dumps(names | {"state": "renamed", "profile_id": renamed.identifier}))
    controller.transport(original).call({"action": "ping"})
    print("ISOLATED_TEST: 原管理员删除本次测试账号并验证连接", flush=True)
    time.sleep(3)
    controller.execute(original, {"operation": "delete_user", "username": renamed.username})
    final = controller.inspect(original)
    if any(u["username"] in {names["created"], names["renamed"]} for u in final["accounts"]): raise ManagerError("测试账号仍存在。")
    if final["ssh"].get("passwordauthentication") != ["no"] or final["ssh"].get("permitrootlogin") != ["no"] or not final["fail2ban"]["active"]: raise ManagerError("最终防护状态验证失败。")
    atomic_private(record, json.dumps(names | {"state": "succeeded", "profile_id": renamed.identifier}))
    atomic_private(private / "snapshot.json", json.dumps(final, ensure_ascii=False))
    print("ISOLATED_TEST_OK: 新增、原名换钥匙、改名、旧钥匙撤销、删除、备用管理连接、防猜密码和安全更新均通过", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        from linux_manager.models import Redactor, atomic_private
        private = Path("/private/tmp/linux-manager-development")
        values = [str(Path.cwd())]
        def collect(v):
            if isinstance(v, dict):
                for x in v.values(): collect(x)
            elif isinstance(v, list):
                for x in v: collect(x)
            elif isinstance(v, str) and v: values.append(v)
        for file in [private / "current.json", *list((private / "security-integration").glob("*.json"))]:
            try: collect(json.loads(file.read_text()))
            except Exception: pass
        diagnostic = Redactor(*values).text(str(error))
        atomic_private(private / "security-integration-error.json", json.dumps({"error_type": type(error).__name__, "message": diagnostic}, ensure_ascii=False))
        print("ISOLATED_TEST_FAILED: " + diagnostic, flush=True)
        raise SystemExit(1)
