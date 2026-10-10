"""Final disposable-server maintenance and database rollback verification."""
from pathlib import Path
import json
import secrets
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from tools.live_redeployment_regression import Regression, PRIVATE, passed
from linux_manager.models import ManagerError, atomic_private
from linux_manager.project_info import credential_alias
from linux_manager.vault import vault_alias


def main():
    r = Regression()
    original = json.loads(json.dumps(r.saved))
    created = False
    try:
        for action in ["stop", "start", "restart", "disable", "enable"]:
            status, _ = r.controller.execute(r.c, {"operation":"service", "service":"nginx", "action":action})
            assert status["state"] == "succeeded"
        assert isinstance(r.controller.transport(r.c).call({"action":"logs", "service":"nginx"})["logs"], str)
        passed("standalone_nginx_maintenance_and_logs")
        status, _ = r.controller.execute(r.c, {"operation":"backup", "service":"nginx"})
        identifier = status["result"]["backup_id"]
        status, _ = r.controller.execute(r.c, {"operation":"restore", "backup_id":identifier})
        assert status["state"] == "succeeded"
        passed("standalone_nginx_backup_restore")

        r.saved["fixture"] = {}
        r.fixture(); created = True
        before = r.info("xui")
        working = r.store.vault.get(credential_alias(r.c, "xui"))
        params = r.params("xui", port=before["port"]+1, panel_password=secrets.token_urlsafe(24),
                          tls_cert="invalid-test-certificate", tls_key="invalid-test-private-material")
        try:
            r.controller.execute(r.c, params)
        except ManagerError as error:
            assert "恢复原项目" in str(error)
        else:
            raise AssertionError("invalid_certificate_not_rejected")
        after = r.info("xui")
        assert before["inbounds"] and all(after.get(key) == before.get(key) for key in ["port", "path", "panel_username", "inbounds", "version"])
        assert r.store.vault.get(credential_alias(r.c, "xui")) == working
        assert not r.store.vault.get(vault_alias("service-pending", credential_alias(r.c, "xui")))
        with r.panel() as api:
            assert api("panel/api/inbounds/list").get("success") is True
        passed("final_sqlite_failed_change_restores_nodes_and_saved_credentials")
        atomic_private(PRIVATE / "final-maintenance-regression-result.json", json.dumps({"final_maintenance_tests_passed":True}))
    finally:
        try:
            if created:
                with r.panel() as api:
                    assert api("panel/api/inbounds/del/"+str(r.saved["fixture"]["id"]), {}).get("success") is True
                r.saved = original; r.save()
        finally:
            r.controller.close_connections()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        import traceback
        atomic_private(PRIVATE / "final-maintenance-regression-error.txt", traceback.format_exc())
        print(json.dumps({"final_maintenance_regression":"failed", "failure_type":type(error).__name__}), flush=True)
        raise SystemExit(1)
