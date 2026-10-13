import contextlib
import importlib.util
import json
import shutil
import sqlite3
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.project_info import credential_alias
from linux_manager.transport import ConnectionInterrupted

spec = importlib.util.spec_from_file_location("redeployment_remote_test", Path(__file__).resolve().parents[1] / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec); spec.loader.exec_module(REMOTE)


class MemoryVault:
    def __init__(self): self.cache = {}
    def get(self, alias): return dict(self.cache.get(alias, {}))
    def put(self, alias, values): self.cache[alias] = dict(values)
    def delete(self, alias): self.cache.pop(alias, None)


class ConditionPlanTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID":"ubuntu", "VERSION_ID":"24.04"}))
        self.stack.enter_context(mock.patch.object(REMOTE.platform, "machine", return_value="x86_64"))
        self.stack.enter_context(mock.patch.object(REMOTE.shutil, "disk_usage", return_value=mock.Mock(free=3*1024**3)))
        self.available = self.stack.enter_context(mock.patch.object(REMOTE, "ensure_port_available"))
        self.current = {"installed":True,"_present":True,"_ready":True,"version":"v1.1.85","port":26483,"host":"fixture.invalid","backend_port":18880,"proxy_password":"fictional-old-password","panel_username":"fixture","_password_hash":"fictional-existing-hash"}
        self.stack.enter_context(mock.patch.object(REMOTE, "_deployment_state", side_effect=lambda *args: dict(self.current)))

    def params(self, kind):
        if kind == "nginx": self.current["version"] = "1.24.0-2ubuntu7"
        return {"service":kind,"host":"fixture.invalid","port":26483,"version_policy":"keep"}

    def test_all_four_projects_are_idempotent_when_conditions_match(self):
        for kind in ["exchange", "hysteria2", "xui", "nginx"]:
            plan = REMOTE.deployment_preflight(self.params(kind))
            self.assertEqual(plan["action"], "unchanged")
            self.assertFalse(plan["requires_archive"])
        self.available.assert_not_called()

    def test_port_change_for_every_project_requires_configuration_only(self):
        for kind in ["exchange", "hysteria2", "xui", "nginx"]:
            plan = REMOTE.deployment_preflight(self.params(kind) | {"port":26482})
            self.assertEqual(plan["action"], "reconfigure")
            self.assertFalse(plan["requires_archive"])
            self.assertEqual([item["field"] for item in plan["changes"]], ["port"])
        self.assertEqual(self.available.call_count, 4)

    def test_versions_in_both_directions_use_verified_update_route(self):
        for kind in ["exchange", "hysteria2", "xui"]:
            for version in ["v1.1.84", "v1.1.86"]:
                plan = REMOTE.deployment_preflight({"service":kind,"host":"fixture.invalid","port":26483,"version":version})
                self.assertEqual(plan["action"], "update"); self.assertTrue(plan["requires_archive"])
        self.available.assert_not_called()

    def test_first_panel_preview_needs_no_bcrypt_before_dependency_install(self):
        self.current = {"installed": False, "_present": False, "_ready": False}
        with mock.patch.dict(sys.modules, {"bcrypt": None}):
            plan = REMOTE.deployment_preflight({"service": "xui", "host": "fixture.invalid", "port": 2053, "version": "v3.9.0", "panel_username": "fixture", "panel_password": "fictional-panel-password"})
        self.assertEqual(plan["action"], "install")

    def test_nginx_uses_exact_versions_from_system_repository(self):
        self.current["version"] = "1.24.0-2ubuntu7"
        with mock.patch.object(REMOTE, "command", return_value=mock.Mock(returncode=0)) as command:
            plan = REMOTE.deployment_preflight({"service":"nginx","host":"fixture.invalid","port":26483,"version":"1.24.0-2ubuntu7.5"})
        self.assertEqual(plan["action"], "update"); self.assertFalse(plan["requires_archive"])
        self.assertIn("nginx=1.24.0-2ubuntu7.5", command.call_args.args[0])

    def test_secret_differences_are_concealed_in_preview(self):
        plan = REMOTE.deployment_preflight(self.params("hysteria2") | {"proxy_password":"fictional-new-password"})
        self.assertEqual(plan["action"], "reconfigure")
        text = json.dumps(plan)
        self.assertNotIn("fictional-old-password", text); self.assertNotIn("fictional-new-password", text)

    def test_unrecognized_payload_is_repaired_without_erasing_business_data(self):
        self.current["_ready"] = False
        with mock.patch.object(REMOTE, "_bootstrap_reset_allowed", return_value=False), mock.patch.object(REMOTE.Path, "is_file", return_value=True):
            plan = REMOTE.deployment_preflight(self.params("exchange"))
        self.assertEqual(plan["action"], "repair"); self.assertTrue(plan["requires_archive"])

    def test_preview_race_stops_before_backup_or_mutation(self):
        plan = REMOTE.deployment_preflight(self.params("exchange") | {"port":26482})
        with mock.patch.object(REMOTE, "deployment_preflight", return_value=plan), mock.patch.object(REMOTE, "_deployment_backup") as backup:
            with self.assertRaises(REMOTE.OperationError): REMOTE.deploy({"deployment_fingerprint":"old-fingerprint"})
        backup.assert_not_called()

    def test_unchanged_deploy_never_stops_or_reinstalls_services(self):
        plan = REMOTE.deployment_preflight(self.params("exchange"))
        with mock.patch.object(REMOTE, "deployment_preflight", return_value=plan), mock.patch.object(REMOTE, "command") as command:
            result = REMOTE.deploy({"deployment_fingerprint":plan["fingerprint"]})
        self.assertEqual(result["action"], "unchanged"); command.assert_not_called()

    def test_financial_project_changes_require_maintenance_confirmation(self):
        plan = REMOTE.deployment_preflight(self.params("exchange") | {"port":26482})
        with mock.patch.object(REMOTE, "deployment_preflight", return_value=plan), mock.patch.object(REMOTE, "_deployment_backup") as backup:
            with self.assertRaises(REMOTE.OperationError): REMOTE.deploy({})
        backup.assert_not_called()


class BackupAndControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.vault = MemoryVault(); self.store = Store(self.root / "local", self.vault)
        self.connection = Connection(host="fixture.invalid", username="fixture", password="fictional-login", remember=False)
        self.controller = Controller(self.store); self.ssh = mock.Mock()
        patch = mock.patch("linux_manager.controller.secrets.token_hex", return_value="a" * 24)
        patch.start(); self.addCleanup(patch.stop)
        self.ssh.redactor.text.side_effect = lambda value: value
        self.controller.transport = mock.Mock(return_value=self.ssh)

    def response(self, kind, state="succeeded"):
        self.ssh.call.side_effect = [
            {"version":"v1.1.85","fingerprint":"current-preview","requires_archive":False,"installed":True,"architecture":"x86_64"},
            {"task_id":"a"*24},
            {"state":state,"message":"fixture result","result":{}},
        ]
        return {"operation":"deploy","service":kind,"version":"v1.1.85","host":"fixture.invalid","port":26482,"deployment_fingerprint":"current-preview"}

    def test_configuration_change_does_not_download_or_upload_an_archive(self):
        params = self.response("exchange")
        with mock.patch("linux_manager.releases.download_exchange") as download:
            result, _ = self.controller.execute(self.connection, params)
        self.assertEqual(result["state"], "succeeded"); download.assert_not_called()
        sent = self.ssh.call.call_args_list[1].args[0]["params"]
        self.assertNotIn("release_archive", sent)

    def test_failed_panel_change_keeps_working_local_credentials(self):
        alias = credential_alias(self.connection, "xui")
        self.vault.put(alias, {"panel_username":"fixture","panel_password":"fictional-original-password"})
        params = self.response("xui", "failed") | {"panel_password":"fictional-proposed-password"}
        with self.assertRaises(ManagerError): self.controller.execute(self.connection, params)
        self.assertEqual(self.vault.get(alias)["panel_password"], "fictional-original-password")

    def test_transient_poll_failure_retries_only_the_existing_task(self):
        params = self.response("exchange")
        responses = list(self.ssh.call.side_effect)
        self.ssh.call.side_effect = responses[:2] + [ConnectionInterrupted("fixture-network-loss")] + responses[2:]
        self.controller.connections = mock.Mock()
        self.controller.connection_status = mock.Mock(return_value={"state":"reconnecting"})
        with mock.patch("linux_manager.controller.time.sleep"):
            result,_ = self.controller.execute(self.connection,params)
        self.assertEqual(result["state"], "succeeded")
        calls = [call.args[0]["action"] for call in self.ssh.call.call_args_list]
        self.assertEqual(calls.count("start"), 1); self.assertEqual(calls.count("task"), 2)

    def test_reconnected_observation_finishes_only_known_local_task_records(self):
        self.store.record({"task_id":"a"*24,"server_id":self.connection.identifier,"state":"submitted","operation":"deploy"})
        tasks=[{"id":"a"*24,"state":"succeeded","message":"completed"}, {"id":"b"*24,"state":"succeeded","message":"another-task"}]
        self.controller.observe_tasks(self.connection,tasks)
        self.controller.observe_tasks(self.connection,tasks)
        rows=self.store.history()
        self.assertEqual(len(rows), 2);self.assertEqual(rows[-1]["state"], "succeeded")

    def test_backup_restores_symlink_target_and_nested_ownership(self):
        previous_root, previous_task = REMOTE.ROOT, REMOTE.TASK
        REMOTE.ROOT = self.root / "remote"; REMOTE.TASK = REMOTE.ROOT / "tasks" / ("b"*24)
        REMOTE.TASK.mkdir(parents=True)
        try:
            source = self.root / "data"; source.mkdir(); (source / "fixture").write_text("preserve-this")
            link = self.root / "current"; link.symlink_to(source)
            REMOTE.backup_files([str(source), str(link)], {"deployment":True})
            (source / "fixture").write_text("modified"); link.unlink(); link.symlink_to(self.root / "different")
            with mock.patch.object(REMOTE, "command"), mock.patch.object(REMOTE.os, "chown") as ownership:
                REMOTE.restore_files("b"*24)
            self.assertEqual((source / "fixture").read_text(), "preserve-this")
            self.assertEqual(link.resolve(), source.resolve())
            self.assertTrue(any(call.kwargs.get("follow_symlinks") is False for call in ownership.call_args_list))
        finally:
            REMOTE.ROOT, REMOTE.TASK = previous_root, previous_task

    def test_panel_backup_checkpoints_wal_and_excludes_temporary_ownership(self):
        source = self.root / "source" / "x-ui.db"; source.parent.mkdir()
        db = sqlite3.connect(source); self.addCleanup(db.close)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE fixture(value TEXT)"); db.commit()
        db.execute("INSERT INTO fixture VALUES('committed-in-wal')"); db.commit()
        source.chmod(0o600)
        root = self.root / "panel-backups"; task = root / "tasks" / ("c" * 24)
        task.mkdir(parents=True)
        backup = task / "backup"; saved = backup / "files" / str(source).lstrip("/")
        original_path = REMOTE.Path
        mapped = lambda value: source.parent if str(value) == "/etc/x-ui" else original_path(value)
        with mock.patch.object(REMOTE,"ROOT",root), mock.patch.object(REMOTE,"TASK",task), mock.patch.object(REMOTE,"Path",side_effect=mapped), mock.patch.object(REMOTE,"unit_info",return_value={"LoadState":"not-found"}):
            REMOTE._deployment_backup("xui","reconfigure")
        with contextlib.closing(sqlite3.connect(saved)) as checked:
            self.assertEqual(checked.execute("SELECT value FROM fixture").fetchone()[0], "committed-in-wal")
            self.assertEqual(checked.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        ownership = json.loads((backup / "manifest.json").read_text())["paths"][0]["ownership"]
        self.assertEqual([item["name"] for item in ownership], ["x-ui.db"])

    def test_daily_panel_backup_is_consistent_and_restorable_without_live_wal(self):
        directory = self.root / "daily-panel"; directory.mkdir()
        source = directory / "x-ui.db"
        original = sqlite3.connect(source)
        original.execute("PRAGMA journal_mode=WAL")
        original.execute("CREATE TABLE fixture(value TEXT)")
        original.execute("INSERT INTO fixture VALUES('preserved')"); original.commit()
        self.addCleanup(original.close)
        root = self.root / "daily-backups"; identifier = "d" * 24
        task = root / "tasks" / identifier; task.mkdir(parents=True)
        original_path = REMOTE.Path
        mapped = lambda value: directory if str(value) == "/etc/x-ui" else original_path(value)
        with mock.patch.object(REMOTE,"ROOT",root), mock.patch.object(REMOTE,"TASK",task), mock.patch.object(REMOTE,"Path",side_effect=mapped), mock.patch.object(REMOTE,"step"), mock.patch.object(REMOTE,"firewall_snapshot",return_value={"active":False}), mock.patch.object(REMOTE,"command"), mock.patch.object(REMOTE.os,"chown"):
            REMOTE.configuration_backup({"service":"xui"})
            original.execute("UPDATE fixture SET value='changed'"); original.commit(); original.close()
            REMOTE.restore_files(identifier)
        with contextlib.closing(sqlite3.connect(source)) as checked:
            self.assertEqual(checked.execute("SELECT value FROM fixture").fetchone()[0], "preserved")
        manifest = json.loads((task / "backup/manifest.json").read_text())
        self.assertEqual([item["name"] for item in manifest["paths"][0]["ownership"]], ["x-ui.db"])

    def test_panel_version_uses_supported_flag_without_false_repair(self):
        binary = self.root / "x-ui"; binary.write_text("fixture-binary")
        database = self.root / "panel.db"
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("CREATE TABLE users(password TEXT)")
            db.execute("INSERT INTO users VALUES('fictional-existing-hash')")
        original_path = REMOTE.Path
        replacements = {"/usr/local/x-ui/x-ui":binary, "/etc/x-ui/x-ui.db":database}
        mapped = lambda value: replacements.get(str(value), original_path(value))
        with mock.patch.object(REMOTE,"Path",side_effect=mapped), mock.patch.object(REMOTE,"connection_details",return_value={"installed":True,"version":"v3.9.0"}), mock.patch.object(REMOTE,"command",return_value=mock.Mock(stdout="3.9.0\n",stderr="")) as command:
            state=REMOTE._deployment_state("xui","fixture.invalid")
        self.assertTrue(state["_ready"])
        self.assertEqual(command.call_args.args[0][-1], "-v")

    def test_insufficient_backup_space_never_stops_existing_services(self):
        with mock.patch.object(REMOTE,"unit_info",return_value={"LoadState":"loaded","ActiveState":"active"}), mock.patch.object(REMOTE,"_deployment_backup_size",return_value=5*1024**3), mock.patch.object(REMOTE.shutil,"disk_usage",return_value=mock.Mock(free=2*1024**3)), mock.patch.object(REMOTE,"command") as command, mock.patch.object(REMOTE,"backup_files") as backup:
            with self.assertRaises(REMOTE.OperationError):REMOTE._deployment_backup("xui","reconfigure")
        command.assert_not_called();backup.assert_not_called()

    def test_panel_migration_keeps_original_connection_json_urls_and_new_schema_marker(self):
        database=self.root/"migration.db"
        original='{"clients":[{"id":"fictional-client","subId":"fictional-subscription"}]}'
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("CREATE TABLE inbounds(id INTEGER,settings TEXT,stream_settings TEXT)")
            db.execute("CREATE TABLE settings(key TEXT,value TEXT)")
            db.execute("CREATE TABLE users(username TEXT,password TEXT)")
            db.execute("INSERT INTO users VALUES('fixture','fictional-hash')")
            db.execute("INSERT INTO inbounds VALUES(1,?,'original-stream')",(original,))
            db.executemany("INSERT INTO settings VALUES(?,?)",[("webBasePath","/original-panel/"),("subPath","/original-sub/")])
        saved=REMOTE._panel_connection_config(database)
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE inbounds SET settings='migration-rewritten-json'")
            db.execute("UPDATE settings SET value='/changed-by-migration/'")
            db.execute("INSERT INTO settings VALUES('migration-marker','new-schema-version')")
            REMOTE._restore_panel_connection_config(db,saved)
            self.assertEqual(db.execute("SELECT settings FROM inbounds").fetchone()[0],original)
            self.assertEqual(dict(db.execute("SELECT key,value FROM settings")),{"webBasePath":"/original-panel/","subPath":"/original-sub/","migration-marker":"new-schema-version"})

    def test_changed_address_cannot_replace_another_projects_certificate(self):
        self.assertEqual(REMOTE.certificate_name("fixture.invalid",False,False),"manager")
        self.assertEqual(REMOTE.certificate_name("fixture.invalid",True,True),"manager")
        independent=REMOTE.certificate_name("second.invalid",True,False)
        self.assertNotEqual(independent,"manager")
        self.assertNotIn("second.invalid",independent)
        self.assertEqual(independent,REMOTE.certificate_name("second.invalid",True,False))
