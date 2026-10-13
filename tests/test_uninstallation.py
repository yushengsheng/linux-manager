import base64
import contextlib
import importlib.util
import json
from pathlib import Path
import secrets
import sqlite3
import types
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.gui import App, SERVICES
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.project_info import credential_alias, information_rows, server_key
from linux_manager.transport import SSH
import tempfile
import time

spec = importlib.util.spec_from_file_location("uninstallation_remote_test", Path(__file__).resolve().parents[1] / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REMOTE)


class MemoryVault:
    def __init__(self): self.cache = {}
    def get(self, alias): return dict(self.cache.get(alias, {}))
    def put(self, alias, values): self.cache[alias] = dict(values)
    def delete(self, alias): self.cache.pop(alias, None)


class UninstallSandboxTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-uninstall-test-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.fs = self.base / "fs"; self.fs.mkdir()
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE, "Path", side_effect=self.path))
        self.root = self.path("/var/lib/linux-server-manager"); self.root.mkdir(parents=True)
        self.stack.enter_context(mock.patch.object(REMOTE, "ROOT", self.root))
        self.stack.enter_context(mock.patch.object(REMOTE, "SECRETS", set()))
        self.stack.enter_context(mock.patch.object(REMOTE, "proxy_certificate_lineage", return_value=None))
        self.active = {}; self.enabled = {}; self.calls = []; self.failure = None
        self.stack.enter_context(mock.patch.object(REMOTE, "command", side_effect=self.command))
        self.secret = secrets.token_urlsafe(30)
        self.records = {kind: {"installed": "fixture-time", "version": {"exchange": "v1.1.88", "hysteria2": "v1.14.3", "reality": "v26.3.27", "xui": "v3.9.0", "nginx": "1.24.0"}[kind], "host": "fixture.invalid", "port": 26484 if kind == "exchange" else 51752 if kind == "hysteria2" else 2053 if kind == "xui" else 80} for kind in REMOTE.UNINSTALL_LAYOUTS}
        self.records["exchange"].update(certificate_source="manager", certificate_lineage="/etc/linux-server-manager/letsencrypt/live/manager")
        self.records["nginx"]["config_file"] = "/etc/nginx/conf.d/linux-manager-default.conf"
        self.write("/var/lib/linux-server-manager/installed.json", json.dumps(self.records))
        for kind, layout in REMOTE.UNINSTALL_LAYOUTS.items():
            for program in layout["programs"]:
                if kind == "hysteria2": self.write(program, "fixture-binary", 0o755)
                else: self.write(program + "/fixture-program", "fixture-binary", 0o755)
            for unit in layout["units"]:
                self.write("/etc/systemd/system/" + unit, self.unit_text(unit), 0o644)
                self.active[unit] = "active" if unit in REMOTE.UNITS.get(kind, []) or unit.endswith(".timer") else "inactive"
                self.enabled[unit] = "enabled" if self.active[unit] == "active" else "static"
            for path in layout["retain"]: self.path(path).mkdir(parents=True, exist_ok=True)
        # The manager's external certificate mode leaves the native renew timer off.
        self.active["xiaojun-exchange-cert-renew.timer"] = "inactive"
        self.enabled["xiaojun-exchange-cert-renew.timer"] = "disabled"
        self.write("/usr/lib/systemd/system/nginx.service", "[Service]\nExecStart=/usr/sbin/nginx\n")
        self.active["nginx.service"] = "active"; self.enabled["nginx.service"] = "enabled"
        self.write("/etc/xiaojun-exchange/server.env", "XIAOJUN_PUBLIC_ORIGIN=https://fixture.invalid:26484\n")
        self.write("/etc/xiaojun-exchange/nginx.conf", "proxy_pass http://127.0.0.1:18881;\n")
        self.write("/var/lib/xiaojun-exchange/ledger", "fixture-encrypted-ledger")
        self.write("/var/lib/xiaojun-exchange/accounts", "fixture-encrypted-accounts")
        self.write("/etc/logrotate.d/xiaojun-exchange", "fixture-rotation-rule")
        self.write("/etc/needrestart/conf.d/xiaojun-exchange.conf", "fixture-maintenance-rule")
        self.write("/etc/sing-box/config.json", json.dumps({"inbounds": [{"type": "hysteria2", "listen_port": 51752, "users": [{"password": self.secret}], "tls": {"certificate_path": "/etc/linux-server-manager/letsencrypt/live/manager/fullchain.pem"}}]}))
        with contextlib.closing(sqlite3.connect(self.path("/etc/x-ui/x-ui.db"))) as db, db:
            db.execute("CREATE TABLE users(username TEXT,password TEXT)")
            db.execute("INSERT INTO users VALUES('fixture','fixture-password-hash')")
            db.execute("CREATE TABLE settings(key TEXT,value TEXT)")
            db.executemany("INSERT INTO settings VALUES(?,?)", [("webPort", "2053"), ("webBasePath", "/fixture-panel/"), ("subEnable", "false")])
            db.execute("CREATE TABLE inbounds(id INTEGER,settings TEXT,stream_settings TEXT)")
            db.execute("INSERT INTO inbounds VALUES(1,'{\"clients\":[]}','{\"network\":\"tcp\"}')")
        self.write("/etc/nginx/conf.d/linux-manager-default.conf", "# Managed by linux-server-manager\nserver { listen 80; server_name fixture.invalid; }\n")
        self.write("/etc/nginx/conf.d/other-site.conf", "fixture-custom-website")
        self.write("/var/www/html/index.html", "fixture-web-content")
        self.write("/etc/linux-server-manager/letsencrypt/live/manager/fullchain.pem", "fixture-certificate")
        self.write("/etc/linux-server-manager/letsencrypt/live/manager/privkey.pem", self.secret)
        self.write("/etc/systemd/system/linux-manager-cert-renew.service", "[Service]\nExecStart=/opt/linux-server-manager/certbot/bin/certbot renew\n")
        self.write("/etc/systemd/system/linux-manager-cert-renew.timer", "[Timer]\nUnit=linux-manager-cert-renew.service\n")
        self.write("/etc/ssh/sshd_config", "fixture-ssh-policy")
        self.write("/etc/passwd", "fixture-system-accounts")
        self.write("/etc/ufw/user.rules", "fixture-firewall-rules")
        self.task = self.root / "tasks" / ("a" * 24); self.task.mkdir(parents=True)
        self.stack.enter_context(mock.patch.object(REMOTE, "TASK", self.task))
        REMOTE.cert_hook()

    def path(self, value):
        path = Path(value)
        if path.is_absolute() and not path.is_relative_to(self.base):
            return self.fs / str(path).lstrip("/")
        return path

    def write(self, name, contents, mode=0o600):
        path = self.path(name); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents); path.chmod(mode)
        return path

    def unit_text(self, unit):
        if unit == "sing-box.service": start = "/usr/local/bin/sing-box run -c /etc/sing-box/config.json"
        elif unit == "linux-manager-xray.service": start = "/usr/local/lib/linux-manager-xray/xray run -config /etc/linux-manager-xray/config.json"
        elif unit == "x-ui.service": start = "/usr/local/x-ui/x-ui"
        elif unit == "xiaojun-exchange-nginx.service": start = "/usr/sbin/nginx -c /etc/xiaojun-exchange/nginx.conf"
        elif unit == "xiaojun-exchange-logrotate.service": start = "/usr/sbin/logrotate /etc/logrotate.d/xiaojun-exchange"
        else: start = "/opt/xiaojun-exchange/venv/bin/python -m fixture"
        return "[Timer]\nUnit=" + unit.replace(".timer", ".service") + "\n[Install]\nWantedBy=timers.target\n" if unit.endswith(".timer") else "[Service]\nExecStart=" + start + "\n[Install]\nWantedBy=multi-user.target\n"

    def command(self, args, **kwargs):
        self.calls.append(list(args))
        if self.failure and self.failure(args):
            raise REMOTE.OperationError("fixture-command-failure")
        output = ""
        if args[:2] == ["systemctl", "show"]:
            unit = args[2]
            file = self.path("/etc/systemd/system/" + unit)
            if not file.exists(): file = self.path("/usr/lib/systemd/system/" + unit)
            loaded = file.exists()
            state = {"LoadState": "loaded" if loaded else "not-found", "ActiveState": self.active.get(unit, "inactive") if loaded else "inactive", "UnitFileState": self.enabled.get(unit, "disabled") if loaded else "", "FragmentPath": str(file) if loaded else "", "DropInPaths": ""}
            output = "\n".join(key + "=" + value for key, value in state.items())
        elif args[:1] == ["systemctl"] and args[1] in {"stop", "start", "restart", "enable", "disable"}:
            for unit in args[2:]:
                if args[1] in {"stop", "start", "restart"}: self.active[unit] = "inactive" if args[1] == "stop" else "active"
                else: self.enabled[unit] = "enabled" if args[1] == "enable" else "disabled"
        elif args[:3] == ["python3", "-m", "venv"]: self.write(args[3] + "/bin/python", "fixture-python", 0o755)
        elif args[-1:] == ["version"]: output = "sing-box version 1.14.3"
        elif args[-1:] == ["-v"]: output = "3.9.0"
        return types.SimpleNamespace(returncode=0, stdout=output, stderr="")

    def params(self, kind="exchange"):
        return {"operation": "uninstall", "service": kind, "keep_data": True, "maintenance_confirmed": True}

    def prepare(self, kind="exchange"):
        params = self.params(kind)
        plan = REMOTE.uninstall_preflight(params)
        params["uninstall_fingerprint"] = plan["fingerprint"]
        return params

    def run_task(self, params):
        REMOTE.write_json(self.task / "request.json", params)
        REMOTE.write_json(self.task / "status.json", {"id": self.task.name, "operation": "uninstall", "state": "queued", "events": [], "message": "fixture"})
        REMOTE.run_task(self.task.name)
        return REMOTE.status_task(self.task.name)

    def protected(self):
        roots = ["/etc/ssh", "/etc/passwd", "/etc/ufw", "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange", "/etc/sing-box", "/etc/x-ui", "/etc/nginx/conf.d/other-site.conf", "/var/www", "/etc/linux-server-manager/letsencrypt/live", "/etc/systemd/system/linux-manager-cert-renew.service", "/etc/systemd/system/linux-manager-cert-renew.timer", "/usr/lib/systemd/system/nginx.service"]
        result = {}
        for root in roots:
            path = self.path(root)
            for file in path.rglob("*") if path.is_dir() else [path]:
                if file.is_file():
                    result[str(file.relative_to(self.fs))] = (file.read_bytes(), file.stat().st_mode, file.stat().st_uid, file.stat().st_gid)
        return result

    def test_preview_is_read_only_and_excludes_business_data_and_secrets(self):
        before = self.protected()
        plan = REMOTE.uninstall_preflight(self.params())
        self.assertEqual(before, self.protected())
        self.assertNotIn(self.secret, json.dumps(plan))
        self.assertTrue(all(path not in plan["remove_paths"] for path in plan["retained_paths"]))
        self.assertTrue(all(args[:2] == ["systemctl", "show"] for args in self.calls))

    def test_exchange_removes_program_all_nine_units_and_preserves_other_projects(self):
        before = self.protected(); params = self.prepare()
        original = self.path("/opt/xiaojun-exchange/fixture-program").stat()
        with mock.patch.object(REMOTE.shutil, "rmtree") as delete:
            result = self.run_task(params)
        delete.assert_not_called()
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(before, self.protected())
        self.assertFalse(self.path("/opt/xiaojun-exchange").exists())
        for unit in REMOTE.UNINSTALL_LAYOUTS["exchange"]["units"]:
            self.assertFalse(self.path("/etc/systemd/system/" + unit).exists())
        manifest = json.loads((self.task / "uninstall/manifest.json").read_text())
        backup = self.task / "uninstall/files" / str(manifest["paths"].index("/opt/xiaojun-exchange")) / "fixture-program"
        self.assertEqual(backup.stat().st_ino, original.st_ino)
        self.assertEqual((self.task / "uninstall").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.task / "uninstall/manifest.json").stat().st_mode & 0o777, 0o600)
        changed = json.loads((self.root / "installed.json").read_text())
        self.assertEqual(changed["hysteria2"], self.records["hysteria2"])
        self.assertTrue(changed["exchange"]["uninstalled"])
        self.assertFalse(any(args[0] in {"apt", "apt-get", "ufw", "userdel"} for args in self.calls))
        self.assertFalse(any("nginx.service" in args for args in self.calls if args[:2] in [["systemctl", "stop"], ["systemctl", "disable"]]))

    def test_hy2_uninstall_preserves_password_configuration_and_other_programs(self):
        before = self.protected()
        self.assertEqual(self.run_task(self.prepare("hysteria2"))["state"], "succeeded")
        self.assertEqual(before, self.protected())
        self.assertFalse(self.path("/usr/local/bin/sing-box").exists())
        self.assertTrue(self.path("/usr/local/x-ui").exists())

    def test_panel_uninstall_preserves_database_and_node_definitions(self):
        before = self.protected()
        self.assertEqual(self.run_task(self.prepare("xui"))["state"], "succeeded")
        self.assertEqual(before, self.protected())
        self.assertFalse(self.path("/usr/local/x-ui").exists())
        self.assertEqual(self.active["sing-box.service"], "active")

    def test_nginx_removes_only_owned_site_without_stopping_shared_core(self):
        before = self.protected()
        self.assertEqual(self.run_task(self.prepare("nginx"))["state"], "succeeded")
        self.assertEqual(before, self.protected())
        self.assertFalse(self.path("/etc/nginx/conf.d/linux-manager-default.conf").exists())
        self.assertIn(["systemctl", "reload", "nginx.service"], self.calls)
        self.assertFalse(any(args[:2] in [["systemctl", "stop"], ["systemctl", "disable"]] for args in self.calls))
        self.assertEqual(self.active["xiaojun-exchange-nginx.service"], "active")

    def test_missing_maintenance_confirmation_never_stops_or_moves_files(self):
        params = self.prepare(); params.pop("maintenance_confirmed")
        result = self.run_task(params)
        self.assertEqual(result["state"], "failed")
        self.assertTrue(self.path("/opt/xiaojun-exchange").exists())
        self.assertFalse((self.task / "uninstall").exists())
        self.assertEqual(self.active["xiaojun-exchange-worker.service"], "active")

    def test_service_stop_verification_refuses_to_move_still_running_program(self):
        params = self.prepare(); original = REMOTE.unit_info
        def running(unit):
            value = original(unit)
            return value | {"ActiveState": "active"} if unit == "xiaojun-exchange-worker.service" else value
        with mock.patch.object(REMOTE, "unit_info", side_effect=running), mock.patch.object(REMOTE.os, "rename") as rename:
            result = self.run_task(params)
        self.assertEqual(result["state"], "failed"); rename.assert_not_called()
        self.assertTrue(self.path("/opt/xiaojun-exchange").exists())

    def test_unload_verification_failure_restores_project_instead_of_claiming_success(self):
        params = self.prepare(); original = REMOTE.unit_info
        def retained_unit(unit):
            value = original(unit)
            return value | {"LoadState": "loaded"} if unit == "xiaojun-exchange-worker.service" else value
        with mock.patch.object(REMOTE, "unit_info", side_effect=retained_unit): result = self.run_task(params)
        self.assertEqual(result["state"], "failed")
        self.assertIn("已恢复", result["message"])
        self.assertTrue(self.path("/opt/xiaojun-exchange").exists())
        self.assertEqual(self.active["xiaojun-exchange-worker.service"], "active")

    def test_panel_wal_commits_are_preserved_without_deleting_database_sidecars(self):
        database = self.path("/etc/x-ui/x-ui.db")
        db = sqlite3.connect(database); self.addCleanup(db.close)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("INSERT INTO inbounds VALUES(2,'committed-in-wal','original-stream')"); db.commit()
        wal = Path(str(database) + "-wal"); self.assertTrue(wal.is_file())
        self.assertEqual(self.run_task(self.prepare("xui"))["state"], "succeeded")
        self.assertTrue(wal.is_file())
        self.assertEqual(db.execute("SELECT settings FROM inbounds WHERE id=2").fetchone()[0], "committed-in-wal")

    def test_stale_preview_rejected_before_mutation(self):
        params = self.prepare(); self.write("/opt/xiaojun-exchange/new-file", "external-change")
        result = self.run_task(params)
        self.assertEqual(result["state"], "failed")
        self.assertFalse((self.task / "uninstall").exists())
        self.assertEqual(self.active["xiaojun-exchange-worker.service"], "active")

    def test_purge_unknown_project_and_unmanaged_installation_are_rejected(self):
        for params in [self.params() | {"keep_data": False}, self.params() | {"purge": True}, self.params() | {"service": "../../etc"}]:
            with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(params)
        self.write("/var/lib/linux-server-manager/installed.json", "{}")
        with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params())

    def test_corrupt_metadata_is_an_explicit_failure_not_a_guessed_uninstall(self):
        self.write("/var/lib/linux-server-manager/installed.json", "broken-json")
        with self.assertRaisesRegex(REMOTE.OperationError, "预检查无法完成"): REMOTE.uninstall_preflight(self.params())
        self.assertTrue(self.path("/opt/xiaojun-exchange").exists())

    def test_program_root_link_is_rejected_and_external_target_untouched(self):
        program = self.path("/opt/xiaojun-exchange"); external = self.base / "external-program"
        program.rename(external); program.symlink_to(external)
        with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params())
        self.assertEqual((external / "fixture-program").read_text(), "fixture-binary")

    def test_nested_external_link_is_moved_as_a_link_without_deleting_target(self):
        external = self.base / "external-content"; external.write_text("do-not-delete")
        self.path("/opt/xiaojun-exchange/linked-content").symlink_to(external)
        self.assertEqual(self.run_task(self.prepare())["state"], "succeeded")
        self.assertEqual(external.read_text(), "do-not-delete")
        self.assertTrue((self.task / "uninstall/files/0/linked-content").is_symlink())

    def test_multiple_sing_box_inbounds_are_not_treated_as_independent_hy2(self):
        data = json.loads(self.path("/etc/sing-box/config.json").read_text())
        data["inbounds"].append({"type": "vless"})
        self.write("/etc/sing-box/config.json", json.dumps(data))
        with self.assertRaisesRegex(REMOTE.OperationError, "其他节点"): REMOTE.uninstall_preflight(self.params("hysteria2"))

    def test_other_service_reference_prevents_removing_shared_program(self):
        self.write("/etc/systemd/system/custom.service", "[Service]\nExecStart=/opt/xiaojun-exchange/venv/bin/python -m custom\n")
        with self.assertRaisesRegex(REMOTE.OperationError, "其他系统服务引用"): REMOTE.uninstall_preflight(self.params())

    def test_unknown_exchange_unit_and_custom_nginx_site_are_not_removed(self):
        extra = self.write("/etc/systemd/system/xiaojun-exchange-extra.service", "[Service]\nExecStart=/opt/custom\n")
        with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params())
        extra.unlink()
        self.write("/etc/nginx/conf.d/linux-manager-default.conf", "customized-unowned-site")
        with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params("nginx"))

    def test_dropin_or_foreign_unit_source_blocks_automatic_uninstall(self):
        original = REMOTE.unit_info
        for change in [{"DropInPaths": "/etc/systemd/system/sing-box.service.d/custom.conf"}, {"FragmentPath": "/usr/lib/systemd/system/sing-box.service"}]:
            with mock.patch.object(REMOTE, "unit_info", side_effect=lambda unit: original(unit) | (change if unit == "sing-box.service" else {})):
                with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params("hysteria2"))

    def test_fallback_unit_and_stop_propagation_are_rejected_before_mutation(self):
        vendor = self.write("/usr/lib/systemd/system/sing-box.service", "[Service]\nExecStart=/usr/bin/sing-box\n")
        with self.assertRaisesRegex(REMOTE.OperationError, "同名"): REMOTE.uninstall_preflight(self.params("hysteria2"))
        vendor.unlink()
        self.write("/etc/systemd/system/sing-box.service", self.unit_text("sing-box.service") + "\n[Unit]\nPropagatesStopTo=nginx.service\n")
        with self.assertRaises(REMOTE.OperationError): REMOTE.uninstall_preflight(self.params("hysteria2"))
        self.assertEqual(self.active["sing-box.service"], "active")
        self.assertEqual(self.active["nginx.service"], "active")

    def test_active_native_certificate_renewal_blocks_exchange_uninstall(self):
        self.enabled["xiaojun-exchange-cert-renew.timer"] = "enabled"
        with self.assertRaisesRegex(REMOTE.OperationError, "迁移续期"): REMOTE.uninstall_preflight(self.params())

    def test_proxy_using_native_exchange_certificate_blocks_uninstall(self):
        with mock.patch.object(REMOTE, "proxy_certificate_lineage", return_value="/etc/xiaojun-exchange/letsencrypt/live/exchange-ip"):
            with self.assertRaisesRegex(REMOTE.OperationError, "代理仍使用"): REMOTE.uninstall_preflight(self.params())

    def test_proxy_copied_certificate_and_node_certificate_links_block_exchange_uninstall(self):
        database = self.path("/etc/x-ui/x-ui.db")
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("INSERT INTO settings VALUES('webCertFile','/etc/xiaojun-exchange/tls/fullchain.pem')")
        with self.assertRaisesRegex(REMOTE.OperationError, "其他代理仍使用"): REMOTE.uninstall_preflight(self.params())
        link = self.path("/etc/x-ui/linked-certificate.pem"); link.symlink_to(self.path("/etc/xiaojun-exchange/tls/fullchain.pem"))
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute("DELETE FROM settings WHERE key='webCertFile'")
            stream = {"tlsSettings": {"certificates": [{"certificateFile": "/etc/x-ui/linked-certificate.pem"}]}}
            db.execute("UPDATE inbounds SET stream_settings=?", (json.dumps(stream),))
        with self.assertRaisesRegex(REMOTE.OperationError, "其他代理仍使用"): REMOTE.uninstall_preflight(self.params())

    def test_other_nginx_site_using_exchange_certificate_blocks_uninstall(self):
        self.write("/etc/nginx/conf.d/other-site.conf", "server { ssl_certificate /etc/xiaojun-exchange/tls/fullchain.pem; }\n")
        with self.assertRaisesRegex(REMOTE.OperationError, "其他 Nginx 网站"): REMOTE.uninstall_preflight(self.params())
        self.assertEqual(self.active["nginx.service"], "active")

    def test_cross_filesystem_program_is_refused_before_stop(self):
        original = Path.stat; target = self.path("/opt/xiaojun-exchange")
        def changed(file, *args, **kwargs):
            state = original(file, *args, **kwargs)
            if file == target:
                values = list(state); values[2] += 1
                return REMOTE.os.stat_result(values)
            return state
        with mock.patch.object(Path, "stat", changed):
            with self.assertRaisesRegex(REMOTE.OperationError, "不同磁盘"): REMOTE.uninstall_preflight(self.params())
        self.assertEqual(self.active["xiaojun-exchange-worker.service"], "active")

    def test_nginx_verification_failure_restores_owned_site_and_preserves_others(self):
        params = self.prepare("nginx"); before = self.protected(); original = self.path("/etc/nginx/conf.d/linux-manager-default.conf").read_bytes()
        failed = []
        def once(args):
            if args == ["nginx", "-t"] and not failed: failed.append(True); return True
            return False
        self.failure = once
        result = self.run_task(params)
        self.assertEqual(result["state"], "failed")
        self.assertIn("已恢复", result["message"])
        self.assertEqual(before, self.protected())
        self.assertEqual(original, self.path("/etc/nginx/conf.d/linux-manager-default.conf").read_bytes())
        self.assertEqual(self.records, json.loads((self.root / "installed.json").read_text()))

    def test_partial_file_move_failure_restores_files_and_original_unit_states(self):
        params = self.prepare(); before = self.protected(); enabled = dict(self.enabled); active = dict(self.active)
        rename = REMOTE.os.rename; count = []
        def fail_once(source, target):
            if str(target).startswith(str(self.task / "uninstall/files")):
                count.append(1)
                if len(count) == 2: raise OSError("fixture-rename-failure")
            return rename(source, target)
        with mock.patch.object(REMOTE.os, "rename", side_effect=fail_once): result = self.run_task(params)
        self.assertEqual(result["state"], "failed")
        self.assertIn("已恢复", result["message"])
        self.assertEqual(before, self.protected())
        self.assertTrue(self.path("/opt/xiaojun-exchange").exists())
        for unit in REMOTE.UNINSTALL_LAYOUTS["exchange"]["units"]:
            self.assertEqual(self.active[unit], active[unit])
            if enabled[unit] != "static": self.assertEqual(self.enabled[unit], enabled[unit])

    def test_restore_failure_is_not_success_and_can_be_retried_from_task_record(self):
        params = self.prepare("hysteria2")
        self.failure = lambda args: args == ["systemctl", "daemon-reload"]
        result = self.run_task(params)
        self.assertEqual(result["state"], "recovery_failed")
        self.assertIn("recovery_diagnostic", result)
        self.failure = None
        REMOTE.recover(self.task.name)
        self.assertEqual(REMOTE.status_task(self.task.name)["state"], "rolled_back")
        self.assertTrue(self.path("/usr/local/bin/sing-box").exists())
        self.assertEqual(self.active["sing-box.service"], "active")

    def test_completed_uninstall_is_idempotent_and_not_reverted_by_recovery(self):
        self.assertEqual(self.run_task(self.prepare("xui"))["state"], "succeeded")
        REMOTE.recover(self.task.name)
        self.assertFalse(self.path("/usr/local/x-ui").exists())
        plan = REMOTE.uninstall_preflight(self.params("xui")); self.assertEqual(plan["action"], "unchanged")
        before = len(self.calls)
        result = REMOTE.uninstall_project(self.params("xui") | {"uninstall_fingerprint": plan["fingerprint"]})
        self.assertEqual(result["action"], "unchanged")
        self.assertTrue(all(args[:2] == ["systemctl", "show"] for args in self.calls[before:]))

    def test_recovery_never_overwrites_new_program_or_foreign_paths(self):
        self.run_task(self.prepare("xui"))
        self.write("/usr/local/x-ui/new-install", "do-not-overwrite")
        with self.assertRaises(REMOTE.OperationError): REMOTE.restore_uninstall(self.task.name)
        self.assertEqual(self.path("/usr/local/x-ui/new-install").read_text(), "do-not-overwrite")
        manifest = self.task / "uninstall/manifest.json"
        data = json.loads(manifest.read_text()); data["paths"].append("/etc/passwd"); manifest.write_text(json.dumps(data))
        with self.assertRaises(REMOTE.OperationError): REMOTE.restore_uninstall(self.task.name)
        self.assertEqual(self.path("/etc/passwd").read_text(), "fixture-system-accounts")

    def test_retained_config_does_not_make_uninstalled_projects_look_installed(self):
        for kind in ["exchange", "hysteria2", "xui", "nginx"]:
            # Separate journal folders simulate independent sequential tasks.
            task = self.root / "tasks" / (str(["exchange", "hysteria2", "xui", "nginx"].index(kind) + 1) * 24); task.mkdir()
            with mock.patch.object(REMOTE, "TASK", task), mock.patch.object(REMOTE, "step"):
                REMOTE.uninstall_project(self.prepare(kind))
            data = REMOTE.connection_details({"service": kind, "host": "fixture.invalid"})
            self.assertFalse(data["installed"]); self.assertTrue(data["uninstalled"])
            self.assertEqual(information_rows(data, Connection(host="fixture.invalid"))[0][1], "已卸载（数据保留）")
            if kind == "exchange": self.assertEqual(data["backend_port"], 18881)
        hook = self.path("/etc/linux-server-manager/letsencrypt/renewal-hooks/deploy/linux-manager-proxies").read_text()
        self.assertNotIn("try-restart", hook); self.assertNotIn("reload xiaojun", hook)

    def test_reinstall_preview_uses_preserved_version_accounts_and_repair_route(self):
        for index, kind in enumerate(["exchange", "hysteria2", "xui"]):
            task = self.root / "tasks" / (str(index + 1) * 24); task.mkdir()
            with mock.patch.object(REMOTE, "TASK", task), mock.patch.object(REMOTE, "step"):
                REMOTE.uninstall_project(self.prepare(kind))
            args = {"service": kind, "host": "fixture.invalid", "port": self.records[kind]["port"], "version_policy": "keep"}
            if kind == "exchange": args["backend_port"] = 18881
            with mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), mock.patch.object(REMOTE.platform, "machine", return_value="x86_64"), mock.patch.object(REMOTE.shutil, "disk_usage", return_value=types.SimpleNamespace(free=3 * 1024**3)), mock.patch.object(REMOTE, "ensure_port_available"):
                plan = REMOTE.deployment_preflight(args)
            self.assertEqual(plan["action"], "repair"); self.assertTrue(plan["reinstall"])
            self.assertEqual(plan["version"], self.records[kind]["version"]); self.assertTrue(plan["requires_archive"])
            self.assertFalse(any(change["field"] in {"proxy_password", "panel_username", "panel_password"} for change in plan["changes"]))

    def reinstall_context(self, kind):
        self.assertEqual(self.run_task(self.prepare(kind))["state"], "succeeded")
        data = REMOTE.connection_details({"service": kind, "host": "fixture.invalid"})
        task = self.root / "tasks" / ("b" * 24); task.mkdir()
        self.stack.enter_context(mock.patch.object(REMOTE, "TASK", task))
        self.stack.enter_context(mock.patch.object(REMOTE, "step"))
        self.stack.enter_context(mock.patch.object(REMOTE, "certificate", return_value=(str(self.path("/etc/linux-server-manager/letsencrypt/live/manager/fullchain.pem")), str(self.path("/etc/linux-server-manager/letsencrypt/live/manager/privkey.pem")))))
        self.stack.enter_context(mock.patch.object(REMOTE, "verify_local_https"))
        self.stack.enter_context(mock.patch.object(REMOTE, "allow_port"))
        self.stack.enter_context(mock.patch.object(REMOTE.time, "sleep"))
        plan = {"service": kind, "action": "repair", "reinstall": True, "host": "fixture.invalid", "port": data["port"], "version": data["version"], "backend_port": data.get("backend_port", 18880), "changes": []}
        return task, plan

    def test_hy2_reinstall_keeps_old_secret_and_enables_recreated_service(self):
        task, plan = self.reinstall_context("hysteria2")
        binary = self.write(task / "unpacked/fixture/sing-box", "new-fixture-binary", 0o755)
        copy = REMOTE.shutil.copy2
        with mock.patch.object(REMOTE, "unpack"), mock.patch.object(REMOTE.shutil, "copy2", side_effect=lambda source, target: copy(self.path(source), self.path(target))), mock.patch.object(REMOTE, "listeners", return_value=[{"port": 51752, "protocol": "udp"}]):
            REMOTE._change_hysteria({}, plan)
        self.assertEqual(self.path("/usr/local/bin/sing-box").read_bytes(), binary.read_bytes())
        config = json.loads(self.path("/etc/sing-box/config.json").read_text())
        self.assertEqual(config["inbounds"][0]["users"][0]["password"], self.secret)
        self.assertEqual(self.enabled["sing-box.service"], "enabled")
        self.assertNotIn("uninstalled", json.loads((self.root / "installed.json").read_text())["hysteria2"])

    def test_panel_reinstall_preserves_accounts_nodes_and_original_web_path(self):
        task, plan = self.reinstall_context("xui")
        database = self.path("/etc/x-ui/x-ui.db")
        before = REMOTE._panel_connection_config(database)
        self.write(task / "unpacked/fixture/x-ui", "new-fixture-panel", 0o755)
        with mock.patch.object(REMOTE, "unpack"), mock.patch.dict("sys.modules", {"bcrypt": types.SimpleNamespace()}):
            REMOTE._change_xui({}, plan)
        after = REMOTE._panel_connection_config(database)
        self.assertEqual(before["users"], after["users"]); self.assertEqual(before["nodes"], after["nodes"])
        self.assertEqual(after["settings"]["webBasePath"], "/fixture-panel/")
        self.assertEqual(self.enabled["x-ui.service"], "enabled")
        self.assertTrue(REMOTE.connection_details({"service": "xui"})["installed"])

    def test_exchange_reinstall_rebuilds_units_preserves_data_and_custom_nginx_config(self):
        task, plan = self.reinstall_context("exchange")
        before = {name: self.path(name).read_bytes() for name in ["/var/lib/xiaojun-exchange/ledger", "/var/lib/xiaojun-exchange/accounts", "/etc/xiaojun-exchange/nginx.conf"]}
        source = task / "exchange-source"; source.mkdir()
        self.write(source / "version.txt", plan["version"])
        self.write(source / "linux_exchange/deploy/proxy-runtimes.json", "{}")
        for unit in REMOTE.UNINSTALL_LAYOUTS["exchange"]["units"]:
            self.write(source / "linux_exchange/deploy" / unit, self.unit_text(unit))
        manifest = {str(file.relative_to(source)): {} for file in source.rglob("*") if file.is_file()}
        self.write(source / "linux-release-manifest.json", json.dumps(manifest))
        installer = types.SimpleNamespace(verify_payload=lambda path: (plan["version"], manifest), nginx_config=mock.Mock())
        with mock.patch.object(REMOTE, "unpack"), mock.patch.object(REMOTE, "_exchange_installer", return_value=installer):
            REMOTE._change_exchange({}, plan)
        installer.nginx_config.assert_not_called()
        self.assertEqual(before, {name: self.path(name).read_bytes() for name in before})
        self.assertTrue(self.path("/opt/xiaojun-exchange/current").is_symlink())
        for unit in [*REMOTE.UNITS["exchange"], "xiaojun-exchange-maintenance.timer", "xiaojun-exchange-logrotate.timer"]:
            self.assertEqual(self.enabled[unit], "enabled"); self.assertEqual(self.active[unit], "active")
        self.assertNotIn("uninstalled", json.loads((self.root / "installed.json").read_text())["exchange"])


class UninstallControllerAndUITests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-uninstall-client-"); self.addCleanup(directory.cleanup)
        self.root = Path(directory.name); self.vault = MemoryVault(); self.store = Store(self.root, self.vault)
        self.connection = Connection(host="fixture.invalid", username="fixture", password=secrets.token_urlsafe(30), remember=False)
        self.controller = Controller(self.store); self.ssh = mock.Mock()
        self.ssh.redactor.text.side_effect = lambda text: text
        self.controller.transport = mock.Mock(return_value=self.ssh)
        self.plan = {"service": "exchange", "action": "uninstall", "fingerprint": "fixture-preview", "remove_paths": ["/opt/xiaojun-exchange"], "retained_paths": ["/var/lib/xiaojun-exchange"], "message": "fixture-owned-removal"}

    def params(self):
        return {"operation": "uninstall", "service": "exchange", "keep_data": True, "maintenance_confirmed": True, "uninstall_fingerprint": "fixture-preview"}

    def test_controller_previews_fresh_then_submits_no_archive_and_keeps_local_credentials(self):
        identifier = "a" * 24
        self.ssh.call.side_effect = [self.plan, {"task_id": identifier}, {"id": identifier, "state": "succeeded", "message": "fixture-uninstalled", "result": {"data_retained": True}}]
        alias = credential_alias(self.connection, "exchange"); values = {"fixture-secret": secrets.token_urlsafe(30)}
        self.vault.put(alias, values)
        with mock.patch("linux_manager.controller.secrets.token_hex", return_value=identifier), mock.patch("linux_manager.releases.download_exchange") as download:
            status, updated = self.controller.execute(self.connection, self.params())
        self.assertEqual(status["state"], "succeeded"); self.assertEqual(updated, self.connection)
        download.assert_not_called(); self.assertEqual(self.vault.get(alias), values)
        actions = [call.args[0]["action"] for call in self.ssh.call.call_args_list]
        self.assertEqual(actions, ["uninstall_preflight", "start", "task"])
        self.assertNotIn("release_archive", self.ssh.call.call_args_list[1].args[0]["params"])

    def test_controller_rejects_stale_confirmation_and_unconfirmed_exchange_before_submission(self):
        for params in [self.params() | {"uninstall_fingerprint": "stale"}, self.params() | {"maintenance_confirmed": False}]:
            self.ssh.call.reset_mock(); self.ssh.call.side_effect = None; self.ssh.call.return_value = self.plan
            with self.assertRaises(ManagerError): self.controller.execute(self.connection, params)
            self.assertEqual(self.ssh.call.call_count, 1)
        self.assertEqual(self.store.history(), [])

    def app(self):
        app = object.__new__(App)
        app.busy = False; app.current = self.connection; app.controller = self.controller
        app.manage_choice = mock.Mock(); app.manage_choice.get.return_value = SERVICES["exchange"][0]
        app._ready = mock.Mock(return_value=True); app._execute = mock.Mock(); app.status = mock.Mock()
        app.maintenance_text = mock.Mock()
        app._run = lambda worker, done, *args: done(worker())
        self.controller.uninstall_preview = mock.Mock(return_value=self.plan)
        return app

    def test_gui_previews_correct_server_and_includes_financial_maintenance_warning(self):
        app = self.app(); app._uninstall()
        self.assertEqual(self.controller.uninstall_preview.call_args.args[0], self.connection)
        params, text = app._execute.call_args.args
        self.assertTrue(params["keep_data"]); self.assertTrue(params["maintenance_confirmed"])
        self.assertIn("撤单", text); self.assertIn("不能代替", text); self.assertIn("仍占磁盘", text)
        self.assertIn(self.connection.label, text)
        self.assertNotIn(self.connection.password, text)

    def test_busy_unchanged_and_late_result_never_execute_uninstall(self):
        app = self.app(); app.busy = True; app._uninstall()
        self.controller.uninstall_preview.assert_not_called()
        app.busy = False; self.controller.uninstall_preview.return_value = self.plan | {"action": "unchanged"}
        with mock.patch("linux_manager.gui.messagebox.showinfo"): app._uninstall()
        app._execute.assert_not_called()
        self.controller.uninstall_preview.return_value = self.plan
        def delayed(worker, done, *args):
            result = worker(); app.current = self.connection.changed(host="another-fixture.invalid"); done(result)
        app._run = delayed; app._uninstall(); app._execute.assert_not_called()

    def test_reinstall_gui_preserves_settings_instead_of_using_new_install_defaults(self):
        app = self.app(); app.report_server_key = server_key(self.connection)
        data = {"installed": False, "uninstalled": "fixture-time", "port": 26484, "version": "v1.1.88"}
        app.project_details = {(server_key(self.connection), "exchange"): {"data": data}}
        self.assertEqual(app._deployment_current("exchange"), data)

    def test_transport_embeds_uninstaller_for_remote_runner_without_local_module_files(self):
        ssh = SSH(self.connection, self.root / "transport")
        with mock.patch.object(ssh, "trusted", return_value=True), mock.patch("linux_manager.transport.Askpass") as askpass, mock.patch("linux_manager.transport.subprocess.run", return_value=types.SimpleNamespace(returncode=0, stdout='LM_RESULT:{"ok":true,"data":{}}\n', stderr="")) as run:
            askpass.return_value.__enter__.return_value = {}
            ssh.call({"action": "uninstall_preflight", "params": self.params()})
        packet = next(line[10:] for line in run.call_args.kwargs["input"].splitlines() if line.startswith("LMREQUEST:"))
        source = json.loads(base64.b64decode(packet))["agent"]
        scope = {"__name__": "uninstall_embedded_fixture"}
        exec(compile(source, "<isolated-embedded-source>", "exec"), scope)
        self.assertIn("uninstall_project", scope); self.assertIn("restore_uninstall", scope)
        self.assertIn("uninstall", scope["JOB_ACTIONS"])


class UninstallNativeUITests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-uninstall-tk-"); self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name), MemoryVault())
        self.errors = []; self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch("linux_manager.gui.Store", return_value=self.store))
        self.controller = self.stack.enter_context(mock.patch("linux_manager.gui.Controller")).return_value
        self.controller.connection_status.return_value = {"state": "disconnected", "token": ""}
        self.stack.enter_context(mock.patch.object(App, "_load_saved_profiles"))
        self.stack.enter_context(mock.patch.object(App, "report_callback_exception", side_effect=lambda *args: self.errors.append(args[0].__name__)))
        self.app = App(); self.addCleanup(self.close)
        self.connection = Connection(host="fixture.invalid", username="fixture", password=secrets.token_urlsafe(30))
        self.app.profiles = [self.connection]; self.app._profile_options(); self.app._load_profile(self.connection)
        self.app.deiconify(); self.app.update()

    def close(self):
        for identifier in self.app.tk.call("after", "info"): self.app.after_cancel(identifier)
        self.app.destroy(); self.assertEqual(self.errors, [])

    def test_actual_button_freezes_controls_and_cancel_never_submits(self):
        app = self.app; app.notebook.select(app.pages["日常维护"]); app.update()
        button = next(button for button in app.buttons if button.cget("text") == "卸载所选项目")
        self.assertTrue(button.winfo_ismapped())
        plan = {"service": "exchange", "action": "uninstall", "fingerprint": "fixture", "remove_paths": ["/opt/xiaojun-exchange"], "retained_paths": ["/var/lib/xiaojun-exchange"], "message": "fixture-preview"}
        self.controller.uninstall_preview.return_value = plan
        with mock.patch.object(app, "_ready", return_value=True), mock.patch("linux_manager.gui.messagebox.askyesno", return_value=False) as confirm:
            button.invoke()
            self.assertTrue(app.busy); self.assertEqual(str(button.cget("state")), "disabled")
            deadline = time.monotonic() + 2
            while app.busy and time.monotonic() < deadline: app.update(); time.sleep(0.01)
            self.assertFalse(app.busy); confirm.assert_called_once()
        self.controller.execute.assert_not_called()
        self.assertEqual(self.store.history(), [])
        self.assertTrue(app.privacy.get())

    def test_uninstalled_site_overview_and_open_action_do_not_treat_shared_core_as_installed(self):
        app = self.app
        data = {"service": "nginx", "installed": False, "uninstalled": "fixture-time", "version": "1.24.0", "port": 80, "config_file": "/etc/nginx/conf.d/linux-manager-default.conf"}
        report = {"os": "fixture-os", "architecture": "x86_64", "supported": True, "disk_free": 2 * 1024**3, "memory": {}, "accounts": [], "ssh": {}, "firewall": {"active": False}, "automatic_updates": False, "tasks": [], "services": {kind: [{"unit": values[1][0], "LoadState": "loaded" if kind == "nginx" else "not-found", "ActiveState": "active" if kind == "nginx" else "inactive"}] for kind, values in SERVICES.items()}, "project_information": {"nginx": {"data": data, "rows": information_rows(data, self.connection)}}}
        app._connected(self.connection, report); app.update()
        self.assertEqual(app.service_tree.item("nginx", "values")[1], "独立站点已卸载")
        self.assertEqual(app.statistics["services"].cget("text"), "0")
        app.service_tree.selection_set("nginx"); app._open_selected_project(); app.update()
        self.assertEqual(app.notebook.select(), str(app.pages["一键部署"]))
        self.assertEqual(app.deploy_port.get(), "80")
        self.controller.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
