"""Release blockers: GUI event continuity, service scope and retryable rollback."""
import contextlib
import json
from pathlib import Path
import queue
import secrets
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from test_linux_manager import MemoryVault, REMOTE
from linux_manager.gui import App
from linux_manager.models import Connection, SERVICES, Store


class EventContinuityTests(unittest.TestCase):
    def app(self):
        app = object.__new__(App)
        app.events = queue.Queue(); app.busy = True
        app.buttons = [mock.Mock()]; app.input_states = []
        app.status = mock.Mock(); app.progress = mock.Mock(); app.after = mock.Mock()
        app._auth_fields = mock.Mock()
        app._redactor = mock.Mock(return_value=mock.Mock(text=lambda value: value))
        return app

    def test_failed_completion_callback_keeps_pump_and_next_operation_available(self):
        app = self.app(); next_result = mock.Mock()
        app.events.put(("done", {}, mock.Mock(side_effect=ValueError("fixture-callback"))))
        app.events.put(("done", "next-operation", next_result))
        with self.assertRaises(ValueError): app._drain()
        app.after.assert_called_once()
        self.assertFalse(app.busy)
        app._drain()
        next_result.assert_called_once_with("next-operation")

    def test_connection_callback_failure_does_not_drop_pending_task_completion(self):
        app = self.app(); done = mock.Mock()
        app._connection_changed = mock.Mock(side_effect=ValueError("fixture-state"))
        app.events.put(("connection", {}, None))
        app.events.put(("done", "task-result", done))
        with self.assertRaises(ValueError): app._drain()
        app.after.assert_called_once()
        self.assertTrue(app.busy)
        app._drain()
        done.assert_called_once_with("task-result")
        self.assertFalse(app.busy)

    def test_progress_display_failure_cannot_stop_future_results(self):
        app = self.app()
        app.status.configure.side_effect = ValueError("fixture-progress")
        app.events.put(("progress", {"message": "fixture"}, None))
        with self.assertRaises(ValueError): app._drain()
        app.after.assert_called_once()


class NativeEventContinuityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-release-ui-")
        self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name), MemoryVault())
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch("linux_manager.gui.Store", return_value=self.store))
        self.stack.enter_context(mock.patch("linux_manager.gui.Controller"))
        self.stack.enter_context(mock.patch.object(App, "_load_saved_profiles"))
        self.alert = self.stack.enter_context(mock.patch("linux_manager.gui.messagebox.showerror"))
        self.app = App(); self.app.withdraw(); self.addCleanup(self.close)
        for identifier in self.app.tk.call("after", "info"):
            self.app.after_cancel(identifier)

    def close(self):
        for identifier in self.app.tk.call("after", "info"):
            self.app.after_cancel(identifier)
        self.app.destroy()

    def test_real_tk_reports_redacted_error_and_processes_the_next_result(self):
        app = self.app; done = mock.Mock(); secret = secrets.token_urlsafe(30)
        app.busy = True
        app.events.put(("done", {}, mock.Mock(side_effect=ValueError(secret))))
        app.events.put(("done", "next-result", done))
        app.after(0, app._drain)
        deadline = time.monotonic() + 1
        while not done.called and time.monotonic() < deadline:
            app.update(); time.sleep(0.01)
        done.assert_called_once_with("next-result")
        self.assertFalse(app.busy)
        self.alert.assert_called_once()
        diagnostic = self.store.directory / "ui-error.json"
        self.assertEqual(json.loads(diagnostic.read_text())["type"], "ValueError")
        self.assertNotIn(secret, diagnostic.read_text())
        self.assertNotIn(secret, self.alert.call_args.args[1])
        self.assertEqual(diagnostic.stat().st_mode & 0o777, 0o600)


class NginxServiceScopeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-release-nginx-")
        self.addCleanup(directory.cleanup)
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE, "ROOT", Path(directory.name)))
        self.stack.enter_context(mock.patch.object(REMOTE, "listeners", return_value=[]))
        self.stack.enter_context(mock.patch.object(REMOTE, "step"))
        self.stack.enter_context(mock.patch.object(REMOTE, "unit_info", return_value={"LoadState": "loaded", "ActiveState": "active"}))
        self.command = self.stack.enter_context(mock.patch.object(REMOTE, "command"))

    def test_local_and_remote_service_scope_excludes_trading_entrance(self):
        self.assertEqual(SERVICES["nginx"][1], ("nginx.service",))
        self.assertEqual(REMOTE.UNITS["nginx"], ["nginx.service"])

    def test_every_nginx_service_action_touches_only_shared_core(self):
        for action in ["start", "stop", "restart", "enable", "disable"]:
            with self.subTest(action=action):
                self.command.reset_mock()
                result = REMOTE.manage_service({"service": "nginx", "action": action})
                self.assertEqual(self.command.call_args.args[0], ["systemctl", action, "nginx.service"])
                self.assertEqual([unit["unit"] for unit in result["services"]], ["nginx.service"])

    def test_only_trading_installed_does_not_make_nginx_management_target_it(self):
        def state(unit):
            return {"LoadState": "loaded" if unit.startswith("xiaojun-") else "not-found"}
        with mock.patch.object(REMOTE, "unit_info", side_effect=state):
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.manage_service({"service": "nginx", "action": "stop"})
            data = REMOTE.connection_details({"service": "nginx"})
        self.assertFalse(data["installed"])
        self.assertFalse(any(call.args[0][:2] == ["systemctl", "stop"] for call in self.command.call_args_list))

    def test_nginx_configuration_restore_does_not_restart_trading_entry(self):
        identifier = "b" * 24
        backup = REMOTE.ROOT / "tasks" / identifier / "backup"; backup.mkdir(parents=True)
        REMOTE.write_json(backup / "manifest.json", {"paths": [], "extra": {"service": "nginx"}})
        with mock.patch.object(REMOTE, "status_task", return_value={"state": "succeeded"}), mock.patch.object(REMOTE, "firewall_snapshot", return_value={"active": False}), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE, "restore_files"):
            REMOTE.configuration_restore({"backup_id": identifier})
        self.command.assert_called_once_with(["systemctl", "restart", "nginx.service"])

    def test_nginx_logs_are_scoped_to_core_not_trading_entry(self):
        self.command.return_value = subprocess.CompletedProcess([], 0, "Started fixture website", "")
        with mock.patch.object(REMOTE.os, "geteuid", return_value=0):
            REMOTE.dispatch({"action": "logs", "service": "nginx"})
        args = self.command.call_args.args[0]
        self.assertIn("nginx.service", args)
        self.assertNotIn("xiaojun-exchange-nginx.service", args)

    def test_nginx_gui_confirmation_warns_about_shared_sites_not_trading(self):
        app = object.__new__(App); app.manage_choice = mock.Mock()
        app.manage_choice.get.return_value = SERVICES["nginx"][0]
        app._execute = mock.Mock()
        with mock.patch("linux_manager.gui.messagebox.askyesno") as confirm:
            app._service("stop")
        params, description = app._execute.call_args.args
        self.assertEqual(params, {"operation": "service", "service": "nginx", "action": "stop"})
        self.assertIn("其他网站", description)
        self.assertIn("不操作交易系统", description)
        confirm.assert_not_called()

    def test_trading_entry_still_requires_maintenance_and_keeps_all_three_units(self):
        for action in ["stop", "restart"]:
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.manage_service({"service": "exchange", "action": action})
            result = REMOTE.manage_service({"service": "exchange", "action": action, "maintenance_confirmed": True})
            self.assertEqual([unit["unit"] for unit in result["services"]], REMOTE.UNITS["exchange"])
        self.assertIn("xiaojun-exchange-nginx.service", REMOTE.UNITS["exchange"])


class DeploymentRecoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-release-recovery-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name); self.identifier = "a" * 24
        self.task = self.root / "tasks" / self.identifier; self.task.mkdir(parents=True)
        self.config = self.root / "project.conf"; self.config.write_text("original-config")
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE, "ROOT", self.root))
        self.stack.enter_context(mock.patch.object(REMOTE, "TASK", self.task))
        self.stack.enter_context(mock.patch.object(REMOTE, "SECRETS", set()))
        self.stack.enter_context(mock.patch.object(REMOTE.os, "chown"))
        self.hook = self.stack.enter_context(mock.patch.object(REMOTE, "cert_hook"))
        self.stack.enter_context(mock.patch.object(REMOTE, "unit_info", side_effect=lambda unit: dict(self.state)))
        self.command = self.stack.enter_context(mock.patch.object(REMOTE, "command", side_effect=self.system_command))
        self.state = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}
        self.failure = None; self.ignore = None
        REMOTE.backup_files([str(self.config)], {"deployment": True, "service": "hysteria2", "unit_states": {"sing-box.service": dict(self.state)}})
        self.config.write_text("failed-new-config")
        self.state.update(ActiveState="inactive", UnitFileState="disabled")
        REMOTE.write_json(self.task / "status.json", {"id": self.identifier, "operation": "deploy", "state": "recovery_failed", "message": "fixture"})

    def system_command(self, args, **kwargs):
        if args[:1] == ["systemctl"]:
            action = args[1]
            if action == self.failure:
                if kwargs.get("check", True): raise REMOTE.OperationError("fixture-command-failure")
                return subprocess.CompletedProcess(args, 1, "", "fixture-command-failure")
            if action != self.ignore:
                if action == "stop": self.state["ActiveState"] = "inactive"
                elif action == "restart": self.state["ActiveState"] = "active"
                elif action in {"enable", "disable"}: self.state["UnitFileState"] = "enabled" if action == "enable" else "disabled"
        return subprocess.CompletedProcess(args, 0, "", "")

    def test_manual_retry_restores_config_service_startup_and_certificate_hook(self):
        REMOTE.recover(self.identifier)
        self.assertEqual(self.config.read_text(), "original-config")
        self.assertEqual(self.state["ActiveState"], "active")
        self.assertEqual(self.state["UnitFileState"], "enabled")
        self.hook.assert_called_once()
        status = REMOTE.status_task(self.identifier)
        self.assertEqual(status["state"], "rolled_back")
        self.assertIn("项目", status["message"])
        self.assertNotIn("新连接", status["message"])

    def test_failed_service_restart_stays_recovery_failed_and_can_retry(self):
        self.failure = "restart"
        REMOTE.recover(self.identifier)
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "recovery_failed")
        self.failure = None
        REMOTE.recover(self.identifier)
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "rolled_back")
        self.assertEqual(self.state["ActiveState"], "active")

    def test_failed_startup_restoration_never_reports_rolled_back(self):
        self.failure = "enable"
        REMOTE.recover(self.identifier)
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "recovery_failed")

    def test_successful_commands_with_wrong_actual_service_or_startup_stay_failed(self):
        for ignored in ["restart", "enable"]:
            with self.subTest(ignored=ignored):
                self.ignore = ignored
                self.state.update(ActiveState="inactive", UnitFileState="disabled")
                REMOTE.write_json(self.task / "status.json", {"id": self.identifier, "operation": "deploy", "state": "recovery_failed"})
                REMOTE.recover(self.identifier)
                self.assertEqual(REMOTE.status_task(self.identifier)["state"], "recovery_failed")

    def test_original_stopped_disabled_project_does_not_get_started(self):
        manifest = self.task / "backup/manifest.json"
        saved = json.loads(manifest.read_text())
        saved["extra"]["unit_states"]["sing-box.service"].update(ActiveState="inactive", UnitFileState="disabled")
        REMOTE.write_json(manifest, saved)
        self.state.update(ActiveState="active", UnitFileState="enabled")
        REMOTE.recover(self.identifier)
        self.assertEqual(self.state["ActiveState"], "inactive")
        self.assertEqual(self.state["UnitFileState"], "disabled")
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "rolled_back")

    def test_static_service_restoration_does_not_attempt_enable_or_disable(self):
        manifest = self.task / "backup/manifest.json"
        saved = json.loads(manifest.read_text())
        saved["extra"]["unit_states"]["sing-box.service"]["UnitFileState"] = "static"
        REMOTE.write_json(manifest, saved)
        self.state["UnitFileState"] = "static"
        REMOTE.recover(self.identifier)
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "rolled_back")
        self.assertFalse(any(call.args[0][1] in {"enable", "disable"} for call in self.command.call_args_list))

    def test_completed_deployment_cannot_be_undone_or_repeat_recovery(self):
        for state in ["succeeded", "failed", "rolled_back"]:
            REMOTE.write_json(self.task / "status.json", {"operation": "deploy", "state": state})
            with mock.patch.object(REMOTE, "restore_deployment") as restore:
                REMOTE.recover(self.identifier)
            restore.assert_not_called()
            self.assertEqual(self.config.read_text(), "failed-new-config")

    def test_non_deployment_recovery_keeps_existing_specialized_routes(self):
        for operation, helper in [("uninstall", "restore_uninstall"), ("password", "restore_files")]:
            REMOTE.write_json(self.task / "status.json", {"operation": operation, "state": "recovery_failed"})
            with mock.patch.object(REMOTE, helper) as restore, mock.patch.object(REMOTE, "restore_deployment") as deploy:
                REMOTE.recover(self.identifier)
            restore.assert_called_once_with(self.identifier); deploy.assert_not_called()

    def test_gui_deployment_recovery_confirmation_describes_full_project_restore(self):
        app = object.__new__(App); app._ready = mock.Mock(return_value=True)
        app.current = Connection(host="fixture.invalid"); app.task_tree = mock.Mock()
        app.task_tree.selection.return_value = (self.identifier,)
        app.latest_tasks = [{"id": self.identifier, "operation": "deploy", "state": "recovery_failed"}]
        app._run = mock.Mock()
        with mock.patch("linux_manager.gui.messagebox.askyesno", return_value=False) as confirm:
            app._recover()
        self.assertIn("项目", confirm.call_args.args[1])
        self.assertIn("服务", confirm.call_args.args[1])
        app._run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
