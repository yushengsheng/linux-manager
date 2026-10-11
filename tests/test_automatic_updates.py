import contextlib
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_linux_manager import REMOTE


class AutomaticUpdateTests(unittest.TestCase):
    def timers(self, enabled=True):
        return {unit: {
            "LoadState": "loaded", "UnitFileState": "enabled" if enabled else "disabled",
            "ActiveState": "active" if enabled else "inactive", "SubState": "waiting" if enabled else "dead",
            "NextElapseUSecRealtime": "Sun 2026-10-11 06:30:00 UTC" if enabled else "n/a", "Persistent": "no",
        } for unit in REMOTE.APT_TIMERS}

    def configuration(self, **changes):
        values = {
            "APT::Periodic::Enable": "1", "APT::Periodic::Update-Package-Lists": "1",
            "APT::Periodic::Unattended-Upgrade": "1", "Unattended-Upgrade::Automatic-Reboot": "false",
            "Unattended-Upgrade::Allowed-Origins::": "Ubuntu:noble-security",
        }
        values.update(changes)
        return "\n".join(f'{key} "{value}";' for key, value in values.items() if value is not None)

    def status(self, config=None, timers=None, installed=True, returncode=0, executing=False):
        timers = timers if timers is not None else self.timers()
        def command(args, **kwargs):
            if args == ["apt-config", "dump"]:
                return subprocess.CompletedProcess(args, returncode, self.configuration() if config is None else config, "")
            if args[:2] == ["systemctl", "show"]:
                return subprocess.CompletedProcess(args, 0, "\n".join(f"{key}={value}" for key, value in timers[args[2]].items()), "")
            raise AssertionError(args)
        def which(name):
            return None if name == "unattended-upgrade" and not installed else "/usr/bin/" + name
        with mock.patch.object(REMOTE, "command", side_effect=command), mock.patch.object(REMOTE.shutil, "which", side_effect=which), mock.patch.object(REMOTE, "unit_info", return_value={"ActiveState": "active" if executing else "inactive"}) as units:
            result = REMOTE.automatic_updates_snapshot()
        self.assertNotIn(mock.call("unattended-upgrades.service"), units.call_args_list)
        return result

    def test_ready_status_requires_actual_scheduler_not_shutdown_helper(self):
        self.assertTrue(self.status()["active"])
        self.assertFalse(self.status(timers=self.timers(False))["active"])

    def test_each_timer_requires_persistent_enablement_activity_and_deadline(self):
        for unit in REMOTE.APT_TIMERS:
            for field, value in [("UnitFileState", "disabled"), ("UnitFileState", "enabled-runtime"), ("LoadState", "masked"), ("ActiveState", "inactive"), ("ActiveState", "failed"), ("NextElapseUSecRealtime", "n/a"), ("NextElapseUSecRealtime", ""), ("NextElapseUSecRealtime", "0")]:
                with self.subTest(unit=unit, field=field, value=value):
                    timers = self.timers(); timers[unit][field] = value
                    self.assertFalse(self.status(timers=timers)["active"])

    def test_running_job_is_ready_only_when_its_actual_service_is_running(self):
        timers = self.timers()
        timers[REMOTE.APT_TIMERS[1]].update(SubState="running", NextElapseUSecRealtime="n/a")
        self.assertTrue(self.status(timers=timers, executing=True)["active"])
        self.assertFalse(self.status(timers=timers, executing=False)["active"])

    def test_final_apt_configuration_is_checked_not_just_manager_file(self):
        for changes in [
            {"APT::Periodic::Enable": "0"}, {"APT::Periodic::Enable": "false"},
            {"APT::Periodic::Update-Package-Lists": "0"}, {"APT::Periodic::Unattended-Upgrade": "0"},
            {"APT::Periodic::Unattended-Upgrade": "invalid"}, {"Unattended-Upgrade::Allowed-Origins::": None},
        ]:
            with self.subTest(changes=changes):
                self.assertFalse(self.status(config=self.configuration(**changes))["active"])
        config = self.configuration(**{"APT::Periodic::Enable": None, "APT::Periodic::Unattended-Upgrade": "always", "Unattended-Upgrade::Automatic-Reboot": None})
        result = self.status(config=config)
        self.assertTrue(result["active"])
        self.assertFalse(result["automatic_reboot"])

    def test_debian_origin_patterns_and_ubuntu_origins_are_supported(self):
        config = self.configuration(**{"Unattended-Upgrade::Allowed-Origins::": None, "Unattended-Upgrade::Origins-Pattern::": "origin=Debian,codename=bookworm-security,label=Debian-Security"})
        self.assertTrue(self.status(config=config)["active"])

    def test_missing_package_or_broken_apt_configuration_is_not_reported_ready(self):
        self.assertFalse(self.status(installed=False)["active"])
        result = self.status(returncode=100)
        self.assertFalse(result["active"])
        self.assertFalse(result["config_valid"])
        self.assertIsNone(result["automatic_reboot"])

    def test_snapshot_preserves_boolean_api_and_exposes_verified_details(self):
        status = self.status(timers=self.timers(False))
        with mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), mock.patch.object(REMOTE.shutil, "disk_usage", return_value=SimpleNamespace(total=100, free=50)), mock.patch.object(REMOTE.Path, "read_text", return_value="MemAvailable: 100 kB"), mock.patch.object(REMOTE, "unit_info", return_value={"ActiveState": "active"}) as units, mock.patch.object(REMOTE.shutil, "which", return_value=None), mock.patch.object(REMOTE, "automatic_updates_snapshot", return_value=status), mock.patch.object(REMOTE, "account_snapshot", return_value=[]), mock.patch.object(REMOTE, "ssh_configuration", return_value={}), mock.patch.object(REMOTE, "firewall_snapshot", return_value={}), mock.patch.object(REMOTE, "listeners", return_value=[]), mock.patch.object(REMOTE, "task_list", return_value=[]):
            result = REMOTE.snapshot()
        self.assertIs(result["automatic_updates"], False)
        self.assertIs(result["update_status"], status)
        self.assertNotIn(mock.call("unattended-upgrades.service"), units.call_args_list)

    def fixture(self, installed=True, status=None):
        ready = self.status() if status is None else status
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(REMOTE, "update_timer_states", return_value=self.timers(False)))
        backup = stack.enter_context(mock.patch.object(REMOTE, "backup_files"))
        writes = stack.enter_context(mock.patch.object(REMOTE, "private_write"))
        apt = stack.enter_context(mock.patch.object(REMOTE, "apt"))
        stack.enter_context(mock.patch.object(REMOTE.shutil, "which", return_value="tool" if installed else None))
        stack.enter_context(mock.patch.object(REMOTE, "automatic_updates_snapshot", return_value=ready))
        stack.enter_context(mock.patch.object(REMOTE, "step"))
        commands = stack.enter_context(mock.patch.object(REMOTE, "command"))
        return backup, writes, apt, commands

    def test_enabling_installed_package_sets_timers_without_immediate_upgrade(self):
        backup, writes, apt, commands = self.fixture()
        result = REMOTE.update_settings({"enabled": True})
        self.assertTrue(result["enabled"])
        self.assertFalse(result["automatic_reboot"])
        apt.assert_not_called()
        self.assertEqual(backup.call_args.args[0], REMOTE.update_configuration_paths())
        self.assertEqual(backup.call_args.args[1]["update_timers"], self.timers(False))
        self.assertIn('APT::Periodic::Enable "1";', writes.call_args_list[0].args[1])
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', writes.call_args_list[0].args[1])
        for call in writes.call_args_list[1:]:
            self.assertEqual(call.args[1], "[Timer]\nPersistent=false\n")
            self.assertEqual(call.args[2], 0o644)
        self.assertIn(mock.call(["systemctl", "enable", "--now", *REMOTE.APT_TIMERS]), commands.call_args_list)
        self.assertIn(mock.call(["systemctl", "restart", *REMOTE.APT_TIMERS]), commands.call_args_list)
        self.assertFalse(any(".service" in argument for call in commands.call_args_list for argument in call.args[0]))
        self.assertFalse(any(call.args[0][0] in {"apt-get", "unattended-upgrade", "reboot", "ufw"} for call in commands.call_args_list))

    def test_overridden_catchup_policy_stops_before_enabling_timers(self):
        _, _, _, commands = self.fixture()
        timers = self.timers(False)
        for state in timers.values(): state["Persistent"] = "yes"
        with mock.patch.object(REMOTE, "update_timer_states", return_value=timers):
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.update_settings({"enabled": True})
        commands.assert_called_once_with(["systemctl", "daemon-reload"])

    def test_missing_package_is_installed_only_after_original_state_is_backed_up(self):
        backup, _, apt, _ = self.fixture(installed=False)
        apt.side_effect = lambda packages: backup.assert_called_once()
        REMOTE.update_settings({"enabled": True})
        apt.assert_called_once_with(["unattended-upgrades"])

    def test_invalid_flag_or_masked_timer_stops_before_configuration_changes(self):
        backup, writes, apt, commands = self.fixture()
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.update_settings({"enabled": "yes"})
        with mock.patch.object(REMOTE, "update_timer_states", return_value={unit: {"LoadState": "masked", "UnitFileState": "masked"} for unit in REMOTE.APT_TIMERS}):
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.update_settings({"enabled": True})
        backup.assert_not_called(); writes.assert_not_called(); apt.assert_not_called(); commands.assert_not_called()

    def test_overridden_config_or_reboot_policy_does_not_start_timers(self):
        for changes in [{"automatic_reboot": True}, {"config_valid": False}, {"origins_configured": False}, {"upgrade_interval": "0"}]:
            with self.subTest(changes=changes):
                _, _, _, commands = self.fixture(status=self.status() | changes)
                with self.assertRaises(REMOTE.OperationError):
                    REMOTE.update_settings({"enabled": True})
                commands.assert_not_called()

    def test_enable_command_failure_or_unready_timer_cannot_succeed(self):
        _, _, _, commands = self.fixture(status=self.status(timers=self.timers(False)))
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.update_settings({"enabled": True})
        commands.side_effect = REMOTE.OperationError("调度启动失败。")
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.update_settings({"enabled": True})

    def test_disabling_upgrades_does_not_stop_shared_apt_timers(self):
        _, writes, apt, commands = self.fixture(status=self.status(config=self.configuration(**{"APT::Periodic::Unattended-Upgrade": "0"})))
        result = REMOTE.update_settings({"enabled": False})
        self.assertFalse(result["enabled"])
        self.assertFalse(result["update_status"]["active"])
        self.assertIn('APT::Periodic::Unattended-Upgrade "0";', writes.call_args.args[1])
        self.assertEqual(writes.call_count, 1)
        apt.assert_not_called(); commands.assert_not_called()

    def test_update_failure_restores_config_and_timer_states_without_touching_ssh(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "e" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            config = base / "updates.conf"; config.write_text("original configuration\n")
            paths = [str(config), str(base / "daily.conf"), str(base / "upgrade.conf")]
            (task / "request.json").write_text(json.dumps({"operation": "updates", "enabled": True}))
            (task / "status.json").write_text(json.dumps({"state": "queued"}))
            timers = self.timers(False)
            previous = copy.deepcopy(timers)
            def command(args, **kwargs):
                if args[1] in {"enable", "disable", "start", "stop"}:
                    for unit in args[2:]:
                        if unit not in timers: continue
                        if args[1] in {"enable", "disable"}:
                            timers[unit]["UnitFileState"] = "enabled" if args[1] == "enable" else "disabled"
                        else:
                            timers[unit]["ActiveState"] = "active" if args[1] == "start" else "inactive"
                        if "--now" in args:
                            timers[unit]["ActiveState"] = "active"
                return subprocess.CompletedProcess(args, 0, "", "")
            ready = self.status()
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "TASK", None), mock.patch.object(REMOTE, "UPDATE_CONFIG", str(config)), mock.patch.object(REMOTE, "update_configuration_paths", return_value=paths), mock.patch.object(REMOTE, "update_timer_states", side_effect=lambda: copy.deepcopy(timers)), mock.patch.object(REMOTE, "automatic_updates_snapshot", side_effect=[ready, ready | {"active": False}]), mock.patch.object(REMOTE.shutil, "which", return_value="tool"), mock.patch.object(REMOTE, "command", side_effect=command) as commands, mock.patch.object(REMOTE.os, "chown"):
                REMOTE.run_task(identifier)
            self.assertEqual(config.read_text(), "original configuration\n")
            self.assertFalse(Path(paths[1]).exists())
            self.assertFalse(Path(paths[2]).exists())
            self.assertEqual(timers, previous)
            self.assertEqual(json.loads((task / "status.json").read_text())["state"], "failed")
            self.assertFalse((task / "request.json").exists())
            self.assertFalse(any("ssh.service" in call.args[0] or "ufw" in call.args[0] for call in commands.call_args_list))

    def test_failed_update_rollback_remains_an_explicit_recovery_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "f" * 24
            task = base / "tasks" / identifier; (task / "backup").mkdir(parents=True)
            (task / "backup/manifest.json").write_text("{}")
            (task / "request.json").write_text(json.dumps({"operation": "updates"}))
            (task / "status.json").write_text(json.dumps({"state": "queued"}))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "TASK", None), mock.patch.object(REMOTE, "update_settings", side_effect=REMOTE.OperationError("启动失败")), mock.patch.object(REMOTE, "restore_files", side_effect=REMOTE.OperationError("恢复失败")), mock.patch.object(REMOTE, "command"):
                REMOTE.run_task(identifier)
            result = json.loads((task / "status.json").read_text())
            self.assertEqual(result["state"], "recovery_failed")
            self.assertIn("恢复失败", result["recovery_diagnostic"])

    def test_legacy_security_manifest_does_not_invent_timer_state(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "a" * 24
            backup = base / "tasks" / identifier / "backup"; backup.mkdir(parents=True)
            (backup / "manifest.json").write_text(json.dumps({"paths": [], "extra": {"service": "security"}}))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "write_account_denials"), mock.patch.object(REMOTE, "managed_accounts", return_value={}), mock.patch.object(REMOTE.shutil, "which", return_value=None), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 1, "", "")), mock.patch.object(REMOTE, "restore_update_timers") as timers:
                REMOTE.restore_files(identifier)
                timers.assert_not_called()

    def test_security_restore_backs_up_current_timer_state_for_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "b" * 24
            saved = base / "tasks" / identifier / "backup"; saved.mkdir(parents=True)
            manifest = {"paths": [], "extra": {"service": "security", "update_timers": self.timers(False)}}
            (saved / "manifest.json").write_text(json.dumps(manifest))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "status_task", return_value={"state": "succeeded"}), mock.patch.object(REMOTE, "firewall_snapshot", return_value={"active": False}), mock.patch.object(REMOTE, "unit_info", return_value={}), mock.patch.object(REMOTE, "update_timer_states", return_value=self.timers()), mock.patch.object(REMOTE, "backup_files") as backup, mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE, "restore_files"):
                result = REMOTE.configuration_restore({"backup_id": identifier})
            self.assertEqual(backup.call_args.args[1]["update_timers"], self.timers())
            self.assertTrue(result["requires_verification"])

    def test_security_backup_includes_update_scheduler(self):
        with mock.patch.object(REMOTE, "TASK", Path("fictional-task")), mock.patch.object(REMOTE, "step"), mock.patch.object(REMOTE, "unit_info", return_value={}), mock.patch.object(REMOTE, "firewall_snapshot", return_value={"active": False}), mock.patch.object(REMOTE, "update_timer_states", return_value=self.timers(False)), mock.patch.object(REMOTE, "backup_files") as backup:
            REMOTE.configuration_backup({"service": "security"})
        self.assertTrue(set(REMOTE.update_configuration_paths()) <= set(backup.call_args.args[0]))
        self.assertEqual(backup.call_args.args[1]["update_timers"], self.timers(False))


if __name__ == "__main__":
    unittest.main()
