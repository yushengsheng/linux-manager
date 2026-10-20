"""Read reuse is scoped to inspections; changes keep independent checks."""
from collections import Counter
from contextlib import ExitStack
import contextvars
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("inspection_agent", Path(__file__).resolve().parents[1] / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REMOTE)


class InspectionQueriesTests(unittest.TestCase):
    def setUp(self):
        self.calls = []; self.active = "active"; self.port = 8080
        def command(args, **kwargs):
            self.calls.append(tuple(args))
            text = ""
            if args[:2] == ["systemctl", "show"]:
                if "--value" in args: text = "--port 18880"
                else: text = "LoadState=loaded\nActiveState=" + self.active + "\nUnitFileState=enabled\nMainPID=123\n"
            elif args[:2] == ["systemctl", "start"]: self.active = "active"
            elif args == ["ss", "-lntupH"]:
                text = f'tcp LISTEN 0 128 0.0.0.0:{self.port} 0.0.0.0:* users:(("fixture",pid=123,fd=3))'
            elif args[:2] == ["/usr/sbin/sshd", "-T"]:
                text = "port 22\npasswordauthentication no\npermitrootlogin no\n"
            return subprocess.CompletedProcess(args, 0, text, "")
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE, "command", side_effect=command))

    def snapshot_fixture(self):
        self.stack.enter_context(mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04", "PRETTY_NAME": "fixture Linux"}))
        self.stack.enter_context(mock.patch.object(REMOTE.shutil, "disk_usage", return_value=SimpleNamespace(total=10000, free=5000)))
        self.stack.enter_context(mock.patch.object(REMOTE.os, "getloadavg", return_value=(0, 0, 0)))
        self.stack.enter_context(mock.patch.object(REMOTE.shutil, "which", return_value=None))
        self.stack.enter_context(mock.patch.object(REMOTE.Path, "exists", return_value=False))
        self.stack.enter_context(mock.patch.object(REMOTE.Path, "is_file", return_value=False))
        def read(path, *args, **kwargs):
            if str(path) == "/proc/meminfo": return "MemTotal: 2000 kB\nMemAvailable: 1000 kB"
            if str(path) == "/etc/shadow": return "fixture:!:1:0:99999:7:::"
            raise AssertionError("Unexpected file read in isolated fixture")
        self.stack.enter_context(mock.patch.object(REMOTE.Path, "read_text", read))
        account = SimpleNamespace(pw_name="fixture", pw_uid=1001, pw_gid=1001, pw_dir="/home/fixture", pw_shell="/bin/bash")
        self.stack.enter_context(mock.patch.object(REMOTE.pwd, "getpwall", return_value=[account]))
        self.stack.enter_context(mock.patch.object(REMOTE.grp, "getgrall", return_value=[]))
        self.stack.enter_context(mock.patch.object(REMOTE, "automatic_updates_snapshot", return_value={"active": False}))
        self.stack.enter_context(mock.patch.object(REMOTE, "firewall_snapshot", return_value={"active": False}))
        self.stack.enter_context(mock.patch.object(REMOTE, "task_list", return_value=[]))

    def test_actual_snapshot_reuses_queries_and_preserves_complete_response(self):
        self.snapshot_fixture()
        baseline = REMOTE.snapshot.__wrapped__(include_projects=True, address="fixture.invalid")
        old_calls = Counter(self.calls); self.calls.clear()
        optimized = REMOTE.snapshot(include_projects=True, address="fixture.invalid")
        new_calls = Counter(self.calls)
        self.assertEqual(optimized, baseline)
        self.assertEqual(new_calls[("ss", "-lntupH")], 1)
        self.assertEqual(new_calls[("/usr/sbin/sshd", "-T")], 1)
        self.assertEqual(new_calls[("/usr/sbin/sshd", "-t")], 1)
        for unit in {unit for units in REMOTE.UNITS.values() for unit in units}:
            queries = [args for args in self.calls if args[:3] == ("systemctl", "show", unit) and "--value" not in args]
            self.assertEqual(len(queries), 1)
        self.assertEqual(len(self.calls), 13)
        self.assertEqual(sum(old_calls.values()), 24)
        self.assertIsNone(REMOTE._INSPECTION_QUERIES.get())

    def test_next_snapshot_observes_new_service_state_and_port(self):
        self.snapshot_fixture()
        first = REMOTE.snapshot(include_projects=True)
        self.active = "inactive"; self.port = 9090
        second = REMOTE.snapshot(include_projects=True)
        self.assertEqual(first["services"]["nginx"][0]["ActiveState"], "active")
        self.assertEqual(second["services"]["nginx"][0]["ActiveState"], "inactive")
        self.assertEqual(second["project_details"]["nginx"]["units"][0]["ActiveState"], "inactive")
        self.assertEqual(first["listeners"][0]["port"], 8080)
        self.assertEqual(second["listeners"][0]["port"], 9090)

    def test_mutating_returned_values_cannot_change_shared_result(self):
        with REMOTE.inspection_queries():
            unit = REMOTE.unit_info("nginx.service"); unit["ActiveState"] = "changed"
            ports = REMOTE.listeners(); ports[0]["processes"].append("changed")
            ssh = REMOTE.ssh_configuration(); ssh["port"].append("changed")
            self.assertEqual(REMOTE.unit_info("nginx.service")["ActiveState"], "active")
            self.assertEqual(REMOTE.listeners()[0]["processes"], ["fixture"])
            self.assertEqual(REMOTE.ssh_configuration()["port"], ["22"])
        self.assertEqual(len(self.calls), 4)

    def test_failed_query_is_retried_within_the_same_inspection(self):
        failed = subprocess.CompletedProcess([], 1, "", "fictional-error")
        success = subprocess.CompletedProcess([], 0, "ActiveState=active\n", "")
        with mock.patch.object(REMOTE, "command", side_effect=[failed, success]) as command, REMOTE.inspection_queries():
            self.assertEqual(REMOTE.unit_info("fixture.service"), {})
            self.assertEqual(REMOTE.unit_info("fixture.service")["ActiveState"], "active")
            REMOTE.unit_info("fixture.service")
        self.assertEqual(command.call_count, 2)

    def test_exceptions_clear_inspection_context_and_never_retain_stale_state(self):
        with self.assertRaises(RuntimeError):
            with REMOTE.inspection_queries():
                REMOTE.unit_info("fixture.service")
                raise RuntimeError("fixture failure")
        self.assertIsNone(REMOTE._INSPECTION_QUERIES.get())
        self.active = "inactive"
        self.assertEqual(REMOTE.unit_info("fixture.service")["ActiveState"], "inactive")

    def test_standalone_details_and_service_change_always_make_fresh_checks(self):
        self.active = "inactive"
        with REMOTE.inspection_queries(): REMOTE.unit_info("nginx.service")
        result = REMOTE.manage_service({"service": "nginx", "action": "start"})
        self.assertEqual(result["services"][0]["ActiveState"], "active")
        shows = [args for args in self.calls if args[:3] == ("systemctl", "show", "nginx.service")]
        self.assertEqual(len(shows), 3)
        self.assertIn(("systemctl", "start", "nginx.service"), self.calls)

    def test_ssh_user_contexts_are_never_mixed_with_global_policy(self):
        with REMOTE.inspection_queries():
            for context in (None, "user=fixture", "user=other"):
                REMOTE.ssh_configuration(context); REMOTE.ssh_configuration(context)
        queries = [args for args in self.calls if args[:2] == ("/usr/sbin/sshd", "-T")]
        self.assertEqual(len(queries), 3)

    def test_nested_inspections_reuse_only_the_current_context(self):
        with REMOTE.inspection_queries():
            self.assertEqual(REMOTE.unit_info("fixture.service")["ActiveState"], "active")
            self.active = "inactive"
            with REMOTE.inspection_queries():
                self.assertEqual(REMOTE.unit_info("fixture.service")["ActiveState"], "active")
            separate = contextvars.Context().run(REMOTE.unit_info, "fixture.service")
            self.assertEqual(separate["ActiveState"], "inactive")
        self.assertIsNone(REMOTE._INSPECTION_QUERIES.get())

    def test_refresh_all_builtin_details_share_one_read_scope_only(self):
        manager = mock.Mock(); manager.discover.return_value = {"projects": [], "warnings": []}
        def details(params): return REMOTE.unit_info("nginx.service")
        with mock.patch.dict(REMOTE._external_projects, ExternalProjects=mock.Mock(return_value=manager)), \
             mock.patch.object(REMOTE, "connection_details", side_effect=details):
            REMOTE.external_project_call("external_projects", {"include_builtin": True})
            REMOTE.external_project_call("external_projects", {"include_builtin": True})
        self.assertEqual(len(self.calls), 2)
        self.assertIsNone(REMOTE._INSPECTION_QUERIES.get())


if __name__ == "__main__": unittest.main()
