import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.models import Connection, SERVICES
from linux_manager.project_info import server_key


def project(identifier, kind="systemd", state="active", **values):
    return dict({"id": identifier, "kind": kind, "name": identifier.rsplit(":", 1)[-1], "state": state,
                 "capabilities": [], "ports": [], "startup": "enabled"}, **values)


class OverviewProjectsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk(); cls.root.withdraw()

    @classmethod
    def tearDownClass(cls): cls.root.destroy()

    def setUp(self):
        self.overview = ttk.Frame(self.root); self.maintenance = ttk.Frame(self.root)
        app = self.app = object.__new__(App)
        app.pages = {"服务器总览": SimpleNamespace(content=self.overview), "日常维护": SimpleNamespace(content=self.maintenance), "一键部署": object()}
        app.current = Connection(label="fixture", host="one.invalid")
        app.profiles = [app.current]; app.privacy = tk.BooleanVar(self.root, value=False)
        app.busy = False; app.buttons = []; app.private_entries = []; app.project_details = {}; app.project_logs = {}
        app._overview_page(); app._maintenance_page()
        app.status = mock.Mock(); app.notebook = mock.Mock(); app.controller = mock.Mock()
        app._ready = mock.Mock(return_value=True); app._configure_project = mock.Mock()
        app.report_server_key = server_key(app.current)
        app.report = {"services": {key: [{"LoadState": "loaded" if key == "xui" else "not-found", "ActiveState": "active" if key == "xui" else "inactive", "UnitFileState": "enabled"}] for key in SERVICES}}
        app._run = lambda work, done, message: done(work())

    def tearDown(self):
        self.overview.destroy(); self.maintenance.destroy()

    def add(self, *projects, saved=False):
        for row in projects:
            information = {"project": row}
            if saved: information["saved_at"] = "2026-10-19T12:00:00+08:00"
            self.app._cache_external_information(self.app.current, information)

    def test_overview_merges_all_discovered_kinds_and_counts_running_projects(self):
        app = self.app
        projects = [project("external:systemd:sample.service", state="inactive"),
                    project("external:systemd-user:1234:hermes.service", "systemd-user", product="Hermes Agent"),
                    project("external:docker:" + "a" * 64, "docker", "running", startup="always"),
                    project("external:pm2:" + "b" * 64, "pm2"),
                    project("external:process:1234:999", "process"),
                    project("external:directory:" + "c" * 64, "directory", "detected")]
        self.add(*projects); app._render_overview_projects()
        self.assertEqual(set(app.service_tree.get_children()), set(SERVICES) | {p["id"] for p in projects})
        self.assertEqual(app.statistics["services"].cget("text"), "5")
        self.assertEqual(app.service_tree.item(projects[1]["id"], "values")[2], "已开启")
        self.assertEqual(app.service_tree.item(projects[2]["id"], "values")[2], "自动重启")
        self.assertIn("待确认", app.service_tree.item(projects[3]["id"], "values")[2])
        self.assertEqual(app.service_tree.item(projects[5]["id"], "values")[2], "—")

    def test_all_projects_refresh_updates_overview_and_uses_latest_builtin_state(self):
        app = self.app; row = project("external:systemd-user:1234:market-watch.service", "systemd-user")
        updated = {"data": {"installed": True, "units": [{"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}]}, "rows": []}
        app.controller.external_projects.return_value = {"projects": [row], "warnings": [], "builtin_information": {"xui": updated}}
        app._external_projects()
        self.assertTrue(app.service_tree.exists(row["id"]))
        self.assertEqual(app.service_tree.item("xui", "values")[1:3], ("已停止", "未开启"))
        self.assertEqual(app.statistics["services"].cget("text"), "1")
        app.controller.transport.assert_not_called()

    def test_saved_catalog_is_visible_offline_and_opens_matching_management_selection(self):
        app = self.app; app.report = None; app.report_server_key = None
        row = project("external:systemd-user:1234:market-watch.service", "systemd-user")
        app._restore_project_snapshots({"servers": {server_key(app.current): {"projects": [row], "saved_at": "2026-10-19T12:00:00+08:00"}}})
        app._project_changed()
        self.assertEqual(app.service_tree.get_children(), (row["id"],))
        self.assertIn("上次读取", app.service_tree.item(row["id"], "values")[1])
        app.service_tree.selection_set(row["id"]); app._open_selected_project()
        self.assertEqual(app._service_key(app.manage_choice.get()), row["id"])
        app.notebook.select.assert_called_once_with(app.pages["日常维护"])
        app.controller.external_project_information.assert_not_called(); app.controller.transport.assert_not_called()
        app._configure_project.assert_not_called(); app._ready.assert_not_called()

    def test_server_switch_never_displays_previous_report_or_discovered_rows(self):
        app = self.app; first = app.current
        one = project("external:systemd:one.service"); self.add(one)
        app._project_changed()
        app.current = first.changed(host="two.invalid"); app._project_changed()
        self.assertFalse(app.service_tree.get_children())
        self.assertEqual(app.statistics["services"].cget("text"), "—")
        two = project("external:systemd:two.service"); self.add(two); app._project_changed()
        self.assertEqual(app.service_tree.get_children(), (two["id"],))
        app.current = first; app._project_changed()
        self.assertTrue(app.service_tree.exists(one["id"])); self.assertFalse(app.service_tree.exists(two["id"]))

    def test_privacy_hides_external_name_and_description_and_preserves_selection(self):
        app = self.app
        row = project("external:systemd:sample.service", name="private-fixture", description="private-description")
        self.add(row); app._project_changed(); app.service_tree.selection_set(row["id"])
        self.assertIn("private-fixture", str(app.service_tree.item(row["id"], "values")))
        app.privacy.set(True); app._project_changed()
        text = str(app.service_tree.item(row["id"], "values"))
        self.assertNotIn("private-fixture", text); self.assertNotIn("private-description", text)
        self.assertEqual(app.service_tree.selection(), (row["id"],))

    def test_same_name_projects_open_by_stable_identity(self):
        app = self.app
        rows = [project("external:systemd:one.service", name="same"), project("external:systemd:two.service", name="same")]
        self.add(*rows); app._project_changed()
        for row in rows:
            app.service_tree.selection_set(row["id"]); app._open_selected_project()
            self.assertEqual(app._service_key(app.manage_choice.get()), row["id"])
        app.controller.execute.assert_not_called()

    def test_refresh_removes_disappeared_project_and_repeated_refresh_does_not_duplicate(self):
        app = self.app; one = project("external:systemd:one.service"); two = project("external:systemd:two.service")
        self.add(one, two); app._project_changed(); app.service_tree.selection_set(one["id"])
        app.controller.external_projects.return_value = {"projects": [one], "warnings": []}
        app._external_projects(); app._external_projects()
        self.assertTrue(app.service_tree.exists(one["id"])); self.assertFalse(app.service_tree.exists(two["id"]))
        self.assertEqual(len(app.service_tree.get_children()), len(SERVICES) + 1)
        self.assertEqual(app.service_tree.selection(), (one["id"],))

    def test_builtin_navigation_and_shared_nginx_uninstall_behavior_are_preserved(self):
        app = self.app; app._project_changed()
        app.service_tree.selection_set("xui"); app._open_selected_project()
        app.notebook.select.assert_called_once_with(app.pages["日常维护"])
        app.service_tree.selection_set("hysteria2"); app._open_selected_project()
        app._configure_project.assert_called_once()
        app.project_details[(server_key(app.current), "nginx")] = {"data": {"installed": False, "uninstalled": True}}
        app.report["services"]["nginx"] = [{"LoadState": "loaded", "ActiveState": "active"}]
        app._project_changed()
        self.assertEqual(app.service_tree.item("nginx", "values")[1], "独立站点已卸载")
        app.service_tree.selection_set("nginx"); app._open_selected_project()
        self.assertEqual(app._configure_project.call_count, 2)
        self.assertEqual(app.statistics["services"].cget("text"), "1")

    def test_saved_builtin_without_runtime_state_is_not_reported_as_stopped(self):
        app = self.app; app.report = None; app.report_server_key = None
        app.project_details[(server_key(app.current), "xui")] = {"data": {"installed": True}, "rows": [("保存时间", "fixture-time")]}
        app._project_changed()
        self.assertIn("运行状态未保存", app.service_tree.item("xui", "values")[1])
        self.assertEqual(app.statistics["services"].cget("text"), "至少 0")
        app.service_tree.selection_set("xui"); app._open_selected_project()
        app.notebook.select.assert_called_once_with(app.pages["日常维护"])


if __name__ == "__main__": unittest.main()
