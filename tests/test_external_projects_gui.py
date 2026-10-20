import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.models import Connection, SERVICES
from linux_manager.project_info import server_key


def project(identifier="external:systemd:sample.service", **values):
    return dict({"id": identifier, "kind": "systemd", "name": "sample", "product": "", "state": "active",
                 "ports": [], "capabilities": ["start", "stop", "restart"]}, **values)


class ExternalProjectsGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk(); cls.root.withdraw()

    @classmethod
    def tearDownClass(cls): cls.root.destroy()

    def setUp(self):
        self.page = ttk.Frame(self.root)
        self.app = object.__new__(App)
        app = self.app
        app.pages = {"日常维护": SimpleNamespace(content=self.page)}
        app.privacy = tk.BooleanVar(self.root, value=True); app.buttons = []; app.private_entries = []
        app.current = Connection(label="fixture", host="fixture.invalid")
        app.busy = False; app.project_details = {}; app.project_logs = {}
        app._maintenance_page(); app._copy = mock.Mock(); app._ready = mock.Mock(return_value=True)
        app.status = mock.Mock(); app.controller = mock.Mock(); app._execute = mock.Mock()
        app._redactor = lambda: SimpleNamespace(add=lambda *args: None, text=lambda value: value)
        app.controller.external_projects.return_value = {"projects": [project()], "warnings": []}
        app.controller.external_project_information.side_effect = lambda connection, identifier: {
            "project": project(identifier), "fingerprint": "fixture-fingerprint",
            "credentials": {"password": "fictional-password", "url": "https://fixture.invalid/admin"}}
        def run(worker, callback=None, message=""):
            result = worker()
            if callback: callback(result)
        app._run = run
        app._external_projects()

    def tearDown(self): self.page.destroy()

    def select(self, identifier=None, read=False):
        identifier = identifier or project()["id"]
        self.app.manage_choice.set(next(label for label, key in self.app.manage_project_labels.items() if key == identifier))
        self.app._project_changed()
        if read: self.app._refresh_project_info()

    def test_refresh_merges_into_existing_dropdown_without_opening_window(self):
        app = self.app
        self.assertEqual(len(app.manage_project_box["values"]), len(SERVICES) + 1)
        self.assertEqual(set(SERVICES), set(app.manage_project_labels.values()) & set(SERVICES))
        self.assertTrue(app.controller.external_projects.call_args.kwargs["include_builtin"])
        self.assertFalse(any(isinstance(widget, tk.Toplevel) for widget in self.root.winfo_children()))
        self.select()
        self.assertEqual(dict(app.project_rows)["项目状态"], "运行中")

    def test_selection_reads_external_details_and_respects_privacy(self):
        app = self.app; self.select(read=True)
        app.controller.external_project_information.assert_called_once_with(app.current, project()["id"])
        rendered = " ".join(str(app.project_info_tree.item(i, "values")) for i in app.project_info_tree.get_children())
        self.assertNotIn("fictional-password", rendered)
        index = next(i for i, row in enumerate(app.project_rows) if row[0] == "登录密码（本机记录）")
        app.project_info_tree.selection_set(str(index)); app._copy_project_item()
        app._copy.assert_called_once_with("fictional-password")
        app.privacy.set(False); app._project_changed()
        rendered = " ".join(str(app.project_info_tree.item(i, "values")) for i in app.project_info_tree.get_children())
        self.assertIn("fictional-password", rendered)

    def test_refresh_preserves_selection_and_removes_disappeared_projects(self):
        app = self.app; self.select()
        app.controller.external_projects.return_value = {"projects": [project(state="inactive")], "warnings": []}
        app._external_projects()
        self.assertEqual(app._service_key(app.manage_choice.get()), project()["id"])
        self.assertEqual(dict(app.project_rows)["项目状态"], "已停止")
        app.controller.external_projects.return_value = {"projects": [], "warnings": []}
        app._external_projects()
        self.assertIn(app._service_key(app.manage_choice.get()), SERVICES)
        self.assertNotIn((server_key(app.current), project()["id"]), app.project_details)

    def test_server_switch_removes_other_servers_dropdown_and_sensitive_rows(self):
        app = self.app; self.select(read=True)
        app.current = app.current.changed(host="other.invalid"); app._project_changed()
        self.assertEqual(len(app.manage_project_box["values"]), len(SERVICES))
        self.assertFalse(app.project_rows)
        self.assertIn(app._service_key(app.manage_choice.get()), SERVICES)

    def test_late_scan_and_detail_responses_from_previous_server_are_ignored(self):
        app = self.app; queued = []
        app._run = lambda worker, callback, message: queued.append((worker, callback))
        app._external_projects(); self.select(); app._refresh_project_info()
        app.current = app.current.changed(host="other.invalid"); app._project_changed()
        for worker, callback in queued: callback(worker())
        self.assertFalse(app.project_rows)
        self.assertEqual(len(app.manage_project_box["values"]), len(SERVICES))

    def test_external_actions_use_selected_identity_and_fingerprint(self):
        app = self.app; self.select(read=True)
        app.controller.execute.return_value = ({"result": {"external_project": project(state="inactive")}}, app.current)
        with mock.patch("linux_manager.gui.messagebox.askyesno", return_value=True): app._service("stop")
        params = app.controller.execute.call_args.args[1]
        self.assertEqual(params, {"operation": "service", "service": project()["id"], "action": "stop", "external_fingerprint": "fixture-fingerprint"})
        self.assertEqual(dict(app.project_rows)["项目状态"], "已停止")
        app._execute.assert_not_called()

    def test_unsupported_external_actions_never_reach_server(self):
        app = self.app; self.select()
        app._service("enable"); app._uninstall(); app._backup(); app._configure_project()
        app.controller.execute.assert_not_called(); app.controller.uninstall_preview.assert_not_called()
        app._execute.assert_not_called()
        self.assertEqual(str(app.manage_service_buttons["enable"].button.cget("state")), "disabled")
        self.assertEqual(str(app.manage_uninstall_button.button.cget("state")), "disabled")

    def test_duplicate_project_names_map_to_distinct_identities(self):
        app = self.app
        other = project("external:systemd:other.service")
        app.controller.external_projects.return_value = {"projects": [project(), other], "warnings": []}
        app._external_projects()
        labels = [label for label, key in app.manage_project_labels.items() if key.startswith("external:")]
        self.assertEqual(len(set(labels)), 2)
        self.assertEqual({app._service_key(label) for label in labels}, {project()["id"], other["id"]})

    def test_refresh_replaces_absent_builtin_cache_and_preserves_builtin_controls(self):
        app = self.app; identity = server_key(app.current)
        app.project_details[(identity, "xui")] = {"rows": [("项目状态", "旧状态")]}
        information = {"rows": [("项目状态", "未安装")]}
        app.controller.external_projects.return_value = {"projects": [], "warnings": [], "builtin_information": {"xui": information}}
        app._external_projects(); app.manage_choice.set(SERVICES["xui"][0]); app._project_changed()
        self.assertEqual(dict(app.project_rows)["项目状态"], "未安装")
        self.assertEqual(str(app.manage_config_button.button.cget("state")), "normal")
        self.assertEqual(str(app.manage_service_buttons["enable"].button.cget("state")), "normal")

    def test_external_logs_and_url_use_existing_management_controls(self):
        app = self.app; self.select(read=True)
        app.controller.transport.return_value.call.return_value = {"logs": "服务生命周期记录"}
        app._logs()
        app.controller.transport.return_value.call.assert_called_once_with({"action": "external_logs", "identifier": project()["id"]})
        self.assertIn("服务生命周期记录", app.maintenance_text.get("1.0", "end"))
        with mock.patch("linux_manager.gui.webbrowser.open") as opened: app._open_project_url()
        opened.assert_called_once_with("https://fixture.invalid/admin")

    def test_private_paths_and_ports_are_hidden(self):
        app = self.app
        app.controller.external_projects.return_value = {"projects": [project(working_directory="/opt/private-fixture", ports=[{"port": 12345, "protocol": "tcp", "local_only": True}])], "warnings": []}
        app._external_projects(); self.select()
        rendered = " ".join(str(app.project_info_tree.item(i, "values")) for i in app.project_info_tree.get_children())
        self.assertNotIn("12345", rendered); self.assertNotIn("/opt/private-fixture", rendered)

    def test_reopened_app_restores_projects_and_selects_without_server_request(self):
        app = self.app; c = app.current; identity = server_key(c)
        app.profiles = [c]; app.external_catalogs = {}; app.project_details = {}
        app._restore_project_snapshots({"servers": {identity: {"projects": [project(web_endpoints=[{
            "url": "https://fixture.invalid/app/", "source": "Nginx", "local_only": False}])], "saved_at": "2026-10-19T12:00:00+08:00"}}, "warnings": []})
        app._project_changed(); self.select()
        app.controller.external_project_information.reset_mock()
        app._project_changed(object())
        app.controller.external_project_information.assert_not_called()
        self.assertEqual(dict(app.project_rows)["项目管理网址"], "https://fixture.invalid/app/")
        self.assertIn("本机保存", dict(app.project_rows)["信息来源"])
        self.assertEqual(len(app.manage_project_box["values"]), len(SERVICES) + 1)

    def test_switching_saved_servers_shows_each_own_catalog_without_network(self):
        app = self.app; first = app.current; second = first.changed(host="second.invalid")
        app.profiles = [first, second]
        one, two = project(), project(id="external:systemd:second.service", name="second")
        app.external_catalogs = {}; app.project_details = {}
        app._restore_project_snapshots({"servers": {server_key(first): {"projects": [one]}, server_key(second): {"projects": [two]}}})
        for c, expected in ((first, one["id"]), (second, two["id"]), (first, one["id"])):
            app.current = c; app._project_changed()
            external = [key for key in app.manage_project_labels.values() if key.startswith("external:")]
            self.assertEqual(external, [expected])
        app.controller.external_project_information.assert_not_called()


if __name__ == "__main__": unittest.main()
