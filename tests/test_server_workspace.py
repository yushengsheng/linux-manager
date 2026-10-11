import json
import secrets
import sys
from pathlib import Path
import tempfile
import tkinter as tk
from tkinter import font, ttk
import unittest
from unittest import mock

from test_linux_manager import MemoryVault
from linux_manager.gui import App, NAVIGATION
from linux_manager.models import Connection, SERVICES, Store
from linux_manager.project_info import server_key
from linux_manager.releases import KEEP_CURRENT


class ServerWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.callback_errors = []
        self.callback_handler = App.report_callback_exception
        def record_error(app, exception, value, traceback):
            self.callback_errors.append(f"{exception.__name__}: {value}")
        patch = mock.patch.object(App, "report_callback_exception", record_error)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(lambda: self.assertEqual(self.callback_errors, [], "界面回调不能出现未处理异常"))
        vault = MemoryVault()
        vault.cache = vault.items
        self.store = Store(Path(self.directory.name), vault)
        with mock.patch("linux_manager.gui.Store", return_value=self.store), mock.patch("linux_manager.gui.Controller") as controller, mock.patch.object(App, "_load_saved_profiles"):
            self.app = App()
        self.addCleanup(self.close_app)
        self.app.withdraw()
        self.controller = controller.return_value
        self.controller.connection_status.return_value = {"state": "disconnected", "token": ""}
        self.app._connect = mock.Mock()
        self.one = Connection(label="测试机器一", host="one.invalid", username="owner", password=secrets.token_urlsafe(24))
        self.two = Connection(label="测试机器二", host="two.invalid", username="owner", password=secrets.token_urlsafe(24))
        self.app.profiles = [self.one, self.two]
        self.app.profiles_loaded = True
        self.app._profile_options()
        self.app.update()

    def close_app(self):
        for identifier in self.app.tk.call("after", "info"):
            self.app.after_cancel(identifier)
        self.app.destroy()

    def report(self, installed="xui"):
        return {
            "os": "测试系统", "architecture": "x86_64", "supported": True,
            "disk_free": 10 * 1024 ** 3, "memory": {"MemAvailable": 1024 ** 3},
            "services": {kind: [{"unit": units[0], "LoadState": "loaded" if kind == installed else "not-found", "ActiveState": "active" if kind == installed else "inactive", "UnitFileState": "enabled"}] for kind, (_, units) in SERVICES.items()},
            "accounts": [], "ssh": {}, "firewall": {"active": False},
            "automatic_updates": False, "tasks": [],
            "project_information": {installed: {"data": {"installed": True, "version": "v3.9.0", "port": 2053}, "rows": [("项目状态", "已安装")]}},
        }

    def test_all_existing_pages_remain_accessible_through_navigation(self):
        app = self.app
        self.assertEqual(len(app.pages), 8)
        self.assertEqual(set(app.navigation_tree.get_children()), set(NAVIGATION))
        for name in NAVIGATION:
            if name == "命令行":
                continue
            app.navigation_tree.selection_set(name)
            app._navigate()
            app.update()
            self.assertEqual(app.notebook.select(), str(app.pages[name]))
        app.notebook.select(app.pages["一键部署"])
        app.update()
        self.assertEqual(app.navigation_tree.selection(), ("日常维护",))
        self.assertEqual(app.workspace_title.cget("text"), "应用管理")
        self.assertTrue(app.application_tabs.winfo_manager())
        app.navigation_tree.selection_set("日常维护")
        app._navigate()
        self.assertEqual(app.notebook.select(), str(app.pages["一键部署"]))
        self.controller.transport.assert_not_called()
        self.controller.execute.assert_not_called()
        self.store.vault.put = mock.Mock()
        app.application_manage.button.invoke()
        app.update()
        self.assertEqual(app.notebook.select(), str(app.pages["日常维护"]))
        self.store.vault.put.assert_not_called()

    def test_sidebar_uses_saved_session_credentials_and_connects_only_selected_host(self):
        app = self.app
        session = self.two.changed(password=secrets.token_urlsafe(24))
        app.sessions[self.two.identifier] = session
        app.server_tree.selection_set(self.two.identifier)
        app._choose_sidebar_server()
        self.assertIs(app.current, session)
        self.assertEqual(app.password_var.get(), session.password)
        app._connect.assert_called_once_with()
        self.assertEqual(app.notebook.select(), str(app.pages["连接服务器"]))
        self.controller.execute.assert_not_called()

    def test_terminal_menu_preserves_the_active_management_page_and_inputs(self):
        app = self.app
        app.notebook.select(app.pages["安全防护"]); app.update()
        app._open_terminal = mock.Mock()
        app.navigation_tree.selection_set("命令行")
        app._navigate(); app.update()
        app._open_terminal.assert_called_once_with()
        self.assertEqual(app.notebook.select(), str(app.pages["安全防护"]))
        self.assertEqual(app.navigation_tree.selection(), ("安全防护",))
        self.controller.execute.assert_not_called()

    def test_mouse_click_connects_saved_server_but_loading_a_profile_does_not(self):
        app = self.app
        app._load_profile(self.one)
        app.update()
        app._connect.assert_not_called()
        app.deiconify()
        app.update()
        x, y, width, height = app.server_tree.bbox(self.two.identifier, "name")
        app.server_tree.event_generate("<Button-1>", x=x + 10, y=y + height // 2)
        app.server_tree.event_generate("<ButtonRelease-1>", x=x + 10, y=y + height // 2)
        app.update()
        self.assertIs(app.current, self.two)
        app._connect.assert_called_once_with()

    def test_existing_connection_and_snapshot_are_reused_without_new_login(self):
        app = self.app
        self.controller.connection_status.return_value = {"state": "connected", "token": "test-session", "message": "连接保持中。"}
        app.fleet_reports[self.one.identifier] = self.report()
        app._activate_profile(self.one.identifier)
        app._connect.assert_not_called()
        self.assertIs(app.report, app.fleet_reports[self.one.identifier])
        self.assertEqual(app.notebook.select(), str(app.pages["服务器总览"]))

    def test_security_summary_describes_scheduler_not_continuous_update_process(self):
        for active, text in [(False, "安全更新：未就绪"), (True, "安全更新：已启用")]:
            report = self.report() | {"automatic_updates": active}
            self.app._connected(self.one, report)
            self.assertIn(text, self.app.security_summary.cget("text"))
            self.assertIn(text, self.app.protection_status.cget("text"))

    def test_existing_connection_without_snapshot_still_reads_state(self):
        self.controller.connection_status.return_value = {"state": "connected", "token": "test-session", "message": "连接保持中。"}
        self.app._activate_profile(self.one.identifier)
        self.app._connect.assert_called_once_with()
        self.assertIsNone(self.app.report)

    def test_busy_operation_blocks_server_switch_and_restores_selection(self):
        app = self.app
        app._load_profile(self.one)
        app.busy = True
        app.server_tree.selection_set(self.two.identifier)
        app._choose_sidebar_server()
        self.assertIs(app.current, self.one)
        self.assertEqual(app.server_tree.selection(), (self.one.identifier,))
        app._connect.assert_not_called()
        app._new_profile()
        self.assertIs(app.current, self.one)

    def test_switch_clears_previous_server_accounts_tasks_backup_and_project_inputs(self):
        app = self.app
        app._connected(self.one, self.report())
        app.restore_id.set("a" * 24)
        app.account_password.set(secrets.token_urlsafe(24))
        app.deploy_password.set(secrets.token_urlsafe(24))
        app._show_tasks([{"id": "b" * 24, "operation": "backup", "state": "succeeded", "message": "测试备份"}])
        app._load_profile(self.two)
        self.assertIsNone(app.report)
        self.assertIsNone(app.report_server_key)
        self.assertFalse(app.service_tree.get_children())
        self.assertFalse(app.account_tree.get_children())
        self.assertFalse(app.task_tree.get_children())
        self.assertFalse(app.project_rows)
        self.assertEqual(app.restore_id.get(), "")
        self.assertEqual(app.account_password.get(), "")
        self.assertEqual(app.deploy_password.get(), "")
        self.assertEqual(app.statistics["disk"].cget("text"), "—")

    def test_new_account_on_same_server_requires_its_own_verified_snapshot(self):
        app = self.app
        app._connected(self.one, self.report())
        other_account = self.one.changed(identifier=Connection().identifier, username="alternate")
        app.profiles.append(other_account)
        app._profile_options()
        app._load_profile(other_account)
        self.assertIsNone(app.report)
        self.assertFalse(app.account_tree.get_children())
        app._render_sidebar()
        self.assertEqual(app.server_count.cget("text"), "2 台服务器 · 3 个登录档案")

    def test_new_server_keeps_saved_profiles_and_opens_connection_settings(self):
        app = self.app
        app._load_profile(self.one)
        app.notebook.select(app.pages["日常维护"])
        app._new_profile()
        self.assertEqual(app.profiles, [self.one, self.two])
        self.assertEqual(app.current.host, "")
        self.assertFalse(app.server_tree.selection())
        self.assertEqual(app.notebook.select(), str(app.pages["连接服务器"]))
        self.controller.disconnect_connection.assert_not_called()

    def test_current_target_respects_privacy_without_hiding_server_remark(self):
        app = self.app
        app._load_profile(self.one)
        self.assertEqual(app.current_server_label.cget("text"), self.one.label)
        app.privacy.set(False)
        app._privacy_changed()
        text = app.current_server_label.cget("text")
        self.assertIn(self.one.host, text)
        self.assertIn(self.one.username, text)
        app.privacy.set(True)
        app._privacy_changed()
        self.assertEqual(app.current_server_label.cget("text"), self.one.label)

    def test_installed_project_configuration_is_loaded_after_auto_connection(self):
        app = self.app
        app._load_profile(self.one)
        app.deploy_choice.set(SERVICES["xui"][0])
        app._connected(self.one, self.report())
        self.assertEqual(app.version_mode.get(), KEEP_CURRENT)
        self.assertEqual(app.deploy_port.get(), "2053")
        self.assertEqual(app.deploy_version.get(), "v3.9.0")

    def test_overview_opens_installed_project_or_install_form_without_mutation(self):
        app = self.app
        app._connected(self.one, self.report())
        app.service_tree.selection_set("xui")
        app._open_selected_project()
        self.assertEqual(app.manage_choice.get(), SERVICES["xui"][0])
        self.assertEqual(app.notebook.select(), str(app.pages["日常维护"]))
        app.service_tree.selection_set("hysteria2")
        app._open_selected_project()
        self.assertEqual(app.deploy_choice.get(), SERVICES["hysteria2"][0])
        self.assertEqual(app.notebook.select(), str(app.pages["一键部署"]))
        self.controller.execute.assert_not_called()
        self.controller.transport.assert_not_called()

    def test_application_configuration_and_navigation_preserve_existing_options(self):
        app = self.app
        app._connected(self.one, self.report())
        app.manage_choice.set(SERVICES["xui"][0])
        app._configure_project()
        app.deploy_port.set("2054")
        app.deploy_optional_open = True
        app.navigation_tree.selection_set("安全防护")
        app._navigate()
        app.application_install.button.invoke()
        self.assertEqual(app.deploy_port.get(), "2054")
        self.assertTrue(app.deploy_optional_open)
        app.busy = True
        app.manage_choice.set(SERVICES["nginx"][0])
        app._configure_project()
        self.assertEqual(app.deploy_choice.get(), SERVICES["xui"][0])
        self.controller.execute.assert_not_called()

    def test_function_titles_use_application_title_size_and_compact_rows(self):
        app = self.app
        style = ttk.Style(app)
        caption = font.nametofont("TkCaptionFont", root=app)
        self.assertEqual(style.lookup("Title.TLabel", "font"), "TkCaptionFont")
        for name in ["Heading.TLabel", "Stat.TLabel", "TLabelframe.Label", "Sidebar.Treeview", "Navigation.Treeview", "TLabel", "TButton", "TEntry", "TCombobox", "Chrome.TLabel", "Muted.TLabel"]:
            current = font.Font(root=app, font=style.lookup(name, "font"))
            self.assertLessEqual(current.metrics("linespace"), caption.metrics("linespace"), name)
        for name in ["Treeview", "Sidebar.Treeview", "Navigation.Treeview"]:
            current = font.Font(root=app, font=style.lookup(name, "font"))
            height = int(style.lookup(name, "rowheight"))
            self.assertLessEqual(height, 26, name)
            self.assertGreaterEqual(height, current.metrics("linespace") + 4, name)
        app.deiconify()
        app.update()
        self.assertEqual(app.wm_geometry().split("+")[0], "1180x820")

    def test_every_widget_font_matches_native_caption_rendering(self):
        app = self.app
        style = ttk.Style(app)
        caption = font.nametofont("TkCaptionFont", root=app)
        count = 0
        def inspect(parent):
            nonlocal count
            for child in parent.winfo_children():
                if isinstance(child, (ttk.Label, ttk.Button, ttk.Entry, ttk.Combobox, ttk.Checkbutton, ttk.Treeview, tk.Text)):
                    value = child.cget("font") if "font" in child.keys() else ""
                    if not value:
                        value = style.lookup(child.cget("style") or child.winfo_class(), "font")
                    self.assertTrue(value, str(child))
                    current = font.Font(root=app, font=value)
                    self.assertLessEqual(current.metrics("linespace"), caption.metrics("linespace"), str(child))
                    count += 1
                inspect(child)
        inspect(app)
        self.assertGreater(count, 100)
        self.assertLessEqual(caption.measure("linux服务器管理"), font.Font(root=app, font=("PingFang SC", 12)).measure("linux服务器管理"))

    def test_all_pages_fit_default_and_existing_minimum_window_width(self):
        app = self.app
        app.deiconify()
        app._toggle_custom_security()
        app._toggle_deploy_optional()
        for geometry in ["1180x820", "1320x860", "1080x760"]:
            app.geometry(geometry)
            app.update()
            for name, page in app.pages.items():
                app.notebook.select(page)
                app.update()
                content = page.content
                overflow = []
                def inspect(widget):
                    for child in widget.winfo_children():
                        if child.winfo_ismapped():
                            offset = child.winfo_rootx() - content.winfo_rootx()
                            if offset < 0 or offset + child.winfo_width() > content.winfo_width() + 1:
                                overflow.append((child.winfo_class(), round(offset), child.winfo_width()))
                            inspect(child)
                inspect(content)
                self.assertEqual(overflow, [], (geometry, name, overflow))

    def test_ui_diagnostic_records_locations_without_exception_secrets(self):
        secret = secrets.token_urlsafe(24)
        try:
            raise ValueError(secret)
        except ValueError:
            exception, value, traceback = sys.exc_info()
        with mock.patch("linux_manager.gui.messagebox.showerror") as showerror:
            self.callback_handler(self.app, exception, value, traceback)
        path = self.store.directory / "ui-error.json"
        raw = path.read_text()
        diagnostic = json.loads(raw)
        self.assertNotIn(secret, raw)
        self.assertEqual(diagnostic["type"], "ValueError")
        self.assertEqual(diagnostic["frames"][-1]["file"], "test_server_workspace.py")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn("诊断已保存", showerror.call_args.args[1])

    def test_ui_diagnostic_write_failure_is_reported(self):
        with mock.patch("linux_manager.models.atomic_private", side_effect=PermissionError), mock.patch("linux_manager.gui.messagebox.showerror") as showerror:
            self.callback_handler(self.app, ValueError, ValueError(), None)
        self.assertIn("诊断未能保存", showerror.call_args.args[1])

    def test_default_security_page_keeps_recommended_and_custom_actions_visible(self):
        app = self.app
        app.geometry("1180x820")
        app.deiconify()
        app._connected(self.one, self.report())
        app.notebook.select(app.pages["安全防护"])
        app.update()
        canvas = app.pages["安全防护"].canvas
        bottom = canvas.winfo_rooty() + canvas.winfo_height()
        for widget in [app.plan_apply.button, app.custom_security_toggle.button]:
            self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(), bottom)


if __name__ == "__main__":
    unittest.main()
