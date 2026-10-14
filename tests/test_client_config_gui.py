from pathlib import Path
import gc
import plistlib
import tempfile
import tkinter as tk
from tkinter import ttk
import unittest
from unittest import mock

from linux_manager.client_config import CLIENTS, ClientConfigurator
from linux_manager.client_apps import ClientApplication
from linux_manager.gui import App
from linux_manager.models import Connection, SERVICES


class ClientConfigurationGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name).resolve()
        cls.patch_directory = mock.patch("linux_manager.gui.data_directory", return_value=cls.directory / "manager")
        cls.patch_directory.start()
        with mock.patch.object(App, "_load_saved_profiles"), mock.patch.object(App, "_record_window_state"):
            cls.app = App()
            cls.app.update()
        cls.app._record_window_state = lambda: None
        cls.app._load_saved_profiles = lambda: None
        cls.app._run = mock.Mock(side_effect=lambda worker, callback=None, message="", **kwargs: callback(worker()) if callback else worker())
        cls.app._ready = mock.Mock(return_value=True)

    @classmethod
    def tearDownClass(cls):
        for identifier in cls.app.tk.splitlist(cls.app.tk.call('after', 'info')):
            cls.app.after_cancel(identifier)
        cls.app.destroy()
        cls.app = None
        gc.collect()
        cls.patch_directory.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.app.current = Connection(host="fixture.invalid", label="测试服务器")
        self.app.busy = False
        self.app.manage_choice.set(SERVICES["cliproxyapi"][0])
        self.app._project_changed()
        self.app.notebook.select(self.app.pages["日常维护"])
        self.app.update()
        self.configurator = ClientConfigurator(self.directory / "backups", self.directory / "clients", {})
        self.patch_configurator = mock.patch.object(self.app, "_client_configurator", return_value=self.configurator)
        self.patch_configurator.start()

    def tearDown(self):
        for widget in self.app.winfo_children():
            if isinstance(widget, tk.Toplevel): widget.destroy()
        self.patch_configurator.stop()

    def children(self, parent):
        rows = []
        for child in parent.winfo_children():
            rows.append(child)
            rows.extend(self.children(child))
        return rows

    def button(self, title, parent=None):
        return next(w for w in self.children(parent or self.app) if isinstance(w, ttk.Button) and w.cget("text") == title)

    def dialog(self):
        return next(w for w in self.app.winfo_children() if isinstance(w, tk.Toplevel))

    def test_client_actions_only_appear_for_cliproxyapi(self):
        self.assertEqual(self.app.ai_clients.winfo_manager(), "pack")
        for title in ("一键配置 GPT", "一键配置 Claude Code", "一键配置 Pi", "一键配置 OpenCode", "恢复原客户端配置"):
            self.assertIsNotNone(self.button(title, self.app.ai_clients))
        self.app.manage_choice.set(SERVICES["exchange"][0])
        self.app._project_changed()
        self.assertFalse(self.app.ai_clients.winfo_manager())

    def test_buttons_fit_minimum_window_width(self):
        self.app.geometry("1080x760")
        self.app.update()
        frame = self.app.ai_clients
        for widget in self.children(frame):
            if isinstance(widget, ttk.Button):
                self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(), frame.winfo_rootx() + frame.winfo_width())

    def test_installed_app_selection_locates_configuration_without_asking_for_a_directory(self):
        self.app.current = None
        self.app.local_client_choice.set(CLIENTS['pi'])
        app = self.directory / "任意安装 空格'目录/Codex.app"
        (app / 'Contents').mkdir(parents=True, exist_ok=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.openai.codex'}))
        row = ClientApplication(app, 'Codex', 'codex')
        with mock.patch('linux_manager.gui.installed_applications', return_value=[row]), mock.patch('linux_manager.gui.filedialog.askdirectory') as picker:
            self.app._choose_local_client_application()
            self.button('◎\nCodex', self.dialog()).invoke()
        picker.assert_not_called()
        self.assertEqual(self.app.local_client_choice.get(), CLIENTS['codex'])
        self.assertIn(str(self.configurator.directories['codex']), self.app.status.cget('text'))
        self.assertFalse(self.configurator.paths('codex')[0].exists())
        self.assertFalse(self.configurator.directory_settings.exists())

    def test_app_inventory_empty_state_can_be_refreshed_without_selecting_paths(self):
        with mock.patch('linux_manager.gui.installed_applications', side_effect=[[], []]) as inventory:
            self.app._choose_local_client_application()
            self.button('刷新应用列表', self.dialog()).invoke()
        self.assertEqual(inventory.call_count, 2)
        self.assertIsNotNone(self.button('取消', self.dialog()))

    def test_configure_dialog_applies_selected_key_and_model_and_reports_backup(self):
        gateway = {"base_url": "https://fixture.invalid:9229/v1", "api_keys": ["key-one", "key-two"]}
        with mock.patch("linux_manager.gui.gateway_models", return_value=["gpt-fixture"]), mock.patch("linux_manager.gui.messagebox.showinfo") as message:
            self.app._local_client_dialog("pi", self.app.current, gateway)
            dialog = self.dialog()
            boxes = [w for w in self.children(dialog) if isinstance(w, ttk.Combobox)]
            boxes[0].set("客户端 Key 2")
            boxes[0].event_generate("<<ComboboxSelected>>")
            self.app.update()
            self.button("备份并应用配置", dialog).invoke()
        self.assertEqual(self.configurator.paths("pi")[2].read_text(), "key-two")
        self.assertEqual(len(self.configurator.backups_for("pi")), 1)
        self.assertIn("原配置备份", message.call_args.args[1])

    def test_no_claude_models_keeps_apply_disabled(self):
        gateway = {"base_url": "https://fixture.invalid:9229/v1", "api_keys": ["key"]}
        with mock.patch("linux_manager.gui.gateway_models", return_value=["gpt-fixture"]):
            self.app._local_client_dialog("claude", self.app.current, gateway)
        self.assertTrue(self.button("备份并应用配置", self.dialog()).instate(["disabled"]))

    def test_dialog_actions_fit_without_clipping(self):
        gateway = {"base_url": "https://fixture.invalid:9229/v1", "api_keys": ["key"]}
        with mock.patch("linux_manager.gui.gateway_models", return_value=["gpt-fixture"]):
            self.app._local_client_dialog("pi", self.app.current, gateway)
        dialog = self.dialog()
        self.app.update()
        for title in ("备份并应用配置", "取消", "重新读取模型"):
            button = self.button(title, dialog)
            self.assertTrue(button.winfo_ismapped())
            self.assertLessEqual(button.winfo_rooty() + button.winfo_height(), dialog.winfo_rooty() + dialog.winfo_height())

    def test_switching_server_prevents_apply(self):
        gateway = {"base_url": "https://fixture.invalid:9229/v1", "api_keys": ["key"]}
        with mock.patch("linux_manager.gui.gateway_models", return_value=["gpt-fixture"]), mock.patch("linux_manager.gui.messagebox.showerror") as message:
            self.app._local_client_dialog("codex", self.app.current, gateway)
            self.app.current = Connection(host="other.invalid")
            self.button("备份并应用配置", self.dialog()).invoke()
        message.assert_called_once()
        self.assertEqual(self.configurator.backups_for("codex"), [])

    def test_restore_works_without_server_and_defaults_to_first_original(self):
        first = self.configurator.configure("claude", "https://fixture.invalid:9229/v1", "key", "claude-first", ["claude-first"])
        self.configurator.configure("claude", "https://fixture.invalid:9229/v1", "key", "claude-second", ["claude-second"])
        self.app.current = None
        self.app.local_client_choice.set(CLIENTS["claude"])
        with mock.patch("linux_manager.gui.messagebox.showinfo"):
            self.app._restore_local_client()
            dialog = self.dialog()
            box = next(w for w in self.children(dialog) if isinstance(w, ttk.Combobox))
            self.assertIn("首次配置前", box.get())
            self.assertTrue(box.get().endswith(first["backup_id"][-8:]))
            self.button("备份当前配置并恢复", dialog).invoke()
        self.assertFalse(self.configurator.paths("claude")[0].exists())


if __name__ == "__main__":
    unittest.main()
