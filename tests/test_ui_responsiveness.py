import queue
import threading
import tkinter as tk
from tkinter import ttk
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.models import Connection
from linux_manager.widgets import install_check_style, sync_tree, ScrollPage


class ResponsiveCallbacksTests(unittest.TestCase):
    def test_explicit_save_runs_keychain_io_on_existing_background_worker(self):
        app = object.__new__(App)
        conn = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        app.current = conn; app.profiles = [conn]
        app.store = mock.Mock(); app.store.last_warning = ""
        threads = []
        app.store.save.side_effect = lambda *args, **kwargs: threads.append(threading.get_ident())
        app._connection = mock.Mock(return_value=conn)
        app._persist_profile = mock.Mock()
        app.status = mock.Mock(); app.progress = mock.Mock()
        app.busy = False; app.buttons = []; app.inputs = []; app.events = queue.Queue()
        app._save_profile()
        kind, result, callback = app.events.get(timeout=3)
        self.assertEqual(kind, "done")
        self.assertNotEqual(threads, [threading.get_ident()])
        self.assertEqual(len(threads), 1)
        callback(result)
        app._persist_profile.assert_called_once_with(conn)

    def test_connected_callback_updates_memory_without_keychain_reads_or_writes(self):
        app = object.__new__(App)
        conn = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        app.profiles = [conn]; app.sessions = {}; app.current = conn
        app.store = mock.Mock(); app.store.last_warning = ""
        for name in ["_profile_options", "profile_box", "_load_profile", "_render_fleet", "connection_badge", "status", "_render_report", "notebook", "_project_changed"]:
            setattr(app, name, mock.Mock())
        app.pages = {"服务器总览": mock.Mock()}
        app.fleet_reports = {}; app.fleet_states = {}
        app._connected(conn, {"fixture": True})
        app.store.save.assert_not_called(); app.store.profiles.assert_not_called()
        self.assertEqual(app.sessions[conn.identifier], conn)

    def test_refresh_of_unchanged_connection_does_not_write_keychain_again(self):
        app = object.__new__(App); app.store = mock.Mock()
        conn = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        app._save_connection(conn, [conn])
        app.store.save.assert_not_called()

    def test_progress_burst_is_coalesced_and_final_callback_runs_once(self):
        app = object.__new__(App)
        app.events = queue.Queue(); app.busy = True; app.buttons = []; app.input_states = []
        app.status = mock.Mock(); app.progress = mock.Mock(); app.after = mock.Mock()
        app._auth_fields = mock.Mock(); app._redactor = mock.Mock(return_value=mock.Mock(text=lambda value: value))
        callback = mock.Mock()
        for i in range(200): app.events.put(("progress", {"message": "本机演示", "progress": i}, None))
        app.events.put(("done", "finished", callback))
        for _ in range(10):
            app._drain()
            if app.events.empty(): break
        callback.assert_called_once_with("finished")
        self.assertLess(app.progress.configure.call_count, 10)
        self.assertFalse(app.busy)

    def test_hiding_information_does_not_reset_custom_security_settings(self):
        app = object.__new__(App); app.private_entries = []
        app._render_accounts = mock.Mock(); app._render_fleet = mock.Mock(); app._render_report = mock.Mock()
        app._privacy_changed()
        app._render_report.assert_not_called()
        app._render_accounts.assert_called_once(); app._render_fleet.assert_called_once()

    def test_custom_settings_fold_is_display_only_and_preserves_options(self):
        app = object.__new__(App); app.custom_security_open = False
        app.custom_security_frame = mock.Mock(); app.custom_security_toggle = mock.Mock()
        app.controller = mock.Mock(); app._run = mock.Mock()
        app._toggle_custom_security(); app._toggle_custom_security()
        self.assertFalse(app.custom_security_open)
        app.custom_security_frame.pack.assert_called_once()
        app.custom_security_frame.pack_forget.assert_called_once()
        app.controller.execute.assert_not_called(); app._run.assert_not_called()


class NativeWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A hidden Tk interpreter for widget checks, not another management window.
        cls.root = tk.Tk(); cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def test_green_tick_replaces_x_without_changing_checkbox_behavior(self):
        style = ttk.Style(self.root); style.theme_use("clam")
        install_check_style(style, self.root)
        value = tk.BooleanVar(self.root, value=False)
        check = ttk.Checkbutton(self.root, variable=value)
        check.invoke(); self.assertTrue(value.get())
        check.invoke(); self.assertFalse(value.get())
        self.assertIn("GreenCheck.indicator", str(style.layout("TCheckbutton")))
        self.assertEqual(self.root._check_images[1].get(8, 13), (22, 163, 74))
        check.destroy()

    def test_incremental_table_updates_keep_selection_and_scroll(self):
        tree = ttk.Treeview(self.root)
        rows = [(str(i), ("fixture " + str(i),)) for i in range(100)]
        sync_tree(tree, rows); tree.selection_set("50"); tree.yview_moveto(0.5)
        selected, position = tree.selection(), tree.yview()
        rows[49] = ("49", ("updated fixture",))
        sync_tree(tree, rows)
        self.assertEqual(tree.selection(), selected)
        self.assertEqual(tree.yview(), position)
        self.assertEqual(tree.item("49", "values"), ("updated fixture",))
        tree.destroy()

    def test_multiple_pages_share_one_wheel_handler(self):
        before = self.root.bind_all("<MouseWheel>")
        first = ScrollPage(self.root, "white")
        once = self.root.bind_all("<MouseWheel>")
        second = ScrollPage(self.root, "white")
        self.assertNotEqual(before, once)
        self.assertEqual(self.root.bind_all("<MouseWheel>"), once)
        first.destroy(); second.destroy()


if __name__ == "__main__":
    unittest.main()
