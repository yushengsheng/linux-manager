import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.models import Connection, SERVICES
from linux_manager.releases import LATEST_STABLE, SPECIFIC_VERSION


class DeploymentFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.page = ttk.Frame(self.root)
        self.app = object.__new__(App)
        self.app.pages = {"一键部署": SimpleNamespace(content=self.page)}
        self.app.privacy = tk.BooleanVar(self.root, value=True)
        self.app.buttons = []
        self.app.private_entries = []
        self.app._deployment_page()

    def tearDown(self):
        self.page.destroy()

    def choose(self, service):
        self.app.deploy_choice.set(SERVICES[service][0])
        self.app._deploy_defaults()

    def visible(self):
        return {name for name, row in self.app.deploy_rows.items() if row.winfo_manager()}

    def test_project_switches_show_only_matching_required_fields(self):
        for service, expected in [
            ("exchange", {"port"}),
            ("hysteria2", {"port", "proxy_password"}),
            ("reality", {"port"}),
            ("xui", {"port", "username", "panel_password"}),
            ("nginx", {"port"}),
            ("exchange", {"port"}),
        ]:
            with self.subTest(service=service):
                self.choose(service)
                self.assertEqual(self.visible(), expected)

    def test_optional_settings_start_collapsed_and_keep_values_when_folded(self):
        app = self.app
        self.assertFalse(app.deploy_optional_frame.winfo_manager())
        app.deploy_host.set("fixture.invalid")
        app.deploy_backend.set("18881")
        app.deploy_password.set("fictional-panel-password")
        app._toggle_deploy_optional()
        self.assertEqual(app.deploy_optional_frame.winfo_manager(), "pack")
        app._toggle_deploy_optional()
        self.assertFalse(app.deploy_optional_frame.winfo_manager())
        self.assertEqual(app.deploy_host.get(), "fixture.invalid")
        self.assertEqual(app.deploy_backend.get(), "18881")
        self.assertEqual(app.deploy_password.get(), "fictional-panel-password")

    def test_advanced_fields_and_version_input_follow_selected_project(self):
        app = self.app
        self.choose("exchange")
        self.assertFalse(app.deploy_optional_rows["version"].winfo_manager())
        app.version_mode.set(SPECIFIC_VERSION); app._version_fields()
        self.assertEqual(app.deploy_optional_rows["version"].winfo_manager(), "grid")
        app.version_mode.set(LATEST_STABLE); app._version_fields()
        self.assertFalse(app.deploy_optional_rows["version"].winfo_manager())
        self.choose("hysteria2")
        self.assertFalse(app.deploy_optional_rows["backend"].winfo_manager())
        self.assertEqual(app.deploy_optional_rows["version_mode"].winfo_manager(), "grid")
        self.assertFalse(app.deploy_optional_rows["version"].winfo_manager())
        self.choose("nginx")
        self.assertTrue(app.deploy_optional_header.winfo_manager())
        self.assertFalse(app.deploy_optional_frame.winfo_manager())
        self.assertTrue(app.deploy_network_hint.winfo_manager())

    def prepare_deployment(self):
        app = self.app
        app.current = Connection(host="fixture.invalid", username="fixture")
        app._ready = mock.Mock(return_value=True)
        app._execute = mock.Mock()
        app.controller = mock.Mock()
        app.controller.deployment_preview.side_effect = lambda c, params, **kwargs: {"version":params.get("version", "v1.1.85"),"fingerprint":"fictional-preview","changes":[],"installed":False,"action":"install"}
        app._run = mock.Mock(side_effect=lambda worker, callback, message, **kwargs: callback(worker()))
        return app

    def test_exchange_uses_existing_defaults_without_proxy_credentials(self):
        app = self.prepare_deployment()
        app.deploy_password.set("unused-proxy-password")
        app.deploy_username.set("unused-panel-user")
        with mock.patch("linux_manager.gui.exchange_version", return_value="v1.1.85"):
            app._deploy()
        params = app._execute.call_args.args[0]
        self.assertEqual(params, {"operation": "deploy", "service": "exchange", "host": "fixture.invalid", "port": 26483, "backend_port": 18880, "version": "v1.1.85", "deployment_fingerprint":"fictional-preview"})

    def test_proxy_panel_submits_its_password_and_ignores_hidden_exchange_fields(self):
        app = self.prepare_deployment()
        self.choose("xui")
        app.deploy_username.set("fixture")
        app.deploy_password.set("fictional-panel-password")
        app.deploy_backend.set("unused")
        app._deploy()
        params = app._execute.call_args.args[0]
        self.assertEqual(params["panel_password"], "fictional-panel-password")
        self.assertEqual(params["panel_username"], "fixture")
        self.assertNotIn("backend_port", params)
        self.assertNotIn("proxy_password", params)

    def test_reality_only_submits_port_and_optional_target_without_password(self):
        app = self.prepare_deployment(); self.choose("reality")
        app.deploy_password.set("unused-hy2-password")
        app._deploy()
        params = app._execute.call_args.args[0]
        self.assertEqual(params["service"], "reality")
        self.assertEqual(params["port"], 443)
        self.assertEqual(params["server_name"], "www.cloudflare.com")
        self.assertNotIn("proxy_password", params); self.assertNotIn("panel_password", params)
        self.assertEqual(app.deploy_optional_rows["server_name"].winfo_manager(), "grid")
        self.assertNotIn("TCP 80", app.deploy_network_hint.cget("text"))


if __name__ == "__main__":
    unittest.main()
