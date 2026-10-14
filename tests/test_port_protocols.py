import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.help_texts import HELP
from linux_manager.models import Connection, SERVICES, Store
from linux_manager.project_info import SERVICE_PROTOCOLS, deployment_network_hint, inbound_port_protocol, information_rows, server_key

spec = importlib.util.spec_from_file_location("port_protocol_remote", Path(__file__).resolve().parents[1] / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REMOTE)


class PortInformationTests(unittest.TestCase):
    def test_all_project_service_ports_have_explicit_protocols(self):
        connection = Connection(host="fixture.invalid")
        self.assertEqual(set(SERVICE_PROTOCOLS), set(SERVICES))
        for service, protocol in SERVICE_PROTOCOLS.items():
            with self.subTest(service=service):
                rows = dict(information_rows({"service": service, "installed": True, "port": 12345}, connection))
                self.assertEqual(rows["服务端口"], "12345 / " + protocol)
                self.assertIn("仅需 " + protocol, rows["端口协议"])

    def test_business_and_certificate_protocols_are_separate(self):
        hint = deployment_network_hint("hysteria2", 443)
        self.assertIn("放行 UDP 443", hint)
        self.assertIn("不需要开放 TCP", hint)
        self.assertIn("另需 TCP 80", hint)
        self.assertNotIn("TCP 443", hint)
        self.assertNotIn("证书", deployment_network_hint("nginx", 8080))
        hint = deployment_network_hint("exchange", 26483, 18881)
        self.assertIn("TCP 18881", hint)
        self.assertIn("不向公网开放", hint)

    def test_proxy_ingress_protocol_follows_transport_not_relay_payload(self):
        cases = [
            ("vless", {}, {}, "TCP"),
            ("vmess", {"network": "ws"}, {}, "TCP"),
            ("vless", {"network": "raw", "security": "reality"}, {}, "TCP"),
            ("trojan", {"network": "grpc"}, {}, "TCP"),
            ("vless", {"network": "httpupgrade"}, {}, "TCP"),
            ("vless", {"network": "kcp"}, {}, "UDP"),
            ("vmess", {"network": "mkcp"}, {}, "UDP"),
            ("vless", {"network": "quic"}, {}, "UDP"),
            ("vless", {"network": "hysteria"}, {}, "UDP"),
            ("hysteria2", {}, {}, "UDP"),
            ("hysteria", {"network": "tcp"}, {}, "UDP"),
            ("wireguard", {}, {}, "UDP"),
            ("mtproto", {}, {}, "TCP"),
            ("shadowsocks", {}, {}, "TCP"),
            ("shadowsocks", {"network": "kcp"}, {}, "UDP"),
            ("shadowsocks", {}, {"network": "tcp"}, "TCP"),
            ("shadowsocks", {}, {"network": "udp"}, "UDP"),
            ("shadowsocks", {}, {"network": "udp, tcp"}, "TCP + UDP"),
            ("dokodemo-door", {}, {"network": "tcp,udp"}, "TCP + UDP"),
            ("tunnel", {}, {"allowedNetwork": "udp"}, "UDP"),
            ("socks", {}, {"udp": True}, "TCP + UDP"),
            ("mixed", {}, {"udp": True}, "TCP + UDP"),
            ("socks", {}, {"udp": False}, "TCP"),
            ("vless", {"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]}}, {}, "UDP"),
            ("vless", {"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h2", "http/1.1"]}}, {}, "TCP"),
        ]
        for protocol, stream, settings, expected in cases:
            with self.subTest(protocol=protocol, stream=stream, settings=settings):
                self.assertEqual(inbound_port_protocol({"protocol": protocol, "stream_settings": stream, "settings": settings}), expected)

    def test_unknown_or_invalid_node_configuration_does_not_guess_both_protocols(self):
        for inbound in [
            {"protocol": "unrecognized"},
            {"protocol": "vless", "stream_settings": {"network": "unrecognized"}},
            {"protocol": "vless", "stream_settings": "broken"},
            {"protocol": "vless", "stream_settings": []},
            {"protocol": "vless", "port_protocol_error": True},
            {"protocol": "shadowsocks", "settings": {"network": "tcp,unrecognized"}},
            {"protocol": "shadowsocks", "settings": {"network": ["tcp", "udp"]}},
        ]:
            with self.subTest(inbound=inbound):
                self.assertIn("协议未识别", inbound_port_protocol(inbound))

    def test_panel_nodes_subscription_and_disabled_ports_are_distinct(self):
        data = {"service": "xui", "installed": True, "port": 2053, "subscription_port": 2096, "inbounds": [
            {"remark": "both", "port": 10001, "protocol": "shadowsocks", "settings": {"network": "tcp,udp"}},
            {"remark": "off", "port": 10002, "protocol": "vless", "enable": False},
        ]}
        rows = dict(information_rows(data, Connection(host="fixture.invalid")))
        self.assertEqual(rows["服务端口"], "2053 / TCP")
        self.assertIn("2096 / TCP", rows["订阅服务端口"])
        self.assertIn("TCP、UDP 两者都需放行", rows["节点端口：both"])
        self.assertIn("已停用；无需", rows["节点端口：off"])
        data["subscription_local_only"] = True
        self.assertIn("无需公网放行", dict(information_rows(data, Connection()))["订阅服务端口"])

    def test_nginx_custom_quic_listener_is_not_mislabeled_tcp(self):
        data = {"service": "nginx", "installed": True, "port": 443, "frontend_ports": [80, 443, 8443], "frontend_listeners": [
            {"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}, {"port": 443, "protocol": "udp"}, {"port": 8443, "protocol": "udp"},
        ]}
        rows = dict(information_rows(data, Connection()))
        self.assertEqual(rows["服务端口"], "443 / TCP + UDP")
        self.assertIn("两者都需放行", rows["端口协议"])
        self.assertEqual(rows["网页入口端口"], "80 / TCP、443 / TCP + UDP、8443 / UDP")

    def test_internal_port_and_help_do_not_request_public_udp_for_hy2(self):
        rows = dict(information_rows({"service": "exchange", "installed": True, "port": 26483, "backend_port": 18880}, Connection()))
        self.assertEqual(rows["内部端口"], "18880 / TCP（仅服务器本机，无需公网放行）")
        self.assertIn("仅 UDP，不需要 TCP", HELP["服务端口"])
        self.assertIn("TCP 22", HELP["SSH 端口（TCP）"])


class PortProtocolUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.page = ttk.Frame(self.root)
        self.addCleanup(self.page.destroy)
        self.app = object.__new__(App)
        self.app.pages = {"一键部署": SimpleNamespace(content=self.page)}
        self.app.privacy = tk.BooleanVar(self.root, value=True)
        self.app.buttons = []
        self.app.private_entries = []
        self.app._deployment_page()

    def test_project_switch_and_edited_port_update_visible_protocol_without_network(self):
        app = self.app
        app.controller = mock.Mock()
        for service, protocol in SERVICE_PROTOCOLS.items():
            with self.subTest(service=service):
                app.deploy_choice.set(SERVICES[service][0])
                app._deploy_defaults()
                self.assertTrue(app.deploy_port_protocol.cget("text").startswith(protocol))
                self.assertEqual(app.deploy_port_protocol.winfo_manager(), "grid")
                app.deploy_port.set("12345")
                self.assertIn("放行 " + protocol + " 12345", app.deploy_network_hint.cget("text"))
                app.deploy_port.set("")
                self.assertIn("所填端口", app.deploy_network_hint.cget("text"))
        app.controller.assert_not_called()
        self.assertFalse(app.controller.mock_calls)

    def test_internal_port_hint_updates_while_optional_settings_stay_folded(self):
        app = self.app
        app.deploy_backend.set("18882")
        self.assertIn("TCP 18882", app.deploy_network_hint.cget("text"))
        self.assertFalse(app.deploy_optional_frame.winfo_manager())

    def test_deployment_confirmation_lists_exact_project_protocol(self):
        app = self.app
        app.current = Connection(host="fixture.invalid")
        app.controller = mock.Mock()
        app.controller.deployment_preview.return_value = {"version": "v1.2.3", "fingerprint": "fixture", "action": "reconfigure", "installed": True, "changes": [], "panel_version": "v1.26.2", "auto_update": True, "host": "fixture.invalid", "port": 12345}
        app._execute = mock.Mock()
        app._run = mock.Mock(side_effect=lambda work, done, message, **kwargs: done(work()))
        for service, protocol in SERVICE_PROTOCOLS.items():
            app._preview_deployment({"service": service, "port": 12345, "backend_port": 18880})
            text = app._execute.call_args.args[1]
            self.assertIn("放行 " + protocol + " 12345", text)
            self.assertIn("保留现有账号", text)

    def test_privacy_keeps_protocol_visible_but_hides_actual_port_and_node(self):
        app = self.app
        app.pages["日常维护"] = SimpleNamespace(content=self.page)
        app._maintenance_page()
        app.current = Connection(host="fixture.invalid")
        app.manage_choice.set(SERVICES["hysteria2"][0])
        app.project_details = {(server_key(app.current), "hysteria2"): {"rows": [("服务端口", "51752 / UDP"), ("端口协议", "UDP（此入口仅需 UDP）"), ("节点：fixture", "fictional-node")]}}
        app.project_logs = {}
        app._project_changed()
        self.assertEqual(app.project_info_tree.item("1", "values")[1], "UDP（此入口仅需 UDP）")
        self.assertNotIn("51752", app.project_info_tree.item("0", "values")[1])
        self.assertNotIn("fictional-node", app.project_info_tree.item("2", "values")[1])

    def test_firewall_preview_lists_real_protocols_and_preserves_original_rules_payload(self):
        app = self.app
        app.current = Connection(host="fixture.invalid", port=2222)
        app._ready = mock.Mock(return_value=True)
        app._execute = mock.Mock()
        app.report = {"listeners": [
            {"port": 51752, "protocol": "udp", "local_only": False},
            {"port": 2053, "protocol": "tcp", "local_only": False},
            {"port": 443, "protocol": "udp", "local_only": False},
            {"port": 443, "protocol": "tcp", "local_only": False},
            {"port": 18880, "protocol": "tcp", "local_only": True},
            {"port": 12345, "protocol": "udp", "local_only": False},
        ]}
        app._firewall()
        params, text = app._execute.call_args.args
        self.assertEqual(params["ports"], [{"port": row["port"], "protocol": row["protocol"]} for row in app.report["listeners"][:4]])
        for rule in ["TCP 2222", "UDP 51752", "TCP 2053", "TCP 443", "UDP 443"]:
            self.assertIn(rule, text)
        for rule in ["TCP 51752", "UDP 2053", "18880", "12345"]:
            self.assertNotIn(rule, text)


class PortLayoutTests(unittest.TestCase):
    def test_protocol_labels_and_hints_fit_all_projects_at_default_and_minimum_width(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory), vault=mock.Mock())
            errors = []
            with mock.patch("linux_manager.gui.Store", return_value=store), mock.patch("linux_manager.gui.Controller") as controller, mock.patch.object(App, "_load_saved_profiles"), mock.patch.object(App, "report_callback_exception", side_effect=lambda *args: errors.append("callback error")):
                app = App()
                try:
                    app.notebook.select(app.pages["一键部署"])
                    app._toggle_deploy_optional()
                    for geometry in ["1180x820", "1080x760"]:
                        app.geometry(geometry)
                        for service in SERVICES:
                            with self.subTest(geometry=geometry, service=service):
                                app.deploy_choice.set(SERVICES[service][0])
                                app._deploy_defaults()
                                app.update()
                                page = app.pages["一键部署"]
                                for widget in [app.deploy_port_protocol, app.deploy_network_hint]:
                                    self.assertTrue(widget.winfo_ismapped())
                                    left = widget.winfo_rootx() - page.content.winfo_rootx()
                                    self.assertGreaterEqual(left, 0)
                                    self.assertLessEqual(left + widget.winfo_width(), page.content.winfo_width() + 1)
                    self.assertEqual(errors, [])
                    controller.return_value.transport.assert_not_called()
                    controller.return_value.execute.assert_not_called()
                finally:
                    for identifier in app.tk.call("after", "info"):
                        app.after_cancel(identifier)
                    app.destroy()


class RemotePortMetadataTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        original = Path
        mapped = lambda value: self.base / str(value).lstrip("/") if str(value).startswith("/") else original(value)
        patch = mock.patch.object(REMOTE, "Path", side_effect=mapped)
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(REMOTE, "unit_info", return_value={"LoadState": "loaded"})
        patch.start(); self.addCleanup(patch.stop)

    def test_subscription_port_is_local_configuration_not_external_custom_url(self):
        database = self.base / "etc/x-ui/x-ui.db"
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE settings(key TEXT,value TEXT)")
            db.executemany("INSERT INTO settings VALUES(?,?)", [("subEnable", "true"), ("subPort", "2097"), ("subListen", "127.0.0.2"), ("subURI", "https://external.invalid:443/sub/")])
        before = database.read_bytes()
        data = REMOTE.connection_details({"service": "xui", "host": "fixture.invalid"})
        self.assertEqual(data["subscription_port"], 2097)
        self.assertTrue(data["subscription_local_only"])
        self.assertEqual(data["subscription_base"], "https://external.invalid:443/sub/")
        self.assertEqual(database.read_bytes(), before)
        with sqlite3.connect(database) as db:
            db.execute("UPDATE settings SET value='false' WHERE key='subEnable'")
        self.assertNotIn("subscription_port", REMOTE.connection_details({"service": "xui", "host": "fixture.invalid"}))

    def test_malformed_remote_node_json_does_not_become_a_guessed_tcp_port(self):
        database = self.base / "etc/x-ui/x-ui.db"
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE inbounds(port INTEGER,protocol TEXT,settings TEXT,stream_settings TEXT)")
            db.execute("INSERT INTO inbounds VALUES(10001,'vless','{}','invalid-json')")
        before = database.read_bytes()
        data = REMOTE.connection_details({"service": "xui"})
        self.assertTrue(data["inbounds"][0]["port_protocol_error"])
        self.assertIn("协议未识别", inbound_port_protocol(data["inbounds"][0]))
        self.assertEqual(database.read_bytes(), before)

    def test_nginx_listener_metadata_retains_both_transports_and_excludes_loopback(self):
        listeners = [
            {"port": 443, "protocol": "tcp", "local_only": False, "processes": ["nginx"]},
            {"port": 443, "protocol": "udp", "local_only": False, "processes": ["nginx"]},
            {"port": 8080, "protocol": "tcp", "local_only": True, "processes": ["nginx"]},
            {"port": 51752, "protocol": "udp", "local_only": False, "processes": ["sing-box"]},
        ]
        with mock.patch.object(REMOTE, "listeners", return_value=listeners):
            data = REMOTE.connection_details({"service": "nginx"})
        self.assertEqual(data["frontend_ports"], [443])
        self.assertEqual(data["frontend_listeners"], [{"port": 443, "protocol": "tcp"}, {"port": 443, "protocol": "udp"}])


if __name__ == "__main__":
    unittest.main()
