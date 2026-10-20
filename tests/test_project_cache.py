import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.project_cache import ProjectCache, safe_url
from linux_manager.project_info import server_key


def project(**values):
    return dict({"id": "external:systemd:sample.service", "kind": "systemd", "name": "sample", "state": "active",
                 "working_directory": "/opt/sample", "ports": [{"port": 8080, "protocol": "tcp", "local_only": False}],
                 "capabilities": ["start", "stop", "restart"],
                 "web_endpoints": [{"url": "https://fixture.invalid/app/", "source": "Nginx 反向代理配置", "local_only": False}]}, **values)


class ProjectCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.connection = Connection(host="fixture.invalid", username="fixture")
        self.cache = ProjectCache(self.root)

    def test_restart_restores_catalog_metadata_and_urls_without_network_or_keychain(self):
        self.cache.update(self.connection, projects=[project()], replace=True,
                          builtins={"xui": {"data": {"service": "xui", "installed": True, "port": 2053, "scheme": "https", "path": "/panel/"}}})
        vault = mock.Mock(); store = Store(self.root, vault)
        controller = Controller(store); controller.transport = mock.Mock(side_effect=AssertionError("network"))
        data = controller.cached_projects([self.connection])
        snapshot = data["servers"][server_key(self.connection)]
        self.assertEqual(snapshot["projects"][0]["web_endpoints"][0]["url"], "https://fixture.invalid/app/")
        self.assertEqual(snapshot["projects"][0]["working_directory"], "/opt/sample")
        self.assertIn("saved_at", snapshot)
        self.assertIn("后台网址", dict(snapshot["builtin_information"]["xui"]["rows"]))
        controller.transport.assert_not_called(); vault.get.assert_not_called()

    def test_cache_never_serializes_credentials_command_environment_or_token_urls(self):
        self.cache.update(self.connection, projects=[project(password="fictional-secret", env={"TOKEN": "fictional-secret"},
                          credentials={"password": "fictional-secret"}, command_line="--token fictional-secret",
                          web_endpoints=[{"url": "http://fixture.invalid/?token=fictional-secret"}])],
                          builtins={"xui": {"data": {"service": "xui", "installed": True, "panel_password": "fictional-secret",
                                                     "api_keys": ["fictional-secret"], "proxy_password": "fictional-secret"},
                                               "rows": [("后台密码", "fictional-secret")]}})
        path = next((self.root / "project-cache").glob("*.json"))
        text = path.read_text()
        self.assertNotIn("fictional-secret", text); self.assertNotIn("password", text); self.assertNotIn("command_line", text)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_server_and_ssh_port_namespaces_are_separate(self):
        self.cache.update(self.connection, projects=[project()])
        self.assertEqual(self.cache.load(self.connection.changed(host="other.invalid"))["projects"], {})
        self.assertEqual(self.cache.load(self.connection.changed(port=2222))["projects"], {})
        self.assertEqual(len(self.cache.load(self.connection.changed(username="another"))["projects"]), 1)

    def test_explicit_complete_refresh_replaces_removed_projects(self):
        self.cache.update(self.connection, projects=[project()])
        self.cache.update(self.connection, projects=[], replace=True)
        self.assertEqual(ProjectCache(self.root).load(self.connection)["projects"], {})

    def test_partial_refresh_and_single_detail_keep_other_projects(self):
        other = project(id="external:systemd:other.service", name="other")
        self.cache.update(self.connection, projects=[project(), other], replace=True)
        self.cache.update(self.connection, projects=[project(state="inactive")])
        result = self.cache.load(self.connection)["projects"]
        self.assertEqual(len(result), 2)
        self.assertEqual(result[project()["id"]]["state"], "inactive")

    def test_corrupt_cache_is_preserved_and_reported_without_breaking_remote_reads(self):
        self.cache.update(self.connection, projects=[project()])
        path = next((self.root / "project-cache").glob("*.json")); path.write_text("invalid")
        with self.assertRaises(ManagerError): self.cache.update(self.connection, projects=[])
        self.assertEqual(path.read_text(), "invalid")
        controller = Controller(Store(self.root, mock.Mock()))
        controller.transport = mock.Mock()
        controller.transport.return_value.call.return_value = {"projects": [project()], "warnings": []}
        result = controller.external_projects(self.connection)
        self.assertEqual(result["projects"][0]["name"], "sample")
        self.assertTrue(result["warnings"])
        snapshots = controller.cached_projects([self.connection])
        self.assertEqual(snapshots["servers"], {}); self.assertTrue(snapshots["warnings"])
        self.assertEqual(path.read_text(), "invalid")

    def test_controller_scan_saves_urls_after_filling_host_without_exposing_local_port(self):
        controller = Controller(Store(self.root, mock.Mock()))
        controller.transport = mock.Mock()
        controller.transport.return_value.call.return_value = {"projects": [project(web_endpoints=[
            {"scheme": "http", "port": 8080, "path": "/", "local_only": False, "source": "HTTP 响应"},
            {"scheme": "http", "port": 8081, "path": "/", "local_only": True, "source": "HTTP 响应"}])], "warnings": []}
        controller.external_projects(self.connection)
        row = self.cache.load(self.connection)["projects"][project()["id"]]
        self.assertEqual(row["web_endpoints"][0]["url"], "http://fixture.invalid:8080/")
        self.assertEqual(row["web_endpoints"][1]["url"], "http://127.0.0.1:8081/")

    def test_complete_failed_component_refresh_keeps_previous_saved_catalog(self):
        self.cache.update(self.connection, projects=[project()])
        controller = Controller(Store(self.root, mock.Mock())); controller.transport = mock.Mock()
        controller.transport.return_value.call.return_value = {"projects": [], "warnings": ["Docker 未能读取"]}
        controller.external_projects(self.connection)
        self.assertIn(project()["id"], self.cache.load(self.connection)["projects"])

    def test_forgetting_directory_removes_saved_snapshot(self):
        directory = project(id="external:directory:" + "a" * 64, kind="directory", registered_local=True)
        self.cache.update(self.connection, projects=[directory])
        controller = Controller(Store(self.root, mock.Mock()))
        controller.forget_external_directory(self.connection, directory["id"])
        self.assertNotIn(directory["id"], self.cache.load(self.connection)["projects"])

    def test_unsafe_urls_never_enter_cached_metadata(self):
        for url in ("https://owner:password@fixture.invalid/", "http://fixture.invalid/?token=secret", "javascript:alert(1)",
                    "https://fixture.invalid/#token", "http://fixture.invalid:99999/", "http://fixture.invalid/path name"):
            self.assertEqual(safe_url(url), "")

    def test_nginx_port_protocols_survive_restart_without_extra_listener_data(self):
        self.cache.update(self.connection, builtins={'nginx': {'data': {
            'service': 'nginx', 'installed': True, 'port': 443, 'frontend_ports': [443],
            'frontend_listeners': [{'port': 443, 'protocol': 'udp', 'secret': 'fictional-secret'}],
        }}})
        controller = Controller(Store(self.root, mock.Mock()))
        restored = controller.cached_projects([self.connection])['servers'][server_key(self.connection)]
        rows = dict(restored['builtin_information']['nginx']['rows'])
        self.assertEqual(rows['网页入口端口'], '443 / UDP')
        self.assertEqual(rows['端口协议'], 'UDP（此入口仅需 UDP）')
        path = next((self.root / 'project-cache').glob('*.json'))
        self.assertNotIn('fictional-secret', path.read_text())

    def test_malformed_builtin_cache_cannot_block_other_server_profiles(self):
        self.cache.update(self.connection, projects=[project()])
        path = next((self.root / 'project-cache').glob('*.json'))
        data = json.loads(path.read_text())
        data['builtins']['xui'] = {'service': 'xui', 'installed': True, 'port': 2053, 'scheme': {'invalid': True}}
        path.write_text(json.dumps(data)); original = path.read_bytes()
        other = self.connection.changed(host='other.invalid')
        self.cache.update(other, projects=[project()])
        controller = Controller(Store(self.root, mock.Mock()))
        restored = controller.cached_projects([self.connection, other])
        self.assertTrue(restored['warnings'])
        self.assertIn(server_key(other), restored['servers'])
        self.assertEqual(path.read_bytes(), original)

    def test_excessive_project_count_does_not_replace_a_readable_cache(self):
        self.cache.update(self.connection, projects=[project()])
        path = next((self.root / 'project-cache').glob('*.json')); original = path.read_bytes()
        rows = [project(id=f'external:systemd:fixture-{i}.service') for i in range(3001)]
        with self.assertRaises(ManagerError):
            self.cache.update(self.connection, projects=rows, replace=True)
        self.assertEqual(path.read_bytes(), original)
        self.assertIn(project()['id'], self.cache.load(self.connection)['projects'])

    def test_excessive_cache_size_does_not_replace_a_readable_cache(self):
        self.cache.update(self.connection, projects=[project()])
        path = next((self.root / 'project-cache').glob('*.json')); original = path.read_bytes()
        row = project(name='x' * 2000, description='x' * 2000,
                      web_endpoints=[{'url': 'https://fixture.invalid/' + 'x' * 1800} for _ in range(30)])
        with self.assertRaises(ManagerError):
            self.cache.update(self.connection, projects=[dict(row, id=f'external:systemd:fixture-{i}.service') for i in range(160)], replace=True)
        self.assertEqual(path.read_bytes(), original)



if __name__ == "__main__": unittest.main()
