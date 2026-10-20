import http.client
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.external_projects import ExternalProjects


class ProjectWebTests(unittest.TestCase):
    def setUp(self): self.manager = ExternalProjects(mock.Mock())

    def test_web_check_uses_head_loopback_and_never_reads_body_or_follows_redirect(self):
        connection = mock.Mock(); response = connection.getresponse.return_value; response.status = 302
        with mock.patch("linux_manager.external_projects.http.client.HTTPConnection", return_value=connection) as factory:
            self.assertEqual(self.manager._web_protocol(8080, float("inf")), "http")
            self.assertEqual(self.manager._web_protocol(8080, float("inf")), "http")
        factory.assert_called_once_with("127.0.0.1", 8080, timeout=0.6)
        self.assertEqual(connection.request.call_args.args, ("HEAD", "/"))
        response.read.assert_not_called(); response.getheader.assert_not_called()
        connection.close.assert_called_once()

    def test_tls_only_web_port_is_detected_with_local_handshake(self):
        plain = mock.Mock(); plain.getresponse.side_effect = http.client.BadStatusLine("fictional")
        encrypted = mock.Mock(); encrypted.getresponse.return_value.status = 401
        with mock.patch("linux_manager.external_projects.http.client.HTTPConnection", return_value=plain), \
             mock.patch("linux_manager.external_projects.http.client.HTTPSConnection", return_value=encrypted):
            self.assertEqual(self.manager._web_protocol(8443, float("inf")), "https")
        self.assertEqual(encrypted.request.call_args.args, ("HEAD", "/"))

    def test_non_web_listener_is_not_guessed_to_be_http_and_budget_is_respected(self):
        with mock.patch("linux_manager.external_projects.http.client.HTTPConnection", side_effect=OSError), \
             mock.patch("linux_manager.external_projects.http.client.HTTPSConnection", side_effect=OSError):
            self.assertEqual(self.manager._web_protocol(5432, float("inf")), "")
        with mock.patch("linux_manager.external_projects.http.client.HTTPConnection") as connection:
            self.assertEqual(self.manager._web_protocol(5433, 0), "")
            connection.assert_not_called()

    def test_nginx_routes_match_backend_port_domain_tls_and_path_without_returning_config_secrets(self):
        text = '''http {
          upstream app_backend { server 127.0.0.1:8080; }
          server { listen 443 ssl; server_name fixture.invalid;
            ssl_certificate_key /private/fictional-key;
            location /app/ { proxy_set_header Authorization "Bearer fictional-secret"; proxy_pass http://app_backend; }
          }
          server { listen 80; server_name other.invalid; location / { proxy_pass http://127.0.0.1:9090; } }
        }'''
        self.manager.command.return_value = SimpleNamespace(returncode=0, stdout=text)
        with mock.patch("linux_manager.external_projects.shutil.which", return_value="/usr/bin/nginx"):
            routes = self.manager._proxy_routes()
        route = next(r for r in routes if r["backend_port"] == 8080)
        self.assertEqual((route["host"], route["port"], route["scheme"], route["path"]), ("fixture.invalid", 443, "https", "/app/"))
        self.assertNotIn("fictional-secret", json.dumps(routes)); self.assertNotIn("fictional-key", json.dumps(routes))
        self.assertEqual(self.manager.command.call_args.args[0], ["nginx", "-T"])

    def test_nginx_external_upstreams_regex_locations_and_credential_urls_are_skipped(self):
        text = '''server { listen 443 ssl; server_name fixture.invalid;
        location /external/ { proxy_pass https://elsewhere.invalid:8080; }
        location /credential/ { proxy_pass http://user:fictional-secret@127.0.0.1:8080; }
        location ~ /regex.* { proxy_pass http://127.0.0.1:8080; }
        }'''
        self.manager.command.return_value = SimpleNamespace(returncode=0, stdout=text)
        with mock.patch("linux_manager.external_projects.shutil.which", return_value="/usr/bin/nginx"):
            self.assertEqual(self.manager._proxy_routes(), [])

    def test_nginx_server_without_listen_uses_its_default_http_port(self):
        text = 'http { server { server_name fixture.invalid; location /app/ { proxy_pass http://127.0.0.1:8080; } } }'
        self.manager.command.return_value = SimpleNamespace(returncode=0, stdout=text)
        with mock.patch('linux_manager.external_projects.shutil.which', return_value='/usr/bin/nginx'):
            routes = self.manager._proxy_routes()
        self.assertEqual([(r['port'], r['scheme'], r['backend_port']) for r in routes], [(80, 'http', 8080)])

    def test_nginx_upstream_default_port_is_independent_of_proxy_scheme(self):
        text = '''http {
          upstream app_backend { server 127.0.0.1; }
          server { listen 443 ssl; server_name fixture.invalid;
            location /group/ { proxy_pass https://app_backend; }
            location /direct/ { proxy_pass https://127.0.0.1; }
          }
        }'''
        self.manager.command.return_value = SimpleNamespace(returncode=0, stdout=text)
        with mock.patch('linux_manager.external_projects.shutil.which', return_value='/usr/bin/nginx'):
            routes = self.manager._proxy_routes()
        self.assertEqual({r['path']: r['backend_port'] for r in routes}, {'/group/': 80, '/direct/': 443})

    def test_generic_project_urls_are_associated_by_owned_tcp_port(self):
        first = {"ports": [{"port": 8080, "protocol": "tcp", "local_only": True}], "version": "1.0"}
        other = {"ports": [{"port": 9090, "protocol": "udp", "local_only": False}], "version": "1.0"}
        route = {"backend_port": 8080, "port": 443, "scheme": "https", "host": "fixture.invalid", "path": "/", "local_only": False, "source": "Nginx"}
        with mock.patch.object(self.manager, "_proxy_routes", return_value=[route]), \
             mock.patch.object(self.manager, "_web_protocol", return_value="http") as probe:
            self.manager._enrich_projects([first, other])
        self.assertEqual(first["web_endpoints"][0]["host"], "fixture.invalid")
        self.assertTrue(first["web_endpoints"][1]["local_only"])
        self.assertEqual(other["web_endpoints"], [])
        probe.assert_called_once()

    def test_generic_package_version_reads_only_selected_public_field(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root / "package.json").write_text('{"version":"2.4.1","token":"fictional-secret"}')
            value = {"working_directory": str(root)}
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root.parent) + "/",)):
                self.manager._read_public_version(value)
            self.assertEqual(value["version"], "2.4.1"); self.assertNotIn("fictional-secret", json.dumps(value))

    def test_generic_git_revision_does_not_read_remote_or_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root / ".git/refs/heads").mkdir(parents=True)
            (root / ".git/HEAD").write_text("ref: refs/heads/main\n")
            (root / ".git/refs/heads/main").write_text("a" * 40)
            (root / ".git/config").write_text("token=fictional-secret")
            value = {"working_directory": str(root)}
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root.parent) + "/",)):
                self.manager._read_public_version(value)
            self.assertEqual(value["revision"], "a" * 12); self.assertNotIn("fictional-secret", json.dumps(value))


if __name__ == "__main__": unittest.main()
