import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.external_projects import ExternalProjects, ExternalProjectError
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.project_info import credential_alias


def unit(name="sample.service", state="active", extra=""):
    return (f"Id={name}\nDescription=Sample application\nFragmentPath=/etc/systemd/system/{name}\n"
            f"ExecStart={{ path=/opt/sample/server ; argv[]=/opt/sample/server --token fictional-secret ; }}\n"
            f"WorkingDirectory=/opt/sample\nMainPID=42\nActiveState={state}\nUnitFileState=disabled\n{extra}")


class ExternalDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.command = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=""))
        self.manager = ExternalProjects(self.command, {"cli-proxy-api.service", "nginx.service"})
        for method in ("_pm2", "_directories", "_proxy_routes"):
            patch = mock.patch.object(self.manager, method, return_value=[])
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(self.manager, "_listeners", return_value=[])
        patch.start(); self.addCleanup(patch.stop)

    def test_templates_system_components_and_managed_services_are_excluded(self):
        names = ["sample.service", "sample@.service", "sample@one.service", "ssh.service", "nginx.service",
                 "linux-manager-task-fixture.service", "pm2-fixture.service", "cli-proxy-api.service"]
        def run(args, **kwargs):
            if args[1] == "list-unit-files": text = "\n".join(name + " enabled" for name in names)
            elif args[1] == "list-units": text = ""
            elif args[1] == "show": text = unit() + "\n" + unit("sample@one.service")
            else: text = ""
            return SimpleNamespace(returncode=0, stdout=text)
        self.command.side_effect = run
        with mock.patch("linux_manager.external_projects.shutil.which", return_value="/usr/bin/tool"):
            result = self.manager.discover()
        self.assertEqual({p["id"] for p in result["projects"]}, {"external:systemd:sample.service", "external:systemd:sample@one.service"})
        show = next(call.args[0] for call in self.command.call_args_list if call.args[0][1] == "show")
        for excluded in names[1:2] + names[3:]: self.assertNotIn(excluded, show)
        self.assertNotIn("fictional-secret", json.dumps(result))
        self.assertNotIn("argv", json.dumps(result))

    def test_vendor_units_need_application_evidence(self):
        plain = unit("ordinary.service").replace("/etc/systemd/system/", "/lib/systemd/system/").replace("/opt/sample", "/usr/bin")
        self.assertIsNone(self.manager._unit_project(self.manager._blocks(plain)[0]))
        self.assertIsNotNone(self.manager._unit_project(self.manager._blocks(plain.replace("ordinary.service", "openlist.service"))[0]))

    def test_protected_or_injected_targets_are_rejected_before_command(self):
        for identifier in ("external:systemd:ssh.service", "external:systemd:nginx.service", "external:systemd:--help.service",
                           "external:systemd:sample.service;reboot", "external:docker:--all", "sample"):
            with self.subTest(identifier=identifier), self.assertRaises(ExternalProjectError):
                self.manager.details(identifier)
        self.command.assert_not_called()

    def test_detail_reads_only_selected_unit_and_its_listeners(self):
        self.command.return_value.stdout = unit()
        project = self.manager.details("external:systemd:sample.service")
        self.assertEqual(project["name"], "sample")
        self.assertEqual(self.command.call_count, 1)
        self.assertEqual(self.command.call_args.args[0][1:3], ["show", "sample.service"])

    def test_changed_or_missing_fingerprint_cannot_execute(self):
        project = self.manager._unit_project(self.manager._blocks(unit())[0])
        with mock.patch.object(self.manager, "details", return_value=project):
            for fingerprint in (None, "outdated"):
                with self.assertRaises(ExternalProjectError): self.manager.manage(project["id"], "stop", fingerprint)
        self.command.assert_not_called()

    def test_service_action_checks_result_and_never_uses_shell(self):
        project = self.manager._unit_project(self.manager._blocks(unit())[0])
        stopped = dict(project, state="inactive")
        with mock.patch.object(self.manager, "details", side_effect=[project, stopped]):
            result = self.manager.manage(project["id"], "stop", self.manager.fingerprint(project))
        self.assertEqual(self.command.call_args.args[0], ["systemctl", "stop", "sample.service"])
        self.assertEqual(result["external_project"]["state"], "inactive")
        with mock.patch.object(self.manager, "details", return_value=project):
            with self.assertRaises(ExternalProjectError): self.manager.manage(project["id"], "stop", self.manager.fingerprint(project))

    def test_docker_details_request_selected_metadata_without_environment(self):
        identifier = "a" * 64
        row = {"id": identifier, "name": "/fixture", "image": "memos:stable", "state": "running",
               "ports": {"5230/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15230"}]}, "restart_policy": "unless-stopped"}
        self.command.return_value.stdout = json.dumps(row)
        project = self.manager.details("external:docker:" + identifier)
        args = self.command.call_args.args[0]
        self.assertEqual(args[:2], ["docker", "inspect"])
        self.assertNotIn(".Env", " ".join(args))
        self.assertNotIn("{{json .}}", args)
        self.assertTrue(project["ports"][0]["local_only"])
        self.assertEqual(project["ports"][0]["container_port"], 5230)

    def test_process_identifier_rejects_pid_reuse(self):
        with mock.patch.object(self.manager, "_process", return_value=("/opt/sample/server", "/opt/sample", "0::/session.scope", "200")):
            with self.assertRaises(ExternalProjectError): self.manager.details("external:process:42:100")
            value = self.manager.details("external:process:42:200")
        self.assertEqual(value["capabilities"], [])

    def test_unsaved_pm2_listener_is_visible_as_readonly_process(self):
        listener = {"port": 3000, "protocol": "tcp", "local_only": True, "pids": [42]}
        with mock.patch("linux_manager.external_projects.shutil.which", return_value=None), \
             mock.patch.object(self.manager, "_listeners", return_value=[listener]), \
             mock.patch.object(self.manager, "_process", return_value=("/usr/bin/node", "/opt/fixture", "0::/system.slice/pm2-fixture.service", "100")):
            projects = self.manager.discover()["projects"]
            self.assertEqual(len(projects), 1)
            self.assertEqual(projects[0]["kind"], "process")
            self.assertEqual(projects[0]["ports"][0]["port"], 3000)
            self.assertEqual(self.manager.details(projects[0]["id"])["capabilities"], [])

    def test_builtin_service_descendants_do_not_become_external_processes(self):
        listener = {"port": 443, "protocol": "tcp", "local_only": False, "pids": [42]}
        with mock.patch("linux_manager.external_projects.shutil.which", return_value=None), \
             mock.patch.object(self.manager, "_listeners", return_value=[listener]), \
             mock.patch.object(self.manager, "_process", return_value=("/opt/fixture/server", "/opt/fixture", "0::/system.slice/nginx.service", "100")):
            self.assertEqual(self.manager.discover()["projects"], [])

    def test_enable_must_verify_startup_state(self):
        project = self.manager._unit_project(self.manager._blocks(unit())[0])
        with mock.patch.object(self.manager, "details", return_value=project):
            with self.assertRaises(ExternalProjectError): self.manager.manage(project["id"], "enable", self.manager.fingerprint(project))

    def test_directory_scanner_is_bounded_and_excludes_managed_paths(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as folder:
            root = Path(folder).resolve()
            app = root / "fixture"; app.mkdir(); (app / "package.json").write_text('{"version":"1.0.0"}')
            nested = root / "group/deep"; nested.mkdir(parents=True); (nested / "package.json").write_text('{}')
            real_scandir = __import__('os').scandir
            def scan(path): return real_scandir(root if str(path) == "/opt" else path)
            # Restore this method patched in setUp; other discovery methods stay isolated.
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root) + "/",)), \
                 mock.patch("linux_manager.external_projects.os.scandir", side_effect=scan), \
                 mock.patch("linux_manager.external_projects.pwd.getpwall", return_value=[]):
                found = ExternalProjects._directories(self.manager, [])
                self.assertIn(str(app), [p["working_directory"] for p in found])
                self.assertNotIn(str(nested), [p["working_directory"] for p in found])
                self.manager.excluded_directories.add(str(app))
                self.assertNotIn(str(app), [p["working_directory"] for p in ExternalProjects._directories(self.manager, [])])

    def test_lifecycle_records_never_return_original_messages(self):
        project = {"id": "external:systemd:sample.service", "kind": "systemd", "unit": "sample.service"}
        self.command.return_value.stdout = json.dumps({"MESSAGE": "Started fictional-secret"}) + "\n" + json.dumps({"MESSAGE": "password=fictional-secret"})
        with mock.patch.object(self.manager, "details", return_value=project): value = self.manager.logs(project["id"])
        self.assertIn("_COMM=systemd", self.command.call_args.args[0])
        self.assertNotIn("fictional-secret", value["logs"])
        self.assertIn("启动：1 次", value["logs"])

    def test_tool_errors_are_fixed_messages_without_command_diagnostics(self):
        self.command.return_value = SimpleNamespace(returncode=1, stdout="", stderr="password=fictional-secret")
        with self.assertRaises(ExternalProjectError) as caught: self.manager._run(["systemctl", "show", "sample.service"])
        self.assertNotIn("fictional-secret", str(caught.exception))


class ExternalDirectoryAndPM2Tests(unittest.TestCase):
    def test_hidden_hermes_install_is_discovered_without_reading_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve(); install = home / ".hermes/hermes-agent"
            (install / "hermes_cli").mkdir(parents=True)
            (install / "hermes_cli/main.py").write_text("raise AssertionError('must not execute')")
            (install / "pyproject.toml").write_text('[project]\nname = "hermes-agent"\nversion = "0.9.0"\n')
            (home / ".hermes/.env").write_text("TOKEN=fictional-secret")
            owner = SimpleNamespace(pw_dir=str(home), pw_uid=1234, pw_name="fixture")
            manager = ExternalProjects(mock.Mock())
            original = Path.read_text
            def read(path, *args, **kwargs):
                self.assertEqual(path, install / "pyproject.toml")
                return original(path, *args, **kwargs)
            with mock.patch.object(manager, "_application_homes", return_value=[owner]), \
                 mock.patch.object(manager, "_directories", return_value=[]), mock.patch.object(Path, "read_text", read):
                projects = manager._hermes([])
                self.assertEqual(len(projects), 1)
                value = projects[0]
                self.assertEqual(value["product"], "Hermes Agent")
                self.assertEqual(value["version"], "0.9.0")
                self.assertEqual(value["capabilities"], [])
                self.assertEqual(manager.details(value["id"])["working_directory"], str(install))
                self.assertNotIn("fictional-secret", json.dumps(projects))
                self.assertEqual(manager._hermes([{"working_directory": str(install)}]), [])
            manager.command.assert_not_called()

    def test_hermes_config_directory_alone_and_unrelated_symlinks_are_not_projects(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve(); (home / ".hermes").mkdir()
            owner = SimpleNamespace(pw_dir=str(home), pw_uid=1234, pw_name="fixture")
            manager = ExternalProjects(mock.Mock())
            with mock.patch.object(manager, "_application_homes", return_value=[owner]):
                self.assertEqual(manager._hermes([]), [])
                outside = home / "other-code"; (outside / "hermes_cli").mkdir(parents=True)
                (outside / "hermes_cli/main.py").touch(); (outside / "pyproject.toml").touch()
                (home / ".hermes/hermes-agent").symlink_to(outside)
                self.assertEqual(manager._hermes([]), [])

    def test_user_service_discovery_details_and_management_use_its_own_user_manager(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder); directory = home / ".config/systemd/user"; directory.mkdir(parents=True)
            (directory / "hermes-gateway.service").touch()
            (directory / "hermes@.service").touch()
            owner = SimpleNamespace(pw_dir=str(home), pw_uid=1234, pw_name="fixture")
            manager = ExternalProjects(mock.Mock())
            text = unit("hermes-gateway.service").replace("/etc/systemd/system/", str(directory) + "/")
            with mock.patch.object(manager, "_application_homes", return_value=[owner]), \
                 mock.patch.object(manager, "_user_systemctl", return_value=text) as control, \
                 mock.patch("linux_manager.external_projects.pwd.getpwuid", return_value=owner), \
                 mock.patch.object(manager, "_listeners", return_value=[]):
                projects = manager._user_systemd()
                self.assertEqual(len(projects), 1)
                project = projects[0]
                self.assertEqual(project["id"], "external:systemd-user:1234:hermes-gateway.service")
                self.assertEqual(manager.details(project["id"])["owner_uid"], 1234)
                with mock.patch.object(manager, "details", side_effect=[project, dict(project, state="inactive")]):
                    manager.manage(project["id"], "stop", manager.fingerprint(project))
                control.assert_called_with(owner, ["stop", "hermes-gateway.service"], timeout=90)
            manager.command.assert_not_called()

    def test_user_service_listener_matching_is_scoped_to_its_owner(self):
        project = {"kind": "systemd-user", "owner_uid": 1234, "unit": "hermes.service"}
        process = ("/usr/bin/python3", "/opt/hermes", "0::/user.slice/user-1234.slice/user@1234.service/app.slice/hermes.service", "100")
        self.assertTrue(ExternalProjects._unit_owns_process(project, process))
        self.assertFalse(ExternalProjects._unit_owns_process(dict(project, owner_uid=5678), process))
        self.assertFalse(ExternalProjects._unit_owns_process(dict(project, kind="systemd"), process))

    def test_user_service_scan_does_not_start_missing_user_manager(self):
        manager = ExternalProjects(mock.Mock())
        owner = SimpleNamespace(pw_uid=1234, pw_name="fixture")
        with mock.patch.object(Path, "is_socket", return_value=False):
            with self.assertRaises(ExternalProjectError): manager._user_systemctl(owner, ["show", "hermes.service"])
        manager.command.assert_not_called()

    def test_generic_stopped_user_service_is_discovered_from_definition_without_starting_manager(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); directory = root / ".config/systemd/user"; directory.mkdir(parents=True)
            (directory / "sample.service").write_text('[Service]\nWorkingDirectory=%h/sample\nEnvironment=TOKEN=fictional-secret\nExecStart=/usr/bin/python3 app.py\n')
            owner = SimpleNamespace(pw_dir=str(root), pw_uid=1234, pw_name="fixture")
            manager = ExternalProjects(mock.Mock())
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root) + "/",)), \
                 mock.patch.object(manager, "_application_homes", return_value=[owner]), \
                 mock.patch.object(manager, "_user_systemctl", side_effect=ExternalProjectError("offline")), \
                 mock.patch.object(manager, "_proxy_routes", return_value=[]), \
                 mock.patch.object(manager, "_listeners", return_value=[]), \
                 mock.patch("linux_manager.external_projects.pwd.getpwuid", return_value=owner):
                values = manager._user_systemd()
                self.assertEqual(len(values), 1)
                value = values[0]
                self.assertEqual(value["working_directory"], str(root / "sample"))
                self.assertEqual(value["capabilities"], [])
                self.assertEqual(manager.details(value["id"])["working_directory"], str(root / "sample"))
                self.assertNotIn("fictional-secret", json.dumps(values))
            manager.command.assert_not_called()

    def test_user_service_specifiers_have_same_fingerprint_in_scan_and_details(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); directory = root / ".config/systemd/user"; directory.mkdir(parents=True)
            (directory / "sample.service").touch()
            owner = SimpleNamespace(pw_dir=str(root), pw_uid=1234, pw_name="fixture")
            text = unit().replace("/etc/systemd/system/", str(directory) + "/").replace("/opt/sample", "%h/sample")
            manager = ExternalProjects(mock.Mock())
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root) + "/",)), \
                 mock.patch.object(manager, "_application_homes", return_value=[owner]), \
                 mock.patch.object(manager, "_user_systemctl", return_value=text), \
                 mock.patch.object(manager, "_proxy_routes", return_value=[]), \
                 mock.patch.object(manager, "_listeners", return_value=[]), \
                 mock.patch("linux_manager.external_projects.pwd.getpwuid", return_value=owner):
                value = manager._user_systemd()[0]
                details = manager.details(value["id"])
                self.assertEqual(manager.fingerprint(value), manager.fingerprint(details))
                self.assertEqual(details["working_directory"], str(root / "sample"))

    def test_directory_version_is_selected_without_exposing_package_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); app = root / "sample"; app.mkdir()
            (app / "package.json").write_text(json.dumps({"version": "1.2.3", "token": "fictional-secret"}))
            with mock.patch("linux_manager.external_projects._CUSTOM_ROOTS", (str(root) + "/",)):
                project = ExternalProjects.directory(str(app))
                self.assertEqual(project["version"], "1.2.3")
                self.assertNotIn("fictional-secret", json.dumps(project))
                self.assertEqual(project["capabilities"], [])
                private = root / ".ssh"; private.mkdir()
                with self.assertRaises(ExternalProjectError): ExternalProjects.directory(str(private))
                link = root / "outside"; link.symlink_to("/etc")
                with self.assertRaises(ExternalProjectError): ExternalProjects.directory(str(link))

    def test_pm2_saved_records_strip_all_environment_and_never_start_daemon(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as folder:
            root = Path(folder); home = root / ".pm2"; home.mkdir(); (home / "pids").mkdir()
            app = str(root / "project")
            (home / "dump.pm2").write_text(json.dumps([{"name": "fixture", "pm_cwd": app, "pm_exec_path": app + "/app.js",
                                                       "env": {"TOKEN": "fictional-secret"}, "PASSWORD": "fictional-secret"}]))
            (home / "pm2.pid").write_text("90"); (home / "pids/fixture-0.pid").write_text("42")
            sock = socket.socket(socket.AF_UNIX); self.addCleanup(sock.close); sock.bind(str(home / "rpc.sock"))
            command = mock.Mock()
            manager = ExternalProjects(command)
            owner = SimpleNamespace(pw_dir=str(root), pw_uid=0)
            with mock.patch.object(manager, "_pm2_homes", return_value=[(owner, home)]), \
                 mock.patch.object(manager, "_process", return_value=("/usr/bin/node", app, "scope", "100")):
                projects = manager._pm2()
            self.assertEqual(len(projects), 1)
            self.assertEqual(projects[0]["state"], "active")
            self.assertNotIn("fictional-secret", json.dumps(projects))
            self.assertNotIn("env", projects[0])
            command.assert_not_called()


class MemoryVault:
    def __init__(self): self.items = {}
    def get(self, key): return dict(self.items.get(key, {}))
    def put(self, key, value): self.items[key] = dict(value)


class ExternalProjectControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name), MemoryVault())
        self.controller = Controller(self.store)
        self.connection = Connection(label="fixture", host="fixture.invalid")
        self.transport = mock.Mock(); self.controller.transport = mock.Mock(return_value=self.transport)

    def test_credentials_are_per_server_and_project_and_only_saved_locally(self):
        identifier = "external:systemd:sample.service"
        values = {"username": "fixture", "password": "fictional-password", "url": "https://fixture.invalid/admin", "notes": "fixture"}
        self.controller.save_external_project_credentials(self.connection, identifier, values)
        self.assertEqual(self.store.vault.get(credential_alias(self.connection, identifier)), values)
        other = self.connection.changed(host="other.invalid")
        self.assertEqual(self.store.vault.get(credential_alias(other, identifier)), {})
        self.transport.call.assert_not_called()
        self.assertFalse((self.store.directory / "external-projects.json").exists())

    def test_unsafe_management_urls_are_rejected(self):
        for url in ("javascript:alert(1)", "file:///etc/passwd", "https://fixture:fictional-password@fixture.invalid", "https://fixture.invalid:99999"):
            with self.subTest(url=url), self.assertRaises(ManagerError):
                self.controller.save_external_project_credentials(self.connection, "external:systemd:sample.service", {"url": url})
        self.assertFalse(self.store.vault.items)

    def test_unavailable_keychain_does_not_hide_server_details(self):
        self.transport.call.return_value = {"id": "external:systemd:sample.service"}
        with mock.patch.object(self.store.vault, "get", side_effect=ManagerError("unavailable")):
            result = self.controller.external_project_information(self.connection, "external:systemd:sample.service")
        self.assertEqual(result["project"]["id"], "external:systemd:sample.service")
        self.assertTrue(result["credentials_warning"])

    def test_refresh_all_requests_builtins_and_external_projects_together(self):
        self.transport.call.return_value = {"projects": [], "warnings": [], "builtin_details": {
            "hysteria2": {"service": "hysteria2", "installed": True, "port": 12345, "units": [{"unit": "sing-box.service", "ActiveState": "active"}]}}}
        result = self.controller.external_projects(self.connection, include_builtin=True)
        self.assertTrue(self.transport.call.call_args.args[0]["include_builtin"])
        project = result["projects"][0]
        self.assertEqual(project["id"], "builtin:hysteria2")
        self.assertEqual(project["ports"][0]["protocol"], "udp")
        self.assertEqual(project["capabilities"], [])

    def test_refresh_all_returns_absent_builtin_info_to_replace_stale_cache(self):
        self.transport.call.return_value = {"projects": [], "warnings": [], "builtin_details": {
            "hysteria2": {"service": "hysteria2", "installed": False}}}
        result = self.controller.external_projects(self.connection, include_builtin=True)
        self.assertEqual(result["projects"], [])
        self.assertFalse(result["builtin_information"]["hysteria2"]["data"]["installed"])

    def test_directory_registration_is_server_scoped_and_keeps_secrets_out_of_json(self):
        identifier = "external:directory:" + "a" * 64
        self.transport.call.return_value = {"id": identifier, "working_directory": "/opt/fixture"}
        self.controller.register_external_directory(self.connection, "/opt/fixture")
        self.controller.save_external_project_credentials(self.connection, identifier, {"password": "fictional-password"})
        raw = (self.store.directory / "external-projects.json").read_text()
        self.assertNotIn("fictional-password", raw)
        self.transport.call.return_value = {"projects": [], "warnings": []}
        self.controller.external_projects(self.connection.changed(host="other.invalid"))
        self.assertEqual(self.transport.call.call_args.args[0]["directories"], [])
        self.controller.external_projects(self.connection)
        self.assertEqual(self.transport.call.call_args.args[0]["directories"], ["/opt/fixture"])
        self.controller.forget_external_directory(self.connection, identifier)
        self.assertTrue(self.store.vault.get(credential_alias(self.connection, identifier)))

    def test_corrupt_registration_is_preserved(self):
        path = self.store.directory / "external-projects.json"; path.write_text("invalid")
        with self.assertRaises(ManagerError): self.controller.external_projects(self.connection)
        self.assertEqual(path.read_text(), "invalid")
        self.transport.call.assert_not_called()


class ExternalAgentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_linux_manager import REMOTE
        cls.remote = REMOTE

    def test_existing_dispatch_routes_new_reads_through_bundled_module(self):
        manager = mock.Mock(); manager.discover.return_value = {"projects": [], "warnings": []}
        factory = mock.Mock(return_value=manager)
        with mock.patch.object(self.remote.os, "geteuid", return_value=0), \
             mock.patch.dict(self.remote._external_projects, ExternalProjects=factory):
            result = self.remote.dispatch({"action": "external_projects", "directories": []})
        self.assertEqual(result, {"projects": [], "warnings": []})
        excluded = factory.call_args.args[1]
        self.assertIn("nginx.service", excluded)
        self.assertIn("cli-proxy-api.service", excluded)

    def test_service_task_uses_same_serial_handler_and_fingerprint(self):
        params = {"service": "external:systemd:sample.service", "action": "stop", "external_fingerprint": "fixture"}
        with mock.patch.object(self.remote, "external_project_call", return_value={"action": "stop"}) as call, \
             mock.patch.object(self.remote, "step"):
            result = self.remote.manage_service(params)
        call.assert_called_once_with("manage", params)
        self.assertEqual(result, {"action": "stop"})

    def test_registered_directories_are_deduplicated(self):
        project = {"id": "external:directory:fixture", "kind": "directory"}
        manager = mock.Mock(); manager.discover.return_value = {"projects": [project], "warnings": []}
        manager.directory.return_value = dict(project)
        with mock.patch.dict(self.remote._external_projects, ExternalProjects=mock.Mock(return_value=manager)):
            result = self.remote.external_project_call("external_projects", {"directories": ["/opt/fixture"]})
        self.assertEqual(len(result["projects"]), 1)
        self.assertTrue(result["projects"][0]["registered_local"])

    def test_invalid_directory_cannot_hide_other_projects(self):
        manager = mock.Mock(); manager.discover.return_value = {"projects": [{"id": "fixture"}], "warnings": []}
        manager.directory.side_effect = self.remote._external_projects["ExternalProjectError"]("fixture missing")
        with mock.patch.dict(self.remote._external_projects, ExternalProjects=mock.Mock(return_value=manager)):
            result = self.remote.external_project_call("external_projects", {"directories": ["/opt/missing"]})
        self.assertEqual(len(result["projects"]), 1)
        self.assertTrue(result["warnings"])


if __name__ == "__main__": unittest.main()
