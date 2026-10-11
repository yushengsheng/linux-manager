import base64
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager.models import Connection, ManagerError, Redactor, Store, atomic_private, validate_host, validate_user
from linux_manager.transport import Askpass, BOOTSTRAP, SSH
from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.releases import LATEST_STABLE, SPECIFIC_VERSION, EXCHANGE_REPOSITORY, exchange_version, download_exchange

spec = importlib.util.spec_from_file_location("remote_agent_test", BASE / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REMOTE)


class MemoryVault:
    def __init__(self):
        self.items = {}

    def get(self, identifier):
        return self.items.get(identifier, {}).copy()

    def put(self, identifier, values):
        self.items[identifier] = values.copy()

    def delete(self, identifier):
        self.items.pop(identifier, None)


class ReleaseSelectionTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch("linux_manager.releases.github_cli", return_value=None)
        patch.start(); self.addCleanup(patch.stop)

    def release(self, version="v1.1.99"):
        return {"tag_name": version, "draft": False, "prerelease": False, "assets": [{"name": "install-linux.sh", "browser_download_url": f"https://github.com/{EXCHANGE_REPOSITORY}/releases/download/{version}/install-linux.sh"}]}

    def response(self, release):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(release).encode()
        return response

    def test_latest_is_resolved_from_official_repository_to_concrete_version(self):
        with mock.patch("linux_manager.releases.urllib.request.urlopen", return_value=self.response(self.release())) as request:
            self.assertEqual(exchange_version(), "v1.1.99")
            sent = request.call_args.args[0]
            self.assertEqual(sent.full_url, f"https://api.github.com/repos/{EXCHANGE_REPOSITORY}/releases/latest")
            self.assertNotIn("Authorization", dict(sent.header_items()))

    def test_drafts_prereleases_and_missing_official_installer_are_rejected(self):
        for changes in [{"draft": True}, {"prerelease": True}, {"assets": []}, {"tag_name": "v1.1.99-rc1"}, {"assets": [{"name": "install-linux.sh", "browser_download_url": "https://untrusted.invalid/install-linux.sh"}]}]:
            with self.subTest(changes=changes), mock.patch("linux_manager.releases.urllib.request.urlopen", return_value=self.response(self.release() | changes)):
                with self.assertRaises(ManagerError): exchange_version()

    def test_specific_version_is_preserved_and_server_response_must_match(self):
        with mock.patch("linux_manager.releases.urllib.request.urlopen", return_value=self.response(self.release("v1.1.84"))) as request:
            self.assertEqual(exchange_version("v1.1.84"), "v1.1.84")
            self.assertTrue(request.call_args.args[0].full_url.endswith("/tags/v1.1.84"))
        with mock.patch("linux_manager.releases.urllib.request.urlopen", return_value=self.response(self.release())):
            with self.assertRaises(ManagerError): exchange_version("v1.1.84")
        with mock.patch("linux_manager.releases.urllib.request.urlopen") as request:
            for invalid in ["latest", "", "v1.1.99;id", "../latest"]:
                with self.assertRaises(ManagerError): exchange_version(invalid)
            request.assert_not_called()

    def test_network_failure_does_not_fall_back_to_another_version(self):
        with mock.patch("linux_manager.releases.urllib.request.urlopen", side_effect=urllib.error.URLError("unavailable")) as request:
            with self.assertRaises(ManagerError): exchange_version()
            self.assertEqual(request.call_count, 2)
            self.assertTrue(request.call_args.args[0].full_url.endswith("/releases/latest"))

    def app(self, mode=LATEST_STABLE):
        app = object.__new__(App)
        app.current = Connection(host="host.invalid", username="tester", password="dummy-password")
        app._ready = mock.Mock(return_value=True)
        for name, value in {"deploy_choice": "小军交易系统", "deploy_host": "", "deploy_port": "26483", "deploy_backend": "18880", "deploy_version": "v1.1.84", "version_mode": mode}.items():
            variable = mock.Mock(); variable.get.return_value = value
            setattr(app, name, variable)
        app.controller = mock.Mock()
        app.controller.deployment_preview.side_effect = lambda c, params: {"version":params["version"],"fingerprint":"fictional-preview","changes":[],"installed":False,"action":"install"}
        app._run = mock.Mock(side_effect=lambda worker, callback, message: callback(worker()))
        return app

    def test_preview_submits_only_the_exact_version_shown(self):
        for mode, version in [(LATEST_STABLE, "v1.1.99"), (SPECIFIC_VERSION, "v1.1.84")]:
            app = self.app(mode); app._execute = mock.Mock()
            with mock.patch("linux_manager.gui.exchange_version", return_value=version) as resolve:
                app._deploy()
            resolve.assert_called_once_with(None if mode == LATEST_STABLE else "v1.1.84")
            params, description = app._execute.call_args.args
            self.assertEqual(params["version"], version)
            self.assertIn("目标版本：" + version, description)

    def test_canceling_version_confirmation_submits_no_remote_task(self):
        app = self.app()
        with mock.patch("linux_manager.gui.exchange_version", return_value="v1.1.99"), mock.patch("linux_manager.gui.messagebox.askyesno", return_value=False) as confirm:
            app._deploy()
        self.assertIn("v1.1.99", confirm.call_args.args[1])
        app.controller.execute.assert_not_called()

    def test_remote_rejects_unconfirmed_version_before_any_mutation(self):
        with mock.patch.object(REMOTE, "command") as command, mock.patch.object(REMOTE, "download_verified") as download:
            for params in [{}, {"version": "latest"}]:
                with self.assertRaises(REMOTE.OperationError): REMOTE.deploy_exchange(params)
            command.assert_not_called(); download.assert_not_called()

    def test_remote_rejects_release_tag_different_from_confirmed_version(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(self.release()).encode()
        with mock.patch.object(REMOTE.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(REMOTE.OperationError): REMOTE.github_release(EXCHANGE_REPOSITORY, "v1.1.84")

    def test_private_release_uses_local_github_login_without_exposing_tokens(self):
        with mock.patch("linux_manager.releases.github_cli", return_value="gh"), mock.patch("linux_manager.releases.urllib.request.urlopen", side_effect=urllib.error.URLError("private")), mock.patch("linux_manager.releases.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(self.release()).encode(), b"")) as run:
            self.assertEqual(exchange_version(), "v1.1.99")
            self.assertEqual(run.call_args.args[0], ["gh", "api", "--hostname", "github.com", f"/repos/{EXCHANGE_REPOSITORY}/releases/latest"])
            self.assertNotIn("env", run.call_args.kwargs)

    def test_local_release_download_rejects_corrupted_package(self):
        release = self.release()
        content = b"downloaded release bytes"
        release["assets"].append({"name": "xiaojun-bn-v1.1.99-linux-amd64.tar.gz", "digest": "sha256:" + hashlib.sha256(content).hexdigest()})
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "release.tar.gz"
            def download(asset, version, target): target.write_bytes(content)
            with mock.patch("linux_manager.releases.release_info", return_value=release), mock.patch("linux_manager.releases.download_asset", side_effect=download):
                self.assertEqual(download_exchange("v1.1.99", destination), hashlib.sha256(content).hexdigest())
                release["assets"][-1]["digest"] = "sha256:" + "0" * 64
                with self.assertRaises(ManagerError): download_exchange("v1.1.99", destination)

    def test_remote_upload_is_verified_and_kept_out_of_task_request(self):
        content = b"a verified release"
        params = {"operation": "deploy", "service": "exchange", "version": "v1.1.99", "release_archive": base64.b64encode(content).decode(), "release_sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")):
                task = REMOTE.start_task(params)["task_id"]
                path = base / "tasks" / task
                self.assertEqual((path / "release.tar.gz").read_bytes(), content)
                request = json.loads((path / "request.json").read_text())
                self.assertNotIn("release_archive", request)
                self.assertEqual((path / "release.tar.gz").stat().st_mode & 0o777, 0o600)
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(REMOTE, "ROOT", Path(folder)), mock.patch.object(REMOTE, "command") as command:
            with self.assertRaises(REMOTE.OperationError): REMOTE.start_task(params | {"release_sha256": "0" * 64})
            command.assert_not_called()


class LocalSecurityTests(unittest.TestCase):
    def test_profiles_never_save_authentication_secrets_and_are_owner_only(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder), vault=MemoryVault())
            connection = Connection(host="host.invalid", username="tester", password="unique-password", sudo_password="sudo-secret", key_passphrase="key-secret", remember=False)
            store.save([connection])
            raw = (Path(folder) / "profiles.json").read_text()
            for secret in [connection.password, connection.sudo_password, connection.key_passphrase]:
                self.assertNotIn(secret, raw)
                self.assertNotIn(secret, repr(connection))
            self.assertEqual((Path(folder) / "profiles.json").stat().st_mode & 0o777, 0o600)
            restored = store.profiles()[0]
            self.assertEqual(restored.identifier, connection.identifier)
            self.assertEqual(restored.password, "")

    def test_input_cannot_inject_ssh_config_or_shell(self):
        for host in ["-oProxyCommand=echo", "host\nUser attacker", "$(whoami)", "host;id", "https://host", "bad..domain"]:
            with self.subTest(host=host), self.assertRaises(ManagerError):
                validate_host(host)
        for account in ["tester\nPermitRootLogin yes", "-x", "a;id", "a b"]:
            with self.assertRaises(ManagerError): validate_user(account)

    def test_redaction_before_diagnostic_export(self):
        secret = "a-password-with-special-characters!"
        path = "/private/example/credentials/private-key"
        redactor = Redactor(secret, path, "host.invalid", "tester")
        value = redactor.text(f"{secret} {path} tester@host.invalid token=abcdef hysteria2://secret@host.invalid:9999/")
        for denied in [secret, path, "tester", "host.invalid", "abcdef", "hysteria2://"]:
            self.assertNotIn(denied, value)

    def test_real_askpass_process_receives_secret_without_environment_or_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = "special:socket-secret@@"
            with Askpass(Path(folder), secret) as environment:
                self.assertNotIn(secret, json.dumps(environment))
                arguments = [environment["SSH_ASKPASS"]]
                self.assertNotIn(secret, " ".join(arguments))
                result = subprocess.run(arguments, capture_output=True, text=True, env=os.environ | environment, check=True)
                self.assertEqual(result.stdout.strip(), secret)

    def test_remote_envelope_handles_sudo_consumed_or_unconsumed_password(self):
        agent = "print('RPC_OK',REQUEST['value'],bool(AGENT_SOURCE))"
        packet = base64.b64encode(json.dumps({"request": {"value": "safe"}, "agent": agent}).encode()).decode()
        for prefix in ["", "sudo-password\n"]:
            result = subprocess.run([sys.executable, "-c", BOOTSTRAP], input=prefix + "LMREQUEST:" + packet + "\n", capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RPC_OK safe True", result.stdout)

    def test_connection_config_keeps_authentication_values_out_of_ssh_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            connection = Connection(host="host.invalid", username="tester", password="secret-password")
            ssh = SSH(connection, Path(folder))
            ssh.trust("host.invalid ssh-ed25519 AAAATEST\n")
            response = subprocess.CompletedProcess([], 0, 'LM_RESULT:{"ok":true,"data":{"safe":true}}\n', "")
            with mock.patch.object(ssh, "trusted", return_value=True), mock.patch("linux_manager.transport.subprocess.run", return_value=response) as run:
                self.assertEqual(ssh.call({"action": "ping"}), {"safe": True})
                arguments = run.call_args.args[0]
                self.assertNotIn(connection.password, " ".join(arguments))
                self.assertNotIn(connection.host, " ".join(arguments))
                self.assertNotIn(connection.username, " ".join(arguments))
                self.assertNotIn(connection.password, json.dumps(run.call_args.kwargs["env"]))

    def test_changed_server_identity_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller(Store(Path(folder)))
            original = mock.Mock()
            original.known_hosts = Path(folder) / "known_hosts"
            original.known_hosts.write_text("host.invalid ssh-ed25519 OLD\n")
            candidate = mock.Mock()
            candidate.trusted.return_value = False
            candidate.fingerprint.return_value = ("SHA256:new", "host.invalid ssh-ed25519 NEW\n")
            with self.assertRaises(ManagerError): controller.trust_same_server(original, candidate)
            candidate.trust.assert_not_called()

    def test_editing_endpoint_requires_reconnection_before_any_operation(self):
        app = object.__new__(App)
        app.current = Connection(host="old.invalid", username="tester", password="dummy-password")
        app.report = {"supported": True}
        for name, value in {"host_var": "new.invalid", "user_var": "tester", "port_var": "22", "auth_var": "密码登录", "key_var": ""}.items():
            variable = mock.Mock(); variable.get.return_value = value
            setattr(app, name, variable)
        app.connection_badge = mock.Mock(); app.notebook = mock.Mock()
        app.pages = {"连接服务器": object()}
        with mock.patch("linux_manager.gui.messagebox.showinfo"):
            self.assertFalse(app._ready())
        self.assertIsNone(app.report)


class RemoteOperationTests(unittest.TestCase):
    def setUp(self):
        REMOTE.SECRETS.clear()

    def test_account_rollback_preserves_other_users_added_after_backup(self):
        original = "old:x:1000:1000::/home/old:/bin/bash\nservice:x:200:200::/:/bin/false\n"
        current = "new:x:1000:1000::/home/new:/bin/bash\nservice:x:200:200::/:/bin/false\nlater:x:1001:1001::/home/later:/bin/bash\n"
        result = REMOTE.merge_accounts("passwd", current, original, {"account_users": ["old", "new"], "renamed_from": "old", "renamed_to": "new"})
        self.assertIn("later:x:1001", result)
        self.assertIn("old:x:1000", result)
        self.assertNotIn("new:x:1000", result)

    def test_account_rollback_restores_membership_without_removing_other_admins(self):
        current = "sudo:x:27:current,later,new\nnew:x:1000:\n"
        old = "sudo:x:27:current,old\nold:x:1000:\n"
        result = REMOTE.merge_accounts("group", current, old, {"account_users": ["old", "new"], "renamed_from": "old", "renamed_to": "new"})
        self.assertIn("sudo:x:27:current,later,old", result)
        self.assertIn("old:x:1000:", result)

    def test_new_account_rollback_preserves_later_group_changes(self):
        result = REMOTE.merge_accounts("group", "sudo:x:27:existing,created,later\ncreated:x:1001:\n", "sudo:x:27:existing\n", {"account_users": ["created"], "created_home": "/home/created"})
        self.assertIn("existing,later", result)
        self.assertNotIn("created", result)

    def test_malformed_task_ids_are_rejected_before_filesystem_access(self):
        for value in ["../etc/passwd", "/tmp/task", "f" * 23, "a" * 25, None]:
            with self.assertRaises(REMOTE.OperationError): REMOTE.validate_task_id(value)

    def test_unrecognized_operations_do_not_start_a_process(self):
        with mock.patch.object(REMOTE, "command") as command:
            with self.assertRaises(REMOTE.OperationError): REMOTE.start_task({"operation": "shell", "command": "echo bad"})
            command.assert_not_called()

    def test_archive_traversal_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for kind in ["traversal", "symlink"]:
                package = Path(folder) / (kind + ".tar.gz")
                with tarfile.open(package, "w:gz") as archive:
                    member = tarfile.TarInfo("../escape" if kind == "traversal" else "link")
                    if kind == "symlink": member.type = tarfile.SYMTYPE; member.linkname = "/etc/passwd"
                    archive.addfile(member)
                with self.assertRaises(REMOTE.OperationError): REMOTE.unpack(package, Path(folder) / kind)
                self.assertFalse((Path(folder).parent / "escape").exists())

    def test_backup_restore_roundtrip_and_file_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "a" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            config = base / "settings.conf"; config.write_text("original"); config.chmod(0o640)
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "TASK", task), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 1, "", "")):
                REMOTE.backup_files([str(config)])
                config.write_text("changed")
                REMOTE.restore_files(identifier)
                self.assertEqual(config.read_text(), "original")
                self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_recovery_does_not_undo_committed_operation(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "b" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            (task / "status.json").write_text(json.dumps({"state": "succeeded"}))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "restore_files") as restore:
                REMOTE.recover(identifier)
                restore.assert_not_called()

    def test_failed_background_job_erases_secret_request_and_sanitizes_result(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "c" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            secret = "private-task-password"
            (task / "request.json").write_text(json.dumps({"operation": "password", "new_password": secret}))
            (task / "status.json").write_text(json.dumps({"state": "queued"}))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "system_password", side_effect=REMOTE.OperationError(secret)), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")):
                REMOTE.run_task(identifier)
            self.assertFalse((task / "request.json").exists())
            raw = (task / "status.json").read_text()
            self.assertNotIn(secret, raw)
            self.assertEqual(json.loads(raw)["state"], "failed")

    def test_transaction_confirm_requires_pending_state(self):
        with mock.patch.object(REMOTE, "status_task", return_value={"state": "failed"}), mock.patch.object(REMOTE, "command") as command:
            with self.assertRaises(REMOTE.OperationError): REMOTE.confirm_task("d" * 24)
            command.assert_not_called()

    def test_confirmation_is_persisted_before_watchdog_is_stopped(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "d" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            (task / "status.json").write_text(json.dumps({"state": "awaiting_verification"}))
            def stop_timer(*args, **kwargs):
                self.assertEqual(json.loads((task / "status.json").read_text())["state"], "succeeded")
                REMOTE.recover(identifier)
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "command", side_effect=stop_timer), mock.patch.object(REMOTE, "restore_files") as restore:
                REMOTE.confirm_task(identifier)
                restore.assert_not_called()

    def test_parallel_submissions_cannot_queue_two_mutations(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(REMOTE, "ROOT", Path(folder)), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")):
                def attempt(_):
                    try:
                        REMOTE.start_task({"operation": "updates"})
                        return True
                    except REMOTE.OperationError:
                        return False
                with ThreadPoolExecutor(max_workers=2) as pool:
                    self.assertEqual(sum(pool.map(attempt, range(2))), 1)

    def test_exchange_restart_requires_explicit_maintenance_confirmation(self):
        loaded = {"LoadState": "loaded"}
        with mock.patch.object(REMOTE, "unit_info", return_value=loaded), mock.patch.object(REMOTE, "command") as command:
            with self.assertRaises(REMOTE.OperationError): REMOTE.manage_service({"service": "exchange", "action": "restart"})
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
