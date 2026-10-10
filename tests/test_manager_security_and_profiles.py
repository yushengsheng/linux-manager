import ast
import json
from pathlib import Path
import subprocess
import tempfile
import tkinter as tk
from types import SimpleNamespace
import unittest
from unittest import mock

from test_linux_manager import REMOTE, MemoryVault
from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.help_texts import HELP
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.vault import LocalVault


class ProfileTests(unittest.TestCase):
    def test_multiple_servers_and_accounts_restore_separate_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = MemoryVault(); store = Store(Path(folder), vault)
            profiles = [Connection(host=host, username=user, password=secret) for host, user, secret in [("one.invalid", "owner", "fictional-first"), ("one.invalid", "alternate", "fictional-second"), ("two.invalid", "owner", "fictional-third")]]
            store.save(profiles)
            restored = Store(Path(folder), vault).profiles()
            self.assertEqual([item.password for item in restored], [item.password for item in profiles])
            raw = (Path(folder) / "profiles.json").read_text()
            self.assertTrue(all(item.password not in raw for item in profiles))
            self.assertTrue(all(key == item.identifier for key, item in zip(vault.items, profiles)))

    def test_saving_one_profile_does_not_erase_another_profiles_saved_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = MemoryVault(); store = Store(Path(folder), vault)
            a = Connection(host="one.invalid", username="owner", password="fictional-first")
            b = Connection(host="two.invalid", username="owner", password="fictional-second")
            store.save([a, b])
            store.save([a.changed(password="changed-fictional"), b.changed(password="")], {a.identifier})
            self.assertEqual(vault.get(b.identifier)["password"], "fictional-second")
            self.assertEqual(store.profiles()[0].password, "changed-fictional")

    def test_forgetting_or_removing_profile_deletes_only_its_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = MemoryVault(); store = Store(Path(folder), vault)
            a = Connection(host="one.invalid", username="owner", password="fictional-first")
            b = Connection(host="two.invalid", username="owner", password="fictional-second")
            store.save([a, b]); store.save([a.changed(remember=False), b], {a.identifier})
            self.assertNotIn(a.identifier, vault.items)
            self.assertEqual(store.profiles()[0].password, "")
            store.remove(a.identifier)
            self.assertEqual([item.identifier for item in store.profiles()], [b.identifier])
            self.assertIn(b.identifier, vault.items)

    def test_locked_keychain_never_falls_back_to_plaintext(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = mock.Mock(); vault.put.side_effect = ManagerError("钥匙串未允许存取。")
            store = Store(Path(folder), vault)
            profile = Connection(host="one.invalid", username="owner", password="fictional-only-local")
            store.save([profile])
            self.assertTrue(store.last_warning)
            self.assertNotIn(profile.password, (Path(folder) / "profiles.json").read_text())
            vault.get.side_effect = ManagerError("未允许读取。")
            restored = store.profiles()
            self.assertEqual(restored[0].password, "")
            self.assertTrue(store.last_warning)

    def test_keychain_query_is_explicitly_local_and_identified_by_alias(self):
        identifier = "a" * 16
        query = LocalVault().query(identifier)
        self.assertIs(query["kSecAttrSynchronizable"], False)
        self.assertIs(query["kSecUseDataProtectionKeychain"], False)
        self.assertEqual(query["kSecAttrAccount"], identifier)
        with self.assertRaises(ManagerError): LocalVault().query("invalid-account")

    def test_password_and_rename_changes_are_scoped_to_host_and_account(self):
        controller = Controller(mock.Mock())
        current = Connection(host="one.invalid", username="owner", password="before")
        same_account = current.changed(identifier="a" * 16)
        other_user = current.changed(identifier="b" * 16, username="alternate")
        other_host = current.changed(identifier="c" * 16, host="two.invalid")
        profiles = [current, same_account, other_user, other_host]
        updated = current.changed(password="new-fictional")
        result, ids = controller.synchronize_profiles(profiles, current, updated, {"operation": "password", "username": "owner", "new_password": "new-fictional"})
        self.assertEqual([p.password for p in result], ["new-fictional", "new-fictional", "before", "before"])
        self.assertEqual(ids, {current.identifier, same_account.identifier})
        result, _ = controller.synchronize_profiles(profiles, current, current.changed(username="renamed"), {"operation": "rename_user", "old_username": "owner", "new_username": "renamed"})
        self.assertEqual([p.username for p in result], ["renamed", "renamed", "alternate", "owner"])

    def test_deleted_accounts_saved_secrets_are_forgotten_without_affecting_admin(self):
        admin = Connection(host="one.invalid", username="alternate", password="admin-fictional")
        deleted = admin.changed(identifier="d" * 16, username="owner", password="deleted-fictional")
        result, _ = Controller(mock.Mock()).synchronize_profiles([admin, deleted], admin, admin, {"operation": "delete_user", "username": "owner"})
        self.assertEqual(result[0].password, admin.password)
        self.assertFalse(result[1].remember)
        self.assertEqual(result[1].password, "")


class AccountProtectionTests(unittest.TestCase):
    def setUp(self):
        REMOTE.SECRETS.clear()

    def test_current_root_and_system_accounts_are_rejected_before_mutation(self):
        with mock.patch.object(REMOTE, "command") as command, mock.patch.object(REMOTE.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=99)):
            for account, admin in [("owner", "owner"), ("root", "alternate"), ("owner", "root"), ("service", "alternate")]:
                for handler in [REMOTE.account_access, REMOTE.delete_user]:
                    with self.assertRaises(REMOTE.OperationError): handler({"username": account, "verified_username": admin, "blocked": True})
            command.assert_not_called()

    def test_spare_admin_must_be_verified_on_fresh_connection_before_submission(self):
        controller = Controller(mock.Mock()); ssh = mock.Mock()
        controller.transport = mock.Mock(return_value=ssh)
        ssh.call.side_effect = ManagerError("备用连接无法验证。")
        connection = Connection(host="one.invalid", username="alternate", password="fictional")
        with self.assertRaises(ManagerError): controller.execute(connection, {"operation": "delete_user", "username": "owner"})
        ssh.call.assert_called_once_with({"action": "ping"})

    def test_delete_refuses_account_with_any_running_process(self):
        process = mock.Mock(); process.name = "123"; process.stat.return_value.st_uid = 1001
        with mock.patch.object(REMOTE.Path, "iterdir", return_value=[process]), mock.patch.object(REMOTE, "command") as command:
            with self.assertRaises(REMOTE.OperationError): REMOTE.require_unused_account(SimpleNamespace(pw_uid=1001, pw_name="owner"))
            command.assert_not_called()

    def test_deleted_user_rollback_restores_memberships_and_preserves_new_admin(self):
        extra = {"account_users": ["deleted"], "deleted_user": "deleted"}
        result = REMOTE.merge_accounts("group", "sudo:x:27:admin,later\n", "sudo:x:27:admin,deleted\ndeleted:x:1001:\n", extra)
        self.assertIn("sudo:x:27:admin,later,deleted", result)
        self.assertIn("deleted:x:1001:", result)
        result = REMOTE.merge_accounts("gshadow", "sudo:!:admin:admin,later\n", "sudo:!:admin,deleted:admin,deleted\n", extra)
        self.assertIn("sudo:!:admin,deleted:admin,later,deleted", result)

    def test_reenable_does_not_unlock_password_changed_outside_program(self):
        user = SimpleNamespace(pw_name="owner")
        saved = {"owner": {"unlock_on_restore": True, "locked_value": "!previous-hash"}}
        with mock.patch.object(REMOTE, "guarded_account", return_value=(user, "alternate")), mock.patch.object(REMOTE, "ssh_files_without_match"), mock.patch.object(REMOTE, "managed_accounts", return_value=saved), mock.patch.object(REMOTE.Path, "read_text", return_value="owner:!changed-hash:1:0:99999:7:::\n"), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE, "write_json"), mock.patch.object(REMOTE, "write_account_denials"), mock.patch.object(REMOTE, "command") as command:
            result = REMOTE.account_access({"blocked": False})
            self.assertTrue(result["requires_verification"])
            command.assert_not_called()

    def test_delete_keeps_files_and_arms_recovery_before_userdel(self):
        user = SimpleNamespace(pw_name="owner", pw_uid=1001)
        sequence = []
        with mock.patch.object(REMOTE, "guarded_account", return_value=(user, "alternate")), mock.patch.object(REMOTE, "ssh_files_without_match"), mock.patch.object(REMOTE, "require_unused_account"), mock.patch.object(REMOTE.Path, "exists", return_value=False), mock.patch.object(REMOTE.Path, "glob", return_value=[]), mock.patch.object(REMOTE, "backup_files", side_effect=lambda *args: sequence.append("backup")), mock.patch.object(REMOTE, "arm_recovery", side_effect=lambda *args: sequence.append("timer")), mock.patch.object(REMOTE, "managed_accounts", return_value={}), mock.patch.object(REMOTE, "write_json"), mock.patch.object(REMOTE, "write_account_denials"), mock.patch.object(REMOTE, "command", side_effect=lambda args: sequence.append(args)):
            result = REMOTE.delete_user({})
        self.assertEqual(sequence[:3], ["backup", "timer", ["userdel", "owner"]])
        self.assertTrue(result["files_retained"])
        self.assertEqual(result["verification"]["username"], "alternate")

    def test_invalid_security_limits_cannot_write_or_run_commands(self):
        with mock.patch.object(REMOTE, "command") as command, mock.patch.object(REMOTE, "backup_files") as backup:
            with self.assertRaises(REMOTE.OperationError): REMOTE.ssh_hardening({"max_auth_tries": 0})
            with self.assertRaises(REMOTE.OperationError): REMOTE.fail2ban_settings({"enabled": True, "ban_minutes": -1})
            command.assert_not_called(); backup.assert_not_called()

    def test_deletion_rollback_refuses_reused_user_id(self):
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.merge_accounts("passwd", "newperson:x:1001:1001::/home/newperson:/bin/bash\n", "deleted:x:1001:1001::/home/deleted:/bin/bash\n", {"account_users": ["deleted"], "deleted_user": "deleted"})

    def test_ssh_hardening_preserves_ports_and_authentication_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "sshd_config"
            original = "Port 2222\nPasswordAuthentication no\nDenyUsers blocked\nMaxAuthTries 6\nAllowTcpForwarding local\n"
            source.write_text(original)
            written = {}
            def write(path, content, mode=0o600): written[str(path)] = content
            params = {"max_auth_tries": 3, "login_grace": 120, "alive_interval": 60, "tcp_forwarding": "local", "x11_forwarding": False, "agent_forwarding": False}
            effective = {"maxauthtries": ["3"], "logingracetime": ["120"], "clientaliveinterval": ["60"], "clientalivecountmax": ["2"], "permitemptypasswords": ["no"], "loglevel": ["VERBOSE"], "allowtcpforwarding": ["local"], "x11forwarding": ["no"], "allowagentforwarding": ["no"]}
            with mock.patch.object(REMOTE, "ssh_files_without_match", return_value=[source]), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE, "private_write", side_effect=write), mock.patch.object(REMOTE, "ssh_configuration", return_value=effective), mock.patch.object(REMOTE, "command"):
                result = REMOTE.ssh_hardening(params)
            modified = written[str(source)]
            for line in ["Port 2222", "PasswordAuthentication no", "DenyUsers blocked"]:
                self.assertIn(line + "\n", modified)
                self.assertNotIn("# linux服务器管理已接管此项: " + line, modified)
            self.assertIn("AllowTcpForwarding local\n", written["/etc/ssh/sshd_config.d/01-linux-manager-protection.conf"])
            self.assertTrue(result["requires_verification"])

    def test_failed_recovery_is_visible_and_blocks_next_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "a" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            (task / "status.json").write_text(json.dumps({"state": "awaiting_verification"}))
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "restore_files", side_effect=REMOTE.OperationError("恢复失败")), mock.patch.object(REMOTE, "command") as command:
                REMOTE.recover(identifier)
                self.assertEqual(json.loads((task / "status.json").read_text())["state"], "recovery_failed")
                with self.assertRaises(REMOTE.OperationError): REMOTE.start_task({"operation": "updates"})
                command.assert_not_called()

    def test_general_security_restore_preserves_current_account_denials(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); identifier = "b" * 24
            task = base / "tasks" / identifier; task.mkdir(parents=True)
            etc = base / "system/etc"
            configuration = etc / "ssh/sshd_config.d/02-linux-manager-accounts.conf"
            configuration.parent.mkdir(parents=True)
            configuration.write_text("DenyUsers previously_blocked\n")
            (base / "blocked-accounts.json").write_text(json.dumps({"currently_blocked": {"unlock_on_restore": False}}))
            real_path = Path
            def mapped(value):
                text = str(value)
                return etc / text[5:] if text.startswith("/etc/") else real_path(value)
            result = subprocess.CompletedProcess([], 0, "denyusers currently_blocked\n", "")
            with mock.patch.object(REMOTE, "ROOT", base), mock.patch.object(REMOTE, "TASK", task), mock.patch.object(REMOTE, "Path", side_effect=mapped), mock.patch.object(REMOTE, "command", return_value=result):
                REMOTE.backup_files(["/etc/ssh/sshd_config.d"], {"service": "security"})
                configuration.write_text("DenyUsers currently_blocked\n")
                REMOTE.restore_files(identifier)
            self.assertIn("DenyUsers currently_blocked", configuration.read_text())
            self.assertNotIn("previously_blocked", configuration.read_text())


class HelpCoverageTests(unittest.TestCase):
    def test_help_dialog_remains_usable_while_a_job_runs(self):
        app = object.__new__(App); app.busy = False; app.buttons = []
        app.status = mock.Mock(); app.progress = mock.Mock()
        dialog = object.__new__(tk.Toplevel)
        dialog.winfo_children = mock.Mock()
        app.winfo_children = mock.Mock(return_value=[dialog])
        with mock.patch("linux_manager.gui.threading.Thread"):
            app._run(mock.Mock())
        dialog.winfo_children.assert_not_called()
        self.assertEqual(app.input_states, [])

    def test_every_literal_action_input_toggle_and_page_has_plain_language_help(self):
        source = Path(__file__).resolve().parents[1] / "linux_manager/gui.py"
        tree = ast.parse(source.read_text())
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr
                index = {"_button": 1, "_field": 2, "_check": 1, "_description": 1, "_help_label": 1}.get(method)
                if index is not None and len(node.args) > index and isinstance(node.args[index], ast.Constant):
                    found.append(node.args[index].value)
                if method == "Button":
                    titles = [keyword.value.value for keyword in node.keywords if keyword.arg == "text" and isinstance(keyword.value, ast.Constant)]
                    self.assertTrue(all(title == "？" for title in titles), "动作按钮必须使用带说明按钮的组件。")
        self.assertGreater(len(found), 65)
        self.assertEqual(sorted(set(found) - set(HELP)), [])
        self.assertTrue(all(len(HELP[topic]) >= 45 for topic in found))

    def test_fleet_check_only_inspects_trusted_profiles_without_switching_current(self):
        app = object.__new__(App)
        profile = Connection(host="one.invalid", username="owner", password="fictional-password")
        untrusted = Connection(host="two.invalid", username="owner", password="fictional-password")
        app.profiles = [profile, untrusted]; app.sessions = {}; app.current = profile
        app.events = mock.Mock(); app.controller = mock.Mock()
        app.controller.transport.side_effect = [mock.Mock(trusted=mock.Mock(return_value=True)), mock.Mock(trusted=mock.Mock(return_value=False))]
        app.controller.inspect.return_value = {"os": "test"}
        result = []
        app._run = mock.Mock(side_effect=lambda worker, callback, message: result.append(worker()))
        app._check_fleet()
        app.controller.inspect.assert_called_once_with(profile)
        app.controller.execute.assert_not_called()
        self.assertIs(app.current, profile)
        self.assertEqual(result[0][untrusted.identifier], ("需要首次确认身份", None))
