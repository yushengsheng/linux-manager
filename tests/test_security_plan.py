import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_linux_manager import REMOTE, MemoryVault
from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.key_info import encrypted_key
from linux_manager.models import Connection, ManagerError, Redactor, Store
from linux_manager.vault import LocalVault


class EncryptedKeyTests(unittest.TestCase):
    def test_real_generated_key_is_encrypted_and_only_correct_phrase_opens_it(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = MemoryVault(); controller = Controller(Store(Path(folder), vault))
            connection = Connection(host="fictional.invalid", username="owner")
            phrase = "fictional-key-password-for-local-test"
            key, public = controller.generate_key(connection, phrase)
            self.assertTrue(encrypted_key(key))
            self.assertEqual(Path(key).stat().st_mode & 0o777, 0o600)
            locked = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", key], capture_output=True)
            self.assertNotEqual(locked.returncode, 0)
            self.assertEqual(controller.public_key(connection.changed(key_path=key, key_passphrase=phrase)).split()[:2], public.split()[:2])
            metadata = Path(key + ".json").read_text()
            self.assertNotIn(phrase, metadata)
            self.assertEqual(next(iter(vault.items.values()))["key_passphrase"], phrase)
            for alias in vault.items:
                self.assertEqual(LocalVault().query(alias)["kSecAttrAccount"], alias)

    def test_keychain_rejection_leaves_no_usable_key_or_remote_change(self):
        with tempfile.TemporaryDirectory() as folder:
            vault = MemoryVault(); controller = Controller(Store(Path(folder), vault))
            vault.put = mock.Mock(side_effect=ManagerError("不可保存。"))
            with self.assertRaises(ManagerError):
                controller.generate_key(Connection(host="fictional.invalid", username="owner"), "fictional-key-password-for-test")
            self.assertFalse(list(Path(folder).rglob("*.pub")))

    def test_private_phrase_is_not_sent_to_server(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller(Store(Path(folder), MemoryVault()))
            connection = Connection(host="fictional.invalid", username="owner", password="fictional-password")
            controller.store.save([connection])
            transport = mock.Mock()
            transport.redactor = Redactor()
            transport.call.side_effect = [{"task_id": "a" * 24}, {"state": "succeeded", "message": "完成。"}]
            controller.transport = mock.Mock(return_value=transport)
            controller.execute(connection, {"operation": "prepare_key", "username": "owner", "public_key": "ssh-ed25519 AAAA", "local_key_path": "fictional-key", "local_key_passphrase": "fictional-private-phrase"})
            packet = transport.call.call_args_list[0].args[0]
            self.assertFalse(any(k.startswith("local_") for k in packet["params"]))
            self.assertNotIn("fictional-private-phrase", json.dumps(packet))


class SecurityPlanTests(unittest.TestCase):
    def fixture(self, folder, failed=None):
        controller = Controller(Store(Path(folder), MemoryVault()))
        connection = Connection(host="fictional.invalid", username="owner", password="fictional-password", sudo_password="fictional-password")
        unrelated = Connection(host="other.invalid", username="owner", password="unrelated-password")
        controller.store.save([connection, unrelated])
        controller.transport = mock.Mock(return_value=mock.Mock())
        controller.trust_same_server = mock.Mock()
        controller.generate_key = mock.Mock(return_value=("fictional-key", "ssh-ed25519 AAAA new"))
        controller.public_key = mock.Mock(return_value="ssh-ed25519 BBBB")
        operations = []
        def execute(current, params, progress):
            operations.append(params)
            if params["operation"] == failed: raise ManagerError("该步骤失败。")
            updated = controller.candidate(current, params, {"verification": {"username": params.get("new_username", params.get("username", current.username))}})
            return {"id": "a" * 24, "state": "succeeded"}, updated
        controller.execute = execute
        return controller, connection, unrelated, operations

    def test_rename_and_key_rotation_before_disabling_passwords(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, unrelated, ops = self.fixture(folder)
            original = original.changed(auth="key", key_path="fictional-original", key_passphrase="fictional-old-pass")
            result = c.security_plan(original, {"mode": "rename", "username": "changed", "retire_old_key": True, "updates": False, "fail2ban": False})
            self.assertTrue(result["complete"])
            self.assertEqual([o["operation"] for o in ops], ["prepare_key", "rename_user", "login_policy", "retire_key"])
            self.assertEqual(result["connection"].username, "changed")
            self.assertEqual(result["connection"].auth, "key")
            self.assertTrue(result["connection"].key_passphrase)
            self.assertEqual(next(p for p in c.store.profiles() if p.identifier == unrelated.identifier).password, unrelated.password)
            self.assertNotIn("firewall", [o["operation"] for o in ops])

    def test_new_admin_has_separate_profile_and_original_login_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, unrelated, ops = self.fixture(folder)
            result = c.security_plan(original, {"mode": "create", "username": "alternate", "updates": False, "fail2ban": False})
            self.assertTrue(result["complete"])
            self.assertNotEqual(result["connection"].identifier, original.identifier)
            self.assertEqual([o["operation"] for o in ops], ["create_admin", "login_policy", "account_access"])
            self.assertEqual(len(c.store.profiles()), 3)
            self.assertGreaterEqual(len(ops[0]["new_password"]), 12)
            self.assertEqual(ops[-1]["username"], original.username)

    def test_same_name_rotates_key_without_rename_and_without_revoking_unknown_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder)
            result = c.security_plan(original, {"mode": "rename", "username": original.username, "retire_old_key": True, "updates": False, "fail2ban": False})
            self.assertTrue(result["complete"])
            self.assertEqual([o["operation"] for o in ops], ["prepare_key", "login_policy"])

    def test_later_failure_keeps_last_verified_new_login_and_reports_partial_result(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder, "fail2ban")
            result = c.security_plan(original, {"mode": "rename", "username": "changed"})
            self.assertFalse(result["complete"])
            self.assertEqual(result["connection"].username, "changed")
            self.assertEqual([s["step"] for s in result["stages"]], ["安装并验证加密密钥", "修改并验证用户名", "启用仅密钥登录与基础防护"])
            self.assertEqual(c.store.profiles()[-1].username, "changed")
            self.assertNotIn("updates", [o["operation"] for o in ops])
            journals = list((Path(folder) / "security-plans").glob("*.json"))
            self.assertTrue(any(json.loads(p.read_text()).get("state") == "incomplete" for p in journals))
            self.assertTrue(all(result["connection"].key_passphrase not in p.read_text() for p in journals))

    def test_preflight_or_vault_failure_submits_no_remote_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder)
            c.transport.return_value.call.side_effect = ManagerError("配置不兼容。")
            with self.assertRaises(ManagerError): c.security_plan(original, {"mode": "rename", "username": "changed"})
            c.generate_key.assert_not_called(); self.assertFalse(ops)
            c.transport.return_value.call.side_effect = None
            c.store.vault.put = mock.Mock(side_effect=ManagerError("钥匙串不可用。"))
            with self.assertRaises(ManagerError): c.security_plan(original, {"mode": "rename", "username": "changed"})
            self.assertFalse(ops)

    def test_root_cannot_be_renamed_and_weak_key_phrase_stops_before_contact(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder)
            for connection, opts in [(original.changed(username="root"), {"mode": "rename", "username": "changed"}), (original, {"mode": "rename", "username": "changed", "key_passphrase": "short"})]:
                with self.assertRaises(ManagerError): c.security_plan(connection, opts)
            c.transport.assert_not_called(); self.assertFalse(ops)


class RemotePlanTests(unittest.TestCase):
    def test_fail2ban_waits_for_its_socket_instead_of_failing_after_startup(self):
        ready = [subprocess.CompletedProcess([], 1, "", "starting"), subprocess.CompletedProcess([], 1, "", "starting"), subprocess.CompletedProcess([], 0, "jail ready", "")]
        def command(args, **kwargs):
            if args[:2] == ["fail2ban-client", "status"]:
                return ready.pop(0)
            return subprocess.CompletedProcess(args, 0, "", "")
        with mock.patch.object(REMOTE, "unit_info", return_value={}), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE.shutil, "which", return_value="tool"), mock.patch.object(REMOTE, "ssh_configuration", return_value={"port": ["22"]}), mock.patch.object(REMOTE, "private_write"), mock.patch.object(REMOTE, "command", side_effect=command), mock.patch.object(REMOTE.time, "sleep") as sleep:
            self.assertTrue(REMOTE.fail2ban_settings({"enabled": True})["enabled"])
            self.assertEqual(sleep.call_count, 2)
        self.assertFalse(ready)

    def test_login_policy_does_not_change_ports_firewall_source_rules_or_tunnels(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "sshd_config"
            source.write_text("Port 2222\nAllowUsers owner alternate\nAllowTcpForwarding local\nPasswordAuthentication yes\n")
            written = {}
            previous = {"maxauthtries": ["2"], "logingracetime": ["20"]}
            effective = {"permitrootlogin": ["no"], "passwordauthentication": ["no"], "kbdinteractiveauthentication": ["no"], "pubkeyauthentication": ["yes"], "authenticationmethods": ["publickey"], "permitemptypasswords": ["no"], "maxauthtries": ["2"], "logingracetime": ["20"], "loglevel": ["VERBOSE"], "x11forwarding": ["no"], "allowagentforwarding": ["no"]}
            with mock.patch.object(REMOTE.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir=folder)), mock.patch.object(REMOTE.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=27)), mock.patch.object(REMOTE.os, "getgrouplist", return_value=[27]), mock.patch.object(REMOTE.Path, "is_file", return_value=True), mock.patch.object(REMOTE, "ssh_files_without_match", return_value=[source]), mock.patch.object(REMOTE, "ssh_configuration", side_effect=[previous, effective]), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE, "private_write", side_effect=lambda p, v, *a: written.update({str(p): v})), mock.patch.object(REMOTE, "command") as command, mock.patch.object(REMOTE, "allow_port") as allow:
                self.assertTrue(REMOTE.login_policy({"username": "owner"})["requires_verification"])
            self.assertIn("Port 2222\nAllowUsers owner alternate\nAllowTcpForwarding local\n", written[str(source)])
            allow.assert_not_called()
            self.assertFalse(any("ufw" in call.args[0] for call in command.call_args_list))
            self.assertIn("LoginGraceTime 20", written["/etc/ssh/sshd_config.d/00-linux-manager-login.conf"])

    def test_retire_only_original_key_and_preserve_quoted_options_and_other_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder); keys = home / ".ssh/authorized_keys"; keys.parent.mkdir()
            lines = 'ssh-ed25519 AAAA new\nfrom="anywhere" ssh-ed25519 BBBB old\ncommand="echo ssh-ed25519 BBBB " ssh-ed25519 CCCC other\n# ssh-ed25519 BBBB documentation\n'
            keys.write_text(lines)
            with mock.patch.object(REMOTE.pwd, "getpwnam", return_value=SimpleNamespace(pw_dir=folder, pw_uid=1001, pw_gid=1001)), mock.patch.object(REMOTE, "backup_files"), mock.patch.object(REMOTE, "arm_recovery"), mock.patch.object(REMOTE.os, "chown"):
                result = REMOTE.retire_key({"username": "owner", "old_public_key": "ssh-ed25519 BBBB", "public_key": "ssh-ed25519 AAAA"})
            self.assertEqual(result["removed_keys"], 1)
            self.assertIn('command="echo ssh-ed25519 BBBB " ssh-ed25519 CCCC other', keys.read_text())
            self.assertIn("# ssh-ed25519 BBBB documentation", keys.read_text())

    def test_account_snapshot_includes_system_users_without_exposing_password_hashes(self):
        users = [SimpleNamespace(pw_name=n, pw_uid=uid, pw_gid=uid, pw_dir="/nonexistent", pw_shell="/usr/sbin/nologin") for n, uid in [("root", 0), ("daemon", 1), ("owner", 1001)]]
        with mock.patch.object(REMOTE.pwd, "getpwall", return_value=users), mock.patch.object(REMOTE.grp, "getgrall", return_value=[]), mock.patch.object(REMOTE.Path, "read_text", return_value="owner:fictional-shadow-hash:1:0:99999:7:::\n"), mock.patch.object(REMOTE.Path, "is_file", return_value=False), mock.patch.object(REMOTE, "managed_accounts", return_value={}), mock.patch.object(REMOTE, "ssh_configuration", return_value={}):
            rows = REMOTE.account_snapshot()
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[1]["system"])
        self.assertFalse(rows[2]["system"])
        self.assertNotIn("fictional-shadow-hash", json.dumps(rows))

    def test_deletion_uses_list_selection_instead_of_editable_account_field(self):
        app = object.__new__(App)
        app._ready = mock.Mock(return_value=True)
        app.current = Connection(username="alternate")
        from linux_manager.project_info import server_key
        app.report_server_key = server_key(app.current)
        app.account_tree = mock.Mock(); app.account_tree.selection.return_value = ["selected"]
        app.account_map = {"selected": "owner"}
        app.account_user = mock.Mock(); app.account_user.get.return_value = "wrong-editable-user"
        app.report = {"accounts": [{"username": "owner", "uid": 1001, "admin": False}, {"username": "alternate", "uid": 1002, "admin": True}]}
        app._execute = mock.Mock()
        app._delete_user()
        self.assertEqual(app._execute.call_args.args[0]["username"], "owner")


if __name__ == "__main__":
    unittest.main()
