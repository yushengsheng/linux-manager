import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tkinter as tk
from tkinter import ttk
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
            with mock.patch("linux_manager.controller.secrets.token_hex", return_value="a" * 24):
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
            self.assertEqual(ops[2]["scope"], "server")
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
            self.assertEqual([o["operation"] for o in ops], ["create_admin", "login_policy"])
            self.assertEqual(ops[1]["scope"], "user")
            self.assertEqual(len(c.store.profiles()), 3)
            self.assertGreaterEqual(len(ops[0]["new_password"]), 12)
            retained = next(p for p in c.store.profiles() if p.identifier == original.identifier)
            self.assertEqual(retained, original.changed(remember=True))

    def test_create_mode_ignores_legacy_block_and_global_protection_options(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder)
            result = c.security_plan(original, {"mode": "create", "username": "alternate", "block_original": True, "updates": True, "fail2ban": True, "retire_old_key": True})
            self.assertTrue(result["complete"])
            self.assertEqual([o["operation"] for o in ops], ["create_admin", "login_policy"])
            self.assertEqual(ops[-1], {"operation": "login_policy", "username": "alternate", "scope": "user"})
            c.public_key.assert_not_called()

    def test_create_from_root_retains_the_original_root_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder)
            original = original.changed(username="root")
            result = c.security_plan(original, {"mode": "create", "username": "alternate"})
            self.assertTrue(result["complete"])
            self.assertEqual([o["operation"] for o in ops], ["create_admin", "login_policy"])
            self.assertEqual(next(p for p in c.store.profiles() if p.identifier == original.identifier), original.changed(remember=True))

    def test_failed_new_user_policy_keeps_verified_account_without_blocking_original(self):
        with tempfile.TemporaryDirectory() as folder:
            c, original, _, ops = self.fixture(folder, "login_policy")
            result = c.security_plan(original, {"mode": "create", "username": "alternate"})
            self.assertFalse(result["complete"])
            self.assertEqual(result["connection"].username, "alternate")
            self.assertEqual([s["step"] for s in result["stages"]], ["创建并验证新管理员"])
            self.assertEqual([o["operation"] for o in ops], ["create_admin", "login_policy"])
            self.assertEqual(next(p for p in c.store.profiles() if p.identifier == original.identifier).password, original.password)

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

    def test_update_scheduler_failure_keeps_verified_login_but_reports_incomplete_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            controller, original, _, operations = self.fixture(folder, "updates")
            result = controller.security_plan(original, {"mode": "rename", "username": "changed"})
            self.assertFalse(result["complete"])
            self.assertEqual(result["connection"].username, "changed")
            self.assertEqual(operations[-1], {"operation": "updates", "enabled": True})
            self.assertNotIn("启用安全更新（不自动重启）", [stage["step"] for stage in result["stages"]])
            self.assertEqual(controller.store.profiles()[-1].username, "changed")

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


@unittest.skipUnless(shutil.which("sshd") and shutil.which("ssh-keygen"), "需要本机 OpenSSH 配置检查工具")
class NativeScopedLoginTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.main = self.root / "etc/ssh/sshd_config"
        self.main.parent.mkdir(parents=True)
        (self.main.parent / "sshd_config.d").mkdir()
        hostkey = self.root / "hostkey"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)], check=True, capture_output=True)
        self.main.write_text(f"Include /etc/ssh/sshd_config.d/*.conf\nHostKey {hostkey}\nPort 2222\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\nPermitRootLogin yes\nPubkeyAuthentication yes\nAuthenticationMethods any\nX11Forwarding yes\nAllowAgentForwarding yes\n")
        self.home = self.root / "home"
        (self.home / ".ssh").mkdir(parents=True)
        (self.home / ".ssh/authorized_keys").write_text("ssh-ed25519 AAAA\n")
        self.commands = []
        self.backups = []
        def isolated_path(path):
            value = str(path)
            return self.root / value.lstrip("/") if value.startswith("/etc/") else Path(path)
        def command(args, **kwargs):
            self.commands.append(args)
            if args[0] == "/usr/sbin/sshd":
                rendered = self.root / "native-sshd-config"
                rendered.write_text(self.main.read_text().replace("/etc/ssh/sshd_config.d/", str(self.main.parent / "sshd_config.d") + "/"))
                result = subprocess.run([shutil.which("sshd"), *args[1:], "-f", str(rendered)], capture_output=True, text=True, timeout=10)
                if kwargs.get("check", True) and result.returncode:
                    raise REMOTE.OperationError(result.stderr)
                return result
            return subprocess.CompletedProcess(args, 1 if args[:2] == ["systemctl", "is-active"] else 0, "", "")
        for patch in (
            mock.patch.object(REMOTE, "Path", side_effect=isolated_path),
            mock.patch.object(REMOTE, "command", side_effect=command),
            mock.patch.object(REMOTE, "backup_files", side_effect=lambda paths, *args: self.backups.append(paths)),
            mock.patch.object(REMOTE, "arm_recovery"),
            mock.patch.object(REMOTE.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir=str(self.home))),
            mock.patch.object(REMOTE.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=27)),
            mock.patch.object(REMOTE.os, "getgrouplist", return_value=[27]),
        ):
            patch.start(); self.addCleanup(patch.stop)

    def effective(self, user):
        return REMOTE.ssh_configuration(f"user={user},host=localhost,addr=127.0.0.1")

    def test_new_admin_key_only_policy_preserves_all_other_login_settings(self):
        before = {u: self.effective(u) for u in ("owner", "other", "root")}
        original = self.main.read_text()
        self.assertTrue(REMOTE.login_policy({"username": "alternate", "scope": "user"})["requires_verification"])
        self.assertEqual({u: self.effective(u) for u in before}, before)
        for field in ("passwordauthentication", "kbdinteractiveauthentication", "x11forwarding", "allowagentforwarding"):
            self.assertEqual(self.effective("alternate")[field], ["no"])
        self.assertEqual(self.effective("alternate")["authenticationmethods"], ["publickey"])
        self.assertEqual(REMOTE.split_user_login_policies(self.main.read_text())[0], original)
        self.assertEqual(self.backups, [[str(self.main)]])
        self.assertFalse(any(args[0] in {"usermod", "ufw", "apt-get"} for args in self.commands))

    def test_repeated_and_second_admin_policies_are_safe_and_preflight_still_works(self):
        REMOTE.login_policy({"username": "alternate", "scope": "user"})
        first = self.main.read_text()
        REMOTE.login_policy({"username": "alternate", "scope": "user"})
        self.assertEqual(self.main.read_text(), first)
        REMOTE.login_policy({"username": "second", "scope": "user"})
        self.assertEqual(self.effective("owner")["passwordauthentication"], ["yes"])
        for user in ("alternate", "second"):
            self.assertEqual(self.effective(user)["passwordauthentication"], ["no"])
        with mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), mock.patch.object(REMOTE.pwd, "getpwall", return_value=[]):
            self.assertTrue(REMOTE.security_preflight({"mode": "create", "username": "third", "current_username": "owner"})["compatible"])

    def test_existing_user_mode_disables_password_globally_and_preserves_user_rules(self):
        REMOTE.login_policy({"username": "alternate", "scope": "user"})
        policies = REMOTE.split_user_login_policies(self.main.read_text())[1]
        REMOTE.login_policy({"username": "owner", "scope": "server"})
        self.assertEqual(REMOTE.split_user_login_policies(self.main.read_text())[1], policies)
        for user in ("owner", "other", "alternate", "root"):
            effective = self.effective(user)
            self.assertEqual(effective["passwordauthentication"], ["no"])
            self.assertEqual(effective["authenticationmethods"], ["publickey"])
        self.assertEqual(self.effective("root")["permitrootlogin"], ["no"])

    def test_custom_or_modified_match_policies_are_rejected_before_writing(self):
        original = self.main.read_text()
        self.main.write_text(original + "\nMatch User other\n    PasswordAuthentication no\n")
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.login_policy({"username": "alternate", "scope": "user"})
        self.assertFalse(self.backups)
        self.main.write_text(original)
        REMOTE.login_policy({"username": "alternate", "scope": "user"})
        self.backups.clear()
        self.main.write_text(self.main.read_text().replace("    PasswordAuthentication no", "    PasswordAuthentication yes"))
        with self.assertRaises(REMOTE.OperationError):
            REMOTE.login_policy({"username": "second", "scope": "user"})
        self.assertFalse(self.backups)

    def test_global_hardening_and_ssh_settings_keep_scoped_policies_intact(self):
        REMOTE.login_policy({"username": "alternate", "scope": "user"})
        policies = REMOTE.split_user_login_policies(self.main.read_text())[1]
        REMOTE.ssh_hardening({"max_auth_tries": 3, "login_grace": 120, "alive_interval": 0, "tcp_forwarding": True, "x11_forwarding": False, "agent_forwarding": False})
        with mock.patch.object(REMOTE, "firewall_snapshot", return_value={"active": False}), mock.patch.object(REMOTE, "allow_port"), mock.patch.object(REMOTE.grp, "getgrall", return_value=[SimpleNamespace(gr_name="sudo", gr_mem=["owner"])]):
            REMOTE.ssh_settings({"username": "owner", "port": 2222, "old_port": 2222, "allow_password": True, "allow_root": True})
        self.assertEqual(REMOTE.split_user_login_policies(self.main.read_text())[1], policies)
        self.assertEqual(self.effective("owner")["passwordauthentication"], ["yes"])
        self.assertEqual(self.effective("alternate")["passwordauthentication"], ["no"])


class SecurityPlanGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk(); cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.page = ttk.Frame(self.root)
        self.addCleanup(self.page.destroy)
        app = self.app = object.__new__(App)
        app.pages = {"安全防护": SimpleNamespace(content=self.page)}
        app.buttons = []; app.private_entries = []
        app.privacy = tk.BooleanVar(self.root, value=True)
        app.current = Connection(username="owner", auth="key")
        app._security_page()
        app._ready = mock.Mock(return_value=True)
        app._run = mock.Mock()
        app.plan_username.set("alternate")

    def test_create_mode_disables_global_options_and_preview_preserves_other_accounts(self):
        app = self.app
        app.plan_mode.set("新增管理员和密钥")
        app._plan_mode_changed()
        self.assertNotIn("新增后禁止原账号登录", app.plan_checks)
        for label in ("验证后撤销原档案旧钥匙", "方案中启用防猜密码保护", "方案中启用自动安全更新"):
            self.assertEqual(str(app.plan_checks[label].cget("state")), "disabled")
        with mock.patch("linux_manager.gui.messagebox.askyesno", return_value=False) as ask:
            app._apply_security_plan()
        preview = ask.call_args.args[1]
        self.assertIn("其他账号及全局登录策略保持不变", preview)
        self.assertNotIn("禁止原账号", preview)
        self.assertNotIn("全局禁止", preview)
        self.assertNotIn("启用系统安全更新", preview)

    def test_existing_mode_restores_options_and_warns_about_global_password_disable(self):
        app = self.app
        app.plan_mode.set("新增管理员和密钥"); app._plan_mode_changed()
        app.plan_mode.set("修改现有用户名和密钥"); app._plan_mode_changed()
        self.assertEqual(str(app.plan_checks["方案中启用自动安全更新"].cget("state")), "normal")
        with mock.patch("linux_manager.gui.messagebox.askyesno", return_value=False) as ask:
            app._apply_security_plan()
        self.assertIn("全局禁止 SSH 密码", ask.call_args.args[1])
        self.assertIn("影响仍使用密码的账号", ask.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
