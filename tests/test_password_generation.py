from pathlib import Path
import secrets
import tempfile
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock

from test_linux_manager import MemoryVault
from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.models import Connection, ManagerError, Redactor, SERVICES, Store, validate_password
from linux_manager.project_info import credential_alias
from linux_manager.vault import LocalVault, vault_alias


class PasswordButtonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.frame = ttk.Frame(self.root)
        self.addCleanup(self.frame.destroy)
        self.app = object.__new__(App)
        app = self.app
        app.pages = {name: SimpleNamespace(content=ttk.Frame(self.frame)) for name in ["连接服务器", "账号与登录", "安全防护", "一键部署", "操作记录"]}
        app.privacy = tk.BooleanVar(self.root, value=True)
        app.buttons = []; app.private_entries = []; app.busy = False; app.current = None
        app.controller = mock.Mock(); app.store = mock.Mock()
        app.status = mock.Mock(); app.progress = mock.Mock()
        app._connection_page(); app._accounts_page(); app._security_page(); app._deployment_page(); app._history_page()

    def generators(self, page, title="生成密码"):
        content = self.app.pages[page].content
        return [button for button in self.app.buttons if str(button).startswith(str(content) + ".") and button.cget("text") == title]

    def assert_password(self, value, length=40):
        self.assertEqual(len(value), length)
        self.assertRegex(value, r"^[A-Za-z0-9_-]+$")
        self.assertEqual(validate_password(value), value)

    def test_every_new_password_input_has_a_generator_and_confirmation_is_synced(self):
        app = self.app
        self.assertEqual(len(self.generators("账号与登录")), 1)
        self.assertEqual(len(self.generators("安全防护")), 1)
        self.assertEqual(len(self.generators("安全防护", "生成口令")), 1)
        self.assertEqual(len(self.generators("一键部署")), 2)
        self.generators("账号与登录")[0].invoke()
        self.assert_password(app.account_password.get())
        self.assertEqual(app.account_password.get(), app.account_confirmation.get())
        self.generators("安全防护")[0].invoke()
        self.assert_password(app.plan_password.get())
        self.generators("安全防护", "生成口令")[0].invoke()
        self.assert_password(app.plan_phrase.get(), 48)
        for button in self.generators("一键部署"):
            button.invoke()
            self.assert_password(app.deploy_password.get())

    def test_generator_uses_explicit_cryptographic_entropy_sizes(self):
        app = self.app
        generator = secrets.token_urlsafe
        with mock.patch("linux_manager.gui.secrets.token_urlsafe", wraps=generator) as token:
            app._generate_password(app.account_password, app.account_confirmation)
            app._generate_password(app.plan_phrase, private_key=True)
        self.assertEqual(token.call_args_list, [mock.call(30), mock.call(36)])

    def test_repeated_generation_refreshes_confirmation_and_never_exposes_value_in_status(self):
        app = self.app
        values = set()
        for _ in range(100):
            app.account_confirmation.set(secrets.token_urlsafe(12))
            app._generate_password(app.account_password, app.account_confirmation)
            self.assert_password(app.account_password.get())
            self.assertEqual(app.account_password.get(), app.account_confirmation.get())
            values.add(app.account_password.get())
        self.assertEqual(len(values), 100)
        messages = " ".join(str(call.kwargs) for call in app.status.configure.call_args_list)
        self.assertTrue(all(value not in messages for value in values))

    def test_old_credentials_and_local_memos_are_not_randomized_or_saved_by_click(self):
        app = self.app
        original = Connection(host="fixture.invalid", username="owner", password=secrets.token_urlsafe(30), key_passphrase=secrets.token_urlsafe(36), sudo_password=secrets.token_urlsafe(30))
        app.current = original
        for variable, value in [(app.password_var, original.password), (app.passphrase_var, original.key_passphrase), (app.sudo_var, original.sudo_password)]:
            variable.set(value)
        app.remember_var.set(False)
        self.assertFalse(self.generators("连接服务器"))
        for page in ["账号与登录", "安全防护", "一键部署"]:
            for button in self.generators(page) + self.generators(page, "生成口令"):
                button.invoke()
        self.assertEqual((app.password_var.get(), app.passphrase_var.get(), app.sudo_var.get()), (original.password, original.key_passphrase, original.sudo_password))
        self.assertIs(app.current, original)
        self.assertFalse(app.remember_var.get())
        app.controller.execute.assert_not_called(); app.controller.transport.assert_not_called()
        app.store.vault.put.assert_not_called()
        self.assertTrue(all(entry.cget("show") == "•" for entry in app.private_entries))

    def test_busy_job_disables_generators_and_direct_calls_cannot_replace_in_flight_passwords(self):
        app = self.app
        app.inputs = []
        before = secrets.token_urlsafe(30)
        app.account_password.set(before); app.account_confirmation.set(before)
        with mock.patch("linux_manager.gui.threading.Thread"):
            app._run(mock.Mock())
        for page in ["账号与登录", "安全防护", "一键部署"]:
            self.assertTrue(all(button.instate(["disabled"]) for button in self.generators(page) + self.generators(page, "生成口令")))
        with mock.patch("linux_manager.gui.secrets.token_urlsafe") as token:
            app._generate_password(app.account_password, app.account_confirmation)
            token.assert_not_called()
        self.assertEqual(app.account_password.get(), before)
        self.assertEqual(app.account_confirmation.get(), before)

    def test_generated_account_password_still_uses_original_validated_submission(self):
        app = self.app
        app._ready = mock.Mock(return_value=True); app._execute = mock.Mock()
        app.account_user.set("owner")
        self.generators("账号与登录")[0].invoke()
        value = app.account_password.get()
        app._account_operation("password")
        self.assertEqual(app._execute.call_args.args[0], {"operation": "password", "username": "owner", "new_password": value})
        app._execute.reset_mock()
        app.account_confirmation.set(secrets.token_urlsafe(30))
        with mock.patch("linux_manager.gui.messagebox.showerror") as error:
            app._account_operation("password")
        app._execute.assert_not_called(); error.assert_called_once()

    def test_generated_service_passwords_reach_original_deployment_flow(self):
        app = self.app
        app.current = Connection(host="fixture.invalid", username="owner")
        app._ready = mock.Mock(return_value=True); app._execute = mock.Mock()
        app._run = mock.Mock(side_effect=lambda worker, done, message, **kwargs: done(worker()))
        app.controller.deployment_preview.side_effect = lambda c, params, **kwargs: {"version": params.get("version", "v1.1.85"), "fingerprint": "fixture-preview", "changes": [], "installed": False, "action": "install"}
        for kind, field in [("hysteria2", "proxy_password"), ("xui", "panel_password")]:
            app.deploy_choice.set(SERVICES[kind][0]); app._deploy_defaults()
            app._generate_password(app.deploy_password)
            value = app.deploy_password.get()
            app._deploy()
            self.assertEqual(app._execute.call_args.args[0][field], value)
            self.assert_password(value)


class PasswordPersistenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.vault = MemoryVault(); self.store = Store(self.root, self.vault)
        self.connection = Connection(host="fixture.invalid", username="owner", password=secrets.token_urlsafe(30))
        self.store.save([self.connection])
        self.controller = Controller(self.store)
        self.ssh = mock.Mock(); self.ssh.redactor = Redactor()
        self.controller.transport = mock.Mock(return_value=self.ssh)
        self.identifier = secrets.token_hex(12)
        patch = mock.patch("linux_manager.controller.secrets.token_hex", return_value=self.identifier)
        patch.start(); self.addCleanup(patch.stop)
        self.password = secrets.token_urlsafe(30)
        self.alias = vault_alias("task-password", self.identifier)
        self.params = {"operation": "password", "username": "owner", "new_password": self.password}
        self.success = {"id": self.identifier, "state": "succeeded", "operation": "password", "message": "验证成功。"}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, self.success]

    def test_password_is_readback_verified_before_submission_without_replacing_old_login(self):
        def call(request, **kwargs):
            if request["action"] == "start":
                self.assertEqual(self.vault.get(self.alias)["password"], self.password)
                self.assertEqual(self.store.profiles()[0].password, self.connection.password)
                return {"task_id": self.identifier}
            return self.success
        self.ssh.call.side_effect = call
        self.controller.execute(self.connection, self.params)
        self.assertEqual(self.vault.get(self.alias)["password"], self.password)
        for path in self.root.rglob("*.json"):
            self.assertNotIn(self.password, path.read_text())

    def test_keychain_write_or_readback_failure_submits_no_mutation(self):
        for fault in ["write", "readback", "corrupt"]:
            with self.subTest(fault=fault):
                self.ssh.call.reset_mock()
                self.ssh.call.side_effect = None
                patch = mock.patch.object(self.vault, "put", side_effect=ManagerError(self.password)) if fault == "write" else mock.patch.object(self.vault, "get", side_effect=ValueError(self.password) if fault == "corrupt" else None, return_value={})
                with patch, self.assertRaises(ManagerError) as caught:
                    self.controller.execute(self.connection, self.params)
                self.assertNotIn(self.password, str(caught.exception))
                self.ssh.call.assert_not_called()
        self.assertEqual(self.store.profiles()[0].password, self.connection.password)

    def test_native_keychain_verification_bypasses_write_cache(self):
        native = LocalVault()
        persisted = dict(self.vault.items)
        reads = []
        def put(alias, values):
            persisted[alias] = dict(values); native.cache[alias] = dict(values)
        def get(alias):
            reads.append((alias, alias in native.cache))
            return dict(native.cache.get(alias, persisted.get(alias, {})))
        with mock.patch.object(native, "put", side_effect=put), mock.patch.object(native, "get", side_effect=get):
            self.store.vault = native
            self.controller.execute(self.connection, self.params)
        self.assertIn((self.alias, False), reads)
        self.assertEqual(persisted[self.alias]["password"], self.password)
        self.assertIsNone(native.native)

    def test_unknown_submission_retains_password_and_can_be_listed_offline(self):
        self.controller._submit_task = mock.Mock(side_effect=ManagerError("尚未确认提交。"))
        with self.assertRaises(ManagerError):
            self.controller.execute(self.connection, self.params)
        self.ssh.call.assert_not_called()
        records = self.controller.saved_password_tasks(self.connection)["tasks"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "submission_unknown")
        self.assertEqual(self.vault.get(self.alias)["password"], self.password)
        self.assertEqual(self.controller.saved_password_tasks(self.connection.changed(host="other.invalid"))["tasks"], [])
        self.assertNotIn(self.password, str(records))

    def test_different_tasks_keep_independent_password_copies(self):
        first = secrets.token_bytes(12).hex(); second = secrets.token_bytes(12).hex()
        other = secrets.token_urlsafe(30)
        with mock.patch("linux_manager.controller.secrets.token_hex", side_effect=[first, second]):
            for identifier, password in [(first, self.password), (second, other)]:
                self.ssh.call.side_effect = [{"task_id": identifier}, self.success | {"id": identifier}]
                self.controller.execute(self.connection, self.params | {"new_password": password})
        self.assertEqual(self.vault.get(vault_alias("task-password", first))["password"], self.password)
        self.assertEqual(self.vault.get(vault_alias("task-password", second))["password"], other)
        self.assertEqual(len(self.controller.saved_password_tasks(self.connection)["tasks"]), 2)

    def test_service_passwords_are_saved_in_existing_service_keychain_records(self):
        for kind, field in [("hysteria2", "proxy_password"), ("xui", "panel_password")]:
            preflight = {"fingerprint": "fixture-preview", "version": "v1.99.0", "requires_archive": False, "installed": False}
            params = {"operation": "deploy", "service": kind, field: self.password}
            if kind == "xui": params["panel_username"] = "owner"
            self.ssh.call.side_effect = [preflight, {"task_id": self.identifier}, self.success | {"operation": "deploy"}]
            self.controller.execute(self.connection, params)
            self.assertEqual(self.vault.get(credential_alias(self.connection, kind))[field], self.password)
            self.assertEqual(self.vault.get(vault_alias("service-pending", credential_alias(self.connection, kind))), {})
            self.assertNotIn(self.password, (self.root / "history.json").read_text())

    def test_other_account_without_a_login_profile_and_nonremembered_connection_keeps_password_copy(self):
        connection = self.connection.changed(remember=False)
        self.store.save([connection])
        params = self.params | {"username": "alternate"}
        _, updated = self.controller.execute(connection, params)
        self.assertEqual(updated.password, connection.password)
        self.assertFalse(updated.remember)
        saved = self.vault.get(self.alias)
        self.assertEqual(saved, {"host": connection.host, "username": "alternate", "password": self.password})
        self.assertEqual(self.store.profiles()[0].password, "")

    def test_failure_keeps_proposed_copy_and_does_not_overwrite_working_credentials(self):
        failure = self.success | {"state": "rolled_back", "message": "已恢复原密码。"}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, failure]
        with self.assertRaises(ManagerError):
            self.controller.execute(self.connection, self.params)
        self.assertEqual(self.store.profiles()[0].password, self.connection.password)
        self.assertEqual(self.vault.get(self.alias)["password"], self.password)

    def test_create_admin_password_is_also_escrowed(self):
        self.params.update(operation="create_admin", username="alternate")
        self.controller.execute(self.connection, self.params)
        self.assertEqual(self.vault.get(self.alias)["username"], "alternate")
        self.assertEqual(self.vault.get(self.alias)["password"], self.password)

    def test_verified_change_updates_matching_profiles_and_preserves_other_accounts_and_servers(self):
        same = self.connection.changed(identifier=secrets.token_bytes(8).hex())
        other = self.connection.changed(identifier=secrets.token_bytes(8).hex(), username="alternate")
        foreign = self.connection.changed(identifier=secrets.token_bytes(8).hex(), host="other.invalid")
        self.store.save([self.connection, same, other, foreign])
        pending = self.success | {"state": "awaiting_verification", "result": {}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, pending, {}, {"verified": True}, self.success]
        self.controller.trust_same_server = mock.Mock()
        _, updated = self.controller.execute(self.connection, self.params)
        self.assertEqual(updated.password, self.password)
        self.assertEqual([profile.password for profile in self.store.profiles()], [self.password, self.password, other.password, foreign.password])
        for path in self.root.rglob("*.json"):
            self.assertNotIn(self.password, path.read_text())

    def test_invalid_password_is_rejected_before_keychain_and_network(self):
        with mock.patch.object(self.vault, "put") as put, self.assertRaises(ManagerError):
            self.controller.execute(self.connection, self.params | {"new_password": ""})
        put.assert_not_called(); self.ssh.call.assert_not_called()

    def test_password_view_is_local_masked_and_does_not_require_server_connection(self):
        self.controller.execute(self.connection, self.params)
        app = object.__new__(App)
        app.busy = False; app.current = self.connection; app.store = self.store
        app.task_tree = mock.Mock(); app.task_tree.selection.return_value = [self.identifier]
        app.latest_tasks = [self.success]
        app.controller = mock.Mock(); app._secret_dialog = mock.Mock()
        app._run = mock.Mock(side_effect=lambda worker, done, message, **kwargs: done(worker()))
        app._task_password()
        self.assertEqual(app._secret_dialog.call_args.args[1], self.password)
        self.assertIn("核对任务结果", app._secret_dialog.call_args.args[0])
        app.controller.transport.assert_not_called(); app.controller.execute.assert_not_called()

    def test_password_view_does_not_return_another_servers_password_or_generate_for_old_records(self):
        self.controller.execute(self.connection, self.params)
        app = object.__new__(App)
        app.busy = False; app.current = self.connection.changed(host="other.invalid"); app.store = self.store
        app.task_tree = mock.Mock(); app.task_tree.selection.return_value = [self.identifier]
        app.latest_tasks = [self.success]
        app._secret_dialog = mock.Mock()
        app._run = mock.Mock(side_effect=lambda worker, done, message, **kwargs: done(worker()))
        with mock.patch("linux_manager.gui.messagebox.showinfo") as info, mock.patch("linux_manager.gui.secrets.token_urlsafe") as token:
            app._task_password()
            app.current = self.connection
            self.vault.delete(self.alias)
            app._task_password()
        app._secret_dialog.assert_not_called(); token.assert_not_called()
        self.assertEqual(info.call_count, 2)

    def test_password_button_without_selection_lists_local_records_without_ssh(self):
        self.controller.execute(self.connection, self.params)
        self.controller.transport.reset_mock()
        app = object.__new__(App)
        app.busy = False; app.current = self.connection; app.controller = self.controller
        app.task_tree = mock.Mock(); app.task_tree.selection.return_value = []
        app.status = mock.Mock(); app._show_tasks = mock.Mock()
        app._run = mock.Mock(side_effect=lambda worker, done, message, **kwargs: done(worker()))
        app._task_password()
        records = app._show_tasks.call_args.args[0]
        self.assertEqual(records[0]["id"], self.identifier)
        self.assertNotIn(self.password, str(records))
        self.controller.transport.assert_not_called()

    def test_rename_migrates_password_copy_ownership_for_later_account_deletion(self):
        identifier = secrets.token_bytes(12).hex()
        alias = vault_alias("task-password", identifier)
        self.vault.put(alias, {"host": self.connection.host, "username": "owner", "password": self.password})
        self.store.record({"task_id": identifier, "operation": "password", "state": "succeeded"})
        pending = self.success | {"state": "awaiting_verification", "result": {"verification": {"username": "renamed"}}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, pending, {}, self.success]
        self.controller.trust_same_server = mock.Mock()
        self.controller.execute(self.connection, {"operation": "rename_user", "old_username": "owner", "new_username": "renamed"})
        self.assertEqual(self.vault.get(alias)["username"], "renamed")
        self.assertEqual(self.vault.get(alias)["password"], self.password)

    def test_delete_account_clears_recorded_password_copies_only_for_target_host_and_account(self):
        aliases = []
        for host, user in [(self.connection.host, "alternate"), (self.connection.host, "owner"), ("other.invalid", "alternate")]:
            identifier = secrets.token_bytes(12).hex()
            alias = vault_alias("task-password", identifier)
            self.vault.put(alias, {"host": host, "username": user, "password": secrets.token_urlsafe(30)})
            self.store.record({"task_id": identifier, "operation": "password", "state": "succeeded"})
            aliases.append(alias)
        self.ssh.call.side_effect = [{}, {"task_id": self.identifier}, self.success | {"operation": "delete_user"}]
        self.controller.execute(self.connection, {"operation": "delete_user", "username": "alternate"})
        self.assertEqual(self.vault.get(aliases[0]), {})
        self.assertTrue(self.vault.get(aliases[1])); self.assertTrue(self.vault.get(aliases[2]))


class PasswordDialogTests(unittest.TestCase):
    def test_real_password_dialog_defaults_to_hidden_and_only_copies_on_request(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder), MemoryVault())
            with mock.patch("linux_manager.gui.Store", return_value=store), mock.patch("linux_manager.gui.Controller"), mock.patch.object(App, "_load_saved_profiles"):
                app = App()
            app.withdraw()
            try:
                app._copy = mock.Mock()
                value = secrets.token_urlsafe(30)
                app._secret_dialog("本次新密码", value)
                dialog = next(child for child in app.winfo_children() if isinstance(child, tk.Toplevel))
                entries = []; buttons = []
                def collect(parent):
                    for child in parent.winfo_children():
                        if isinstance(child, ttk.Entry): entries.append(child)
                        if isinstance(child, ttk.Button): buttons.append(child)
                        collect(child)
                collect(dialog)
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0].get(), value)
                self.assertEqual(entries[0].cget("show"), "•")
                app._copy.assert_not_called()
                next(button for button in buttons if button.cget("text") == "复制").invoke()
                app._copy.assert_called_once_with(value)
            finally:
                for identifier in app.tk.call("after", "info"):
                    app.after_cancel(identifier)
                app.destroy()


if __name__ == "__main__":
    unittest.main()
