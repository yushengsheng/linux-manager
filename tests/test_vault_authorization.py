import copy
from contextlib import contextmanager, nullcontext
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.models import Connection, ManagerError
from linux_manager.vault import LocalVault


class VaultAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.vault = LocalVault()
        self.storage = {}
        self.reads = []
        def read(identifier, maximum=16384):
            self.reads.append(identifier)
            return copy.deepcopy(self.storage.get(identifier))
        def write(identifier, values): self.storage[identifier] = copy.deepcopy(values)
        self.vault._read_item = read; self.vault._write_item = write
        self.vault._write_lock = nullcontext

    def test_all_saved_aliases_share_one_native_keychain_read_at_startup(self):
        values = {str(index).zfill(16): {"password": "fictional-" + str(index)} for index in range(8)}
        self.storage[LocalVault.BUNDLE] = {"version": 1, "records": values}
        for alias in values: self.assertEqual(self.vault.get(alias), values[alias])
        self.assertEqual(self.reads, [LocalVault.BUNDLE])

    def test_legacy_migration_is_lazy_and_original_is_preserved(self):
        alias = "a" * 16; self.storage[alias] = {"password": "fictional-old"}
        self.assertEqual(self.vault.get(alias), self.storage[alias])
        self.assertEqual(self.storage[LocalVault.BUNDLE]["records"][alias], self.storage[alias])
        self.assertEqual(set(self.reads), {alias, LocalVault.BUNDLE})
        self.assertIn(alias, self.storage)

    def test_denied_migration_write_keeps_original_and_does_not_cache_success(self):
        alias = "a" * 16; self.storage[alias] = {"password": "fictional-old"}
        self.vault._write_item = mock.Mock(side_effect=ManagerError("denied"))
        with self.assertRaises(ManagerError): self.vault.get(alias)
        self.assertEqual(self.storage[alias], {"password": "fictional-old"})
        self.assertNotIn(alias, self.vault.cache)

    def test_verification_after_cache_removal_reads_native_data(self):
        alias = "a" * 16
        self.vault.put(alias, {"password": "fictional-new"})
        self.storage[LocalVault.BUNDLE]["records"][alias] = {"password": "fictional-different"}
        before = len(self.reads); self.vault.cache.pop(alias)
        self.assertEqual(self.vault.get(alias), {"password": "fictional-different"})
        self.assertEqual(len(self.reads), before + 1)

    def test_deleted_alias_tombstone_cannot_restore_old_credential(self):
        alias = "a" * 16; self.storage[alias] = {"password": "fictional-old"}
        @contextmanager
        def dictionary(values): yield values
        self.vault.dictionary = dictionary
        self.vault.sec = mock.Mock(); self.vault.sec.SecItemDelete.return_value = -25300
        self.vault.delete(alias)
        self.vault.cache.clear(); self.vault._records = None
        self.assertEqual(self.vault.get(alias), {})
        self.assertIn(alias, self.storage[LocalVault.BUNDLE]["records"])

    def test_corrupt_bundle_is_not_overwritten_or_replaced_by_legacy(self):
        alias = "a" * 16
        self.storage[LocalVault.BUNDLE] = {"version": 99, "records": {}}
        original = copy.deepcopy(self.storage)
        for operation in (lambda: self.vault.get(alias), lambda: self.vault.put(alias, {})):
            with self.assertRaises(ManagerError): operation()
        self.assertEqual(self.storage, original)

    def test_empty_bundle_is_corrupt_and_is_not_silently_overwritten(self):
        self.storage[LocalVault.BUNDLE] = {}
        with self.assertRaises(ManagerError): self.vault.put("a" * 16, {})
        self.assertEqual(self.storage[LocalVault.BUNDLE], {})

    def test_write_preserves_other_aliases_and_empty_values(self):
        first, second = "a" * 16, "b" * 16
        self.vault.put(first, {"password": "fictional-first"})
        self.vault.put(second, {})
        self.assertEqual(self.storage[LocalVault.BUNDLE]["records"], {first: {"password": "fictional-first"}, second: {}})
        values = self.vault.get(first); values["password"] = "changed"
        self.assertEqual(self.vault.get(first)["password"], "fictional-first")

    def test_write_merges_changes_from_another_instance(self):
        first, second = "a" * 16, "b" * 16
        self.vault.put(first, {"password": "fictional-first"})
        self.storage[LocalVault.BUNDLE]["records"][second] = {"password": "fictional-second"}
        self.vault.put(first, {"password": "fictional-new"})
        self.assertEqual(self.storage[LocalVault.BUNDLE]["records"][second], {"password": "fictional-second"})

    def test_denied_bundle_read_does_not_repeat_system_prompts(self):
        self.vault._read_item = mock.Mock(side_effect=ManagerError("denied"))
        for alias in ("a" * 16, "b" * 16):
            with self.assertRaises(ManagerError): self.vault.get(alias)
        self.vault._read_item.assert_called_once()

    def test_denied_legacy_read_does_not_prompt_for_every_saved_project(self):
        def read(identifier, maximum=16384):
            self.reads.append(identifier)
            if identifier == LocalVault.BUNDLE: return None
            raise ManagerError("denied")
        self.vault._read_item = read
        for alias in ("a" * 16, "b" * 16):
            with self.assertRaises(ManagerError): self.vault.get(alias)
        self.assertEqual(self.reads, [LocalVault.BUNDLE, "a" * 16])

    def test_startup_does_not_eagerly_read_seven_project_credentials(self):
        app = object.__new__(App)
        app.controller = mock.Mock()
        app.store = mock.Mock(); app.store.profiles.return_value = [Connection(host="fixture.invalid")]
        work = []
        app._run = lambda worker, callback, message: work.append(worker)
        app._load_saved_profiles(); profiles, keys = work[0]()
        self.assertEqual(len(profiles), 1); self.assertEqual(keys, {})
        app.store.vault.get.assert_not_called()


if __name__ == "__main__": unittest.main()
