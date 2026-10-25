import importlib.util
from contextlib import closing
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'new_api_auto_update.py'
spec = importlib.util.spec_from_file_location('new_api_auto_update', MODULE)
up = importlib.util.module_from_spec(spec)
spec.loader.exec_module(up)


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.state = self.root / 'state'
        self.data.mkdir()
        self.state.mkdir()
        self.db = self.data / 'new-api.db'
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, quota INTEGER, used_quota INTEGER)')
            connection.execute('INSERT INTO users VALUES (1, 777, 23)')
            connection.execute('CREATE TABLE options (key TEXT PRIMARY KEY, value TEXT)')
            connection.execute("INSERT INTO options VALUES ('ModelRatio', 'keep-pricing')")
            connection.execute('CREATE TABLE tokens (id INTEGER PRIMARY KEY, key TEXT)')
            connection.execute("INSERT INTO tokens VALUES (1, 'test-only-key')")
        self.binary = self.root / 'new-api'
        self.binary.write_bytes(b'old-binary')
        self.binary.chmod(0o755)
        self.candidate = self.root / 'candidate'
        self.candidate.write_bytes(b'new-binary')
        self.config = dict(binary=str(self.binary), data_dir=str(self.data), database=str(self.db),
                           maintenance_marker=str(self.root / 'maintenance'), unit='test.service')
        self.updater = up.Updater(self.config, self.state)
        self.controls = []
        self.release = dict(tag='v1.0.0-rc.47', sha256='a' * 64)

    def tearDown(self):
        self.temp.cleanup()

    def hooks(self, mutation=None, reject=False):
        def control(action):
            self.controls.append(action)
            if action == 'start' and self.binary.read_bytes() == b'new-binary':
                if mutation:
                    mutation()
                if reject:
                    raise RuntimeError('simulated_new_service_failure')
        return patch.object(self.updater, 'control', side_effect=control)

    def apply(self):
        self.updater.apply(self.release, self.candidate, 'v1.0.0-rc.46')

    def test_success_retains_balance_pricing_keys_and_backup(self):
        before = up.database_signatures(self.db)
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=[503, 503, 200]):
            self.apply()
        self.assertEqual(self.binary.read_bytes(), b'new-binary')
        self.assertEqual(up.database_signatures(self.db), before)
        self.assertFalse(self.updater.pending.exists())
        self.assertFalse(self.updater.marker.exists())
        self.assertTrue((self.state / 'last-success.json').is_file())
        self.assertEqual(len(list(self.state.glob('backup-*/manifest.json'))), 1)
        self.assertEqual(os.stat(self.binary).st_mode & 0o777, 0o755)

    def test_failed_new_binary_rolls_back_program_and_database(self):
        before = up.database_signatures(self.db)
        def migration():
            with closing(sqlite3.connect(self.db)) as connection, connection:
                connection.execute('UPDATE users SET quota=0')
        with self.hooks(migration, reject=True), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', return_value=503):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertEqual(self.binary.read_bytes(), b'old-binary')
        self.assertEqual(up.database_signatures(self.db), before)
        self.assertFalse(self.updater.marker.exists())

    def test_healthy_start_with_changed_prices_is_rejected(self):
        before = up.database_signatures(self.db)
        def migration():
            with closing(sqlite3.connect(self.db)) as connection, connection:
                connection.execute("UPDATE options SET value='unwanted-price'")
        with self.hooks(migration), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', return_value=503):
            with self.assertRaisesRegex(RuntimeError, 'business_data_changed'):
                self.apply()
        self.assertEqual(self.binary.read_bytes(), b'old-binary')
        self.assertEqual(up.database_signatures(self.db), before)

    def test_added_schema_columns_allowed(self):
        def migration():
            with closing(sqlite3.connect(self.db)) as connection, connection:
                connection.execute('ALTER TABLE users ADD COLUMN extra TEXT')
        with self.hooks(migration), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=[503, 503, 200]):
            self.apply()
        self.assertEqual(self.binary.read_bytes(), b'new-binary')

    def test_changed_effective_prices_roll_back_before_reopening(self):
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'effective_pricing', side_effect=['old-pricing', 'changed-pricing']), patch.object(up, 'ingress_status', return_value=503):
            with self.assertRaisesRegex(RuntimeError, 'effective_model_prices_changed'):
                self.apply()
        self.assertEqual(self.binary.read_bytes(), b'old-binary')
        self.assertFalse(self.updater.marker.exists())

    def create_runtime_tables(self):
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute('CREATE TABLE system_instances (id INTEGER PRIMARY KEY, info TEXT, last_seen_at INTEGER)')
            connection.execute("INSERT INTO system_instances VALUES (1, 'old-heartbeat', 100)")
            connection.execute('CREATE TABLE casbin_rule (id INTEGER PRIMARY KEY, v0 TEXT, v1 TEXT)')
            connection.execute("INSERT INTO casbin_rule VALUES (1, 'user', 'own-data')")

    def test_runtime_heartbeat_and_permission_ids_may_refresh(self):
        self.create_runtime_tables()
        def migration():
            with closing(sqlite3.connect(self.db)) as connection, connection:
                connection.execute("UPDATE system_instances SET info='new-heartbeat',last_seen_at=200")
                connection.execute('UPDATE casbin_rule SET id=2')
        with self.hooks(migration), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=[503, 503, 200]):
            self.apply()
        self.assertEqual(self.binary.read_bytes(), b'new-binary')

    def test_permission_contents_remain_protected(self):
        self.create_runtime_tables()
        def migration():
            with closing(sqlite3.connect(self.db)) as connection, connection:
                connection.execute("UPDATE casbin_rule SET v1='all-data'")
        with self.hooks(migration), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', return_value=503):
            with self.assertRaisesRegex(RuntimeError, 'business_data_changed'):
                self.apply()
        self.assertEqual(self.binary.read_bytes(), b'old-binary')

    def test_failed_gate_does_not_stop_current_service(self):
        with self.hooks(), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', return_value=200):
            with self.assertRaisesRegex(RuntimeError, 'maintenance_gate'):
                self.apply()
        self.assertNotIn('stop', self.controls)
        self.assertEqual(self.binary.read_bytes(), b'old-binary')
        self.assertFalse(self.updater.marker.exists())
        self.assertFalse((self.state / 'last-failure.json').exists())

    def test_active_requests_skip_update_without_stopping_service(self):
        with self.hooks(), patch.object(up, 'wait_drained', side_effect=RuntimeError('inflight_requests')), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', return_value=503):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertNotIn('stop', self.controls)
        self.assertFalse(self.updater.installed_attempt)
        self.assertFalse(self.updater.marker.exists())

    def test_power_loss_recovers_persisted_transaction(self):
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy', side_effect=RuntimeError('simulated_kill')), patch.object(up, 'ingress_status', return_value=503), patch.object(self.updater, 'recover', side_effect=RuntimeError('process_gone')):
            with self.assertRaises(RuntimeError):
                self.apply()
        self.assertTrue(self.updater.marker.exists())
        self.assertTrue(self.updater.pending.exists())
        second = up.Updater(self.config, self.state)
        with patch.object(second, 'control'), patch.object(up, 'wait_healthy'), patch.object(up, 'wait_drained'), patch.object(up, 'ingress_status', return_value=503):
            second.recover()
        self.assertEqual(self.binary.read_bytes(), b'old-binary')
        self.assertFalse(second.marker.exists())
        self.assertEqual(json.loads((self.state / 'last-failure.json').read_text())['sha256'], self.release['sha256'])

    def interrupt_installed_update(self):
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy', side_effect=RuntimeError('simulated_kill')), patch.object(up, 'ingress_status', return_value=503), patch.object(self.updater, 'recover', side_effect=RuntimeError('process_gone')):
            with self.assertRaises(RuntimeError):
                self.apply()

    def test_missing_gate_preserves_later_usage_and_requires_review_on_every_retry(self):
        self.interrupt_installed_update()
        self.updater.marker.unlink()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute('UPDATE users SET quota=700, used_quota=100')
        before = up.database_signatures(self.db)
        second = up.Updater(self.config, self.state)
        with patch.object(second, 'control') as control, patch.object(up, 'ingress_status', return_value=503), patch.object(up, 'wait_drained'):
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, 'rollback_requires_manual_review'):
                    second.recover()
            control.assert_not_called()
        self.assertEqual(up.database_signatures(self.db), before)
        self.assertEqual(self.binary.read_bytes(), b'new-binary')
        self.assertTrue(second.marker.exists())
        self.assertTrue(second.pending.exists())

    def test_recovery_checks_gate_and_drains_before_stopping_service(self):
        self.interrupt_installed_update()
        second = up.Updater(self.config, self.state)
        order = []
        def ingress(config):
            self.assertTrue(second.marker.is_file())
            order.append('gate')
            return 503
        with patch.object(second, 'control', side_effect=lambda action: order.append(action)), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=ingress), patch.object(up, 'wait_drained', side_effect=lambda config: order.append('drain')):
            second.recover()
        self.assertEqual(order, ['gate', 'drain', 'stop', 'start'])
        self.assertEqual(self.binary.read_bytes(), b'old-binary')

    def test_recovery_rejects_ineffective_gate_without_touching_data(self):
        self.interrupt_installed_update()
        before = up.database_signatures(self.db)
        second = up.Updater(self.config, self.state)
        with patch.object(second, 'control') as control, patch.object(up, 'ingress_status', return_value=200):
            with self.assertRaisesRegex(RuntimeError, 'maintenance_gate_failed'):
                second.recover()
            control.assert_not_called()
        self.assertEqual(up.database_signatures(self.db), before)
        self.assertTrue(json.loads(second.pending.read_text())['maintenance_lost'])

    def test_lost_gate_before_commit_does_not_roll_back_new_usage(self):
        def ingress(config):
            if self.binary.read_bytes() == b'new-binary':
                with closing(sqlite3.connect(self.db)) as connection, connection:
                    connection.execute('UPDATE users SET quota=700, used_quota=100')
                return 200
            return 503
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=ingress):
            with self.assertRaises(RuntimeError):
                self.apply()
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute('SELECT used_quota FROM users').fetchone()[0], 100)
        self.assertEqual(self.binary.read_bytes(), b'new-binary')
        self.assertTrue(json.loads(self.updater.pending.read_text())['maintenance_lost'])

    def test_interrupted_install_attempt_is_recorded_before_installed_phase(self):
        self.interrupt_installed_update()
        record = json.loads(self.updater.pending.read_text())
        self.assertTrue(record['installed_attempt'])
        record['phase'] = 'backed_up'
        up.atomic_json(self.updater.pending, record)
        second = up.Updater(self.config, self.state)
        with patch.object(second, 'control'), patch.object(up, 'wait_healthy'), patch.object(up, 'wait_drained'), patch.object(up, 'ingress_status', return_value=503):
            second.recover()
        failure = json.loads((self.state / 'last-failure.json').read_text())
        self.assertEqual(failure['sha256'], self.release['sha256'])

    def test_recovered_failed_release_is_skipped_unless_retry_is_requested(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps(self.config))
        cases = [([], self.release['sha256'], self.release['tag'], False),
                 (['--retry-failed'], self.release['sha256'], self.release['tag'], True),
                 ([], 'b' * 64, self.release['tag'], True),
                 ([], None, self.release['tag'], False),
                 ([], None, 'v1.0.0-rc.48', True)]
        for args, failed_digest, failed_version, download_expected in cases:
            up.atomic_json(self.state / 'last-failure.json', dict(version=failed_version, sha256=failed_digest))
            with self.subTest(args=args, failed_digest=failed_digest, failed_version=failed_version), patch.object(up, 'STATE', self.state), patch.object(up, 'CONFIG', config), patch.object(up.os, 'geteuid', return_value=0), patch.object(up.os, 'umask'), patch.object(up.sys, 'argv', ['updater'] + args), patch.object(up, 'status', return_value='v1.0.0-rc.46'), patch.object(up, 'get_json', return_value={}), patch.object(up, 'select_release', return_value=dict(self.release, size=100)), patch.object(up.shutil, 'disk_usage', return_value=type('Disk', (), {'free': 10 ** 12})()), patch.object(up, 'download') as download, patch.object(up.Updater, 'apply'), patch.object(up.Updater, 'prune'):
                up.main()
                self.assertEqual(download.called, download_expected)

    def test_release_policy_and_official_digest(self):
        asset = dict(name='new-api-v1.0.0-rc.47', browser_download_url='https://github.com/QuantumNous/new-api/releases/download/v1.0.0-rc.47/new-api-v1.0.0-rc.47', digest='sha256:' + 'a' * 64, size=120000000)
        release = dict(tag_name='v1.0.0-rc.47', prerelease=False, draft=False, assets=[asset])
        self.assertIsNotNone(up.select_release(release, 'v1.0.0-rc.46', 'x86_64'))
        self.assertIsNone(up.select_release(release, 'v1.0.0-rc.47', 'x86_64'))
        self.assertIsNone(up.select_release(release, 'v1.0.0', 'x86_64'))
        release['prerelease'] = True
        self.assertIsNone(up.select_release(release, 'v1.0.0-rc.46', 'x86_64'))
        release['prerelease'] = False
        asset['digest'] = None
        with self.assertRaisesRegex(ValueError, 'sha256_missing'):
            up.select_release(release, 'v1.0.0-rc.46', 'x86_64')

    def test_backup_retention_only_touches_managed_backups(self):
        self.config['keep_backups'] = 2
        for index in range(4):
            folder = self.state / ('backup-' + str(index))
            folder.mkdir()
            (folder / 'manifest.json').write_text('{}')
        unrelated = self.state / 'unrelated'
        unrelated.mkdir()
        self.updater.prune()
        self.assertTrue(unrelated.is_dir())
        self.assertEqual(len(list(self.state.glob('backup-*'))), 2)

    def test_bad_download_checksum_is_rejected_before_maintenance(self):
        response = io.BytesIO(b'bad-binary')
        response.url = 'https://release-assets.githubusercontent.com/test-only'
        release = dict(url='https://github.com/QuantumNous/new-api/test-only', sha256='0' * 64, size=10)
        with patch.object(up.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'sha256_mismatch'):
                up.download(release, self.root / 'downloaded')
        self.assertFalse(self.updater.marker.exists())

    def test_committed_upgrade_never_restores_over_later_usage(self):
        with self.hooks(), patch.object(up, 'wait_drained'), patch.object(up, 'wait_healthy'), patch.object(up, 'ingress_status', side_effect=[503, 503, 200]):
            self.apply()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute('UPDATE users SET quota=700, used_quota=100')
        self.assertFalse(self.updater.recover())
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute('SELECT quota FROM users').fetchone()[0], 700)


if __name__ == '__main__':
    unittest.main()
