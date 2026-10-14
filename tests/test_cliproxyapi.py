import contextlib
import importlib.util
import json
import secrets
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from linux_manager.models import Connection, Redactor
from linux_manager.project_info import information_rows

spec = importlib.util.spec_from_file_location('cliproxy_remote_test', Path(__file__).resolve().parents[1] / 'linux_manager/remote_agent.py')
REMOTE = importlib.util.module_from_spec(spec); spec.loader.exec_module(REMOTE)


class ConfigurationTests(unittest.TestCase):
    def test_port_and_first_client_key_change_preserves_other_keys_and_upstreams(self):
        source = {'config-version': 8, 'access': {'api-keys': ['old', 'second']},
                  'api-keys': {'openai-compatibility': [{'name': 'fixture', 'api-key': 'upstream'}]},
                  'management': {'secret-key': '$2-hash'}, 'requests': {'custom': {'untouched': True}},
                  'oauth': {'model-alias': [{'alias': 'test'}]}, 'routing': {'strategy': 'fill-first'}}
        result = REMOTE.cp_merge(source, 8319, api_key='new')
        self.assertEqual(result['access']['api-keys'], ['new', 'second'])
        self.assertEqual(result['api-keys'], source['api-keys'])
        self.assertEqual(result['requests'], source['requests'])
        self.assertEqual(result['oauth']['model-alias'], source['oauth']['model-alias'])
        self.assertEqual(result['management']['secret-key'], '$2-hash')
        self.assertEqual(result['routing']['strategy'], 'fill-first')
        self.assertEqual(source['access']['api-keys'][0], 'old')
        self.assertEqual(result['server']['host'], '127.0.0.1')

    def test_new_config_requires_both_separate_credentials_and_sets_session_affinity(self):
        with self.assertRaises(REMOTE.OperationError): REMOTE.cp_merge({}, 8317, 'management')
        result = REMOTE.cp_merge({}, 8317, 'management', 'client')
        self.assertTrue(result['routing']['session-affinity'])
        self.assertFalse(result['plugins']['enabled'])
        self.assertTrue(result['management']['disable-auto-update-panel'])

    def test_details_show_current_client_keys_and_separate_client_base_paths(self):
        rows = dict(information_rows({'service': 'cliproxyapi', 'installed': True, 'port': 9229,
                                     'api_keys': ['current'], 'management_key_valid': True},
                                    Connection(host='fixture.invalid'), {'management_key': 'management'}))
        self.assertEqual(rows['客户端 API Key 1'], 'current')
        self.assertEqual(rows['管理 Key'], 'management')
        self.assertEqual(rows['API 基础地址'], 'https://fixture.invalid:9229/v1')
        self.assertEqual(rows['Claude Code 基础地址'], 'https://fixture.invalid:9229')
        self.assertIn('未实测', rows['模型实测'])

    def test_partial_gateway_information_does_not_break_other_projects(self):
        rows = dict(information_rows({'service': 'cliproxyapi', 'installed': True,
                                     'information_error': '配置读取失败',
                                     'units': [{'unit': REMOTE.CP_UNIT, 'ActiveState': 'active'}]},
                                    Connection(host='fixture.invalid')))
        self.assertIn('配置读取失败', rows['配置信息'])
        self.assertNotIn('后台网址', rows)

    def test_log_redaction_removes_bearer_management_key_and_oauth_callback(self):
        token = secrets.token_urlsafe(24)
        text = 'Authorization: Bearer ' + token + '\nmanagement_key=' + token + '\nhttps://fixture.invalid/callback?code=' + token + '&scope=test'
        with mock.patch.object(REMOTE, 'SECRETS', set()):
            for redact in [Redactor().text, REMOTE.clean]:
                self.assertNotIn(token, redact(text))
                self.assertIn('scope=test', redact(text))

    def test_calendar_timers_have_future_schedule_without_service_start_timestamp(self):
        writes = {}
        with mock.patch.object(REMOTE, 'private_write', side_effect=lambda path, text, *args, **kwargs: writes.update({str(path): text})), mock.patch.object(REMOTE, 'command'):
            REMOTE.cp_install_units(True)
        self.assertIn('OnCalendar=*:0/30', writes['/etc/systemd/system/linux-manager-cliproxyapi-update.timer'])
        self.assertIn('OnCalendar=daily', writes['/etc/systemd/system/linux-manager-cliproxyapi-backup.timer'])

    def test_reverse_proxy_streaming_and_websocket_without_added_limits(self):
        site = REMOTE.cp_site({'port': 9229, 'host': 'fixture.invalid'}, 8317, '/cert.pem', '/key.pem')
        for expected in ['proxy_buffering off', 'proxy_request_buffering off', 'proxy_http_version 1.1', 'Upgrade $http_upgrade']:
            self.assertIn(expected, site)
        for unwanted in ['limit_req', 'limit_conn', 'allow ', 'deny ']: self.assertNotIn(unwanted, site)

    def test_health_refuses_client_access_to_management_or_wrong_page(self):
        key = secrets.token_urlsafe(24)
        config = {'server': {'host': '127.0.0.1', 'port': 8317}, 'access': {'api-keys': [key]}}
        record = {'host': 'fixture.invalid', 'port': 9229}
        for bad_management, bad_page in [(True, False), (False, True), (False, False)]:
            def request(base, path, credential='', **kwargs):
                if path == '/v8/management/config':
                    return (200 if bad_management and credential == key else 401), b'{}'
                if path == '/management.html':
                    return 200, b'unrelated page' if bad_page else b'official page /v8/management'
                return (200, b'{"data":[]}') if credential == key else (401, b'{}')
            with self.subTest(management=bad_management, page=bad_page), mock.patch.object(REMOTE, 'cp_request', side_effect=request):
                if bad_management or bad_page:
                    with self.assertRaises(REMOTE.OperationError): REMOTE.cp_health(config, record)
                else: self.assertEqual(REMOTE.cp_health(config, record), [])

    def test_archive_symlink_and_duplicate_binary_are_rejected(self):
        import io, tarfile
        for symlink in [True, False]:
            with tempfile.TemporaryDirectory() as temp:
                archive = Path(temp) / 'core.tar.gz'
                with tarfile.open(archive, 'w:gz') as package:
                    row = tarfile.TarInfo('cli-proxy-api')
                    if symlink: row.type = tarfile.SYMTYPE; row.linkname = '/etc/shadow'; package.addfile(row)
                    else:
                        row.size = 1
                        package.addfile(row, io.BytesIO(b'a')); package.addfile(row, io.BytesIO(b'b'))
                with self.assertRaises(REMOTE.OperationError): REMOTE.cp_extract(archive)


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.base = Path(directory); self.state = self.base / 'state'; self.state.mkdir()
        self.data = self.base / 'data'; (self.data / 'static').mkdir(parents=True)
        self.binary = self.base / 'binary'; self.binary.write_bytes(b'old core')
        self.page = self.data / 'static/management.html'; self.page.write_bytes(b'old page')
        self.config_file = self.base / 'config.yaml'; self.config_file.write_bytes(b'live config')
        for key, value in [('CP_STATE', self.state), ('CP_DATA', self.data), ('CP_BINARY', self.binary), ('CP_CONFIG', self.config_file)]:
            self.stack.enter_context(mock.patch.object(REMOTE, key, value))
        (self.state / 'versions.json').write_text(json.dumps({'core': 'v8.0.26', 'panel': 'v1.26.2'}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_records', return_value={'port': 9229, 'host': 'fixture.invalid'}))
        self.unit = self.stack.enter_context(mock.patch.object(REMOTE, 'unit_info', return_value={'ActiveState': 'active'}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_version', return_value='v8.0.26'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'server_release_version', side_effect=lambda service: 'v8.0.27' if service == 'cliproxyapi' else 'v1.26.2'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_read', return_value={'access': {'api-keys': ['fixture-key']}}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_fingerprint', return_value='same'))
        self.health = self.stack.enter_context(mock.patch.object(REMOTE, 'cp_health', return_value=[]))
        self.stack.enter_context(mock.patch.object(REMOTE, 'mark_installed'))
        self.command = self.stack.enter_context(mock.patch.object(REMOTE, 'command'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_extract', return_value=b'new core'))
        self.stack.enter_context(mock.patch.object(REMOTE.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=1, pw_gid=1)))
        self.stack.enter_context(mock.patch.object(REMOTE.os, 'chown'))
        self.stack.enter_context(mock.patch.object(REMOTE.time, 'sleep'))
        self.download = self.stack.enter_context(mock.patch.dict(REMOTE._downloads, {
            'download_release': mock.Mock(),
            'download_panel': lambda version, destination: Path(destination).write_bytes(b'new page /v8/management'),
        }))

    def test_stopped_service_is_never_started_by_automatic_update(self):
        self.unit.return_value = {'ActiveState': 'inactive'}
        result = REMOTE.cp_update()
        self.assertIn('跳过', result['result']); self.command.assert_not_called()

    def test_health_failure_restores_binary_page_without_overwriting_live_config(self):
        calls = 0
        def health(*args, **kwargs):
            nonlocal calls
            calls += 1
            if 2 <= calls <= 21:
                self.config_file.write_bytes(b'new live user edits')
                raise REMOTE.OperationError('fixture health failure')
            return []
        self.health.side_effect = health
        result = REMOTE.cp_update()
        self.assertEqual(result['result'], '更新失败')
        self.assertEqual(result['rollback'], '已恢复并通过检查')
        self.assertEqual(self.binary.read_bytes(), b'old core')
        self.assertEqual(self.page.read_bytes(), b'old page')
        self.assertEqual(self.config_file.read_bytes(), b'new live user edits')
        self.assertGreater(result['retry_after'], REMOTE.time.time())

    def test_failed_release_backoff_skips_download_and_restart(self):
        (self.state / 'update-status.json').write_text(json.dumps({'failed_target': 'v8.0.27/v1.26.2', 'retry_after': REMOTE.time.time() + 3600}))
        result = REMOTE.cp_update()
        self.assertEqual(result['result'], '失败版本退避中'); self.command.assert_not_called(); self.health.assert_not_called()

    def test_cross_major_update_is_not_automatically_installed(self):
        with mock.patch.object(REMOTE, 'server_release_version', return_value='v9.0.0'):
            result = REMOTE.cp_update()
        self.assertIn('跨大版本', result['reason']); self.command.assert_not_called()

    def test_interrupted_upgrade_is_recovered_before_stopped_core_skip(self):
        folder = self.state / 'rollback'; folder.mkdir()
        (folder / 'core').write_bytes(b'recovery core')
        (folder / 'management.html').write_bytes(b'recovery page')
        (folder / 'versions.json').write_text(json.dumps({'core': 'v8.0.26', 'panel': 'v1.26.2'}))
        (self.state / 'update-transaction.json').write_text(json.dumps({'target': 'v8.0.27/v1.26.2'}))
        self.unit.return_value = {'ActiveState': 'failed'}
        with mock.patch.object(REMOTE.os, 'fchown'):
            result = REMOTE.cp_update()
        self.assertEqual(result['result'], '已恢复中断的升级')
        self.assertEqual(self.binary.read_bytes(), b'recovery core')
        self.assertEqual(self.page.read_bytes(), b'recovery page')
        self.assertFalse((self.state / 'update-transaction.json').exists())
        self.assertEqual(self.config_file.read_bytes(), b'live config')

    def test_unhealthy_public_baseline_skips_update_instead_of_weakening_checks(self):
        def health(*args, **kwargs):
            if kwargs.get('public'):
                raise REMOTE.OperationError('fixture public baseline unavailable')
            return []
        self.health.side_effect = health
        result = REMOTE.cp_update()
        self.assertIn('跳过', result['result'])
        self.command.assert_not_called()
        self.assertEqual(self.binary.read_bytes(), b'old core')
        self.assertFalse((self.state / 'update-transaction.json').exists())

    def test_failed_rollback_keeps_transaction_and_blocks_automatic_restart_loop(self):
        count = 0
        def health(*args, **kwargs):
            nonlocal count
            count += 1
            if count > 1: raise REMOTE.OperationError('fixture post-update and rollback failure')
            return []
        self.health.side_effect = health
        result = REMOTE.cp_update()
        self.assertEqual(result['rollback'], '恢复失败')
        self.assertTrue((self.state / 'update-transaction.json').exists())
        self.command.reset_mock()
        result = REMOTE.cp_update()
        self.assertIn('手动检查', result['result'])
        self.command.assert_not_called()
        self.health.side_effect = None
        with mock.patch.object(REMOTE.os, 'fchown'):
            result = REMOTE.cp_update(force=True)
        self.assertEqual(result['result'], '已恢复中断的升级')
        self.assertFalse((self.state / 'update-transaction.json').exists())

    def test_explicit_update_can_retry_failed_version_before_automatic_backoff_ends(self):
        (self.state / 'update-status.json').write_text(json.dumps({'failed_target': 'v8.0.27/v1.26.2', 'retry_after': REMOTE.time.time() + 3600}))
        with mock.patch.object(REMOTE, 'cp_version', side_effect=['v8.0.26', 'v8.0.27']):
            result = REMOTE.cp_update(force=True)
        self.assertEqual(result['result'], '更新成功')

    def test_healthy_public_baseline_is_required_after_replacement(self):
        with mock.patch.object(REMOTE, 'cp_version', side_effect=['v8.0.26', 'v8.0.27']):
            result = REMOTE.cp_update()
        self.assertEqual(result['result'], '更新成功')
        self.assertTrue(self.health.call_args.kwargs['public'])
        self.assertEqual(self.binary.read_bytes(), b'new core')


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.identifier = 'a' * 24
        self.task = self.root / 'tasks' / self.identifier; self.task.mkdir(parents=True)
        self.config = self.root / 'config.yaml'; self.config.write_text('previous config')
        self.stack.enter_context(mock.patch.object(REMOTE, 'ROOT', self.root))
        self.stack.enter_context(mock.patch.object(REMOTE, 'TASK', self.task))
        self.stack.enter_context(mock.patch.object(REMOTE, 'CP_CONFIG', self.config))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_daily_backup'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_records', return_value={'installed': 'fixture'}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_read', return_value={'config-version': 8}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cert_hook'))
        self.stack.enter_context(mock.patch.object(REMOTE.time, 'sleep'))
        self.health = self.stack.enter_context(mock.patch.object(REMOTE, 'cp_health', return_value=[]))
        self.command = self.stack.enter_context(mock.patch.object(REMOTE, 'command'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'unit_info', return_value={'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}))

    def test_fresh_install_refuses_unknown_existing_core_service_before_dependencies(self):
        params = {'service': 'cliproxyapi', 'host': 'fixture.invalid', 'port': 9229}
        self.config.unlink()
        with mock.patch.object(REMOTE, 'unit_info', return_value={'LoadState': 'loaded', 'FragmentPath': '/usr/lib/systemd/system/foreign.service'}), mock.patch.object(REMOTE, 'cp_records', return_value={}), mock.patch.object(REMOTE, 'CP_BINARY', self.root / 'binary'), mock.patch.object(REMOTE, 'CP_SITE', self.root / 'site'), mock.patch.object(REMOTE, 'CP_DATA', self.root / 'data'), mock.patch.object(REMOTE, 'CP_STATE', self.root / 'state'), mock.patch.object(REMOTE, 'CP_RUNNER', self.root / 'runner'), mock.patch.object(REMOTE.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}), mock.patch.object(REMOTE.platform, 'machine', return_value='x86_64'), mock.patch.object(REMOTE, 'apt') as apt:
            with self.assertRaisesRegex(REMOTE.OperationError, '自定义 AI 服务'):
                REMOTE.deploy(params)
        apt.assert_not_called()

    def test_configuration_backup_is_scoped_away_from_ssh_recovery(self):
        REMOTE.configuration_backup({'service': 'cliproxyapi'})
        manifest = json.loads((self.task / 'backup/manifest.json').read_text())
        self.assertTrue(manifest['extra'].get('deployment'))

    def test_restoring_config_preserves_stopped_core_and_does_not_reload_ssh(self):
        REMOTE.configuration_backup({'service': 'cliproxyapi'})
        (self.task / 'status.json').write_text(json.dumps({'state': 'succeeded'}))
        # Previously created AI backups lacked the project-only marker.
        manifest_path = self.task / 'backup/manifest.json'
        manifest = json.loads(manifest_path.read_text()); manifest['extra'].pop('deployment')
        manifest_path.write_text(json.dumps(manifest))
        current = self.root / 'tasks' / ('b' * 24); current.mkdir()
        self.config.write_text('new current config')
        with mock.patch.object(REMOTE, 'TASK', current):
            result = REMOTE.configuration_restore({'backup_id': self.identifier})
        self.assertEqual(self.config.read_text(), 'previous config')
        self.health.assert_not_called()
        self.assertEqual(result['verified'], 'configuration-restored-core-stopped')
        for call in self.command.call_args_list:
            self.assertNotIn('ssh.service', call.args[0])
            self.assertNotEqual(call.args[0], ['systemctl', 'start', REMOTE.CP_UNIT])


if __name__ == '__main__': unittest.main()
