import contextlib
import gc
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import time
import tkinter as tk
import types
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

from linux_manager.oauth import CallbackPortBusy, LoopbackCallback, OAuthLogin, validate_authorization
from linux_manager.models import Connection, ManagerError, Redactor, SERVICES
from linux_manager.controller import Controller
from linux_manager.gui import App

spec = importlib.util.spec_from_file_location('oauth_remote_test', Path(__file__).resolve().parents[1] / 'linux_manager/remote_agent.py')
REMOTE = importlib.util.module_from_spec(spec); spec.loader.exec_module(REMOTE)
REMOTE_HTTP = REMOTE.cp_oauth_http


def auth_data(provider, port, state, **extra):
    url = 'https://' + ('auth.openai.com/authorize' if provider == 'codex' else 'accounts.google.com/o/oauth2/auth')
    query = {'state': state, 'redirect_uri': f'http://localhost:{port}' + ('/auth/callback' if provider == 'codex' else '/oauth-callback')}
    if provider == 'codex': query.update(code_challenge=secrets.token_urlsafe(32), code_challenge_method='S256')
    return {'phase': 'ready', 'mode': 'callback', 'state': state, 'url': url + '?' + urllib.parse.urlencode(query), **extra}


class LoopbackTests(unittest.TestCase):
    def setUp(self):
        self.receiver = LoopbackCallback('antigravity', port=0)
        self.addCleanup(self.receiver.close)
        self.state = secrets.token_urlsafe(24); self.receiver.arm(self.state)

    def get(self, query, path='/oauth-callback'):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f'http://127.0.0.1:{self.receiver.port}{path}?' + query
        try:
            with opener.open(url, timeout=3) as response:
                return response.status, response.read().decode(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(), error.headers

    def test_callback_is_single_use_without_logging_or_echoing_secrets(self):
        code = secrets.token_urlsafe(24)
        query = urllib.parse.urlencode({'state': self.state, 'code': code})
        status, body, headers = self.get(query)
        self.assertEqual(status, 200); self.assertNotIn(code, body); self.assertNotIn(self.state, body)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.receiver.payload['code'], code)
        self.assertEqual(self.get(query)[0], 409)

    def test_wrong_state_provider_path_host_and_duplicate_parameters_are_rejected(self):
        cases = [('state=wrong&code=fixture', '/oauth-callback', 400),
                 ('state=' + self.state + '&code=fixture&provider=codex', '/oauth-callback', 400),
                 ('state=' + self.state + '&code=fixture&state=other', '/oauth-callback', 400),
                 ('state=' + self.state + '&code=fixture', '/auth/callback', 404),
                 ('state=' + self.state + '&code=fixture&error=access_denied', '/oauth-callback', 400)]
        for query, path, status in cases:
            with self.subTest(path=path, status=status): self.assertEqual(self.get(query, path)[0], status)
        self.assertEqual(self.receiver.accept('/oauth-callback?state=' + self.state + '&code=fixture', 'evil.invalid')[0], 400)
        self.assertFalse(self.receiver.event.is_set())

    def test_expiry_cancellation_and_ipv4_ipv6_ports_are_cleaned(self):
        self.receiver.deadline = time.monotonic() - 1
        self.assertEqual(self.get('state=' + self.state + '&code=fixture')[0], 410)
        number = self.receiver.port; self.receiver.close(); self.receiver.close()
        for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            with socket.socket(family) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((address, number))
        self.assertFalse(any(thread.is_alive() for thread in self.receiver.threads))

    def test_conflict_does_not_close_or_take_over_existing_listener(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0)); occupied.listen()
            number = occupied.getsockname()[1]
            with self.assertRaises(CallbackPortBusy): LoopbackCallback('codex', port=number)
            self.assertEqual(occupied.getsockname()[1], number)

    def test_denial_is_normalized_without_echoing_provider_error(self):
        self.get(urllib.parse.urlencode({'state': self.state, 'error': 'sensitive provider detail'}))
        self.assertEqual(self.receiver.payload['error'], 'authorization_failed')

    def test_ipv6_conflict_releases_ipv4_listener(self):
        with socket.socket(socket.AF_INET6) as occupied:
            occupied.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            occupied.bind(('::1', 0)); occupied.listen()
            number = occupied.getsockname()[1]
            with self.assertRaises(CallbackPortBusy): LoopbackCallback('codex', port=number)
            with socket.socket() as probe: probe.bind(('127.0.0.1', number))

    def test_authorization_contract_rejects_url_state_redirect_and_pkce_mutation(self):
        good = auth_data('codex', 1455, self.state)
        validate_authorization('codex', good, 1455)
        for bad in [{**good, 'state': 'wrong'}, {**good, 'url': good['url'].replace('auth.openai.com', 'evil.invalid')},
                    {**good, 'url': good['url'].replace('S256', 'plain')},
                    {**good, 'url': good['url'].replace('1455', '1456')}]:
            with self.assertRaises(ManagerError): validate_authorization('codex', bad, 1455)


class LoginTests(unittest.TestCase):
    def run_synthetic(self, provider, conflict=False, failure=None):
        calls = []; state = secrets.token_urlsafe(24); owner = {}
        def rpc(operation, **params):
            calls.append((operation, params))
            if operation == 'probe_port': return {'available': True}
            if operation == 'start':
                if params['mode'] == 'device':
                    return {'phase': 'ready', 'mode': 'device', 'url': 'https://auth.openai.com/codex/device', 'user_code': 'TEST-CODE'}
                return auth_data(provider, params['callback_port'], state, mode=params['mode'])
            if operation == 'callback':
                if failure == 'ssh': raise ManagerError('合成断线')
                return {'phase': 'exchanging'}
            if operation == 'status':
                if failure == 'expired': return {'phase': 'expired'}
                return {'phase': 'succeeded', 'recognized': True}
            return {'phase': 'cancelled'}
        login = OAuthLogin(provider, rpc); owner['login'] = login
        actual = LoopbackCallback
        def receiver(name, port=None, **kwargs):
            if conflict and port is None: raise CallbackPortBusy('合成占用')
            return actual(name, port=0)
        def ready(data):
            if failure == 'cancel': login.cancel(); return
            if login.receiver:
                query = urllib.parse.urlencode({'state': state, 'code': secrets.token_urlsafe(24)})
                self.assertEqual(login.receiver.accept(login.receiver.path + '?' + query, f'localhost:{login.receiver.port}')[0], 200)
        # Codex's production port stays fixed; synthetic tests use an unoccupied
        # ephemeral listener while checking its contract separately above.
        with mock.patch('linux_manager.oauth.LoopbackCallback', side_effect=receiver), mock.patch('linux_manager.oauth.validate_authorization', wraps=validate_authorization if provider == 'antigravity' or conflict else lambda *args: None):
            if failure:
                with self.assertRaises(ManagerError): login.run(ready)
            else:
                self.assertTrue(login.run(ready)['recognized'])
        self.assertTrue(login.finished.is_set())
        if login.receiver: self.assertTrue(login.receiver.closed)
        self.assertEqual(sum(operation == 'callback' for operation, _ in calls), 0 if provider == 'codex' and conflict or failure == 'cancel' else 1)
        if failure: self.assertEqual(calls[-1][0], 'cancel')
        return calls

    def test_codex_and_antigravity_end_to_end(self):
        for provider in ['codex', 'antigravity']:
            with self.subTest(provider=provider): self.run_synthetic(provider)

    def test_busy_codex_uses_device_and_busy_antigravity_uses_free_port(self):
        for provider, mode in [('codex', 'device'), ('antigravity', 'cli')]:
            calls = self.run_synthetic(provider, conflict=True)
            self.assertEqual(next(params for operation, params in calls if operation == 'start')['mode'], mode)

    def test_cancel_expiry_and_disconnect_cleanup(self):
        for reason in ['cancel', 'expired', 'ssh']:
            with self.subTest(reason=reason): self.run_synthetic('antigravity', failure=reason)

    def test_controller_pins_target_and_does_not_allow_concurrent_authorization(self):
        secret = secrets.token_urlsafe(24)
        controller = Controller(types.SimpleNamespace(vault=types.SimpleNamespace(get=lambda _: {'management_key': secret})))
        target = Connection(host='first.invalid'); login = controller.oauth_login(target, 'codex')
        with self.assertRaises(ManagerError): controller.oauth_login(target.changed(host='second.invalid'), 'antigravity')
        target.host = 'mutated.invalid'
        with mock.patch.object(controller, 'retry_call', return_value={}) as call:
            login.rpc('status', session_id=login.identifier, provider='codex')
        self.assertEqual(call.call_args.args[0].host, 'first.invalid')
        self.assertEqual(call.call_args.args[1]['management_key'], secret)
        controller.close_connections(); self.assertTrue(login.cancel_event.is_set())

    def test_query_code_and_state_are_redacted(self):
        value = secrets.token_urlsafe(24)
        for redact in [Redactor().text, REMOTE.clean]:
            self.assertNotIn(value, redact('http://localhost:1455/auth/callback?state=' + value + '&code=' + value))

    def test_cleanup_disconnect_preserves_browser_error_and_releases_local_login(self):
        def rpc(operation, **params):
            if operation == 'start':
                return {'phase': 'ready', 'mode': 'api-device', 'url': 'https://auth.kimi.com/device', 'user_code': 'TEST-CODE'}
            raise ManagerError('取消时断线')
        login = OAuthLogin('kimi', rpc)
        def browser(_): raise ManagerError('浏览器未能打开')
        with self.assertRaisesRegex(ManagerError, '^浏览器未能打开$'):
            login.run(browser)
        self.assertTrue(login.finished.is_set()); self.assertTrue(login.cleanup_pending)

    def test_next_login_retries_exact_previous_cancellation_before_start(self):
        from linux_manager.transport import ConnectionInterrupted
        controller = Controller(types.SimpleNamespace(vault=types.SimpleNamespace(get=lambda _: {'management_key': secrets.token_urlsafe(24)})))
        connection = Connection(host='fixture.invalid')
        calls = []; offline = True
        def call(target, request, **kwargs):
            self.assertEqual(target.host, 'fixture.invalid')
            calls.append(request)
            if request['oauth_operation'] == 'cancel':
                self.assertLessEqual(kwargs['timeout'], 6)
                self.assertLessEqual(kwargs['deadline'] - time.monotonic(), 12)
                if offline: raise ConnectionInterrupted('合成断线')
                return {'phase': 'cancelled'}
            if request['oauth_operation'] == 'start':
                return {'phase': 'ready', 'mode': 'api-device', 'url': 'https://auth.kimi.com/device', 'user_code': 'TEST-CODE'}
            return {'phase': 'succeeded', 'recognized': True}
        with mock.patch.object(controller, 'retry_call', side_effect=call):
            first = controller.oauth_login(connection, 'kimi')
            def fail(_): raise ManagerError('浏览器失败')
            with self.assertRaisesRegex(ManagerError, '浏览器失败'): first.run(fail)
            self.assertEqual(len(controller._oauth_pending_cancellations), 1)
            offline = False
            second = controller.oauth_login(connection, 'kimi')
            self.assertTrue(second.run()['recognized'])
        self.assertEqual(calls[-3]['oauth_operation'], 'cancel')
        self.assertEqual(calls[-3]['session_id'], first.identifier)
        self.assertEqual(calls[-2]['session_id'], second.identifier)
        self.assertFalse(controller._oauth_pending_cancellations)


class RemoteBridgeTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.identifier = secrets.token_hex(12); self.key = secrets.token_urlsafe(24)
        self.stack.enter_context(mock.patch.object(REMOTE, 'ROOT', self.root))
        self.stack.enter_context(mock.patch.object(REMOTE, 'CP_STATE', self.root / 'state'))
        self.stack.enter_context(mock.patch.object(REMOTE, 'CP_DATA', self.root / 'data'))
        self.stack.enter_context(mock.patch.object(REMOTE.os, 'geteuid', return_value=0))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_records', return_value={'installed': True}))
        self.stack.enter_context(mock.patch.object(REMOTE, 'task_list', return_value=[]))
        self.stack.enter_context(mock.patch.object(REMOTE, 'cp_oauth_baseline', return_value={}))
        self.command = self.stack.enter_context(mock.patch.object(REMOTE, 'command'))
        self.state = secrets.token_urlsafe(24)
        self.http = self.stack.enter_context(mock.patch.object(REMOTE, 'cp_oauth_http', side_effect=self.response))

    def response(self, path, *args, **kwargs):
        if '/auth-url?' in path: return {'status': 'ok', **auth_data('codex', 1455, self.state)}
        if '/oauth/status?' in path: return {'status': 'wait'}
        return {'status': 'ok'}

    def call(self, operation, **extra):
        return REMOTE.cp_oauth_dispatch({'oauth_operation': operation, 'session_id': self.identifier, 'provider': 'codex',
                                         'management_key': self.key, 'mode': 'callback', 'callback_port': 1455, **extra})

    def test_start_is_idempotent_and_does_not_enable_linux_wildcard_forwarder(self):
        self.assertEqual(self.call('start')['phase'], 'ready'); self.call('start')
        auth_calls = [call for call in self.http.call_args_list if '/auth-url?' in call.args[0]]
        self.assertEqual(len(auth_calls), 1); self.assertIn('is_webui=false', auth_calls[0].args[0])
        self.assertTrue(REMOTE.cp_oauth_busy()); self.command.assert_called_once()
        self.assertNotIn(self.key, (REMOTE.cp_oauth_folder(self.identifier) / 'session.json').read_text())

    def test_wrong_state_provider_and_old_session_do_not_forward(self):
        self.call('start')
        for params in [{'state': 'wrong'}, {'state': self.state, 'provider': 'antigravity'}, {'state': self.state, 'session_id': secrets.token_hex(12)}]:
            with self.assertRaises(REMOTE.OperationError): self.call('callback', code='fixture', **params)
        self.assertFalse(any('/oauth/callback' in call.args[0] for call in self.http.call_args_list))

    def test_repeat_callback_only_forwards_once_and_cancels_exact_session(self):
        self.call('start'); code = secrets.token_urlsafe(24)
        self.call('callback', state=self.state, code=code)
        self.call('callback', state=self.state, code=code)
        self.assertEqual(sum('/oauth/callback' in call.args[0] for call in self.http.call_args_list), 1)
        with self.assertRaises(REMOTE.OperationError): self.call('callback', state=self.state, code='different')
        self.call('cancel'); self.assertFalse(REMOTE.cp_oauth_busy())
        text = (REMOTE.cp_oauth_folder(self.identifier) / 'session.json').read_text()
        self.assertNotIn(code, text); self.assertNotIn(self.state, text)
        self.assertEqual(self.call('status')['phase'], 'cancelled')

    def test_unknown_completed_or_unrecognized_account_is_not_success(self):
        self.call('start'); self.call('callback', state=self.state, code='fixture')
        with mock.patch.object(REMOTE, 'cp_oauth_http', return_value={'status': 'ok'}), mock.patch.object(REMOTE, 'cp_oauth_recognized', return_value=False):
            self.assertEqual(self.call('status')['phase'], 'verifying')
        with mock.patch.object(REMOTE, 'cp_oauth_http', return_value={'status': 'ok'}), mock.patch.object(REMOTE, 'cp_oauth_recognized', return_value=True):
            self.assertTrue(self.call('status')['recognized'])
        self.assertFalse(REMOTE.cp_oauth_busy())

    def test_expired_session_rejects_late_callback(self):
        self.call('start'); file = REMOTE.cp_oauth_folder(self.identifier) / 'session.json'
        session = json.loads(file.read_text()); session['expires'] = time.time() - 1; file.write_text(json.dumps(session))
        self.assertEqual(self.call('callback', state=self.state, code='fixture')['phase'], 'expired')
        self.assertFalse(any('/oauth/callback' in call.args[0] for call in self.http.call_args_list))

    def test_cancellation_can_be_retried_after_core_disconnect_without_forwarding_old_callback(self):
        self.call('start')
        def disconnected(path, *args, **kwargs):
            if kwargs.get('method') == 'DELETE': raise REMOTE.OperationError('核心断线')
            return self.response(path, *args, **kwargs)
        with mock.patch.object(REMOTE, 'cp_oauth_http', side_effect=disconnected):
            result = self.call('cancel')
            self.assertEqual(result['phase'], 'cancelled'); self.assertTrue(result['cancel_unconfirmed'])
            self.assertTrue(REMOTE.cp_oauth_busy())
            self.assertEqual(self.call('callback', state=self.state, code='old')['phase'], 'cancelled')
        self.identifier = secrets.token_hex(12)
        self.assertEqual(self.call('start')['phase'], 'ready')
        deletes = [c for c in self.http.call_args_list if c.kwargs.get('method') == 'DELETE']
        self.assertEqual(len(deletes), 1); self.assertIn(self.state, deletes[0].args[0])

    def test_cancel_nonexistent_session_is_idempotent(self):
        self.assertEqual(self.call('cancel')['phase'], 'cancelled')
        self.assertFalse(REMOTE.cp_oauth_busy())

    def test_retry_accepts_expired_legacy_cancel_record_without_a_saved_state(self):
        old_id = secrets.token_hex(12); folder = REMOTE.cp_oauth_folder(old_id); folder.mkdir(parents=True)
        session = {'id': old_id, 'provider': 'codex', 'mode': 'callback', 'phase': 'failed',
                   'expires': time.time() - 1, 'cancel_unconfirmed': True}
        (folder / 'session.json').write_text(json.dumps(session))
        self.assertEqual(self.call('start')['phase'], 'ready')
        self.assertNotIn('cancel_unconfirmed', json.loads((folder / 'session.json').read_text()))

    def test_expiry_finishes_even_when_core_cancellation_is_unavailable(self):
        self.call('start'); file = REMOTE.cp_oauth_folder(self.identifier) / 'session.json'
        session = json.loads(file.read_text()); session['expires'] = time.time() - 1; file.write_text(json.dumps(session))
        def disconnected(path, *args, **kwargs):
            if kwargs.get('method') == 'DELETE': raise REMOTE.OperationError('核心断线')
            return self.response(path, *args, **kwargs)
        with mock.patch.object(REMOTE, 'cp_oauth_http', side_effect=disconnected):
            self.assertEqual(self.call('status')['phase'], 'expired')
        self.assertFalse(REMOTE.cp_oauth_busy())

    def test_retry_recovers_failed_temporary_cleanup_without_deleting_saved_accounts(self):
        old_id = secrets.token_hex(12); folder = REMOTE.cp_oauth_folder(old_id); folder.mkdir(parents=True)
        session = {'id': old_id, 'provider': 'antigravity', 'mode': 'cli', 'callback_port': 45678,
                   'phase': 'failed', 'expires': time.time() - 1, 'cleanup_failed': True, 'cleanup_pending': True}
        (folder / 'session.json').write_text(json.dumps(session))
        temporary = REMOTE.CP_DATA / ('.oauth-' + old_id + '-fixture'); temporary.mkdir(parents=True)
        account = REMOTE.CP_DATA / 'auth/saved.json'; account.parent.mkdir(); account.write_text('saved-account')
        self.assertTrue(REMOTE.cp_oauth_busy())
        with mock.patch.object(REMOTE, 'unit_info', return_value={'ActiveState': 'inactive'}), mock.patch.object(REMOTE, 'cp_oauth_firewall') as firewall:
            self.assertEqual(self.call('start')['phase'], 'ready')
        firewall.assert_called_once_with(old_id, 45678, remove=True)
        self.assertFalse(temporary.exists()); self.assertEqual(account.read_text(), 'saved-account')
        self.assertFalse(json.loads((folder / 'session.json').read_text())['cleanup_failed'])

    def test_retry_does_not_cancel_another_macs_active_login(self):
        self.call('start'); self.identifier = secrets.token_hex(12)
        with self.assertRaisesRegex(REMOTE.OperationError, '另一项授权'):
            self.call('start')
        self.assertFalse(any(c.kwargs.get('method') == 'DELETE' for c in self.http.call_args_list))

    def test_missing_core_session_is_success_only_for_delete(self):
        opener = mock.Mock(); opener.open.side_effect = urllib.error.HTTPError('http://fixture.invalid', 404, '', {}, None)
        with mock.patch.object(REMOTE, 'cp_read', return_value={'server': {'host': '127.0.0.1', 'port': 8317}}), mock.patch.object(REMOTE.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(REMOTE_HTTP('/v8/management/oauth/session?state=fixture', self.key, method='DELETE')['status'], 'ok')
            with self.assertRaises(REMOTE.OperationError):
                REMOTE_HTTP('/v8/management/config', self.key)

    def test_active_login_blocks_update_and_maintenance_submission(self):
        self.call('start')
        with mock.patch.object(REMOTE, 'cp_records', return_value={}):
            self.assertIn('授权正在进行', REMOTE.cp_update()['result'])
        with self.assertRaisesRegex(REMOTE.OperationError, '授权正在进行'):
            REMOTE.start_task({'operation': 'service', 'service': 'cliproxyapi', 'action': 'restart'})

    def test_registry_routes_every_native_provider_and_claude_alias(self):
        from linux_manager.oauth_contract import OAUTH_PROVIDERS
        for provider, spec in OAUTH_PROVIDERS.items():
            self.identifier = secrets.token_hex(12)
            mode = spec['flow']; number = spec['port'] or (8317 if provider == 'devin' else 0)
            def response(path, *args, **kwargs):
                if '/auth-url?' in path:
                    data = {'status': 'ok', 'url': 'https://' + spec['hosts'][0] + '/authorize', 'state': self.state}
                    if mode == 'api-device': data.update(flow='device', user_code='TEST-CODE')
                    return data
                return {'status': 'wait'} if '/oauth/status?' in path else {'status': 'ok'}
            with mock.patch.object(REMOTE, 'cp_oauth_http', side_effect=response) as http, mock.patch.object(REMOTE, 'cp_read', return_value={'server': {'port': 8317}}):
                self.assertEqual(self.call('start', provider=provider, mode=mode, callback_port=number)['phase'], 'ready')
                if mode == 'callback':
                    self.call('callback', provider=provider, state=self.state, code='fixture')
                    sent = next(call.kwargs['data']['provider'] for call in http.call_args_list if '/oauth/callback' in call.args[0])
                    self.assertEqual(sent, spec.get('callback_provider', provider))
                self.call('cancel', provider=provider)
                self.assertTrue(any(call.kwargs.get('method') == 'DELETE' for call in http.call_args_list))
                self.assertFalse(REMOTE.cp_oauth_busy())

    def test_firewall_is_specific_to_new_port_and_cleanup_never_changes_policy(self):
        with mock.patch.object(REMOTE.shutil, 'which', return_value='/tool'), mock.patch.object(REMOTE, 'command', return_value=types.SimpleNamespace(returncode=0)) as command:
            REMOTE.cp_oauth_firewall(self.identifier, 45678)
            REMOTE.cp_oauth_firewall(self.identifier, 45678, remove=True)
        for call in command.call_args_list:
            args = call.args[0]
            self.assertIn(args[0], ['iptables', 'ip6tables']); self.assertIn('45678', args)
            self.assertIn('lm-oauth-' + self.identifier, args); self.assertIn('lo', args)
            self.assertNotIn('-F', args); self.assertNotIn('-P', args)

    def test_missing_ipv6_tool_does_not_insert_an_ipv4_rule(self):
        with mock.patch.object(REMOTE.shutil, 'which', side_effect=lambda tool: '/tool' if tool == 'iptables' else None):
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.cp_oauth_firewall(self.identifier, 45678)
        self.command.assert_not_called()

    def test_worker_cleans_partial_firewall_insertion_and_allows_retry(self):
        folder = REMOTE.cp_oauth_folder(self.identifier); folder.mkdir(parents=True)
        REMOTE.CP_DATA.mkdir()
        session = {'id': self.identifier, 'provider': 'antigravity', 'mode': 'cli', 'callback_port': 45678,
                   'phase': 'starting', 'expires': time.time() + 300, 'cleanup_pending': True}
        REMOTE.write_json(folder / 'session.json', session)
        REMOTE.write_json(folder / 'private.json', {'management_key': self.key})
        with mock.patch.object(REMOTE.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=501, pw_gid=20)), \
             mock.patch.object(REMOTE.os, 'chown'), mock.patch.object(REMOTE.os, 'fchown'), \
             mock.patch.object(REMOTE, 'cp_read', return_value={'oauth': {}}), mock.patch.object(REMOTE, 'cp_yaml', return_value=types.SimpleNamespace(safe_dump=lambda *a, **k: '{}')), \
             mock.patch.object(REMOTE, 'ensure_port_available'), mock.patch.object(REMOTE.subprocess, 'Popen') as process, \
             mock.patch.object(REMOTE, 'cp_oauth_firewall', side_effect=[REMOTE.OperationError('fixture-ipv6-insert-failure'), None]) as firewall:
            REMOTE.cp_oauth_worker(self.identifier)
        process.assert_not_called()
        self.assertEqual(firewall.call_args_list, [mock.call(self.identifier, 45678), mock.call(self.identifier, 45678, remove=True)])
        result = json.loads((folder / 'session.json').read_text())
        self.assertEqual(result['phase'], 'failed'); self.assertFalse(result['cleanup_pending'])
        self.assertFalse((folder / 'private.json').exists())
        self.assertFalse(list(REMOTE.CP_DATA.glob('.oauth-*')))
        self.assertFalse(REMOTE.cp_oauth_busy())

    def test_firewall_cleanup_attempts_ipv6_after_ipv4_delete_failure(self):
        def command(args, **kwargs):
            if args[0] == 'iptables' and '-D' in args:
                raise REMOTE.OperationError('fixture-delete-failure')
            return types.SimpleNamespace(returncode=0)
        with mock.patch.object(REMOTE.shutil, 'which', return_value='/tool'), mock.patch.object(REMOTE, 'command', side_effect=command) as calls:
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.cp_oauth_firewall(self.identifier, 45678, remove=True)
        self.assertTrue(any(c.args[0][0] == 'ip6tables' and '-D' in c.args[0] for c in calls.call_args_list))

    def test_firewall_check_error_is_not_mistaken_for_an_absent_rule(self):
        with mock.patch.object(REMOTE.shutil, 'which', return_value='/tool'), mock.patch.object(REMOTE, 'command', return_value=types.SimpleNamespace(returncode=2)) as calls:
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.cp_oauth_firewall(self.identifier, 45678, remove=True)
        self.assertEqual({c.args[0][0] for c in calls.call_args_list}, {'iptables', 'ip6tables'})

    def test_corrupt_session_blocks_maintenance_without_a_python_exception(self):
        folder = REMOTE.cp_oauth_folder(self.identifier); folder.mkdir(parents=True)
        valid = {'id': self.identifier, 'provider': 'codex', 'mode': 'callback', 'phase': 'ready', 'expires': time.time() + 300}
        for bad in [[], None, {}, valid | {'id': secrets.token_hex(12)}, valid | {'provider': []},
                    valid | {'phase': {}}, valid | {'expires': 'tomorrow'}, valid | {'expires': float('nan')},
                    valid | {'mode': 'cli', 'callback_port': None}]:
            with self.subTest(bad=bad):
                (folder / 'session.json').write_text(json.dumps(bad))
                with self.assertRaisesRegex(REMOTE.OperationError, '授权会话记录无法读取'):
                    REMOTE.cp_oauth_busy()
                with self.assertRaisesRegex(REMOTE.OperationError, '授权会话记录无法读取'):
                    self.call('status')
        self.command.assert_not_called()


class ProviderMatrixTests(unittest.TestCase):
    def test_mac_browser_falls_back_without_fixed_app_path_or_automation_permission(self):
        from linux_manager.oauth import open_authorization_browser
        import shlex
        url = 'https://auth.openai.com/authorize?state=fixture&extra=a\'b'
        with mock.patch('linux_manager.oauth.sys.platform', 'darwin'), mock.patch('linux_manager.oauth.subprocess.run', side_effect=[types.SimpleNamespace(returncode=1), types.SimpleNamespace(returncode=0)]) as run:
            self.assertTrue(open_authorization_browser(url))
        self.assertEqual(shlex.split(run.call_args_list[0].kwargs['input']), ['exec', '/usr/bin/open', '-b', 'com.google.Chrome', url])
        self.assertEqual(shlex.split(run.call_args_list[1].kwargs['input']), ['exec', '/usr/bin/open', url])
        self.assertEqual(run.call_args.args[0], ['/bin/sh'])

    def test_all_eight_native_login_contracts_validate_without_guessing_redirect(self):
        from linux_manager.oauth_contract import OAUTH_PROVIDERS
        self.assertEqual(set(OAUTH_PROVIDERS), {'codex', 'antigravity', 'claude', 'devin', 'kimi', 'kimi-ai', 'xai', 'meta'})
        for provider, spec in OAUTH_PROVIDERS.items():
            with self.subTest(provider=provider):
                state = secrets.token_urlsafe(24); number = spec['port'] or (8317 if provider == 'devin' else 0)
                if spec['flow'] == 'api-device':
                    data = {'mode': 'api-device', 'url': 'https://' + spec['hosts'][0] + '/device?user_code=TEST-CODE', 'user_code': 'TEST-CODE'}
                else:
                    query = {'redirect_uri': f"http://{spec['redirect_host']}:{number}{spec['path']}", 'state': state,
                             'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'}
                    data = {'mode': 'callback', 'state': state, 'url': 'https://' + spec['hosts'][0] + '/authorize?' + urllib.parse.urlencode(query)}
                validate_authorization(provider, data, number)
                with self.assertRaises(ManagerError):
                    validate_authorization(provider, {**data, 'url': data['url'].replace(spec['hosts'][0], 'evil.invalid')}, number)

    def test_claude_and_devin_occupied_ports_observe_only_matching_chrome_state(self):
        from linux_manager.oauth_contract import OAUTH_PROVIDERS
        actual = LoopbackCallback
        for provider in ['claude', 'devin']:
            spec = OAUTH_PROVIDERS[provider]; number = spec['port'] or 8317
            state = secrets.token_urlsafe(24); code = secrets.token_urlsafe(24); callbacks = []
            def rpc(operation, **params):
                if operation == 'capabilities': return {'callback_port': number}
                if operation == 'start':
                    self.assertEqual(params['mode'], 'observe'); self.assertEqual(params['callback_port'], number)
                    query = {'redirect_uri': f"http://{spec['redirect_host']}:{number}{spec['path']}", 'state': state,
                             'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'}
                    return {'phase': 'ready', 'mode': 'observe', 'state': state, 'url': 'https://' + spec['hosts'][0] + '/authorize?' + urllib.parse.urlencode(query)}
                if operation == 'callback': callbacks.append(params); return {'phase': 'exchanging'}
                if operation == 'status': return {'phase': 'succeeded', 'recognized': True}
                return {'phase': 'cancelled'}
            def receiver(name, **kwargs):
                if kwargs.get('listen', True): raise CallbackPortBusy('合成占用')
                return actual(name, **kwargs)
            prefix = f"http://{spec['redirect_host']}:{number}{spec['path']}?"
            wrong = prefix + urllib.parse.urlencode({'state': 'other-client', 'code': 'other-code'})
            valid = prefix + urllib.parse.urlencode({'state': state, 'code': code})
            with mock.patch('linux_manager.oauth.LoopbackCallback', side_effect=receiver), mock.patch('linux_manager.oauth.chrome_callback_urls', side_effect=[[], [wrong, valid]]):
                login = OAuthLogin(provider, rpc)
                self.assertTrue(login.run()['recognized'])
            self.assertEqual(len(callbacks), 1); self.assertEqual(callbacks[0]['code'], code)
            self.assertFalse(login.receiver.servers)

    def test_native_device_flows_never_bind_a_callback_port_or_submit_callback(self):
        from linux_manager.oauth_contract import OAUTH_PROVIDERS
        for provider in ['kimi', 'kimi-ai', 'xai', 'meta']:
            calls = []
            def rpc(operation, **params):
                calls.append(operation)
                if operation == 'start':
                    self.assertEqual(params['mode'], 'api-device'); self.assertEqual(params['callback_port'], 0)
                    return {'phase': 'ready', 'mode': 'api-device', 'url': 'https://' + OAUTH_PROVIDERS[provider]['hosts'][0] + '/device', 'user_code': 'TEST-CODE'}
                return {'phase': 'succeeded', 'recognized': True}
            with mock.patch('linux_manager.oauth.LoopbackCallback') as callback:
                self.assertTrue(OAuthLogin(provider, rpc).run()['recognized'])
                callback.assert_not_called()
            self.assertNotIn('callback', calls)

    def test_chrome_bridge_uses_stdin_and_does_not_echo_secret_url(self):
        from linux_manager.oauth import open_authorization_browser, chrome_callback_urls
        secret = secrets.token_urlsafe(24)
        url = 'https://auth.openai.com/authorize?state=' + secret
        with mock.patch('linux_manager.oauth.sys.platform', 'darwin'), mock.patch('linux_manager.oauth.subprocess.run', return_value=types.SimpleNamespace(returncode=0, stdout='')) as run:
            self.assertTrue(open_authorization_browser(url))
            self.assertNotIn(secret, str(run.call_args.args))
            self.assertIn(secret, run.call_args.kwargs['input'])
            self.assertIn('com.google.Chrome', run.call_args.kwargs['input'])
            chrome_callback_urls('127.0.0.1', 8317, '/callback')
            self.assertIn('http://127.0.0.1:8317/callback?', run.call_args.kwargs['input'])


class NativeOAuthUITests(unittest.TestCase):
    def tearDown(self):
        # Collect destroyed fixture windows on the Tk thread, before another
        # test starts a worker that could otherwise collect their Variables.
        gc.collect()

    @staticmethod
    def destroy_window(root):
        for thread, _ in root.__dict__.get('_worker_contexts', []):
            thread.join(timeout=2)
        if isinstance(root, App) and '_worker_contexts' in root.__dict__:
            root._reap_workers()
        for identifier in root.tk.splitlist(root.tk.call('after', 'info')):
            root.after_cancel(identifier)
        root.destroy()

    def test_gui_browser_failure_and_cancel_disconnect_release_controls_for_another_login(self):
        from linux_manager import gui
        from linux_manager.project_info import server_key
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(gui, 'data_directory', return_value=Path(folder)), mock.patch.object(App, '_load_saved_profiles'):
                app = App(); app.withdraw()
            try:
                connection = Connection(host='fixture.invalid', username='fixture')
                app._load_profile(connection); app.report = {'supported': True}; app.report_server_key = server_key(connection)
                app.controller.connection_status = lambda _: {'state': 'connected'}
                spec = {'phase': 'ready', 'mode': 'api-device', 'url': 'https://auth.kimi.com/device', 'user_code': 'TEST-CODE'}
                def rpc(operation, **params):
                    if operation == 'cancel': raise ManagerError('取消时断线')
                    return spec if operation == 'start' else {'phase': 'succeeded', 'recognized': True}
                logins = [OAuthLogin('kimi', rpc), OAuthLogin('kimi', rpc)]
                app.controller.oauth_login = mock.Mock(side_effect=logins)
                app._refresh_project_info = mock.Mock()
                with mock.patch('linux_manager.oauth.open_authorization_browser', side_effect=[ManagerError('浏览器未能打开'), True]), mock.patch.object(gui.messagebox, 'showerror') as error:
                    for login in logins:
                        app._oauth('kimi')
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline and (not login.finished.is_set() or app.busy):
                            app.update(); time.sleep(0.02)
                        self.assertTrue(login.finished.is_set()); self.assertFalse(app.busy)
                    error.assert_called_once()
                    self.assertEqual(error.call_args.args[1], '浏览器未能打开')
                    app._refresh_project_info.assert_called_once()
            finally:
                app.controller.close_connections(); self.destroy_window(app)

    def test_actual_gui_worker_opens_chrome_and_finishes_without_freezing_tk(self):
        from linux_manager import gui
        from linux_manager.project_info import server_key
        temporary = tempfile.TemporaryDirectory()
        with mock.patch.object(gui, 'data_directory', return_value=Path(temporary.name)), mock.patch.object(App, '_load_saved_profiles'):
            app = App(); app.withdraw()
        try:
            connection = Connection(host='fixture.invalid', username='fixture')
            app._load_profile(connection); app.report = {'supported': True}; app.report_server_key = server_key(connection)
            app.controller.connection_status = lambda _: {'state': 'connected'}
            spec = {'phase': 'ready', 'mode': 'api-device', 'url': 'https://auth.kimi.com/device', 'user_code': 'TEST-CODE'}
            def rpc(operation, **params):
                return spec if operation == 'start' else {'phase': 'succeeded', 'recognized': True}
            login = OAuthLogin('kimi', rpc)
            app.controller.oauth_login = lambda *args: login
            app._refresh_project_info = mock.Mock()
            app.manage_choice.set(SERVICES['cliproxyapi'][0]); app._project_changed()
            app.oauth_provider.set('Kimi 国内站')
            ticks = []
            def tick():
                ticks.append(True)
                if not login.finished.is_set(): app.after(30, tick)
            def slow_browser(_):
                time.sleep(0.5)
                return True
            with mock.patch('linux_manager.oauth.open_authorization_browser', side_effect=slow_browser) as browser, mock.patch.object(gui.messagebox, 'showerror') as error:
                buttons = [child.button for child in app.ai_oauth.winfo_children() if hasattr(child, 'button')]
                buttons[2].invoke(); app.after(30, tick)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and (not login.finished.is_set() or app.busy):
                    app.update(); time.sleep(0.02)
                self.assertTrue(login.finished.is_set()); self.assertFalse(app.busy)
                self.assertGreater(len(ticks), 5)
                browser.assert_called_once_with(spec['url']); error.assert_not_called()
                app._refresh_project_info.assert_called_once()
        finally:
            app.controller.close_connections(); self.destroy_window(app); temporary.cleanup()

    def test_buttons_are_project_scoped_and_have_help(self):
        from tkinter import ttk
        from linux_manager.help_texts import HELP
        root = tk.Tk(); root.withdraw()
        try:
            app = object.__new__(App); page = ttk.Frame(root)
            app.pages = {'日常维护': types.SimpleNamespace(content=page)}; app.buttons = []; app.private_entries = []
            app.privacy = tk.BooleanVar(root); app.current = Connection(host='fixture.invalid')
            app.project_details = {}; app.project_logs = {}; app._maintenance_page()
            app.manage_choice.set(SERVICES['cliproxyapi'][0]); app._project_changed()
            self.assertTrue(app.ai_oauth.winfo_manager())
            self.assertIn('登录 Codex', HELP); self.assertIn('登录 Antigravity', HELP)
            app.manage_choice.set(SERVICES['exchange'][0]); app._project_changed()
            self.assertFalse(app.ai_oauth.winfo_manager())
        finally: self.destroy_window(root)


if __name__ == '__main__': unittest.main()
