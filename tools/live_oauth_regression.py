"""Explicit authorized-host OAuth verification; never prints URLs, states, codes or tokens."""
import argparse
import json
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
import tempfile
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager.controller import Controller
from linux_manager.models import ManagerError, Store, atomic_private, SERVICES
from linux_manager.oauth import OAuthLogin, LoopbackCallback, CallbackPortBusy
from tools import live_direct_download_regression as live

BASELINE = '''import hashlib,json,pathlib,subprocess
result={'pid':subprocess.check_output(['systemctl','show','cli-proxy-api.service','-p','MainPID','-p','InvocationID'],text=True),'config':hashlib.sha256(pathlib.Path('/etc/cliproxyapi/config.yaml').read_bytes()).hexdigest(),'auth':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/var/lib/cliproxyapi/auth').glob('*.json')},'rules':{tool:subprocess.check_output([tool,'-w','5','-S','INPUT'],text=True) for tool in ['iptables','ip6tables']},'temporary_count':len(list(pathlib.Path('/var/lib/cliproxyapi').glob('.oauth-*')))}
'''


def check(value, label):
    if not value: raise RuntimeError(label)
    print('PASS: ' + label, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--saved-test-server', action='store_true', required=True)
    parser.add_argument('--native-provider', choices=['codex', 'antigravity'])
    parser.add_argument('--provider-matrix', action='store_true', help='Start/cancel all built-in login contracts without importing an account.')
    args = parser.parse_args()
    store = Store(Path.home() / 'Library/Application Support/linux服务器管理')
    profiles = store.profiles(); check(len(profiles) == 1 and not store.last_warning, 'single saved authorized test identity')
    connection = profiles[0]; controller = Controller(store)
    ssh = controller.transport(connection, fresh=True); check(ssh.trusted(), 'saved SSH identity is trusted')
    live.EVIDENCE = Path('/private/tmp/linux-manager-cliproxyapi-live')
    live.EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    before = live.remote_python(ssh, BASELINE)
    if args.native_provider:
        native(controller, connection, args.native_provider, before)
        return
    results = []
    cases = [(provider, False) for provider in ['codex', 'antigravity', 'claude', 'devin', 'kimi', 'kimi-ai', 'xai', 'meta']] if args.provider_matrix else [('codex', False), ('antigravity', False), ('codex', True), ('antigravity', True)]
    for provider, conflict in cases:
        login = controller.oauth_login(connection, provider)
        actual = LoopbackCallback
        def receiver(name, port=None, **kwargs):
            if conflict and port is None: raise CallbackPortBusy('端口冲突回归')
            return actual(name, port=port, **kwargs)
        got_ready = []
        def ready(data):
            got_ready.append(True)
            if data['mode'] in {'device', 'api-device', 'observe'}:
                login.cancel()  # No real account imported in this negative-path test.
            else:
                callback = login.receiver
                query = 'state=' + callback.state + '&error=access_denied'
                status, _ = callback.accept(callback.path + '?' + query, f'localhost:{callback.port}')
                check(status == 200, provider + ' local receiver accepts only its live state')
        try:
            with mock.patch('linux_manager.oauth.LoopbackCallback', side_effect=receiver):
                login.run(ready)
            raise RuntimeError('negative OAuth test unexpectedly succeeded')
        except ManagerError:
            if args.provider_matrix and not got_ready:
                try:
                    state = login.rpc('status', session_id=login.identifier, provider=provider)
                except ManagerError:
                    raise RuntimeError(provider + ' preflight failed before creating a server session; no compatibility success claimed') from None
                check(state.get('phase') in {'failed', 'cancelled'} and not state.get('cleanup_failed'), provider + ' unavailable upstream is reported and cleaned; no success claimed')
                results.append({'provider': provider, 'entry_available': False, 'phase': state['phase']})
                continue
            check(bool(got_ready), provider + (' occupied-port fallback' if conflict else ' normal callback') + ' reached real official authorization entry')
        check(login.finished.is_set() and (not login.receiver or login.receiver.closed), provider + ' local callback resources released')
        time.sleep(2)
        state = login.rpc('status', session_id=login.identifier, provider=provider)
        check(state['phase'] in {'cancelled', 'failed'} and not state.get('cleanup_failed'), provider + ' remote denial/cancellation terminal state')
        results.append({'provider': provider, 'conflict': conflict, 'phase': state['phase'], 'entry_available': True})
    after = live.remote_python(ssh, BASELINE)
    check(before == after, 'core never restarted; original auth/config/firewall and temporary directory count preserved')
    atomic_private(live.EVIDENCE / ('oauth-provider-matrix.json' if args.provider_matrix else 'oauth-negative-regression.json'), json.dumps({'passed': True, 'cases': results}, ensure_ascii=False))
    controller.close_connections()


def native(controller, connection, provider, before):
    from linux_manager.gui import App
    from linux_manager import gui
    from linux_manager.project_info import server_key
    errors = []
    directory = tempfile.TemporaryDirectory(prefix='lm-native-oauth-', dir='/private/tmp')
    with mock.patch.object(gui, 'data_directory', return_value=Path(directory.name)), mock.patch.object(App, '_load_saved_profiles'):
        app = App()
    app.title('OAuth 授权验证 · 源码入口')
    app.controller.close_connections(); app.controller = controller
    controller.connection_listener = lambda state: app.events.put(('connection', state, None))
    target = connection.changed(label='已授权测试服务器')
    app._load_profile(target); app.report = {'supported': True}; app.report_server_key = server_key(target)
    app.manage_choice.set(SERVICES['cliproxyapi'][0]); app._project_changed()
    app.notebook.select(app.pages['日常维护'])
    controller.keep_connection(connection)
    deadline = time.monotonic() + 880
    started = False
    def poll():
        nonlocal started
        if not started and controller.connection_status(connection)['state'] == 'connected':
            buttons = [child.button for child in app.ai_oauth.winfo_children() if hasattr(child, 'button')]
            buttons[0 if provider == 'codex' else 1].invoke()
            started = True
        login = controller._oauth_login
        if started and login and login.finished.is_set() and not app.busy and app.events.empty():
            app.destroy(); return
        if time.monotonic() >= deadline:
            if login: login.cancel()
            errors.append('本次真实授权验证超时。'); app.destroy(); return
        app.after(200, poll)
    def record_error(title, text, **kwargs):
        # GUI messages are already fixed, redacted categories; no raw errors here.
        errors.append(text)
    with mock.patch.object(gui.messagebox, 'showerror', side_effect=record_error):
        app.after(100, poll); app.mainloop()
    login = controller._oauth_login
    state = login.rpc('status', session_id=login.identifier, provider=provider) if login else {}
    after = live.remote_python(controller.transport(connection, fresh=True), BASELINE)
    preserved = before['pid'] == after['pid'] and before['config'] == after['config'] and before['rules'] == after['rules'] and before['temporary_count'] == after['temporary_count']
    evidence = {'provider': provider, 'native_button_invoked': started, 'phase': state.get('phase'), 'recognized': state.get('recognized', False),
                'errors': errors, 'core_config_firewall_preserved': preserved, 'real_inference': False,
                'new_authorization_saved': before['auth'] != after['auth']}
    atomic_private(live.EVIDENCE / ('oauth-native-' + provider + '.json'), json.dumps(evidence, ensure_ascii=False, indent=2))
    check(preserved, 'native OAuth leaves core, original config and firewall unchanged')
    check(not errors and state.get('phase') == 'succeeded' and state.get('recognized'), 'native GUI OAuth saves and recognizes authorization on selected Linux host')
    controller.close_connections(); directory.cleanup()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'passed': False, 'type': type(error).__name__, 'reason': str(error) if isinstance(error, RuntimeError) else 'Private redacted diagnostics only'}), flush=True)
        raise SystemExit(1)
