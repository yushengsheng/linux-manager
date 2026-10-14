"""Resume the already-installed, explicitly authorized test gateway; no paid inference.

Keeps the existing keys and upstream configuration. Requires an empty upstream
account list before briefly testing the AI core's stopped/restored lifecycle.
Never reinstalls trading, changes SSH policy, or modifies desktop providers.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager.controller import Controller
from linux_manager.models import Store, atomic_private
from tools import live_direct_download_regression as live

IDENTITY = '''import hashlib,json,pathlib,runpy,subprocess
ns=runpy.run_path('/var/lib/linux-server-manager/cliproxyapi/maintenance.py',run_name='lm_readonly_probe')
g=ns['cp_read'].__globals__
units=['xiaojun-exchange-web.service','xiaojun-exchange-worker.service','xiaojun-exchange-nginx.service','sing-box.service','linux-manager-xray.service','x-ui.service','nginx.service','ssh.service','ssh.socket','fail2ban.service']
result={'services':{u:subprocess.check_output(['systemctl','show',u,'-p','MainPID','-p','InvocationID','-p','ActiveState'],text=True) for u in units},'files':{},'gateway_config':hashlib.sha256(json.dumps(g['cp_read'](),sort_keys=True).encode()).hexdigest(),'authorization_files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (g['CP_DATA']/'auth').glob('*.json')}}
for name in ['/etc/sing-box/config.json','/etc/linux-manager-xray/config.json','/etc/nginx/conf.d/linux-manager-default.conf','/etc/ssh/sshd_config']:
 p=pathlib.Path(name)
 if p.is_file():result['files'][name]=hashlib.sha256(p.read_bytes()).hexdigest()
'''

SCHEDULE = '''import json,pathlib,runpy,subprocess
ns=runpy.run_path('/var/lib/linux-server-manager/cliproxyapi/maintenance.py',run_name='lm_readonly_probe')
g=ns['cp_read'].__globals__;result={}
for action in ['update','backup']:
 prefix='linux-manager-cliproxyapi-'+action
 fields=subprocess.check_output(['systemctl','show',prefix+'.timer','-p','ActiveState','-p','SubState','-p','NextElapseUSecRealtime','-p','LastTriggerUSec','-p','UnitFileState'],text=True)
 result[action]=dict(line.split('=',1) for line in fields.splitlines() if '=' in line)
 result[action]['definition']=pathlib.Path('/etc/systemd/system/'+prefix+'.timer').read_text()
result['maintenance_source_matches_current_agent']=pathlib.Path('/var/lib/linux-server-manager/cliproxyapi/maintenance.py').read_text()==EXPECTED_SOURCE
result['update_status']=json.loads((g['CP_STATE']/'update-status.json').read_text())
result['backup_status']=json.loads((g['CP_STATE']/'backup-status.json').read_text())
'''


def check(condition, label):
    if not condition:
        raise RuntimeError(label)
    print('PASS: ' + label, flush=True)


def current_agent_source(ssh):
    import base64
    import unittest.mock
    from linux_manager import transport
    packet = {}
    def capture(args, **kwargs):
        encoded = next(line[10:] for line in kwargs['input'].splitlines() if line.startswith('LMREQUEST:'))
        packet.update(json.loads(base64.b64decode(encoded)))
        return type('Completed', (), {'stdout': 'LM_RESULT:{"ok":true,"data":{}}', 'stderr': '', 'returncode': 0})()
    with unittest.mock.patch.object(ssh, 'trusted', return_value=True), unittest.mock.patch.object(transport.subprocess, 'run', side_effect=capture):
        ssh.call({'action': 'ping'})
    return packet['agent']


def main():
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--authorized-test-host')
    target.add_argument('--saved-test-server', action='store_true', help='Use the single already-trusted saved test identity without exposing it in argv.')
    parser.add_argument('--skip-lifecycle', action='store_true', help='Do not stop/restore a gateway that already has upstream accounts.')
    parser.add_argument('--sync-maintenance-only', action='store_true', help='Update only the owned maintenance source without restarting the core or rewriting config.')
    args = parser.parse_args()
    store = Store(Path.home() / 'Library/Application Support/linux服务器管理')
    profiles = store.profiles()
    targets = profiles if args.saved_test_server else [p for p in profiles if p.host == args.authorized_test_host]
    check(len(targets) == 1 and not store.last_warning, 'exact saved authorized test identity')
    connection = targets[0]
    controller = Controller(store)
    ssh = controller.transport(connection, fresh=True)
    check(ssh.trusted(), 'existing SSH host identity remains trusted')
    live.EVIDENCE = Path('/private/tmp/linux-manager-cliproxyapi-live')
    live.EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    report = ssh.call({'action': 'snapshot'})
    check(not any(t['state'] in {'queued', 'running', 'awaiting_verification', 'recovery_failed'} for t in report['tasks']), 'no unfinished task is replayed')
    info = controller.project_information(connection, 'cliproxyapi')['data']
    check(info.get('installed') and info.get('management_key_valid'), 'existing gateway and saved management key verified')
    check(not info.get('accounts') or args.skip_lifecycle or args.sync_maintenance_only, 'live upstream accounts require skipping stop/restore lifecycle')
    before = live.remote_python(ssh, IDENTITY)
    if args.sync_maintenance_only:
        source = current_agent_source(ssh)
        code = 'SOURCE=' + repr(source) + '\n' + '''import fcntl,json,runpy,pathlib
ns=runpy.run_path('/var/lib/linux-server-manager/cliproxyapi/maintenance.py',run_name='lm_readonly_probe');g=ns['cp_read'].__globals__
with g['state_lock'](g['ROOT']/'submission',timeout=5), (g['ROOT']/'operation.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 assert not g['cp_oauth_busy']()
 assert not any(t['state'] in {'queued','running','awaiting_verification','recovery_failed'} for t in g['task_list']())
 file=g['CP_RUNNER'];assert file.is_file() and not file.is_symlink() and file.stat().st_uid==0
 compile(SOURCE,'<linux-manager-maintenance>','exec')
 g['private_write'](file.with_name('maintenance.before-oauth-matrix.py'),file.read_bytes())
 g['private_write'](file,SOURCE)
check=runpy.run_path(str(file),run_name='lm_readonly_probe')
result={'source_matches':file.read_text()==SOURCE,'native_provider_count':len(check['OAUTH_PROVIDERS'])}
'''
        result = live.remote_python(ssh, code)
        check(result['source_matches'] and result['native_provider_count'] == 8, 'autonomous maintenance uses current eight-provider bridge and update guard')
        schedule = live.remote_python(ssh, 'EXPECTED_SOURCE=' + repr(source) + '\n' + SCHEDULE)
        for action in ['update', 'backup']:
            check(schedule[action]['NextElapseUSecRealtime'] not in ['', '0', 'infinity', 'n/a'], action + ' timer still has a real future deadline')
        check(before == live.remote_python(ssh, IDENTITY), 'source-only sync never restarts core/other services or changes keys/config/authorization')
        atomic_private(live.EVIDENCE / 'oauth-maintenance-sync.json', json.dumps({'passed': True, 'source_matches': True, 'provider_count': 8, 'core_not_restarted': True}, ensure_ascii=False))
        return
    params = {'operation': 'deploy', 'service': 'cliproxyapi', 'host': info['host'],
              'port': info['port'], 'backend_port': info['backend_port'],
              'version_policy': 'keep', 'auto_update': True}
    plan = controller.deployment_preview(connection, params)
    check(plan['version'] == info['version'] and not plan['requires_archive'], 'sync keeps the installed core version and client keys')
    params.update(version=plan['version'], deployment_fingerprint=plan['fingerprint'])
    status, _ = controller.execute(connection, params)
    check(status['state'] == 'succeeded', 'existing installation maintenance source and timers synchronized')
    current = controller.project_information(connection, 'cliproxyapi')['data']
    check(current['api_keys'] == info['api_keys'] and current['management_key_valid'], 'both original credential roles preserved')
    check('通过' in current.get('health', ''), 'local TLS, management page and distinct client authentication healthy')
    base = 'https://' + info['host'] + ':' + str(info['port'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    key = info['api_keys'][0]
    def get(path, credential=''):
        headers = {'Authorization': 'Bearer ' + credential} if credential else {}
        try:
            with opener.open(urllib.request.Request(base + path, headers=headers), timeout=15) as response:
                return response.status, response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as error:
            return error.code, b''
    check(all(get('/v1/models', k)[0] in {401, 403} for k in ['', secrets.token_urlsafe(24)]), 'public API rejects missing and incorrect keys')
    code, body = get('/v1/models', key)
    check(code == 200 and isinstance(json.loads(body).get('data'), list), 'Mac directly verifies public HTTPS and model catalog')
    check(get('/v8/management/config', key)[0] in {401, 403}, 'client key cannot administer the public gateway')
    for credential in ['', secrets.token_urlsafe(24)]:
        client = http.client.HTTPSConnection(info['host'], info['port'], timeout=15, context=ssl.create_default_context())
        headers = {'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13',
                   'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='}
        if credential:
            headers['Authorization'] = 'Bearer ' + credential
        try:
            client.request('GET', '/v1/responses', headers=headers)
            response = client.getresponse()
            check(response.status in {401, 403}, 'WebSocket upgrade rejects unauthenticated requests')
        finally:
            client.close()
    if not args.skip_lifecycle:
        backup, _ = controller.execute(connection, {'operation': 'backup', 'service': 'cliproxyapi'})
        controller.execute(connection, {'operation': 'service', 'service': 'cliproxyapi', 'action': 'stop'})
        try:
            result = live.remote_python(ssh, '''import json,subprocess,runpy
subprocess.run(['systemctl','start','linux-manager-cliproxyapi-update.service'],check=True,timeout=120)
ns=runpy.run_path('/var/lib/linux-server-manager/cliproxyapi/maintenance.py',run_name='lm_readonly_probe');g=ns['cp_read'].__globals__
result={'state':g['unit_info'](g['CP_UNIT'])['ActiveState'],'update':json.loads((g['CP_STATE']/'update-status.json').read_text())}
''', timeout=150)
            check(result['state'] != 'active' and '跳过' in result['update']['result'], 'scheduled update does not restart a deliberately stopped core')
            restored, _ = controller.execute(connection, {'operation': 'restore', 'backup_id': backup['result']['backup_id']})
            check(restored['result']['verified'] == 'configuration-restored-core-stopped', 'configuration restore preserves the stopped core')
        finally:
            controller.execute(connection, {'operation': 'service', 'service': 'cliproxyapi', 'action': 'start'})
    time.sleep(1)
    live.remote_python(ssh, '''import json,subprocess
for action in ['update','backup']:
 subprocess.run(['systemctl','start','linux-manager-cliproxyapi-'+action+'.service'],check=True,timeout=150)
result={'systemd_maintenance_executed':True}
''', timeout=320)
    schedule_code = 'EXPECTED_SOURCE=' + repr(current_agent_source(ssh)) + '\n' + SCHEDULE
    schedule = live.remote_python(ssh, schedule_code)
    for action in ['update', 'backup']:
        timer = schedule[action]
        check(timer['ActiveState'] == 'active' and timer['UnitFileState'] == 'enabled' and timer['NextElapseUSecRealtime'] not in ['', '0', 'infinity', 'n/a'], action + ' timer has a real future calendar deadline')
    check(schedule['maintenance_source_matches_current_agent'], 'server autonomous maintenance byte-matches current embedded source')
    after = live.remote_python(ssh, IDENTITY)
    check(before == after, 'original keys, authorization files, other services, SSH and configurations unchanged')
    evidence = {'passed': True, 'target': 'authorized-test-server', 'sync_task': status['id'],
                'local_public_https': True, 'credentials_preserved': True, 'other_services_preserved': True,
                'stopped_restore_preserved': not args.skip_lifecycle, 'timers': {k: schedule[k] for k in ['update', 'backup']},
                'update_result': schedule['update_status']['result'], 'real_upstream_inference': False}
    atomic_private(live.EVIDENCE / 'resume-regression.json', json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'passed': False, 'type': type(error).__name__,
                          'reason': str(error) if isinstance(error, RuntimeError) else 'See the private task diagnostics; no credentials printed'}), flush=True)
        raise SystemExit(1)
