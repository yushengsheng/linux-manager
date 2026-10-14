"""Run only on the currently configured, user-authorized disposable server."""
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager.controller import Controller
from linux_manager.models import Store, atomic_private
from linux_manager.project_info import credential_alias, node_links
from linux_manager.qr import qr_png
from linux_manager.transport import Askpass, BOOTSTRAP, ConnectionInterrupted, WaitingStopped, interruptible_ssh

EVIDENCE = Path('/private/tmp/linux-manager-direct-download-live')


def check(condition, label):
    if not condition: raise RuntimeError(label)
    print('PASS: ' + label, flush=True)


def remote_python(ssh, code, timeout=90):
    source = code + '\nprint("LM_RESULT:" + json.dumps({"ok": True, "data": result}))\n'
    envelope = json.dumps({'agent': source, 'request': {}}).encode()
    payload = (ssh.connection.sudo_password or ssh.connection.password) + '\nLMREQUEST:' + base64.b64encode(envelope).decode() + '\n'
    invocation = 'if [ "$(id -u)" = 0 ]; then python3 -c ' + shlex.quote(BOOTSTRAP) + '; else sudo -S -p \'\' python3 -c ' + shlex.quote(BOOTSTRAP) + '; fi'
    c = ssh.connection
    with tempfile.TemporaryDirectory(prefix='lm-live-', dir=EVIDENCE) as directory:
        folder = Path(directory)
        with Askpass(folder, c.key_passphrase if c.auth == 'key' else c.password) as env:
            configuration = ssh._config(folder)
            completed = interruptible_ssh(['ssh', '-F', str(configuration), '-T', 'linux-manager-server', invocation], cancel_event=threading.Event(), timeout=timeout, input=payload, text=True, encoding='utf-8', env=os.environ | env, start_new_session=True)
    for line in reversed(completed.stdout.splitlines()):
        if line.startswith('LM_RESULT:'):
            response = json.loads(line[10:])
            if response.get('ok'):return response['data']
    atomic_private(EVIDENCE/'remote-error.txt', ssh.redactor.text(completed.stderr))
    raise RuntimeError('test remote check returned no result')


def identity(ssh):
    return remote_python(ssh, '''import json,subprocess
units=['xiaojun-exchange-web.service','xiaojun-exchange-worker.service','xiaojun-exchange-nginx.service','nginx.service']
result={u:subprocess.check_output(['systemctl','show',u,'-p','MainPID','-p','InvocationID','-p','ActiveState'],text=True).strip() for u in units}
''')


def main():
    EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    store = Store(Path.home()/'Library/Application Support/linux服务器管理')
    profiles = store.profiles()
    check(len(profiles)==1 and profiles[0].label=='wyl' and not store.last_warning, 'exact configured test profile selected')
    c = profiles[0]; controller = Controller(store); ssh = controller.transport(c, fresh=True)
    report = controller.inspect(c)
    check(report['supported'] and report['architecture']=='x86_64', 'supported disposable Linux server')
    check(not any(t['state'] in {'queued','running','awaiting_verification','recovery_failed'} for t in report['tasks']), 'no unfinished server operation')
    before = identity(ssh)
    baseline_file = EVIDENCE/'baseline.json'
    if baseline_file.exists():
        baseline = json.loads(baseline_file.read_text())
    else:
        check(all(all(u['LoadState']=='not-found' for u in report['services'][kind]) for kind in ['hysteria2','reality','xui']), 'proxy test starts without existing installations')
        baseline = {'original_services': before, 'done': [], 'tasks': []}
        atomic_private(baseline_file, json.dumps(baseline))
    check(before==baseline['original_services'], 'original trading and Nginx processes unchanged')
    def save():atomic_private(baseline_file,json.dumps(baseline))
    def wait(identifier):
        previous = None
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            status = controller.retry_call(c, {'action':'task','task_id':identifier})
            state = (status['state'],status.get('message'))
            if state!=previous:
                print(json.dumps({'state':status['state'],'message':ssh.redactor.text(status.get('message',''))},ensure_ascii=False),flush=True);previous=state
            if status['state'] in {'succeeded','failed','recovery_failed','rolled_back'}:
                check(status['state']=='succeeded', 'original Linux installation finishes successfully')
                controller.observe_tasks(c,[status])
                return status
            time.sleep(2)
        raise RuntimeError('test observer deadline reached; inspect saved original task')
    def params(kind):
        p={'operation':'deploy','service':kind,'host':c.host,'port':{'hysteria2':51752,'reality':443,'xui':2053}[kind]}
        if kind=='hysteria2':p['proxy_password']=secrets.token_urlsafe(30)
        if kind=='xui':p.update(panel_username='manager',panel_password=secrets.token_urlsafe(30))
        return p
    if 'hy2' not in baseline['done']:
        if baseline['tasks']:
            identifier=baseline['tasks'][0]
        else:
            hy2=params('hysteria2');plan=controller.deployment_preview(c,hy2)
            hy2.update(version=plan['version'],deployment_fingerprint=plan['fingerprint'])
            cancel=threading.Event();starts=[];original=controller.transport
            def lossy(current,fresh=False):
                transport=original(current,fresh=fresh);call=transport.call
                def invoke(request,**kwargs):
                    result=call(request,**kwargs)
                    if request['action']=='start':
                        check('release_archive' not in request['params'], 'HY2 submission contains no Mac package')
                        starts.append(request['task_id']);baseline['tasks'].append(request['task_id']);save()
                        raise ConnectionInterrupted('injected submission reply loss')
                    return result
                transport.call=invoke
                return transport
            controller.transport=lossy
            def progress(status):
                if status.get('state')=='queued':cancel.set()
            try:
                controller.execute(c,hy2,progress,cancel_event=cancel)
                raise RuntimeError('observer cancellation was not exercised')
            except WaitingStopped:
                check(len(starts)==1, 'lost reply reconciled without resubmission; local waiting stopped')
                identifier=starts[0]
            finally:controller.transport=original
        status=wait(identifier)
        check(any('Linux' in e['message'] and '下载' in e['message'] for e in status['events']), 'Linux direct download progress recorded')
        baseline['done'].append('hy2');save()
    for kind in ['reality','xui']:
        if kind in baseline['done']:continue
        p=params(kind);plan=controller.deployment_preview(c,p)
        p.update(version=plan['version'],deployment_fingerprint=plan['fingerprint'])
        def progress(status):
            message=ssh.redactor.text(status.get('message',''))
            if message:print(json.dumps({'service':kind,'state':status.get('state'),'message':message},ensure_ascii=False),flush=True)
        status,_=controller.execute(c,p,progress,cancel_event=threading.Event())
        check(any('Linux' in e['message'] and '下载' in e['message'] for e in status['events']), kind+' installed through Linux download')
        baseline['done'].append(kind);baseline['tasks'].append(status['id']);save()
    for kind in ['hysteria2','reality']:
        data=controller.project_information(c,kind)['data'];link=node_links(data,c.host)[0][1]
        from PIL import Image
        import zxingcpp
        import io
        decoded=zxingcpp.read_barcode(Image.open(io.BytesIO(qr_png(link))))
        check(decoded is not None and decoded.text==link,kind+' QR decodes to the complete import link')
    traffic=remote_python(ssh,(BASE/'tools/live_proxy_traffic.py').read_text(),timeout=90)
    for kind,passed in traffic.items():check(passed,kind+' actual server traffic succeeds')
    credentials=store.vault.get(credential_alias(c,'xui'))
    checked=ssh.call({'action':'verify_project_password','service':'xui','username':credentials['panel_username'],'password':credentials['panel_password']})
    check(checked['verified'],'xui installed account and password verified')
    package=remote_python(ssh,'''import json,platform,runpy,tempfile
from pathlib import Path
version=Path('/opt/xiaojun-exchange/current/version.txt').read_text().strip()
runners=sorted(Path('/var/lib/linux-server-manager/tasks').glob('*/runner.py'),key=lambda p:p.stat().st_mtime,reverse=True)
scope=runpy.run_path(str(runners[0]),run_name='linux_manager_test_probe')
with tempfile.TemporaryDirectory(prefix='lm-exchange-download-') as directory:
 digest=scope['_downloads']['download_release']('exchange',version,platform.machine(),Path(directory)/'release.tar.gz')
result={'downloaded':True,'verified':len(digest)==64,'version':version}
''',timeout=180)
    check(package['downloaded'] and package['verified'],'exchange package downloaded and verified on Linux without reinstalling business services')
    check(identity(ssh)==baseline['original_services'],'original trading and Nginx processes preserved after all installs')
    atomic_private(EVIDENCE/'result.json',json.dumps({'passed':True,'checks':baseline['done'],'traffic':traffic,'exchange_direct_download':package,'original_services_preserved':True}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'passed':False,'type':type(error).__name__,'reason':str(error) if isinstance(error,RuntimeError) else 'See private diagnostic; no credentials printed'}),flush=True)
        raise SystemExit(1)
