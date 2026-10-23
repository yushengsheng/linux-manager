"""Real HY2/REALITY traffic acceptance on disposable GitHub Actions runners."""
import contextlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.parse
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager.project_info import node_links
from linux_manager.qr import qr_png
from linux_manager.controller import Controller
from linux_manager.models import Connection, Store
from linux_manager.transport import ConnectionInterrupted, WaitingStopped


def check(condition, message):
    if not condition:raise RuntimeError(message)
    print('PASS: ' + message, flush=True)


def require_disposable_runner():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('Requires a disposable GitHub Actions runner with root and systemd')


@contextlib.contextmanager
def reality_test_origin(remote, origin_port):
    """Allow only the synthetic HTTP origin while testing; restore exact bytes."""
    require_disposable_runner()
    if type(origin_port) is not int or not 1 <= origin_port <= 65535:
        raise ValueError('Invalid isolated HTTP origin port')
    path = Path(remote.REALITY_CONFIG)
    original = path.read_bytes()
    mode = stat.S_IMODE(path.stat().st_mode)
    config = json.loads(original)
    direct = [item for item in config.get('outbounds', [])
              if item.get('tag') == 'direct' and item.get('protocol') == 'freedom']
    if len(direct) != 1:
        raise RuntimeError('Expected one test-node direct outbound')
    settings = direct[0].setdefault('settings', {})
    # New Xray versions block private targets by default. This exception belongs
    # only to the disposable CI fixture, never to generated production configs.
    rule = {'action':'allow', 'network':'tcp', 'ip':['127.0.0.1/32'], 'port':str(origin_port)}
    settings['finalRules'] = [rule, *settings.get('finalRules', [])]
    with tempfile.TemporaryDirectory(prefix='.ci-origin-', dir=path.parent) as folder:
        candidate = Path(folder) / 'config.json'
        remote.private_write(candidate, json.dumps(config), mode)
        remote.command([remote.REALITY_BINARY, 'run', '-test', '-config', str(candidate)])
        try:
            remote.private_write(path, candidate.read_bytes(), mode)
            remote.command(['systemctl', 'restart', remote.REALITY_UNIT])
            yield
        finally:
            remote.private_write(path, original, mode)
            remote.command(['systemctl', 'restart', remote.REALITY_UNIT])


def main():
    require_disposable_runner()
    if any(Path(name).exists() for name in ['/var/lib/linux-server-manager','/etc/linux-manager-xray','/usr/local/lib/linux-manager-xray','/etc/sing-box/config.json','/usr/local/bin/sing-box']):
        raise SystemExit('Existing installation detected; refusing to modify it')
    artifacts=Path(os.environ['RUNNER_TEMP'])/'proxy-acceptance';artifacts.mkdir(mode=0o700)
    spec=importlib.util.spec_from_file_location('proxy_ci_remote',BASE/'linux_manager/remote_agent.py')
    remote=importlib.util.module_from_spec(spec);spec.loader.exec_module(remote)
    source=(BASE/'linux_manager/remote_agent.py').read_text()
    for name in ['server_downloads','reality','redeployment','uninstallation']:
        source=source.replace('#LM_BUNDLED_'+name.upper()+'#','LM_'+name.upper()+'_SOURCE = '+repr((BASE/'linux_manager'/ (name+'.py')).read_text()))
    source=source.replace('#LM_BUNDLED_CERTBOT#','CERTBOT_LOCK = '+repr((BASE/'linux_manager/resources/requirements-certbot.lock').read_text()))
    remote.AGENT_SOURCE=source
    remote.ROOT.mkdir(parents=True,mode=0o700)
    def submit(params):
        identifier=secrets.token_hex(12)
        if params['operation']=='deploy':
            plan=remote.deployment_preflight(params)
            params=params|{'version':plan['version'],'deployment_fingerprint':plan['fingerprint']}
        elif params['operation']=='uninstall':
            params=params|{'uninstall_fingerprint':remote.uninstall_preflight(params)['fingerprint']}
        remote.start_task(params,identifier)
        for _ in range(240):
            status=remote.status_task(identifier)
            if status['state']=='awaiting_verification':
                check(params['operation']=='restore', 'only configuration restore needs confirmation')
                traffic(params['service'])
                remote.confirm_task(identifier)
                status=remote.status_task(identifier)
            if status['state'] not in {'queued','running'}:
                check(status['state']=='succeeded', 'task '+params['operation']+' '+params.get('service','')+' succeeded: '+status.get('message','')+' '+status.get('diagnostic',''))
                return status
            time.sleep(1)
        raise RuntimeError('Proxy task timed out')
    def details(service):return remote.connection_details({'service':service,'host':'127.0.0.1'})
    def identity(data):return tuple(data[key] for key in ['uuid','public_key','short_id'])
    def qr_check(data):
        from PIL import Image
        import zxingcpp
        link=node_links(data,'127.0.0.1')[0][1]
        decoded=zxingcpp.read_barcode(Image.open(io.BytesIO(qr_png(link))))
        check(decoded is not None and decoded.text==link, data['service']+' QR decodes to exact complete link')
        return link
    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b'linux-manager-proxy-ok')
        def log_message(self,*args):pass
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    def traffic(service):
        fixture = reality_test_origin(remote, origin.server_port) if service == 'reality' else contextlib.nullcontext()
        with fixture:
            probe_traffic(service)
    def probe_traffic(service):
        data=details(service);link=qr_check(data);parsed=urllib.parse.urlsplit(link);query=urllib.parse.parse_qs(parsed.query)
        if service=='reality':
            config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':10880,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':parsed.hostname,'port':parsed.port,'users':[{'id':parsed.username,'encryption':'none','flow':query['flow'][0]}]}]},'streamSettings':{'network':'raw','security':'reality','realitySettings':{'serverName':query['sni'][0],'fingerprint':query['fp'][0],'password':query['pbk'][0],'shortId':query['sid'][0]}}}]}
            binary=remote.REALITY_BINARY;args=[binary,'run','-config']
        else:
            config={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':10880}],'outbounds':[{'type':'hysteria2','server':parsed.hostname,'server_port':parsed.port,'password':urllib.parse.unquote(parsed.username),'tls':{'enabled':True,'server_name':query['sni'][0],'certificate_path':str(artifacts/'hy2.crt')}}]}
            args=['/usr/local/bin/sing-box','run','-c']
        path=artifacts/'client.json';remote.private_write(path,json.dumps(config))
        with (artifacts/'client.log').open('w') as log:
            client=subprocess.Popen(args+[str(path)],stdout=log,stderr=log)
            try:
                for _ in range(30):
                    try:
                        with socket.create_connection(('127.0.0.1',10880),timeout=1):break
                    except OSError:time.sleep(.2)
                result=subprocess.run(['curl','--silent','--show-error','--fail','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','20','http://127.0.0.1:'+str(origin.server_port)+'/'],capture_output=True,timeout=25)
                if result.returncode or result.stdout!=b'linux-manager-proxy-ok':
                    print(remote.clean(result.stderr.decode()+'\n'+(artifacts/'client.log').read_text()),flush=True)
                    if service=='reality':
                        print(remote.clean(remote.command(['journalctl','--no-pager','-n','30','-u',remote.REALITY_UNIT],check=False).stdout),flush=True)
                check(result.returncode==0 and result.stdout==b'linux-manager-proxy-ok', service+' actual SOCKS to proxy to HTTP traffic succeeded')
            finally:
                client.terminate();client.wait(timeout=10)
    xray_version=remote.server_release_version('reality');hy2_version=remote.server_release_version('hysteria2')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(artifacts/'hy2.key'),'-out',str(artifacts/'hy2.crt'),'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
    hy2={'operation':'deploy','service':'hysteria2','host':'127.0.0.1','port':51752,'version':hy2_version,'proxy_password':secrets.token_urlsafe(30),'tls_cert':(artifacts/'hy2.crt').read_text(),'tls_key':(artifacts/'hy2.key').read_text()}
    # Exercise the real desktop SSH path with a lost submission reply, then
    # stop the local observer and verify that Linux completes the same job.
    remote.apt(['openssh-server'])
    key = artifacts / 'ci-ssh-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); ssh_port = listener.getsockname()[1]
    Path('/run/sshd').mkdir(exist_ok=True)
    ssh_config = artifacts / 'sshd-config'
    ssh_config.write_text(f'Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile {key}.pub\nStrictModes no\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nUsePAM no\nPidFile {artifacts}/sshd.pid\n')
    daemon = subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(ssh_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                with socket.create_connection(('127.0.0.1',ssh_port),timeout=1):break
            except OSError:time.sleep(.1)
        values = {}
        vault = types.SimpleNamespace(get=lambda alias: dict(values.get(alias,{})), put=lambda alias,data: values.__setitem__(alias,dict(data)),delete=lambda alias: values.pop(alias,None))
        controller = Controller(Store(artifacts/'local-observer',vault))
        connection = Connection(host='127.0.0.1',port=ssh_port,username='root',auth='key',key_path=str(key),remember=False)
        ssh = controller.transport(connection);_,host_keys = ssh.fingerprint();ssh.trust(host_keys)
        cancel = threading.Event(); starts = []
        transport = controller.transport
        def lossy_transport(c, fresh=False):
            ssh = transport(c, fresh=fresh); call = ssh.call
            def interrupted(request, **options):
                data = call(request, **options)
                if request['action']=='start':
                    starts.append(request['task_id'])
                    check('release_archive' not in request['params'] and len(json.dumps(request['params'])) < 10000,'HY2 submitted without an archive through real SSH')
                    raise ConnectionInterrupted('injected lost submission reply')
                return data
            ssh.call = interrupted
            return ssh
        controller.transport = lossy_transport
        def observe(status):
            if status.get('state') == 'queued':cancel.set()
        try:
            controller.execute(connection,hy2,observe,cancel_event=cancel)
            raise RuntimeError('Local observer was not stopped')
        except WaitingStopped:
            check(len(starts)==1,'lost submission response reconciles original task without resubmission')
        identifier = starts[0]
        for _ in range(300):
            status = remote.status_task(identifier)
            if status['state'] not in {'queued','running'}:break
            time.sleep(1)
        check(status['state']=='succeeded','Linux HY2 installation completes after local waiting stops: '+status['message'])
        check(any('Linux' in event['message'] and '下载' in event['message'] for event in status['events']),'Linux download progress recorded in task history')
        check(transport(connection).call({'action':'task','task_id':identifier})['state']=='succeeded','new SSH connection reads completed original HY2 task')
    finally:
        daemon.terminate();daemon.wait(timeout=10)
    traffic('hysteria2')
    hy2_config=Path('/etc/sing-box/config.json').read_bytes()
    params={'operation':'deploy','service':'reality','host':'127.0.0.1','port':443,'version':xray_version}
    submit(params);traffic('reality');original=identity(details('reality'))
    check(Path('/etc/sing-box/config.json').read_bytes()==hy2_config,'HY2 configuration preserved by REALITY install')
    same=submit(params|{'version_policy':'keep'});check(same['result']['action']=='unchanged','identical deployment does not reinstall')
    params=params|{'port':8443};submit(params|{'version_policy':'keep'});traffic('reality')
    check(identity(details('reality'))==original,'port change preserves UUID and REALITY keys')
    backup=submit({'operation':'backup','service':'reality'})['result']['backup_id']
    submit(params|{'port':8444,'version_policy':'keep'})
    submit({'operation':'restore','service':'reality','backup_id':backup});traffic('reality')
    check(details('reality')['port']==8443 and identity(details('reality'))==original,'configuration backup restores port and credentials')
    for action in ['stop','start']:
        submit({'operation':'service','service':'reality','action':action})
        check(remote.unit_info(remote.REALITY_UNIT)['ActiveState']==('inactive' if action=='stop' else 'active'),'REALITY service '+action)
    traffic('reality')
    for version in ['v26.2.6',xray_version]:
        submit(params|{'version':version});traffic('reality')
        check(identity(details('reality'))==original,'version switch preserves node credentials')
    before=Path(remote.REALITY_CONFIG).read_bytes()
    identifier=secrets.token_hex(12);remote.TASK=remote.ROOT/'tasks'/identifier;remote.TASK.mkdir(parents=True)
    plan=remote.deployment_preflight(params|{'port':8444,'version_policy':'keep'})
    remote.write_json(remote.TASK/'request.json',params|{'port':8444,'version_policy':'keep','deployment_fingerprint':plan['fingerprint']})
    remote.write_json(remote.TASK/'status.json',{'id':identifier,'operation':'deploy','state':'queued','events':[]})
    change=remote._change_reality
    def fail_after_change(values,planned):
        change(values,planned)
        raise remote.OperationError('injected post-change failure')
    with mock.patch.object(remote,'_change_reality',side_effect=fail_after_change):remote.run_task(identifier)
    check(remote.status_task(identifier)['state']=='failed' and Path(remote.REALITY_CONFIG).read_bytes()==before,'failed deployment restores previous configuration and running service')
    traffic('reality');traffic('hysteria2')
    submit({'operation':'uninstall','service':'reality','keep_data':True})
    check(Path(remote.REALITY_CONFIG).read_bytes()==before,'uninstall retains node configuration')
    submit(params);traffic('reality');check(identity(details('reality'))==original,'reinstall retains credentials')
    traffic('hysteria2')
    panel_version = remote.server_release_version('xui')
    panel = {'operation':'deploy','service':'xui','host':'127.0.0.1','port':2053,'version':panel_version,
             'panel_username':'manager','panel_password':secrets.token_urlsafe(30),
             'tls_cert':hy2['tls_cert'],'tls_key':hy2['tls_key']}
    submit(panel)
    panel_data = details('xui')
    remote.verify_local_https('127.0.0.1',2053,panel_data['path'],certificate_data=hy2['tls_cert'])
    verified = subprocess.run(['/usr/bin/python3','-c', "import bcrypt,sqlite3,sys; p=sys.stdin.read(); db=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True); h=db.execute('SELECT password FROM users WHERE username=?',('manager',)).fetchone()[0]; sys.exit(0 if bcrypt.checkpw(p.encode(),h.encode()) else 1)"],input=panel['panel_password'],text=True,capture_output=True,timeout=10)
    check(verified.returncode == 0, 'Linux downloaded panel installs with verified HTTPS and login')
    traffic('reality');traffic('hysteria2')
    origin.shutdown()
    result={'passed':True,'architecture':remote.platform.machine(),'xray_version':xray_version,'hy2_version':hy2_version,'panel_version':panel_version,'checks':['linux-direct-download','panel-https-login','real-hy2-traffic','real-reality-traffic','qr-decode','idempotency','port-change','configuration-backup-restore','service-stop-start','downgrade-upgrade','rollback','uninstall-reinstall','coexistence']}
    (artifacts/'result.json').write_text(json.dumps(result,indent=2))
    (artifacts/'result.json').chmod(0o644)
    artifacts.chmod(0o755)
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()
