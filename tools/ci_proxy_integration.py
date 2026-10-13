"""Real HY2/REALITY traffic acceptance on disposable GitHub Actions runners."""
import base64
import contextlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager.official_packages import download_project, official_version
from linux_manager.project_info import node_links
from linux_manager.qr import qr_png


def check(condition, message):
    if not condition:raise RuntimeError(message)
    print('PASS: ' + message, flush=True)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('Requires a disposable GitHub Actions runner with root and systemd')
    if any(Path(name).exists() for name in ['/var/lib/linux-server-manager','/etc/linux-manager-xray','/usr/local/lib/linux-manager-xray','/etc/sing-box/config.json','/usr/local/bin/sing-box']):
        raise SystemExit('Existing installation detected; refusing to modify it')
    artifacts=Path(os.environ['RUNNER_TEMP'])/'proxy-acceptance';artifacts.mkdir(mode=0o700)
    spec=importlib.util.spec_from_file_location('proxy_ci_remote',BASE/'linux_manager/remote_agent.py')
    remote=importlib.util.module_from_spec(spec);spec.loader.exec_module(remote)
    source=(BASE/'linux_manager/remote_agent.py').read_text()
    for name in ['reality','redeployment','uninstallation']:
        source=source.replace('#LM_BUNDLED_'+name.upper()+'#','LM_'+name.upper()+'_SOURCE = '+repr((BASE/'linux_manager'/ (name+'.py')).read_text()))
    source=source.replace('#LM_BUNDLED_CERTBOT#','CERTBOT_LOCK = '+repr((BASE/'linux_manager/resources/requirements-certbot.lock').read_text()))
    remote.AGENT_SOURCE=source
    remote.ROOT.mkdir(parents=True,mode=0o700)
    archives={}
    def archive(service,version):
        key=(service,version)
        if key not in archives:
            path=artifacts/(service+'-'+version+'.archive')
            digest=download_project(service,version,remote.platform.machine(),path)
            archives[key]={'release_sha256':digest,'release_archive':base64.b64encode(path.read_bytes()).decode()}
        return archives[key]
    def submit(params):
        identifier=secrets.token_hex(12)
        if params['operation']=='deploy':
            plan=remote.deployment_preflight(params)
            params=params|{'version':plan['version'],'deployment_fingerprint':plan['fingerprint']}
            if plan['requires_archive']:params=params|archive(params['service'],plan['version'])
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
    xray_version=official_version('reality');hy2_version=official_version('hysteria2')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(artifacts/'hy2.key'),'-out',str(artifacts/'hy2.crt'),'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
    hy2={'operation':'deploy','service':'hysteria2','host':'127.0.0.1','port':51752,'version':hy2_version,'proxy_password':secrets.token_urlsafe(30),'tls_cert':(artifacts/'hy2.crt').read_text(),'tls_key':(artifacts/'hy2.key').read_text()}
    submit(hy2);traffic('hysteria2')
    hy2_config=Path('/etc/sing-box/config.json').read_bytes()
    params={'operation':'deploy','service':'reality','host':'127.0.0.1','port':443,'version':xray_version,'server_name':'www.microsoft.com'}
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
    origin.shutdown()
    result={'passed':True,'architecture':remote.platform.machine(),'xray_version':xray_version,'hy2_version':hy2_version,'checks':['real-hy2-traffic','real-reality-traffic','qr-decode','idempotency','port-change','configuration-backup-restore','service-stop-start','downgrade-upgrade','rollback','uninstall-reinstall','coexistence']}
    (artifacts/'result.json').write_text(json.dumps(result,indent=2))
    (artifacts/'result.json').chmod(0o644)
    artifacts.chmod(0o755)
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()
