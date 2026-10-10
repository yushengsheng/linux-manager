"""Disposable-server functional regression. Credentials never leave local memory/UI."""
from pathlib import Path
import http.cookiejar
import http.client
import contextlib
import json
import secrets
import shutil
import ssl
import subprocess
import sys
import socket
import tempfile
import time
import urllib.request
import urllib.parse
import uuid

BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from linux_manager.models import Store,Connection,ManagerError,atomic_private
from linux_manager.controller import Controller
from linux_manager.project_info import credential_alias,server_key

PRIVATE=Path('/private/tmp/linux-manager-development')
STACK=contextlib.ExitStack()


def context():
    from linux_manager.releases import https_context
    result=https_context()
    # Nonbundled macOS Python may not have a CA file. Use public system roots.
    roots=subprocess.run(['security','find-certificate','-a','-p','/System/Library/Keychains/SystemRootCertificates.keychain'],capture_output=True,timeout=20)
    if roots.returncode==0:result.load_verify_locations(cadata=roots.stdout.decode())
    return result


def check(name,action):
    action();print(json.dumps({'check':name,'result':'passed'}),flush=True)


def main():
    state=json.loads((PRIVATE/'bundle-process.json').read_text());store=Store(Path(state['data']))
    old=json.loads((BASE/'scripts/.rename_account_gui_state.json').read_text())
    candidates=[p for p in store.profiles() if p.host!=old['host']]
    assert len(candidates)==1 and not store.last_warning
    conn=candidates[0];controller=Controller(store)
    report=controller.inspect(conn)
    assert all(any(u.get('ActiveState')=='active' for u in report['services'][kind]) for kind in ['exchange','hysteria2','xui'])
    print(json.dumps({'check':'three_services_active','result':'passed'}),flush=True)
    tls=context()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=tls),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    information={kind:controller.project_information(conn,kind) for kind in ['exchange','hysteria2','xui','nginx']}
    rows={kind:dict(item['rows']) for kind,item in information.items()}
    public_access=True
    for kind in ['exchange','xui']:
        url=rows[kind]['软件网址' if kind=='exchange' else '后台网址']
        try:
            with opener.open(url,timeout=8) as response:assert response.status==200
            print(json.dumps({'check':kind+'_public_https','result':'passed'}),flush=True)
        except Exception:
            public_access=False
            print(json.dumps({'check':kind+'_public_https','result':'unreachable_from_local_network'}),flush=True)
    # The SSH tunnel lets all application/API tests continue independently of
    # a cloud business-port rule. TLS still checks the actual server identity.
    from linux_manager.transport import Askpass
    ssh=controller.transport(conn)
    folder=Path(STACK.enter_context(tempfile.TemporaryDirectory(prefix='functional-tunnel-',dir=PRIVATE)))
    environment=STACK.enter_context(Askpass(folder,conn.key_passphrase if conn.auth=='key' else conn.password))
    configuration=ssh._config(folder);mapping={}
    for kind in ['exchange','xui']:
        with socket.socket() as unused:
            unused.bind(('127.0.0.1',0));mapping[information[kind]['data']['port']]=unused.getsockname()[1]
    arguments=['ssh','-F',str(configuration),'-N','-o','ExitOnForwardFailure=yes']
    for remote,local in mapping.items():arguments += ['-L','127.0.0.1:'+str(local)+':127.0.0.1:'+str(remote)]
    import os
    tunnel=subprocess.Popen(arguments+['linux-manager-server'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=os.environ|environment,start_new_session=True)
    def close_tunnel():
        if tunnel.poll() is None:tunnel.terminate();tunnel.wait(timeout=10)
    STACK.callback(close_tunnel)
    for attempt in range(100):
        assert tunnel.poll() is None
        try:
            for local in mapping.values():
                with socket.create_connection(('127.0.0.1',local),timeout=0.3):pass
            break
        except OSError:time.sleep(0.2)
    else:raise RuntimeError('test_ssh_tunnel_not_ready')
    class TunnelConnection(http.client.HTTPSConnection):
        def connect(self):
            self.sock=socket.create_connection(('127.0.0.1',mapping[self.port]),timeout=self.timeout)
            self.sock=self._context.wrap_socket(self.sock,server_hostname=self.host)
    class TunnelHandler(urllib.request.HTTPSHandler):
        def https_open(self,request):return self.do_open(TunnelConnection,request,context=tls)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),TunnelHandler(context=tls),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    assert rows['exchange'].get('初始化码') and rows['exchange'].get('内部端口')
    assert rows['hysteria2'].get('Hysteria2 节点') and rows['xui'].get('后台密码')
    assert all(item['server_key']==server_key(conn) for item in information.values())
    print(json.dumps({'check':'maintenance_information_complete','result':'passed'}),flush=True)
    base=rows['xui']['后台网址'];credentials=store.vault.get(credential_alias(conn,'xui'))
    csrf=''
    def api(path,data=None):
        payload=json.dumps(data).encode() if data is not None else None
        parsed=urllib.parse.urlsplit(base)
        headers={'Content-Type':'application/json','Origin':parsed.scheme+'://'+parsed.netloc,'Referer':base}
        if csrf:headers['X-CSRF-Token']=csrf
        request=urllib.request.Request(base+path,data=payload,headers=headers)
        with opener.open(request,timeout=25) as response:return json.load(response)
    def token():
        data=api('csrf-token');obj=data.get('obj')
        if isinstance(obj,str):return obj
        if isinstance(obj,dict):return obj.get('token') or obj.get('csrfToken') or obj.get('csrf_token') or ''
        return data.get('token') or data.get('csrfToken') or ''
    csrf=token();assert csrf
    login=api('login',{'username':credentials['panel_username'],'password':credentials['panel_password']})
    assert login.get('success') is True
    csrf=token();assert csrf
    print(json.dumps({'check':'panel_login_saved_credentials','result':'passed'}),flush=True)
    client_id=str(uuid.uuid4());subscription=secrets.token_urlsafe(12)
    inbound={'up':0,'down':0,'total':0,'remark':'Local regression fixture','enable':True,'expiryTime':0,'listen':'','port':10085,'protocol':'vless','settings':json.dumps({'clients':[{'id':client_id,'flow':'','email':'regression-'+client_id[:8],'enable':True,'subId':subscription,'totalGB':0,'expiryTime':0,'limitIp':0,'reset':0}],'decryption':'none','fallbacks':[]}),'streamSettings':json.dumps({'network':'tcp','security':'none','tcpSettings':{'header':{'type':'none'}}}),'sniffing':json.dumps({'enabled':False,'destOverride':['http','tls']}),'allocate':json.dumps({'strategy':'always','refresh':5,'concurrency':3})}
    created=api('panel/api/inbounds/add',inbound);assert created.get('success') is True
    identity=created.get('obj',{}).get('id')
    try:
        # The panel may finish its asynchronous client update after the API
        # responds. Verify the persisted node, not the response timing.
        for _ in range(10):
            details=controller.project_information(conn,'xui');links=details['rows']
            if any(name.startswith('节点：') and client_id in value for name,value in links) and any(name.startswith('订阅：') and subscription in value for name,value in links):break
            time.sleep(.5)
        else:
            atomic_private(PRIVATE/'functional-node-export.json',json.dumps({'details':details,'client_id':client_id,'subscription':subscription}))
            raise AssertionError('persisted_node_and_subscription_export')
        print(json.dumps({'check':'panel_node_and_subscription_export','result':'passed'}),flush=True)
    finally:
        if identity:assert api('panel/api/inbounds/del/'+str(identity),{}).get('success') is True
    for kind in ['exchange','hysteria2','xui']:
        for action in ['stop','start','restart','disable','enable']:
            params={'operation':'service','service':kind,'action':action}
            if kind=='exchange' and action in {'stop','restart'}:params['maintenance_confirmed']=True
            status,_=controller.execute(conn,params);assert status['state']=='succeeded'
        logs=controller.transport(conn).call({'action':'logs','service':kind});assert isinstance(logs['logs'],str)
        print(json.dumps({'check':kind+'_maintenance_and_logs','result':'passed'}),flush=True)
    for kind in ['hysteria2','xui','security']:
        status,_=controller.execute(conn,{'operation':'backup','service':kind});identifier=status['result']['backup_id']
        status,_=controller.execute(conn,{'operation':'restore','backup_id':identifier});assert status['state']=='succeeded'
        print(json.dumps({'check':kind+'_backup_restore','result':'passed'}),flush=True)
    for kind in ['exchange','hysteria2','xui']:
        params={'operation':'deploy','service':kind,'host':conn.host,'port':information[kind]['data']['port'],'version':information[kind]['data']['version']}
        if kind=='exchange':params['backend_port']=18880
        if kind=='xui':params['panel_username']=information[kind]['data']['panel_username']
        status,_=controller.execute(conn,params)
        assert status['state']=='succeeded' and status['result']['action']=='unchanged'
    print(json.dumps({'check':'matching_deployment_preserves_projects_without_reinstallation','result':'passed'}),flush=True)
    # A separate local store keeps fixture account records out of the user's list.
    fixture=Store(PRIVATE/'functional-security');fixture_controller=Controller(fixture)
    fixture.save([conn]);atomic_private(fixture_controller.transport(conn).known_hosts,controller.transport(conn).known_hosts.read_bytes())
    created_name='lmcheck_'+secrets.token_hex(4);renamed_name='lmcheck_'+secrets.token_hex(4)
    result=fixture_controller.security_plan(conn,{'mode':'create','username':created_name,'block_original':False,'fail2ban':False,'updates':False})
    assert result['complete'];created_conn=result['connection']
    before=fixture_controller.account_details(created_conn,created_name)
    result=fixture_controller.security_plan(created_conn,{'mode':'rename','username':renamed_name,'retire_old_key':True,'fail2ban':False,'updates':False})
    assert result['complete'];renamed_conn=result['connection']
    after=fixture_controller.account_details(renamed_conn,renamed_name)
    assert before['uid']==after['uid'] and not set(before['public_key_fingerprints'])&set(after['public_key_fingerprints'])
    fixture_controller.transport(conn).call({'action':'ping'})
    time.sleep(3)
    fixture_controller.execute(conn,{'operation':'account_access','username':renamed_name,'blocked':True})
    blocked=fixture_controller.account_details(conn,renamed_name);assert blocked['managed_blocked']
    fixture_controller.execute(conn,{'operation':'account_access','username':renamed_name,'blocked':False})
    fixture_controller.execute(conn,{'operation':'delete_user','username':renamed_name})
    final=controller.inspect(conn)
    assert not any(a['username'] in {created_name,renamed_name} for a in final['accounts'])
    assert final['ssh']['passwordauthentication']==['no'] and final['ssh']['permitrootlogin']==['no']
    assert all(any(u.get('ActiveState')=='active' for u in final['services'][kind]) for kind in ['exchange','hysteria2','xui'])
    print(json.dumps({'check':'security_create_rename_rotate_block_restore_delete','result':'passed'}),flush=True)
    atomic_private(PRIVATE/'functional-regression-result.json',json.dumps({'functional_tests_passed':True,'public_https_from_local_network':public_access}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        # Full errors can include URLs. Keep them local; return only the type.
        import traceback
        atomic_private(PRIVATE/'functional-regression-error.txt',traceback.format_exc())
        print(json.dumps({'functional_regression':'failed','failure_type':type(error).__name__}),flush=True)
        raise SystemExit(1)
    finally:STACK.close()
