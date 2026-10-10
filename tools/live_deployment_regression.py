"""Real deployment regression, restricted to the authorized disposable alias.

All connection values are loaded locally. Only assertions/status go to stdout.
"""
from pathlib import Path
import json
import socket
import sys
import time

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
PRIVATE=Path('/private/tmp/linux-manager-development')


def rpc(request):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(105);client.connect(str(PRIVATE/'access-session/session.sock'))
        client.sendall(json.dumps(request).encode()+b'\n')
        reply=json.loads(client.makefile('rb').readline(4*1024*1024))
    if not reply.get('ok'):raise RuntimeError('authorized_session_operation_failed')
    return reply['data']


def wait(name):
    previous=None
    for _ in range(1100):
        status=rpc({'op':'result','name':name});state=status.get('state');progress=status.get('progress')
        if (state,progress)!=previous:
            print(json.dumps({'job':name,'state':state,'progress':progress}),flush=True);previous=(state,progress)
        if state in {'succeeded','failed','rolled_back','recovery_failed'}:
            if state!='succeeded':raise RuntimeError('live_install_failed_'+name)
            return status
        time.sleep(3)
    raise RuntimeError('live_install_did_not_finish')


def main():
    tracking=json.loads((PRIVATE/'bundle-process.json').read_text())
    profiles=json.loads((Path(tracking['data'])/'profiles.json').read_text())
    legacy=json.loads((BASE/'scripts/.rename_account_gui_state.json').read_text())
    rows=[row for row in profiles if row['host']!=legacy['host']]
    assert len(rows)==1
    profile=rows[0]
    wait('exchange-install-v3')
    for service,port,version in [('hysteria2',51752,'v1.14.3'),('xui',2053,'v3.9.0')]:
        name=service+'-live-install'
        started=rpc({'op':'execute','server':'test','name':name,'params':{'operation':'deploy','service':service,'host':profile['host'],'port':port,'version':version}})
        assert started['started'];wait(name)
    print(json.dumps({'all_three_real_installations':'passed'}),flush=True)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'regression':'failed','failure_type':type(error).__name__,'reason':str(error) if str(error).startswith(('live_','authorized_')) else 'check_failed_locally'}),flush=True)
        raise SystemExit(1)
