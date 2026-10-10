"""Verify real Hysteria2 traffic from this Mac using a verified official client."""
from pathlib import Path
import hashlib
import json
import platform
import secrets
import socket
import subprocess
import sys
import tarfile
import time

BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from linux_manager.models import Store,atomic_private
from linux_manager.controller import Controller
from tools.live_functional_regression import context

PRIVATE=Path('/private/tmp/linux-manager-development')
STAGE='preparing'


def receive(connection,size):
    data=b''
    while len(data)<size:
        block=connection.recv(size-len(data))
        if not block:raise RuntimeError('proxy_stream_closed')
        data+=block
    return data


def main():
    global STAGE
    release=json.loads((PRIVATE/'installer-audit/hysteria2-release.json').read_text())
    assert release['tag_name']=='v1.14.3' and not release['draft'] and not release['prerelease']
    arch='arm64' if platform.machine()=='arm64' else 'amd64'
    name='sing-box-1.14.3-darwin-'+arch+'.tar.gz'
    asset=next(a for a in release['assets'] if a['name']==name)
    folder=PRIVATE/'mac-proxy-regression';folder.mkdir(mode=0o700,exist_ok=True)
    archive=folder/'client.tar.gz'
    if not archive.exists():
        with archive.open('wb') as output:
            result=subprocess.run(['gh','api','--hostname','github.com','/repos/SagerNet/sing-box/releases/assets/'+str(asset['id']),'-H','Accept: application/octet-stream'],stdout=output,stderr=subprocess.PIPE,timeout=180)
        assert result.returncode==0
    with archive.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
    assert archive.stat().st_size==asset['size'] and 'sha256:'+digest==asset['digest']
    with tarfile.open(archive) as package:
        candidates=[member for member in package if member.isfile() and Path(member.name).name=='sing-box']
        assert len(candidates)==1
        binary=folder/'sing-box';binary.write_bytes(package.extractfile(candidates[0]).read());binary.chmod(0o700)
    print(json.dumps({'check':'official_mac_client_digest','result':'passed'}),flush=True)
    state=json.loads((PRIVATE/'bundle-process.json').read_text());store=Store(Path(state['data']))
    legacy=json.loads((BASE/'scripts/.rename_account_gui_state.json').read_text())
    profiles=[p for p in store.profiles() if p.host!=legacy['host']];assert len(profiles)==1
    conn=profiles[0];data=Controller(store).project_information(conn,'hysteria2')['data']
    with socket.socket() as unused:unused.bind(('127.0.0.1',0));local=unused.getsockname()[1]
    config={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}],'outbounds':[{'type':'hysteria2','server':conn.host,'server_port':data['port'],'password':data['proxy_password'],'tls':{'enabled':True,'server_name':data.get('sni') or conn.host}}]}
    path=folder/'client.json';atomic_private(path,json.dumps(config))
    output=(folder/'client-output.log').open('wb')
    process=subprocess.Popen([str(binary),'run','-c',str(path)],stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        for _ in range(50):
            assert process.poll() is None
            try:connection=socket.create_connection(('127.0.0.1',local),timeout=1);break
            except OSError:time.sleep(.2)
        else:raise RuntimeError('test_client_not_ready')
        with connection:
            STAGE='socks_greeting'
            connection.settimeout(35);connection.sendall(b'\x05\x01\x00');assert receive(connection,2)==b'\x05\x00'
            target=b'example.com';connection.sendall(b'\x05\x01\x00\x03'+bytes([len(target)])+target+(443).to_bytes(2,'big'))
            STAGE='socks_connect'
            reply=receive(connection,4);assert reply[1]==0
            if reply[3]==1:receive(connection,6)
            elif reply[3]==4:receive(connection,18)
            elif reply[3]==3:receive(connection,receive(connection,1)[0]+2)
            else:raise RuntimeError('invalid_socks_response')
            with context().wrap_socket(connection,server_hostname='example.com') as tls:
                STAGE='proxied_https_response'
                tls.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                body=b''
                while len(body)<32768:
                    block=tls.recv(4096)
                    if not block:break
                    body+=block
                assert b'200 OK' in body and b'Example Domain' in body
        print(json.dumps({'check':'public_udp_hysteria2_authenticated_tls_traffic','result':'passed'}),flush=True)
        atomic_private(PRIVATE/'proxy-regression-result.json',json.dumps({'public_udp_traffic_passed':True}))
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=10)
        output.close();path.unlink(missing_ok=True)


if __name__=='__main__':
    try:main()
    except Exception as error:
        atomic_private(PRIVATE/'proxy-regression-error.txt',type(error).__name__+': '+str(error))
        print(json.dumps({'proxy_regression':'failed','failure_type':type(error).__name__,'stage':STAGE}),flush=True)
        raise SystemExit(1)
