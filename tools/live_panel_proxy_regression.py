"""Verify a real VLESS node through an owned SSH tunnel; secrets stay local."""
from pathlib import Path
import contextlib
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from tools.live_redeployment_regression import Regression,PRIVATE
from tools.live_proxy_regression import receive
from tools.live_functional_regression import context
from linux_manager.models import atomic_private
from linux_manager.transport import Askpass


def unused_port():
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def main():
 r=Regression();stack=contextlib.ExitStack();created=False;original=json.loads(json.dumps(r.saved))
 try:
  node=r.saved['fixture']
  if not node.get('client') or not any(node['client'] in json.dumps(item.get('settings',{})) for item in r.info('xui')['inbounds']):
   r.saved['fixture']={};r.fixture();node=r.saved['fixture'];created=True
  release=json.loads((PRIVATE/'installer-audit/hysteria2-release.json').read_text())
  arch='arm64' if platform.machine()=='arm64' else 'amd64'
  asset=next(a for a in release['assets'] if a['name']=='sing-box-1.14.3-darwin-'+arch+'.tar.gz')
  archive=PRIVATE/'mac-proxy-regression/client.tar.gz'
  with archive.open('rb') as stream:assert 'sha256:'+hashlib.file_digest(stream,'sha256').hexdigest()==asset['digest']
  folder=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='lm-vless-check-',dir=PRIVATE)))
  with tarfile.open(archive) as package:
   members=[m for m in package if m.isfile() and Path(m.name).name=='sing-box'];assert len(members)==1
   binary=folder/'sing-box';binary.write_bytes(package.extractfile(members[0]).read());binary.chmod(0o700)
  local=unused_port();forwarded=unused_port();ssh=r.controller.transport(r.c,fresh=True)
  environment=stack.enter_context(Askpass(folder,r.c.key_passphrase if r.c.auth=='key' else r.c.password))
  config=ssh._config(folder)
  tunnel=subprocess.Popen(['ssh','-F',str(config),'-N','-T','-o','ExitOnForwardFailure=yes','-L',f'127.0.0.1:{forwarded}:127.0.0.1:10085','linux-manager-server'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=os.environ|environment,start_new_session=True)
  def stop(process):
   if process.poll() is None:process.terminate();process.wait(timeout=10)
  stack.callback(stop,tunnel)
  for _ in range(100):
   assert tunnel.poll() is None
   try:
    with socket.create_connection(('127.0.0.1',forwarded),timeout=.3):pass
    break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('node_tunnel_not_ready')
  client={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}],'outbounds':[{'type':'vless','server':'127.0.0.1','server_port':forwarded,'uuid':node['client']}]}
  file=folder/'client.json';atomic_private(file,json.dumps(client));output=(folder/'client.log').open('wb');stack.callback(output.close)
  process=subprocess.Popen([str(binary),'run','-c',str(file)],stdout=output,stderr=subprocess.STDOUT,start_new_session=True);stack.callback(stop,process)
  for _ in range(100):
   assert process.poll() is None
   try:connection=socket.create_connection(('127.0.0.1',local),timeout=1);break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('vless_client_not_ready')
  with connection:
   connection.settimeout(30);connection.sendall(b'\x05\x01\x00');assert receive(connection,2)==b'\x05\x00'
   target=b'example.com';connection.sendall(b'\x05\x01\x00\x03'+bytes([len(target)])+target+(443).to_bytes(2,'big'))
   reply=receive(connection,4);assert reply[1]==0
   if reply[3]==1:receive(connection,6)
   elif reply[3]==4:receive(connection,18)
   elif reply[3]==3:receive(connection,receive(connection,1)[0]+2)
   else:raise RuntimeError('invalid_socks_response')
   with context().wrap_socket(connection,server_hostname='example.com') as tls:
    tls.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');body=b''
    while len(body)<32768:
     block=tls.recv(4096)
     if not block:break
     body+=block
    assert b'200 OK' in body and b'Example Domain' in body
  print(json.dumps({'check':'panel_vless_authenticated_https_proxy_traffic','result':'passed'}),flush=True)
  atomic_private(PRIVATE/'panel-proxy-regression-result.json',json.dumps({'vless_node_real_traffic_passed':True}))
 finally:
  try:
   stack.close()
   if created:
    with r.panel() as api:assert api('panel/api/inbounds/del/'+str(r.saved['fixture']['id']),{}).get('success') is True
    r.saved=original;r.save()
  finally:r.controller.close_connections()


if __name__=='__main__':
 try:main()
 except Exception as error:
  import traceback
  atomic_private(PRIVATE/'panel-proxy-regression-error.txt',traceback.format_exc())
  print(json.dumps({'panel_proxy_regression':'failed','failure_type':type(error).__name__}),flush=True)
  raise SystemExit(1)
