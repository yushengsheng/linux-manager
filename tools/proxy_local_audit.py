"""Disposable-test localhost proxy traffic check. No existing configuration changed."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

def receive(connection,size):
 data=b''
 while len(data)<size:
  block=connection.recv(size-len(data))
  if not block:raise RuntimeError('stream_closed')
  data+=block
 return data

config=json.loads(Path('/etc/sing-box/config.json').read_text())
inbound=next(i for i in config['inbounds'] if i['type']=='hysteria2')
host=json.loads(Path('/var/lib/linux-server-manager/installed.json').read_text())['hysteria2']['host']
with socket.socket() as unused:unused.bind(('127.0.0.1',0));number=unused.getsockname()[1]
fixture={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':number}],'outbounds':[{'type':'hysteria2','server':'127.0.0.1','server_port':inbound['listen_port'],'password':inbound['users'][0]['password'],'tls':{'enabled':True,'server_name':host}}]}
checks={}
with tempfile.TemporaryDirectory(prefix='lm-proxy-test-') as temporary:
 path=Path(temporary)/'client.json';path.write_text(json.dumps(fixture));path.chmod(0o600)
 output=(Path(temporary)/'output.log').open('wb')
 process=subprocess.Popen(['/usr/local/bin/sing-box','run','-c',str(path)],stdout=output,stderr=subprocess.STDOUT)
 try:
  time.sleep(1)
  with socket.create_connection(('127.0.0.1',number),timeout=5) as connection:
   connection.settimeout(25);connection.sendall(b'\x05\x01\x00');assert receive(connection,2)==b'\x05\x00'
   target=b'example.com';connection.sendall(b'\x05\x01\x00\x03'+bytes([len(target)])+target+(443).to_bytes(2,'big'))
   reply=receive(connection,4);checks['socks_status']=reply[1]
   if reply[1]==0:
    if reply[3]==1:receive(connection,6)
    elif reply[3]==4:receive(connection,18)
    elif reply[3]==3:receive(connection,receive(connection,1)[0]+2)
    with ssl.create_default_context().wrap_socket(connection,server_hostname='example.com') as secured:
     secured.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
     body=b''
     while len(body)<32768:
      block=secured.recv(4096)
      if not block:break
      body+=block
     checks['actual_https_traffic']=b'200 OK' in body and b'Example Domain' in body
 except Exception as error:checks['failure_type']=type(error).__name__
 finally:
  process.terminate();process.wait(timeout=10);output.close()
 log=(Path(temporary)/'output.log').read_text().lower()
 checks['log_categories']={word:word in log for word in ['dns','deadline','certificate','authentication','timeout']}
print(json.dumps(checks))
