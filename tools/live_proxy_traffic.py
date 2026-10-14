"""Server-side traffic probes using only already-installed proxy binaries."""
import contextlib
import base64
import http.server
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'linux-manager-live-ok')
    def log_message(self,*args):pass


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        return listener.getsockname()[1]


origin = http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
threading.Thread(target=origin.serve_forever,daemon=True).start()
result = {}
try:
    for kind in ['hysteria2','reality']:
        number=unused_port()
        if kind=='hysteria2':
            server=json.loads(Path('/etc/sing-box/config.json').read_text())['inbounds'][0]
            installed=json.loads(Path('/var/lib/linux-server-manager/installed.json').read_text())[kind]
            config={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':number}],'outbounds':[{'type':'hysteria2','server':'127.0.0.1','server_port':server['listen_port'],'password':server['users'][0]['password'],'tls':{'enabled':True,'server_name':installed['host'],'certificate_path':server['tls']['certificate_path']}}]}
            args=['/usr/local/bin/sing-box','run','-c']
        else:
            server=json.loads(Path('/etc/linux-manager-xray/config.json').read_text())['inbounds'][0]
            reality=server['streamSettings']['realitySettings']
            private = bytes.fromhex('302e020100300506032b656e04220420') + base64.urlsafe_b64decode(reality['privateKey']+'=')
            output=subprocess.check_output(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=private,stderr=subprocess.DEVNULL)
            public=base64.urlsafe_b64encode(output[-32:]).decode().rstrip('=')
            config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':number,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':server['port'],'users':[{'id':server['settings']['clients'][0]['id'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},'streamSettings':{'network':'raw','security':'reality','realitySettings':{'serverName':reality['serverNames'][0],'fingerprint':'chrome','password':public,'shortId':reality['shortIds'][0]}}}]}
            args=['/usr/local/lib/linux-manager-xray/xray','run','-config']
        with tempfile.TemporaryDirectory(prefix='lm-traffic-') as directory:
            path=Path(directory)/'client.json';path.write_text(json.dumps(config));path.chmod(0o600)
            with (Path(directory)/'client.log').open('wb') as log:
                client=subprocess.Popen(args+[str(path)],stdout=log,stderr=subprocess.STDOUT)
                try:
                    for _ in range(30):
                        try:
                            with socket.create_connection(('127.0.0.1',number),timeout=.2):break
                        except OSError:time.sleep(.2)
                    response=subprocess.run(['curl','--silent','--show-error','--fail','--noproxy','','--socks5-hostname','127.0.0.1:'+str(number),'--max-time','20','http://127.0.0.1:'+str(origin.server_port)+'/'],capture_output=True,timeout=25)
                    result[kind]=response.returncode==0 and response.stdout==b'linux-manager-live-ok'
                finally:
                    client.terminate();client.wait(timeout=10)
    with contextlib.closing(sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True)) as db:
        settings=dict(db.execute('SELECT key,value FROM settings'))
    address=json.loads(Path('/var/lib/linux-server-manager/installed.json').read_text())['xui']['host']
    panel=subprocess.run(['curl','--silent','--show-error','--fail','--noproxy','*','--cacert',settings['webCertFile'],'--resolve',f"{address}:{settings['webPort']}:127.0.0.1",'--max-time','15',f"https://{address}:{settings['webPort']}{settings['webBasePath']}"],capture_output=True,timeout=20)
    result['xui_https']=panel.returncode==0 and bool(panel.stdout)
finally:
    origin.shutdown()
