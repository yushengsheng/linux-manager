"""Development-only session: secrets stay in memory; replies are redacted locally."""
from pathlib import Path
import base64
import contextlib
import importlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager.models import Connection, Store, Redactor, atomic_private
from linux_manager.transport import SSH, Askpass
from linux_manager.key_info import encrypted_key
from linux_manager.vault import vault_alias

PRIVATE = Path('/private/tmp/linux-manager-development/access-session')
ENDPOINT = PRIVATE / 'session.sock'


class Session:
    def __init__(self):
        PRIVATE.mkdir(mode=0o700, exist_ok=True)
        PRIVATE.chmod(0o700)
        state = json.loads((PRIVATE.parent / 'bundle-process.json').read_text())
        self.store = Store(Path(state['data']))
        profiles = self.store.profiles()
        if self.store.last_warning:
            raise RuntimeError('keychain_access_not_ready')
        self.aliases = {}
        legacy_file = BASE / 'scripts/.rename_account_gui_state.json'
        if legacy_file.is_file():
            legacy = json.loads(legacy_file.read_text())
            self.aliases['old'] = Connection(host=legacy['host'], username=legacy['ssh_user'], auth='key', key_path=legacy['key_path'], remember=False)
        old_host = self.aliases.get('old').host if 'old' in self.aliases else None
        for profile in profiles:
            if profile.host == old_host:
                self.aliases['old'] = profile
            elif 'test' not in self.aliases:
                self.aliases['test'] = profile
        self.redactor = Redactor(str(BASE))
        self.results = {}
        self.job = None
        for conn in self.aliases.values():
            if conn.auth == 'key' and encrypted_key(conn.key_path) and not conn.key_passphrase:
                for metadata in (self.store.directory / 'keys').rglob('*.json'):
                    row = json.loads(metadata.read_text())
                    if row.get('private_key') == conn.key_path and row.get('vault_alias'):
                        conn.key_passphrase = self.store.vault.get(row['vault_alias']).get('key_passphrase', '')
            conn.validate()
            self.redactor.add(*(getattr(conn, key) for key in ['host','username','key_path','password','key_passphrase','sudo_password']))
            if conn.auth == 'key' and encrypted_key(conn.key_path) and not conn.key_passphrase:
                raise RuntimeError('encrypted_key_passphrase_unavailable')
            # Read every known project's local credentials now, before work begins.
            for kind in ['exchange','hysteria2','xui']:
                self.store.vault.get(vault_alias('service', conn.host + ':' + str(conn.port) + ':' + kind))

    def ssh(self, alias):
        conn = self.aliases[alias]
        ssh = SSH(conn, PRIVATE / alias)
        if alias == 'old' and not (self.store.directory / 'ssh' / conn.identifier / 'known_hosts').is_file():
            ssh.known_hosts = Path.home() / '.ssh/known_hosts'
        else:
            ssh.known_hosts = self.store.directory / 'ssh' / conn.identifier / 'known_hosts'
        return ssh

    def scrub(self, value):
        def collect(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if isinstance(child, str) and any(word in key.lower() for word in ['username','password','passphrase','token','initialization_code','key_path','secret','private_key']):
                        self.redactor.add(child, json.dumps(child, ensure_ascii=False)[1:-1])
                    collect(child)
            elif isinstance(item, list):
                for child in item:collect(child)
        collect(value)
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and any(word in key.lower() for word in ['username','password','passphrase','token','initialization_code','key_path','secret','private_key']):
                    self.redactor.add(item, json.dumps(item, ensure_ascii=False)[1:-1])
            return {key: self.scrub(item) for key,item in value.items()}
        if isinstance(value, list):
            return [self.scrub(item) for item in value]
        if isinstance(value, str):
            text = self.redactor.text(value)
            text = re.sub(r'(ssl_certificate_key\s+)[^;\n]+', r'\1[凭据路径已隐藏]', text)
            return text
        return value

    def remote_read(self, alias, file):
        reader = (BASE / 'tools' / file).resolve()
        if reader.parent != (BASE / 'tools').resolve() or not reader.name.endswith('_audit.py'):
            raise RuntimeError('read_script_not_allowlisted')
        ssh = self.ssh(alias)
        if not ssh.trusted():
            raise RuntimeError('saved_host_identity_unavailable')
        conn = self.aliases[alias]
        bootstrap = "import sys,base64; s=sys.stdin.read(); p=next(x[7:] for x in s.splitlines() if x.startswith('LMREAD:')); exec(compile(base64.b64decode(p),'<read-only-audit>','exec'))"
        command = 'if [ "$(id -u)" = 0 ]; then python3 -c ' + shlex.quote(bootstrap) + '; else sudo -S -p \'\' python3 -c ' + shlex.quote(bootstrap) + '; fi'
        payload = (conn.sudo_password or conn.password) + '\nLMREAD:' + base64.b64encode(reader.read_bytes()).decode() + '\n'
        with tempfile.TemporaryDirectory(prefix='read-', dir=PRIVATE) as folder:
            with Askpass(Path(folder), conn.password if conn.auth=='password' else conn.key_passphrase) as env:
                config = ssh._config(Path(folder))
                result = subprocess.run(['ssh','-F',str(config),'-T','linux-manager-server',command],input=payload,capture_output=True,text=True,timeout=90,env=os.environ|env,start_new_session=True)
        if result.returncode:
            raise RuntimeError('read_only_ssh_failed')
        return json.loads(result.stdout)

    def handle(self, request):
        operation = request['op']
        if operation == 'ready':
            return {'aliases_available': sorted(self.aliases), 'saved_identities_ready': {name:self.ssh(name).trusted() for name in self.aliases}, 'credential_cache_in_memory': True}
        if operation == 'result':
            return self.scrub(self.results.get(request['name'], {}))
        if operation == 'read':
            result = self.remote_read(request['server'], request['file'])
        elif operation == 'call':
            if request['server']=='old' and request['request'].get('action') not in {'ping','snapshot','tasks','details','logs'}:
                raise RuntimeError('old_server_is_read_only')
            result = self.ssh(request['server']).call(request['request'],timeout=90)
        elif operation == 'execute':
            if request['server']!='test' or self.job and self.job.is_alive():
                raise RuntimeError('test_execution_not_available')
            name = request['name']
            def work():
                try:
                    import linux_manager.controller as module
                    importlib.reload(module)
                    controller = module.Controller(self.store)
                    self.results[name] = {'state':'preparing'}
                    params = dict(request['params'])
                    if params.get('service')=='hysteria2':
                        import secrets
                        params['proxy_password']=secrets.token_urlsafe(24)
                        self.redactor.add(params['proxy_password'])
                    elif params.get('service')=='xui':
                        import secrets
                        params['panel_username']='manager'
                        params['panel_password']=secrets.token_urlsafe(24)
                        self.redactor.add(params['panel_username'],params['panel_password'])
                    result, _ = controller.execute(self.aliases['test'], params, lambda progress:self.results.__setitem__(name,self.scrub(progress)))
                    self.results[name]=self.scrub(result)
                except Exception as error:
                    self.results[name]={'state':'failed','failure_type':type(error).__name__,'message':self.scrub(str(error))}
            self.job=threading.Thread(target=work,daemon=True);self.job.start()
            return {'started':True}
        else:
            raise RuntimeError('unsupported_session_operation')
        if request.get('name'):
            self.results[request['name']]=result
        return self.scrub(result)


def main():
    session = Session()
    ENDPOINT.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(ENDPOINT));ENDPOINT.chmod(0o600);server.listen(2)
        print(json.dumps({'authorization_stage_complete':True,**session.handle({'op':'ready'})}),flush=True)
        while True:
            connection,_=server.accept()
            with connection:
                stream=connection.makefile('rb')
                request=json.loads(stream.readline(2*1024*1024))
                if request.get('op')=='close':break
                try:result={'ok':True,'data':session.handle(request)}
                except Exception as error:result={'ok':False,'failure_type':type(error).__name__,'message':session.scrub(str(error))}
                connection.sendall(json.dumps(result,ensure_ascii=False).encode()+b'\n')
    ENDPOINT.unlink(missing_ok=True)


if __name__=='__main__':
    try:main()
    except Exception as error:print(json.dumps({'authorization_stage_complete':False,'failure_type':type(error).__name__}),flush=True)
