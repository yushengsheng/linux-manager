"""Reset ONLY a failed, uninitialized disposable-test trade installation.

Invoked through the development session's test alias only. Never use on production.
Preserve the failed fixture for diagnostics instead of deleting project data.
"""
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

root=Path('/opt/xiaojun-exchange')
marker=root/'.install-incomplete.json'
data=Path('/var/lib/xiaojun-exchange')
uninitialized=False
try:
 env=Path('/etc/xiaojun-exchange/server.env')
 origin=next((line.partition('=')[2].strip().strip('"') for line in env.read_text().splitlines() if line.startswith('XIAOJUN_PUBLIC_ORIGIN=')), '')
 request=urllib.request.Request('http://127.0.0.1:18880/api/health',headers={'Host':origin.partition('://')[2]})
 with urllib.request.urlopen(request,timeout=5) as response:uninitialized=json.load(response).get('configured') is False
except Exception:pass
assert uninitialized or (marker.is_file() and json.loads(marker.read_text()).get('phase')=='services') or (not root.exists() and not Path('/etc/xiaojun-exchange').exists())
assert uninitialized or not data.exists() or all(p.name=='setup-token' for p in data.iterdir())
assert not root.is_symlink() and not data.is_symlink()
units=list(Path('/etc/systemd/system').glob('xiaojun-exchange-*'))
for unit in units:
    if unit.name.endswith('.service') and unit.name!='xiaojun-exchange-nginx.service':
        result=subprocess.run(['systemctl','is-active',unit.name],capture_output=True,text=True)
        assert uninitialized or result.stdout.strip()!='active'
target=Path('/var/lib/linux-server-manager/dev-fixtures')/datetime.datetime.now().strftime('failed-acme-%Y%m%d%H%M%S')
target.mkdir(parents=True,mode=0o700)
for unit in units:
    if unit.is_file():
        subprocess.run(['systemctl','disable','--now',unit.name],capture_output=True)
        shutil.move(str(unit),str(target/unit.name))
for name,p in [('application',root),('configuration',Path('/etc/xiaojun-exchange')),('data',data)]:
    if p.exists():shutil.move(str(p),str(target/name))
subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True)
print(json.dumps({'fixture_preserved':True,'uninitialized_partial_install_reset':True}))
