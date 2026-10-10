import json
from pathlib import Path
import subprocess
root=Path('/opt/xiaojun-exchange');data=Path('/var/lib/xiaojun-exchange');marker=root/'.install-incomplete.json'
saved=json.loads(marker.read_text()) if marker.is_file() else {}
files=list(data.iterdir()) if data.is_dir() else []
active={}
for name in ['xiaojun-exchange-web.service','xiaojun-exchange-worker.service','xiaojun-exchange-nginx.service']:
 r=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True);active[name]=r.stdout.strip()
print(json.dumps({'marker':marker.is_file(),'phase':saved.get('phase'), 'data_count':len(files), 'setup_only':all(p.name=='setup-token' for p in files),'database_exists':any(p.suffix=='.db' for p in files),'config_exists':Path('/etc/xiaojun-exchange').exists(),'active':active}))
