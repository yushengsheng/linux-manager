"""Read-only certificate failure classification; no challenge tokens returned."""
from pathlib import Path
import json
import os
import pwd
import re
import subprocess

result={'accounts':[{'username':entry.pw_name} for entry in pwd.getpwall()]}
root=Path('/var/log/xiaojun-exchange-acme/letsencrypt.log')
if root.exists():
    text=root.read_text(errors='replace')[-200000:]
    result['failure_categories']={key:bool(re.search(pattern,text,re.I)) for key,pattern in {'connection_timeout':'timeout during connect|connection timed out','connection_refused':'connection refused','invalid_http_response':'invalid response','permission_denied':'permission denied','dns_failure':'dns problem|nxdomain','unsupported_profile':'profile.*not supported|invalidProfile'}.items()}
    reasons=[]
    for line in text.splitlines():
        if any(word in line.lower() for word in ['timeout during connect','connection refused','invalid response','detail:']):
            line=re.sub(r'https?://[^\s\"\']+','[验证地址]',line)
            line=re.sub(r'/\.well-known/acme-challenge/[^\s\"\']+','[验证文件]',line)
            line=re.sub(r'"(?:token|nonce|keyAuthorization)"\s*:\s*"[^"]*"','"challenge":"[已隐藏]"',line)
            reasons.append(line[:400])
    result['failure_reasons']=reasons[-6:]
result['webroot_permissions']=[]
for path in ['/var/lib/xiaojun-exchange-acme-webroot','/var/lib/xiaojun-exchange-acme-webroot/.well-known','/var/lib/xiaojun-exchange-acme-webroot/.well-known/acme-challenge']:
    item=Path(path)
    result['webroot_permissions'].append({'exists':item.exists(),'mode':oct(item.stat().st_mode&0o777) if item.exists() else None})
result['firewall']=subprocess.run(['ufw','status'],capture_output=True,text=True).stdout
result['nginx_state']=subprocess.run(['systemctl','is-active','xiaojun-exchange-nginx.service'],capture_output=True,text=True).stdout.strip()
print(json.dumps(result,ensure_ascii=False))
