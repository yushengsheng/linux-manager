"""Read-only remote inventory for deployment diagnosis and runtime defaults."""
from pathlib import Path
import json
import platform
import pwd
import re
import subprocess


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=25)
    return {'code':result.returncode,'output':result.stdout[:160000]}


units = ['xiaojun-exchange-web.service','xiaojun-exchange-worker.service','xiaojun-exchange-nginx.service','nginx.service','sing-box.service','x-ui.service']
result = {'accounts':[{'username':p.pw_name} for p in pwd.getpwall()], 'os':platform.freedesktop_os_release(), 'architecture':platform.machine(), 'units':{}}
for name in units:
    result['units'][name] = {
        'configuration':command(['systemctl','cat',name]),
        'properties':command(['systemctl','show',name,'-p','ActiveState','-p','SubState','-p','UnitFileState','-p','Restart','-p','RestartUSec','-p','NRestarts','-p','StartLimitIntervalUSec','-p','StartLimitBurst','-p','TimeoutStartUSec','-p','LimitNOFILE','-p','MemoryMax','-p','CPUQuotaPerSecUSec','-p','ExecMainStatus']),
    }
result['paths_present']={name:Path(name).exists() for name in ['/opt/xiaojun-exchange','/etc/xiaojun-exchange','/var/lib/xiaojun-exchange','/var/lib/xiaojun-exchange/install-state.json','/var/lib/linux-server-manager/installed.json','/etc/sing-box/config.json','/etc/x-ui/x-ui.db','/usr/local/x-ui']}
root=Path('/var/lib/linux-server-manager/tasks')
result['recent_tasks']=[]
if root.exists():
    for file in sorted(root.glob('*/status.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:5]:
        try:result['recent_tasks'].append(json.loads(file.read_text()))
        except (OSError,ValueError):pass
result['nginx_directives']=[]
for folder in [Path('/etc/nginx'),Path('/etc/xiaojun-exchange/nginx')]:
    if folder.exists():
        for file in folder.rglob('*.conf'):
            try:
                lines=[line.strip() for line in file.read_text().splitlines() if re.match(r'\s*(?:listen|server_name|worker_processes|worker_connections|worker_rlimit_nofile|proxy_pass|proxy_read_timeout|proxy_send_timeout|proxy_connect_timeout|keepalive_timeout|client_max_body_size|proxy_buffering|proxy_request_buffering|ssl_certificate|ssl_certificate_key|access_log|error_log)\s',line)]
                if lines:result['nginx_directives'].append({'configuration':str(file),'directives':lines})
            except (OSError,UnicodeError):pass
result['sysctl']={}
for name in ['fs.file-max','fs.nr_open','net.core.somaxconn','net.core.rmem_max','net.core.wmem_max','net.ipv4.tcp_keepalive_time','net.ipv4.tcp_keepalive_intvl','net.ipv4.tcp_keepalive_probes','net.core.default_qdisc','net.ipv4.tcp_congestion_control']:
    try:result['sysctl'][name]=Path('/proc/sys/'+name.replace('.','/')).read_text().strip()
    except OSError:pass
result['space']=command(['df','-h','/'])
result['memory']=command(['free','-m'])
result['listeners']=command(['ss','-lntu'])
result['journal']=command(['journalctl','--no-pager','-n','60','-u','xiaojun-exchange-web.service','-u','xiaojun-exchange-worker.service','-u','xiaojun-exchange-nginx.service'])
print(json.dumps(result,ensure_ascii=False))
