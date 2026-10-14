"""Project information for the local UI. Never use formatted secrets in logs."""
import base64
import hashlib
import json
import urllib.parse

from .vault import vault_alias

SERVICE_PROTOCOLS = {"exchange": "TCP", "hysteria2": "UDP", "reality": "TCP", "xui": "TCP", "nginx": "TCP", "cliproxyapi": "TCP"}


def deployment_network_hint(service, number, backend=None):
    protocol = SERVICE_PROTOCOLS[service]
    other = "TCP" if protocol == "UDP" else "UDP"
    purpose = "面板网页" if service == "xui" else "HY2 节点" if service == "hysteria2" else "REALITY 节点" if service == "reality" else "网页"
    lines = [f"{purpose}入口：放行 {protocol} {number or '所填端口'}，此入口不需要开放 {other}。"]
    if service in {"exchange", "cliproxyapi"}:
        lines.append(f"内部服务：TCP {backend or '内部端口'}，仅服务器本机使用，不向公网开放。")
    if service == "xui":
        lines.append("代理节点和订阅端口独立于面板；节点按配置使用 TCP、UDP 或两者，请在「运行与备份」查看各节点协议。")
    if service == "reality":
        lines.append("无需自有域名和证书；只需此 TCP 节点端口。部署后复制 VLESS 单节点链接导入支持 REALITY / Vision 的客户端。")
    elif service != "nginx":
        lines.append("证书申请 / 续期的 HTTP 验证另需 TCP 80，与业务端口的协议无关。")
    lines.append("服务器防火墙与云平台安全组都需按对应协议放行；云平台规则需自行设置。")
    return "\n".join(lines)


def inbound_port_protocol(inbound):
    """Describe the public listener, not the traffic carried inside a proxy."""
    protocol = str(inbound.get("protocol") or "").lower()
    settings = inbound.get("settings", {})
    stream = inbound.get("stream_settings", {})
    unknown = "协议未识别，请核对节点配置"
    if protocol in {"hysteria", "hysteria2", "hy2", "wireguard"}:
        return "UDP"
    if protocol == "mtproto":
        return "TCP"
    if inbound.get("port_protocol_error") or not isinstance(settings, dict) or not isinstance(stream, dict):
        return unknown
    network = str(stream.get("network") or "tcp").lower()
    if protocol in {"shadowsocks", "dokodemo-door", "tunnel"}:
        field = "allowedNetwork" if protocol == "tunnel" else "network"
        networks = settings.get(field)
        if networks not in (None, ""):
            if not isinstance(networks, str):
                return unknown
            parts = {part.strip().lower() for part in networks.split(",")}
            if not parts or not parts <= {"tcp", "udp"}:
                return unknown
            return " + ".join(part.upper() for part in ("tcp", "udp") if part in parts)
    if protocol in {"socks", "mixed"} and settings.get("udp") is True:
        return "TCP + UDP"
    if network in {"kcp", "mkcp", "quic", "hysteria", "hysteria2"}:
        return "UDP"
    if network in {"xhttp", "splithttp"} and stream.get("security") == "tls":
        tls = stream.get("tlsSettings") or {}
        if not isinstance(tls, dict):
            return unknown
        if tls.get("alpn") == ["h3"]:
            return "UDP"
    if protocol in {"vless", "vmess", "trojan", "http", "socks", "mixed", "shadowsocks", "dokodemo-door", "tunnel"} and network in {"tcp", "raw", "ws", "websocket", "grpc", "http", "h2", "httpupgrade", "splithttp", "xhttp"}:
        return "TCP"
    return unknown


def frontend_port_protocol(data, number):
    protocols = {row.get("protocol") for row in data.get("frontend_listeners", []) if row.get("port") == number}
    return " + ".join(value.upper() for value in ("tcp", "udp") if value in protocols) or "TCP"


def server_key(connection):
    return hashlib.sha256((connection.host.lower()+':'+str(connection.port)).encode()).hexdigest()[:16]


def credential_alias(connection, service):
    return vault_alias('service',connection.host+':'+str(connection.port)+':'+service)


def authority(host, port):
    return ('['+host+']' if ':' in host and not host.startswith('[') else host)+':'+str(port)


def node_links(data, fallback_host):
    host=data.get('host') or fallback_host
    if data.get('service') == 'reality':
        required = ('uuid', 'public_key', 'short_id', 'server_name', 'port')
        if not all(data.get(key) for key in required):return []
        query = {'encryption':'none', 'type':'tcp', 'security':'reality', 'flow':'xtls-rprx-vision', 'sni':data['server_name'], 'fp':'chrome', 'pbk':data['public_key'], 'sid':data['short_id']}
        return [('VLESS 节点链接', 'vless://' + urllib.parse.quote(data['uuid'], safe='') + '@' + authority(host, data['port']) + '?' + urllib.parse.urlencode(query) + '#' + urllib.parse.quote('VLESS REALITY Vision', safe=''))]
    if data.get('service')=='hysteria2' and data.get('proxy_password') and data.get('port'):
        query=urllib.parse.urlencode({'sni':data.get('sni') or host})
        return [('Hysteria2 节点','hysteria2://'+urllib.parse.quote(data['proxy_password'],safe='')+'@'+authority(host,data['port'])+'/?'+query+'#Hysteria2')]
    links=[]
    for inbound in data.get('inbounds',[]):
        if not inbound.get('enable',True):continue
        protocol=inbound.get('protocol','');settings=inbound.get('settings') or {};stream=inbound.get('stream_settings') or {}
        if not isinstance(settings,dict) or not isinstance(stream,dict):continue
        network=stream.get('network','tcp');security=stream.get('security','none')
        transport=stream.get(network+'Settings') or {};tls=stream.get('tlsSettings') or {};reality=stream.get('realitySettings') or {}
        clients=settings.get('clients',[])
        if protocol=='shadowsocks' and not clients:clients=[settings]
        for client in clients:
            if not client.get('enable',True):continue
            name=client.get('email') or inbound.get('remark') or protocol
            if client.get('subId') and data.get('subscription_base'):
                links.append(('订阅：'+name,data['subscription_base'].rstrip('/')+'/'+urllib.parse.quote(client['subId'],safe='')))
            identifier=client.get('id') or client.get('password') or settings.get('password')
            if not identifier or not inbound.get('port'):continue
            port=inbound['port'];query={'type':network,'security':security}
            if client.get('flow'):query['flow']=client['flow']
            sni=tls.get('serverName') or reality.get('serverName') or next(iter(reality.get('serverNames',[])),None)
            if sni:query['sni']=sni
            if tls.get('fingerprint') or reality.get('fingerprint'):query['fp']=tls.get('fingerprint') or reality.get('fingerprint')
            if security=='reality':
                public=reality.get('publicKey') or (reality.get('settings') or {}).get('publicKey')
                if public:query['pbk']=public
                short=next(iter(reality.get('shortIds',[])),None)
                if short:query['sid']=short
            if transport.get('path'):query['path']=transport['path']
            header=(transport.get('headers') or {}).get('Host')
            if header:query['host']=header
            if transport.get('serviceName'):query['serviceName']=transport['serviceName']
            if protocol in {'vless','trojan'}:
                if protocol=='vless':query['encryption']='none'
                uri=protocol+'://'+urllib.parse.quote(identifier,safe='')+'@'+authority(host,port)+'?'+urllib.parse.urlencode(query)+'#'+urllib.parse.quote(name,safe='')
            elif protocol=='vmess':
                payload={'v':'2','ps':name,'add':host,'port':str(port),'id':identifier,'aid':'0','scy':'auto','net':network,'type':'none','host':header or '', 'path':transport.get('path',''),'tls':'tls' if security=='tls' else '', 'sni':sni or ''}
                uri='vmess://'+base64.b64encode(json.dumps(payload,ensure_ascii=False).encode()).decode()
            elif protocol=='shadowsocks':
                method=client.get('method') or settings.get('method')
                if not method:continue
                user=base64.urlsafe_b64encode((method+':'+identifier).encode()).decode().rstrip('=')
                uri='ss://'+user+'@'+authority(host,port)+'#'+urllib.parse.quote(name,safe='')
            else:continue
            links.append(('节点：'+name,uri))
    return links


def information_rows(data, connection, credentials=None):
    credentials=credentials or {};kind=data.get('service','');host=data.get('host') or connection.host
    rows=[('项目状态','已卸载（数据保留）' if data.get('uninstalled') else '已安装' if data.get('installed') else '尚未安装'),('服务器',connection.label+' · '+connection.host)]
    if not data.get('installed'):return rows
    if data.get('version'):rows.append(('安装版本',data['version']))
    protocol = frontend_port_protocol(data, data.get('port')) if kind == 'nginx' else SERVICE_PROTOCOLS.get(kind, '协议未识别')
    if data.get('port'):
        rows.append(('服务端口',str(data['port'])+' / '+protocol))
        rows.append(('端口协议',protocol+'（两者都需放行）' if protocol == 'TCP + UDP' else protocol+'（此入口仅需 '+protocol+'）'))
    if data.get('backend_port'):rows.append(('内部端口',str(data['backend_port'])+' / TCP（仅服务器本机，无需公网放行）'))
    if data.get('frontend_ports'):rows.append(('网页入口端口','、'.join(str(number)+' / '+frontend_port_protocol(data,number) for number in data['frontend_ports'])))
    if kind in {'exchange','xui','nginx'} and data.get('port'):
        url=(data.get('scheme') or ('http' if kind=='nginx' else 'https'))+'://'+authority(host,data['port'])+(data.get('path') or '/')
        rows.append(('后台网址' if kind=='xui' else '软件网址',url))
    if kind == 'cliproxyapi' and not data.get('port'):
        rows.append(('配置信息', data.get('information_error') or '公网入口未能读取；请检查配置，不要重复安装'))
        rows.extend(('服务：' + unit['unit'], '运行中' if unit.get('ActiveState') == 'active' else '已停止') for unit in data.get('units', []))
        return rows
    if kind == 'cliproxyapi':
        base = 'https://' + authority(host, data['port'])
        rows.extend([('后台网址', base + '/management.html'), ('API 基础地址', base + '/v1'),
                     ('Claude Code 基础地址', base), ('Responses 接口', base + '/v1/responses'),
                     ('Messages 接口', base + '/v1/messages'), ('Chat Completions 接口', base + '/v1/chat/completions'),
                     ('后台登录方式', '独立管理 Key，无需用户名'),
                     ('管理 Key', credentials.get('management_key') or '未在本机保存；点击补充登录信息'),
                     ('管理 Key 状态', '已验证有效' if data.get('management_key_valid') else '当前未验证或保存值已失效'),
                     ('基础健康', data.get('health', '当前未验证')),
                     ('内部监听', str(data.get('internal_host', '')) + ':' + str(data.get('backend_port', ''))),
                     ('管理页面版本', data.get('versions', {}).get('panel', '未能读取')),
                     ('Nginx 状态', data.get('nginx', {}).get('ActiveState', '未知'))])
        rows.extend(('客户端 API Key ' + str(i), key) for i, key in enumerate(data.get('api_keys', []), 1))
        timers = data.get('timers', {})
        rows.extend([('自动更新', str(timers.get('linux-manager-cliproxyapi-update.timer', {}).get('UnitFileState', '未知'))),
                     ('更新与备份调度', data.get('public_schedule') or data.get('update_schedule', '未能读取')),
                     ('证书续期', str(data.get('certificate_renewal', {}).get('ActiveState', '未能读取'))),
                     ('自动备份', str(timers.get('linux-manager-cliproxyapi-backup.timer', {}).get('ActiveState', '未知'))),
                     ('最近更新检查', json.dumps(data.get('update_status', {}), ensure_ascii=False)),
                     ('最近备份', json.dumps(data.get('backup_status', {}), ensure_ascii=False)),
                     ('可回滚版本', json.dumps(data.get('rollback_version', {}), ensure_ascii=False) if data.get('rollback_version') else '尚无升级恢复版本'),
                     ('运行详情', data.get('runtime', '未能读取')),
                     ('上游账号数量', json.dumps(data.get('accounts', {}), ensure_ascii=False) if data.get('accounts') else '尚未添加'),
                     ('模型目录', '、'.join(data.get('models', [])) or '尚无可用模型；请先在后台添加上游'),
                     ('模型实测', '未实测；目录可读取不等于模型调用成功'),
                     ('配额', '暂不可查询；以供应商和管理后台实际返回为准'),
                     ('检查时间', data.get('checked', '未检查'))])
        rows.extend(('授权账号 ' + str(i), account['provider'] + ' · ' + account['identity'] + ' · ' + account['state']) for i, account in enumerate(data.get('account_details', []), 1))
    if kind=='exchange':
        rows.append(('程序密码','首次打开管理网页时设置；本程序不读取交易系统的程序密码'))
        if data.get('initialization_code'):rows.append(('初始化码',data['initialization_code']))
    if kind=='xui':
        rows.extend([('后台账号',data.get('panel_username') or credentials.get('panel_username') or '未能读取'),('后台密码',credentials.get('panel_password') or '未在本机保存；可点击「补充登录信息」填写')])
    if kind=='hysteria2' and data.get('proxy_password'):rows.append(('服务密码',data['proxy_password']))
    if kind == 'reality':
        rows.append(('节点协议', 'VLESS + REALITY + Vision'))
        if data.get('server_name'):rows.append(('REALITY 目标域名', data['server_name']))
        rows.append(('导入方式', '复制 VLESS 节点链接到支持 REALITY / Vision 的客户端；这是单节点链接'))
    if kind=='xui' and data.get('subscription_port'):
        scope = '仅服务器本机，无需公网放行' if data.get('subscription_local_only') else '订阅入口，需单独放行'
        rows.append(('订阅服务端口',str(data['subscription_port'])+' / TCP（'+scope+'）'))
    rows.extend(node_links(data,host))
    for inbound in data.get('inbounds',[]):
        protocol = inbound_port_protocol(inbound)
        enabled = inbound.get('enable',True)
        rule = ('TCP、UDP 两者都需放行' if protocol == 'TCP + UDP' else '仅需放行 '+protocol) if protocol in {'TCP','UDP','TCP + UDP'} else protocol
        rows.append(('节点端口：'+(inbound.get('remark') or inbound.get('protocol','代理')),str(inbound.get('port','未知'))+' / '+protocol+' · '+inbound.get('protocol','未知')+' · '+('已开启；'+rule if enabled else '已停用；无需为此节点新增放行')))
    if kind=='xui' and not data.get('inbounds'):rows.append(('代理节点','尚未创建节点；先登录后台添加节点'))
    for unit in data.get('units',[]):
        state='运行中' if unit.get('ActiveState')=='active' else '已停止'
        rows.append(('服务：'+unit['unit'],state+' · '+('开机启动' if unit.get('UnitFileState')=='enabled' else '未启用开机启动')))
    if kind == 'cliproxyapi' and data.get('certificate'): rows.append(('证书有效期', data['certificate']))
    if data.get('certificate_expiry'):rows.append(('证书有效期',data['certificate_expiry']))
    return rows
