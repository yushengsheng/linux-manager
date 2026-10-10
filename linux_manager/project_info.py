"""Project information for the local UI. Never use formatted secrets in logs."""
import base64
import hashlib
import json
import urllib.parse

from .vault import vault_alias


def server_key(connection):
    return hashlib.sha256((connection.host.lower()+':'+str(connection.port)).encode()).hexdigest()[:16]


def credential_alias(connection, service):
    return vault_alias('service',connection.host+':'+str(connection.port)+':'+service)


def authority(host, port):
    return ('['+host+']' if ':' in host and not host.startswith('[') else host)+':'+str(port)


def node_links(data, fallback_host):
    host=data.get('host') or fallback_host
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
    rows=[('项目状态','已安装' if data.get('installed') else '尚未安装'),('服务器',connection.label+' · '+connection.host)]
    if not data.get('installed'):return rows
    if data.get('version'):rows.append(('安装版本',data['version']))
    if data.get('port'):rows.append(('服务端口',str(data['port'])))
    if data.get('backend_port'):rows.append(('内部端口',str(data['backend_port'])+'（仅服务器本机）'))
    if data.get('frontend_ports'):rows.append(('网页入口端口','、'.join(map(str,data['frontend_ports']))))
    if kind in {'exchange','xui','nginx'} and data.get('port'):
        url=(data.get('scheme') or ('http' if kind=='nginx' else 'https'))+'://'+authority(host,data['port'])+(data.get('path') or '/')
        rows.append(('后台网址' if kind=='xui' else '软件网址',url))
    if kind=='exchange':
        rows.append(('程序密码','首次打开管理网页时设置；本程序不读取交易系统的程序密码'))
        if data.get('initialization_code'):rows.append(('初始化码',data['initialization_code']))
    if kind=='xui':
        rows.extend([('后台账号',data.get('panel_username') or credentials.get('panel_username') or '未能读取'),('后台密码',credentials.get('panel_password') or '未在本机保存；可点击「补充登录信息」填写')])
    if kind=='hysteria2' and data.get('proxy_password'):rows.append(('服务密码',data['proxy_password']))
    rows.extend(node_links(data,host))
    for inbound in data.get('inbounds',[]):
        rows.append(('节点端口：'+(inbound.get('remark') or inbound.get('protocol','代理')),str(inbound.get('port','未知'))+' · '+inbound.get('protocol','未知')+' · '+('已开启' if inbound.get('enable',True) else '已停用')))
    if kind=='xui' and not data.get('inbounds'):rows.append(('代理节点','尚未创建节点；先登录后台添加节点'))
    for unit in data.get('units',[]):
        state='运行中' if unit.get('ActiveState')=='active' else '已停止'
        rows.append(('服务：'+unit['unit'],state+' · '+('开机启动' if unit.get('UnitFileState')=='enabled' else '未启用开机启动')))
    if data.get('certificate_expiry'):rows.append(('证书有效期',data['certificate_expiry']))
    return rows
