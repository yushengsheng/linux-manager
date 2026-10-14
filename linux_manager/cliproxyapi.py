"""Embedded after the existing deployment/uninstall helpers; owned AI gateway only."""
import copy

CP_CONFIG = Path('/etc/cliproxyapi/config.yaml')
CP_BINARY = Path('/opt/cli-proxy-api/cli-proxy-api')
CP_DATA = Path('/var/lib/cliproxyapi')
CP_SITE = Path('/etc/nginx/conf.d/linux-manager-cliproxyapi.conf')
CP_STATE = ROOT / 'cliproxyapi'
CP_UNIT = 'cli-proxy-api.service'
CP_TIMERS = ['linux-manager-cliproxyapi-update.timer', 'linux-manager-cliproxyapi-backup.timer']
CP_UNITS = [CP_UNIT, 'linux-manager-cliproxyapi-update.service', *CP_TIMERS,
            'linux-manager-cliproxyapi-backup.service']
CP_RUNNER = CP_STATE / 'maintenance.py'
UNITS['cliproxyapi'] = [CP_UNIT]
UNINSTALL_LAYOUTS['cliproxyapi'] = {
    'programs': [str(CP_BINARY.parent)], 'units': CP_UNITS,
    'extras': [str(CP_SITE), str(CP_RUNNER)],
    'retain': [str(CP_CONFIG.parent), str(CP_DATA), str(CP_STATE)],
}


def cp_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        raise OperationError('Linux 缺少 python3-yaml，无法安全读取配置；已保留数据。') from None


def cp_read():
    if not CP_CONFIG.is_file():
        return {}
    try:
        value = cp_yaml().safe_load(CP_CONFIG.read_text())
        require(isinstance(value, dict) and value.get('config-version') == 8,
                'CLIProxyAPI 配置不是受支持的 v8 格式，不能猜测覆盖。')
        require(all(isinstance(value.get(section), dict) for section in ['server', 'management', 'access']), '核心配置分组无法识别。')
        keys = value['access'].get('api-keys')
        require(isinstance(keys, list) and keys and all(isinstance(k, str) and k and not any(c in k for c in '\r\n\x00') for k in keys), '客户端 Key 配置为空或无法识别。')
        return value
    except (OSError, ValueError, cp_yaml().YAMLError):
        raise OperationError('CLIProxyAPI 配置读取失败，已保留数据。') from None


def cp_merge(existing, backend, management_key='', api_key=''):
    """Change only installer fields; preserve upstream keys, unknown fields and accounts."""
    value = copy.deepcopy(existing)
    if not value:
        value = {
            'config-version': 8,
            'routing': {'strategy': 'round-robin', 'session-affinity': True,
                        'retry': {'request-retry': 3, 'max-retry-interval': 30}},
            'requests': {'streaming': {'keepalive-seconds': 15, 'bootstrap-retries': 1},
                         'nonstream-keepalive-interval': 15},
            'plugins': {'enabled': False},
            'observability': {'logs': {'debug': False, 'logging-to-file': True,
                                     'logs-max-total-size-mb': 128, 'error-logs-max-files': 10,
                                     'request-log': False}, 'usage': {'usage-statistics-enabled': True},
                              'pprof': {'enable': False}},
        }
    value.setdefault('server', {}).update(host='127.0.0.1', port=backend,
                                         **{'trusted-proxies': ['127.0.0.1'], 'tls': {'enable': False},
                                            'discovery': {'enabled': False}})
    value.setdefault('management', {}).update({
        'allow-remote': True, 'disable-control-panel': False, 'disable-auto-update-panel': True,
        'panel-github-repository': 'https://github.com/router-for-me/Cli-Proxy-API-Management-Center',
    })
    value.setdefault('oauth', {})['auth-dir'] = str(CP_DATA / 'auth')
    if management_key:
        value['management']['secret-key'] = management_key
    if api_key:
        # Reconfiguration changes only the first key; optional other keys remain valid.
        keys = value.setdefault('access', {}).setdefault('api-keys', [])
        value['access']['api-keys'] = [api_key] + [k for k in keys[1:] if k != api_key]
    require(value['management'].get('secret-key') and value.get('access', {}).get('api-keys'),
            '首次安装需要独立管理 Key 和客户端 API Key。')
    return value


def cp_records():
    file = ROOT / 'installed.json'
    return json.loads(file.read_text()).get('cliproxyapi', {}) if file.is_file() else {}


def cp_version():
    if not CP_BINARY.is_file():
        return ''
    result = command([str(CP_BINARY), '-h'], check=False)
    output = result.stdout + result.stderr
    match = re.search(r'(?:Version:\s*|\bv)(\d+\.\d+\.\d+)', output)
    return 'v' + match.group(1) if match else ''


def cp_request(base, path, key='', local_tls=False, address=''):
    """Bounded probes; TLS verification is always enabled, with optional loopback transport."""
    headers = {'Authorization': 'Bearer ' + key} if key else {}
    if local_tls:
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', port(base)), timeout=8) as connection:
            with context.wrap_socket(connection, server_hostname=address) as secured:
                request = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + address + '\r\nConnection: close\r\n'
                request += ''.join(k + ': ' + v + '\r\n' for k, v in headers.items()) + '\r\n'
                secured.sendall(request.encode())
                response = http.client.HTTPResponse(secured); response.begin()
                return response.status, response.read(4 * 1024 * 1024)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(base + path, headers=headers), timeout=8) as response:
            return response.status, response.read(4 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, b''


def cp_health(config, record, management_key='', public=False):
    require(config['server']['host'] == '127.0.0.1', '核心未配置为仅本机监听。')
    backend = config['server']['port']; keys = config['access']['api-keys']
    require(keys and all(isinstance(k, str) and k for k in keys), '没有有效的客户端 API Key。')
    base = 'http://127.0.0.1:' + str(backend)
    status, _ = cp_request(base, '/v1/models')
    require(status in {401, 403}, '未携带 Key 的 API 请求没有被拒绝。')
    status, _ = cp_request(base, '/v1/models', secrets.token_urlsafe(32))
    require(status in {401, 403}, '错误 Key 的 API 请求没有被拒绝。')
    status, body = cp_request(base, '/v1/models', keys[0])
    listing = json.loads(body) if status == 200 else {}
    require(isinstance(listing, dict) and isinstance(listing.get('data'), list), '客户端 Key 或模型目录检查失败。')
    require(all(isinstance(m, dict) and isinstance(m.get('id'), str) for m in listing['data']), '模型目录格式无法识别。')
    models = [m['id'] for m in listing['data']]
    status, _ = cp_request(base, '/v8/management/config')
    require(status in {401, 403}, '管理接口没有要求独立管理 Key。')
    status, _ = cp_request(base, '/v8/management/config', keys[0])
    require(status in {401, 403}, '客户端 Key 可以访问管理接口，独立鉴权检查失败。')
    if management_key:
        status, _ = cp_request(base, '/v8/management/config', management_key)
        require(status == 200, '管理 Key 验证失败。')
    status, body = cp_request(str(record['port']), '/management.html', local_tls=True, address=record['host'])
    require(status == 200 and b'/v8/management' in body, 'HTTPS 管理页面内容或兼容接口检查失败。')
    status, _ = cp_request(str(record['port']), '/v1/models', local_tls=True, address=record['host'])
    require(status in {401, 403}, 'HTTPS API 入口鉴权检查失败。')
    status, _ = cp_request(str(record['port']), '/v1/models', keys[0], local_tls=True, address=record['host'])
    require(status == 200, 'HTTPS API 转发检查失败。')
    if public:
        status, body = cp_request('https://' + record['host'] + ':' + str(record['port']), '/v1/models', keys[0])
        require(status == 200 and isinstance(json.loads(body).get('data'), list), '公网 HTTPS 自测失败。')
    return models


def cp_fingerprint():
    files = [CP_CONFIG, CP_BINARY, CP_SITE, CP_RUNNER, CP_STATE / 'versions.json', ROOT / 'installed.json',
             *[Path('/etc/systemd/system/' + u) for u in CP_UNITS]]
    digest = hashlib.sha256()
    for file in files:
        digest.update(str(file).encode())
        if file.is_file():
            with file.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
    return digest.hexdigest()


_cp_previous_preflight = deployment_preflight


def deployment_preflight(params):
    if params.get('service') != 'cliproxyapi': return _cp_previous_preflight(params)
    address = host(params.get('host')); number = port(params.get('port', 9229))
    release = platform.freedesktop_os_release()
    require((release.get('ID'), release.get('VERSION_ID')) in {('ubuntu', '24.04'), ('debian', '12'), ('debian', '13')}, '当前系统尚未支持自动部署。')
    require(platform.machine() in {'x86_64', 'aarch64'}, '服务器架构不支持 CLIProxyAPI。')
    require(shutil.disk_usage('/').free >= 1024 ** 3, '磁盘可用空间不足 1 GiB。')
    record = cp_records(); present = any(p.exists() for p in [CP_CONFIG, CP_BINARY, CP_SITE, CP_DATA])
    require(not present or record.get('installed') or record.get('uninstalled') or record.get('incomplete'), '发现未知来源 CLIProxyAPI，已保留现场，不能覆盖。')
    for file in [CP_CONFIG.parent, CP_BINARY.parent, CP_DATA, CP_SITE, CP_STATE, CP_RUNNER]:
        require(file.resolve() == file.absolute(), 'CLIProxyAPI 使用自定义链接布局，不能自动覆盖。')
    if CP_SITE.exists(): require(CP_SITE.read_text().startswith('# Managed by linux-server-manager\n'), 'AI 入口归属无法确认。')
    for unit in CP_UNITS:
        state = unit_info(unit)
        require(state.get('LoadState') in {'loaded', 'not-found'}, 'AI 服务来源或屏蔽状态无法确认，不能自动覆盖。')
        if state.get('LoadState') == 'loaded':
            file = Path('/etc/systemd/system/' + unit)
            require(state.get('FragmentPath') == str(file) and not state.get('DropInPaths') and file.is_file(), '发现自定义 AI 服务定义，已保留原服务。')
            if unit.endswith('.service'):
                executable = CP_BINARY if unit == CP_UNIT else CP_RUNNER
                require(str(executable) in file.read_text(), 'AI 服务执行程序不属于本程序，不能覆盖。')
    config = cp_read() if CP_CONFIG.exists() else {}
    backend = port(params.get('backend_port', config.get('server', {}).get('port', 8317)))
    require(backend != number and backend != 80 and number != 80, '内部、公网和证书端口必须分别设置。')
    for key in ['management_key', 'api_key']:
        if params.get(key):
            password(params[key]); require(all(ord(c) >= 33 and ord(c) < 127 for c in params[key]), 'Key 仅支持无空格的 ASCII 字符。')
    if not config: require(params.get('management_key') and params.get('api_key'), '首次安装需要填写两种 Key。')
    require(not params.get('management_key') or params['management_key'] != (params.get('api_key') or next(iter(config.get('access', {}).get('api-keys', [])), '')), '管理 Key 和客户端 Key 必须不同。')
    if not record or record.get('port') != number or record.get('uninstalled'): ensure_port_available(number)
    if not config or config['server']['port'] != backend or record.get('uninstalled'): ensure_port_available(backend)
    current = cp_version()
    if not current and record.get('uninstalled'):
        file = CP_STATE / 'versions.json'
        current = json.loads(file.read_text()).get('core', '') if file.is_file() else record.get('version', '')
    requested = current if params.get('version_policy') == 'keep' else params.get('version')
    require(params.get('version_policy') != 'keep' or current, '没有可保持的核心版本。')
    requested = server_release_version('cliproxyapi', requested or None)
    require(requested.startswith('v8.'), '目前自动集成只支持核心 v8，跨大版本需兼容验证。')
    panel = server_release_version('cliproxyapi-panel')
    changes = []
    for field, old, new, label in [('port', record.get('port'), number, '公网 HTTPS 端口'),
                                  ('host', record.get('host'), address, '访问地址'),
                                  ('backend_port', config.get('server', {}).get('port'), backend, '内部端口'),
                                  ('version', current, requested, '核心版本'),
                                  ('auto_update', record.get('auto_update'), params.get('auto_update', record.get('auto_update', True)), '自动更新')]:
        if old != new: changes.append({'field': field, 'name': label, 'before': old, 'after': new})
    if params.get('management_key'):
        stored = config.get('management', {}).get('secret-key', '')
        if stored.startswith('$2'):
            import bcrypt
            matched = bcrypt.checkpw(params['management_key'].encode(), stored.encode())
        else: matched = stored == params['management_key']
        if not matched: changes.append({'field': 'management_key', 'name': '管理 Key', 'before': '已隐藏', 'after': '将更新'})
    if params.get('api_key') and (not config or config['access']['api-keys'][0] != params['api_key']):
        changes.append({'field': 'api_key', 'name': '客户端首个 Key', 'before': '已隐藏', 'after': '将更新'})
    if config and cp_merge(config, backend) != config:
        changes.append({'field': 'managed_configuration', 'name': '内部监听与管理入口', 'before': '受管配置发生变化', 'after': '恢复本机监听和鉴权'})
    source = globals().get('AGENT_SOURCE', Path(__file__).read_text() if '__file__' in globals() else '')
    if CP_RUNNER.is_file() and source and CP_RUNNER.read_text() != source:
        changes.append({'field': 'maintenance_script', 'name': '服务器维护脚本', 'before': '旧版', 'after': '同步当前管理程序'})
    ready = bool(current and config and CP_SITE.is_file() and all(Path('/etc/systemd/system/' + u).is_file() for u in CP_UNITS) and not record.get('uninstalled'))
    action = 'install' if not present else 'repair' if not ready else 'update' if current != requested else 'reconfigure' if changes else 'unchanged'
    return {'service': 'cliproxyapi', 'architecture': platform.machine(), 'preflight': 'passed',
            'installed': present, 'reinstall': bool(record.get('uninstalled')), 'action': action,
            'version': requested, 'panel_version': panel, 'host': address, 'port': number, 'backend_port': backend,
            'auto_update': params.get('auto_update', record.get('auto_update', True)), 'changes': changes,
            'fingerprint': cp_fingerprint(), 'requires_archive': action in {'install', 'update', 'repair'}}


def cp_extract(archive):
    with tarfile.open(archive, 'r:gz') as package:
        members = [m for m in package.getmembers() if Path(m.name).name == 'cli-proxy-api']
        require(len(members) == 1 and members[0].isfile() and members[0].size <= 150 * 1024 * 1024, '核心安装包结构不符合预期。')
        with package.extractfile(members[0]) as stream:
            return stream.read()


def cp_save_config(value):
    account = pwd.getpwnam('cliproxy')
    # The config watcher must be able to read the file as soon as rename fires.
    private_write(CP_CONFIG, cp_yaml().safe_dump(value, allow_unicode=True, sort_keys=False),
                  owner=(account.pw_uid, account.pw_gid))


def cp_site(record, backend, cert, key):
    return f'''# Managed by linux-server-manager
map $http_upgrade $linux_manager_ai_connection {{ default upgrade; '' close; }}
server {{
 listen {record['port']} ssl;
 server_name {record['host']};
 ssl_certificate {cert};
 ssl_certificate_key {key};
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 0;
 location / {{
  proxy_pass http://127.0.0.1:{backend};
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection $linux_manager_ai_connection;
  proxy_buffering off;
  proxy_request_buffering off;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
 }}
}}
'''


def cp_install_units(auto_update):
    unit = '''[Unit]
Description=CLIProxyAPI AI gateway
After=network-online.target
Wants=network-online.target
[Service]
User=cliproxy
Group=cliproxy
WorkingDirectory=/var/lib/cliproxyapi
Environment=HOME=/var/lib/cliproxyapi
Environment=MANAGEMENT_STATIC_PATH=/var/lib/cliproxyapi/static
ExecStart=/opt/cli-proxy-api/cli-proxy-api -config /etc/cliproxyapi/config.yaml
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/cliproxyapi /var/lib/cliproxyapi
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    private_write('/etc/systemd/system/' + CP_UNIT, unit, 0o644)
    private_write(CP_RUNNER, globals().get('AGENT_SOURCE', Path(__file__).read_text() if '__file__' in globals() else ''))
    for action, interval in [('update', '*:0/30'), ('backup', 'daily')]:
        prefix = 'linux-manager-cliproxyapi-' + action
        private_write('/etc/systemd/system/' + prefix + '.service',
                      '[Unit]\nDescription=CLIProxyAPI ' + action + '\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=15min\nExecStart=/usr/bin/python3 ' + str(CP_RUNNER) + ' cp-' + action + '\n', 0o644)
        private_write('/etc/systemd/system/' + prefix + '.timer',
                      '[Unit]\nDescription=CLIProxyAPI ' + action + '\n[Timer]\nOnBootSec=10min\nOnCalendar=' + interval + '\nPersistent=true\n[Install]\nWantedBy=timers.target\n', 0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', CP_TIMERS[1]])
    command(['systemctl', 'enable' if auto_update else 'disable', '--now', CP_TIMERS[0]])


def cp_backup_paths():
    return [str(CP_CONFIG), str(CP_BINARY), str(CP_SITE), str(CP_DATA / 'static/management.html'),
            str(CP_RUNNER), str(CP_STATE / 'versions.json'),
            *['/etc/systemd/system/' + u for u in CP_UNITS]]


_cp_previous_deploy = deploy
_cp_previous_restore = restore_deployment


def deploy(params):
    if params.get('service') != 'cliproxyapi': return _cp_previous_deploy(params)
    plan = deployment_preflight(params)
    # Check unknown service ownership before installing even public dependencies.
    if not CP_CONFIG.exists(): apt(['python3-yaml', 'python3-bcrypt'])
    require(not params.get('deployment_fingerprint') or plan['fingerprint'] == params['deployment_fingerprint'], '项目在预览后变化，请重新预览。')
    if plan['action'] == 'unchanged': return {'service': 'cliproxyapi', 'action': 'unchanged', 'version': plan['version']}
    if plan['requires_archive']: prepare_deployment_archive(params, plan)
    panel = TASK / 'management.html'
    _downloads['download_panel'](plan['panel_version'], panel)
    require(b'/v8/management' in panel.read_bytes(), '管理页面不使用已支持的 v8 管理接口，未安装。')
    require(cp_fingerprint() == plan['fingerprint'], '下载期间配置发生变化，已停止。')
    cert, key = ensure_certificate(plan['host'])
    require(shutil.which('nginx') and unit_info('nginx.service').get('LoadState') == 'loaded',
            '需要已有系统 Nginx 网页入口；请先在安装选项部署 Nginx，已有网站不会覆盖。')
    require(cp_fingerprint() == plan['fingerprint'], '证书准备期间配置发生变化，已停止。')
    step('备份 AI 核心和入口配置，保留上游授权数据…', 30)
    # Freeze the writer before taking a coherent configuration snapshot.
    states = {u: unit_info(u) for u in CP_UNITS}
    # A deployment backup must also restore the ownership/version record.
    previous_record = cp_records()
    command(['systemctl', 'stop', CP_UNIT], check=False)
    try:
        backup_files(cp_backup_paths(), {'deployment': True, 'service': 'cliproxyapi', 'unit_states': states, 'previous_record': previous_record})
    except Exception:
        if states[CP_UNIT].get('ActiveState') == 'active': command(['systemctl', 'start', CP_UNIT])
        raise
    if not previous_record:
        file = ROOT / 'installed.json'
        records = json.loads(file.read_text()) if file.is_file() else {}
        write_json(file, records | {'cliproxyapi': {'incomplete': True, 'host': plan['host'], 'port': plan['port']}})
    config = cp_read()
    if command(['getent', 'passwd', 'cliproxy'], check=False).returncode:
        command(['useradd', '--system', '--home-dir', str(CP_DATA), '--shell', '/usr/sbin/nologin', 'cliproxy'])
    account = pwd.getpwnam('cliproxy')
    for folder in [CP_CONFIG.parent, CP_DATA, CP_DATA / 'auth', CP_DATA / 'static', CP_DATA / 'logs']:
        folder.mkdir(parents=True, exist_ok=True); folder.chmod(0o700); os.chown(folder, account.pw_uid, account.pw_gid)
    config = cp_merge(config, plan['backend_port'], params.get('management_key', ''), params.get('api_key', ''))
    cp_save_config(config)
    CP_BINARY.parent.mkdir(parents=True, exist_ok=True); CP_BINARY.parent.chmod(0o755)
    if plan['requires_archive']: private_write(CP_BINARY, cp_extract(TASK / 'release.tar.gz'), 0o755)
    private_write(CP_DATA / 'static/management.html', panel.read_bytes(), 0o600)
    os.chown(CP_DATA / 'static/management.html', account.pw_uid, account.pw_gid)
    record = {k: plan[k] for k in ['version', 'panel_version', 'port', 'host', 'backend_port', 'auto_update']}
    record.update(certificate_lineage=str(Path(cert).parent))
    private_write(CP_SITE, cp_site(record, plan['backend_port'], cert, key), 0o644)
    command(['nginx', '-t'])
    cp_install_units(plan['auto_update'])
    command(['systemctl', 'enable', '--now', CP_UNIT])
    command(['systemctl', 'reload', 'nginx.service'])
    allow_port(plan['port'])
    step('检查 HTTPS、管理 Key 与 API 鉴权…', 80)
    for attempt in range(20):
        try:
            models = cp_health(cp_read(), record, params.get('management_key', '')); break
        except (OperationError, OSError, ValueError):
            if attempt == 19: raise
            time.sleep(0.5)
    require(cp_version() == plan['version'], '实际运行核心版本与目标版本不一致。')
    write_json(CP_STATE / 'versions.json', {'core': plan['version'], 'panel': plan['panel_version']})
    mark_installed('cliproxyapi', record)
    cp_daily_backup()
    return {'service': 'cliproxyapi', 'version': plan['version'], 'port': plan['port'],
            'verified': 'tls-api-management-auth', 'model_count': len(models), 'backup_id': TASK.name}


def restore_deployment(identifier):
    manifest = json.loads((ROOT / 'tasks' / identifier / 'backup/manifest.json').read_text())
    if manifest.get('extra', {}).get('service') != 'cliproxyapi': return _cp_previous_restore(identifier)
    for unit in manifest['extra']['unit_states']: command(['systemctl', 'stop', unit], check=False)
    restore_files(identifier, project_only=True)
    command(['systemctl', 'daemon-reload']); command(['nginx', '-t']); command(['systemctl', 'reload', 'nginx.service'])
    extra = manifest['extra']
    records_file = ROOT / 'installed.json'
    if records_file.is_file():
        records = json.loads(records_file.read_text())
        if extra.get('previous_record'): records['cliproxyapi'] = extra['previous_record']
        else: records['cliproxyapi'] = {'incomplete': True, 'installed': False}
        write_json(records_file, records)
        cert_hook()
    for unit, state in extra['unit_states'].items():
        if state.get('LoadState') == 'loaded':
            if state.get('UnitFileState') in {'enabled', 'disabled'}:
                command(['systemctl', 'enable' if state['UnitFileState'] == 'enabled' else 'disable', unit])
            active = state.get('ActiveState') == 'active' or unit == CP_UNIT and extra.get('core_was_active')
            command(['systemctl', 'start' if active else 'stop', unit])
            restored = unit_info(unit)
            require((restored.get('ActiveState') == 'active') == bool(active), 'AI 服务原运行状态恢复未通过。')
            if state.get('UnitFileState') in {'enabled', 'disabled'}:
                require(restored.get('UnitFileState') == state['UnitFileState'], 'AI 服务原开机启动状态恢复未通过。')
        else: command(['systemctl', 'disable', unit], check=False)


def cp_daily_backup():
    folder = CP_STATE / 'backups' / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3))
    folder.mkdir(parents=True, mode=0o700)
    private_write(folder / 'config.yaml', CP_CONFIG.read_bytes())
    auth = CP_DATA / 'auth'
    if auth.is_dir(): shutil.copytree(auth, folder / 'auth', symlinks=True)
    for old in sorted(folder.parent.iterdir())[:-7]: shutil.rmtree(old)
    write_json(CP_STATE / 'backup-status.json', {'checked': now(), 'path': str(folder), 'result': '已备份；保留最近 7 份'})


def cp_update(*, force=False):
    """Stable v8 updates, checksum, atomic replacement, baseline and rollback; no paid probe."""
    record = cp_records()
    state_file = CP_STATE / 'update-status.json'
    previous = json.loads(state_file.read_text()) if state_file.is_file() else {}
    result = {'checked': now(), 'result': '检查中'}
    transaction = CP_STATE / 'update-transaction.json'
    try:
        if globals().get('cp_oauth_busy') and cp_oauth_busy():
            result['result'] = '跳过：授权正在进行，核心与管理页面保持不变'
            return result
        if transaction.is_file() and previous.get('rollback') == '恢复失败' and not force:
            result.update(previous, checked=now(), result='跳过：上次恢复失败，需要手动检查或重试')
            return result
        if record and not record.get('uninstalled') and transaction.is_file():
            pending = json.loads(transaction.read_text())
            backup = CP_STATE / 'rollback'
            require(all((backup / name).is_file() for name in ['core', 'management.html', 'versions.json']), '中断升级的恢复文件缺失，需要手动检查。')
            command(['systemctl', 'stop', CP_UNIT], check=False)
            private_write(CP_BINARY, (backup / 'core').read_bytes(), 0o755)
            account = pwd.getpwnam('cliproxy')
            private_write(CP_DATA / 'static/management.html', (backup / 'management.html').read_bytes(),
                          owner=(account.pw_uid, account.pw_gid))
            command(['systemctl', 'start', CP_UNIT]); time.sleep(1)
            cp_health(cp_read(), record)
            versions = json.loads((backup / 'versions.json').read_text())
            require(cp_version() == versions['core'], '中断升级恢复后的版本检查失败。')
            write_json(CP_STATE / 'versions.json', versions)
            transaction.unlink()
            result.update(result='已恢复中断的升级', rollback='已恢复并通过检查',
                          failed_target=pending['target'], retry_after=time.time() + 86400)
            return result
        if not record or record.get('uninstalled') or unit_info(CP_UNIT).get('ActiveState') != 'active':
            result['result'] = '跳过：核心已停止或卸载'; return result
        core = server_release_version('cliproxyapi'); panel = server_release_version('cliproxyapi-panel')
        result.update(latest=core, latest_panel=panel)
        require(core.startswith('v8.'), '跨大版本更新需要兼容验证，已跳过。')
        target = core + '/' + panel
        if not force and previous.get('failed_target') == target and time.time() < previous.get('retry_after', 0):
            result.update(previous, checked=now(), result='失败版本退避中'); return result
        versions = json.loads((CP_STATE / 'versions.json').read_text())
        if cp_version() == core and versions.get('panel') == panel:
            result['result'] = '已是最新稳定版'; return result
        config = cp_read()
        public = True
        try:
            cp_health(config, record, public=True)
        except (OSError, OperationError, ValueError, http.client.HTTPException):
            result.update(result='跳过：更新前公网或本地健康检查未通过；原版本保留', public_probe='未通过')
            return result
        fingerprint = cp_fingerprint()
        with tempfile.TemporaryDirectory(dir=CP_STATE, prefix='update-') as temporary:
            folder = Path(temporary)
            _downloads['download_release']('cliproxyapi', core, platform.machine(), folder / 'core.tar.gz')
            _downloads['download_panel'](panel, folder / 'management.html')
            require(b'/v8/management' in (folder / 'management.html').read_bytes(), '新版管理页面不使用 v8 管理接口，未替换。')
            require(cp_fingerprint() == fingerprint, '下载期间配置发生变化，跳过更新。')
            backup = CP_STATE / 'rollback'; backup.mkdir(mode=0o700, exist_ok=True)
            old_binary = CP_BINARY.read_bytes(); page = CP_DATA / 'static/management.html'; old_page = page.read_bytes()
            private_write(backup / 'core', old_binary, 0o700)
            private_write(backup / 'config.yaml', CP_CONFIG.read_bytes())
            private_write(backup / 'management.html', old_page)
            write_json(backup / 'versions.json', versions)
            account = pwd.getpwnam('cliproxy')
            write_json(transaction, {'target': target, 'previous': versions, 'created': now()})
            command(['systemctl', 'stop', CP_UNIT])
            try:
                private_write(CP_BINARY, cp_extract(folder / 'core.tar.gz'), 0o755)
                private_write(page, (folder / 'management.html').read_bytes(), 0o600)
                account = pwd.getpwnam('cliproxy'); os.chown(page, account.pw_uid, account.pw_gid)
                command(['systemctl', 'start', CP_UNIT])
                for attempt in range(20):
                    try: cp_health(cp_read(), record, public=public); break
                    except (OperationError, OSError, ValueError):
                        if attempt == 19: raise
                        time.sleep(0.5)
                require(cp_version() == core, '升级后核心版本检查失败。')
            except Exception:
                command(['systemctl', 'stop', CP_UNIT], check=False)
                private_write(CP_BINARY, old_binary, 0o755); private_write(page, old_page, 0o600)
                os.chown(page, account.pw_uid, account.pw_gid)
                # Preserve live user edits and refreshed OAuth tokens; config is never overwritten.
                command(['systemctl', 'start', CP_UNIT]); time.sleep(1)
                cp_health(cp_read(), record, public=public)
                result['rollback'] = '已恢复并通过检查'
                transaction.unlink(missing_ok=True)
                raise
            write_json(CP_STATE / 'versions.json', {'core': core, 'panel': panel})
            mark_installed('cliproxyapi', record | {'version': core, 'panel_version': panel})
            transaction.unlink(missing_ok=True)
            result.update(result='更新成功', before=versions, after={'core': core, 'panel': panel},
                          public_probe='通过' if public else '更新前公网自测不可达；本机 TLS 验证通过')
    except Exception as error:
        if transaction.is_file(): result['rollback'] = '恢复失败'
        result.update(result='更新失败', reason=clean(error) if isinstance(error, (OperationError, _downloads['DownloadError'])) else '维护检查失败',
                      failed_target=result.get('latest', '') + '/' + result.get('latest_panel', ''), retry_after=time.time() + 86400)
    finally:
        write_json(state_file, result)
    return result


def cp_maintenance(action):
    # Same lock as desktop jobs prevents update, install, restore and uninstall races.
    with (ROOT / 'operation.lock').open('a') as stream:
        try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return
        if any(t.get('state') in {'queued', 'running', 'awaiting_verification', 'recovery_failed'} for t in task_list()): return
        if not CP_CONFIG.is_file() or cp_records().get('uninstalled'): return
        if globals().get('cp_oauth_busy') and cp_oauth_busy(): return
        if action == 'cp-update': cp_update()
        elif action == 'cp-backup': cp_daily_backup()


_cp_previous_details = connection_details


def connection_details(params):
    if params.get('service') != 'cliproxyapi': return _cp_previous_details(params)
    record = cp_records()
    data = dict(record, service='cliproxyapi', installed=CP_CONFIG.is_file() and not record.get('uninstalled'),
                units=[dict(unit=CP_UNIT, **unit_info(CP_UNIT))])
    if not data['installed']: return data
    config = cp_read()
    data.update(version=cp_version(), backend_port=config['server']['port'],
                api_keys=config['access']['api-keys'], internal_host=config['server']['host'], checked=now(),
                nginx=unit_info('nginx.service'), timers={u: unit_info(u) for u in CP_TIMERS})
    for file, field in [('versions.json', 'versions'), ('update-status.json', 'update_status'), ('backup-status.json', 'backup_status')]:
        path = CP_STATE / file
        if path.is_file(): data[field] = json.loads(path.read_text())
    try:
        data['models'] = cp_health(config, record)
        data['health'] = 'HTTPS、页面、API 鉴权通过；模型推理未实测'
    except (OperationError, OSError, ValueError): data['health'] = '基础检查失败；请核对服务、监听和证书'
    summary = {}
    for file in (CP_DATA / 'auth').glob('*.json'):
        try:
            auth = json.loads(file.read_text())
            if not isinstance(auth, dict): raise ValueError('invalid authorization mapping')
            provider = str(auth.get('type') or auth.get('provider') or '未识别')
            summary[provider] = summary.get(provider, 0) + 1
        except (OSError, ValueError): summary['授权文件读取失败'] = summary.get('授权文件读取失败', 0) + 1
    for provider, groups in config.get('api-keys', {}).items() if isinstance(config.get('api-keys'), dict) else []:
        summary[provider] = summary.get(provider, 0) + (len(groups) if isinstance(groups, list) else 1)
    data['accounts'] = summary
    data['account_details'] = []
    for file in (CP_DATA / 'auth').glob('*.json'):
        try:
            auth = json.loads(file.read_text())
            if not isinstance(auth, dict): raise ValueError('invalid authorization mapping')
            data['account_details'].append({
                'provider': str(auth.get('type') or auth.get('provider') or '未识别'),
                'identity': str(auth.get('email') or auth.get('account_id') or file.stem),
                'state': '已停用' if auth.get('disabled') else '授权文件已配置；实时有效性以后台查询为准',
            })
        except (OSError, ValueError):
            data['account_details'].append({'provider': '未能读取', 'identity': file.name,
                                            'state': '授权文件读取失败；请在后台检查，未修改原文件'})
    cert = record.get('certificate_lineage')
    if cert:
        data['certificate'] = command(['openssl', 'x509', '-in', cert + '/fullchain.pem', '-noout', '-enddate'], check=False).stdout.strip()
    process = command(['systemctl', 'show', CP_UNIT, '-p', 'MemoryCurrent', '-p', 'ActiveEnterTimestamp', '-p', 'ExecMainStartTimestamp'], check=False)
    data['runtime'] = process.stdout.strip()
    schedule = command(['systemctl', 'show', CP_TIMERS[0], '-p', 'NextElapseUSecMonotonic', '-p', 'LastTriggerUSec'], check=False)
    data['update_schedule'] = schedule.stdout.strip()
    data['certificate_renewal'] = unit_info('linux-manager-cert-renew.timer')
    data['public_schedule'] = command(['systemctl', 'list-timers', '--all', *CP_TIMERS, '--no-pager'], check=False).stdout.strip()
    rollback = CP_STATE / 'rollback/versions.json'
    data['rollback_version'] = json.loads(rollback.read_text()) if rollback.is_file() else {}
    return data


_cp_previous_dispatch = dispatch


def dispatch(request):
    if request.get('action') == 'verify_cliproxy_key':
        secret = request.get('management_key', '')
        register_secrets(request)
        password(secret)
        config = cp_read(); require(config, 'CLIProxyAPI 尚未安装。')
        status, _ = cp_request('http://127.0.0.1:' + str(config['server']['port']), '/v8/management/config', secret)
        return {'verified': status == 200}
    return _cp_previous_dispatch(request)


_cp_previous_backup = configuration_backup
_cp_previous_config_restore = configuration_restore


def configuration_backup(params):
    if params.get('service') != 'cliproxyapi': return _cp_previous_backup(params)
    cp_daily_backup()
    backup_files([str(CP_CONFIG)], {'deployment': True, 'service': 'cliproxyapi'})
    return {'service': 'cliproxyapi', 'backup_id': TASK.name}


def configuration_restore(params):
    identifier = params.get('backup_id'); validate_task_id(identifier)
    manifest = json.loads((ROOT / 'tasks' / identifier / 'backup/manifest.json').read_text())
    if manifest.get('extra', {}).get('service') != 'cliproxyapi': return _cp_previous_config_restore(params)
    require(status_task(identifier)['state'] in {'succeeded', 'failed', 'rolled_back'}, '原备份操作未完成。')
    require([p['path'] for p in manifest['paths']] == [str(CP_CONFIG)], '部署备份只能由原任务回滚，不能覆盖当前账号数据。')
    state = unit_info(CP_UNIT)
    require(state.get('LoadState') == 'loaded' and state.get('ActiveState') in {'active', 'inactive', 'failed'}, '核心状态无法确认，未恢复配置。')
    backup_files([str(CP_CONFIG)], {'deployment': True, 'service': 'cliproxyapi',
                                  'unit_states': {CP_UNIT: state}, 'previous_record': cp_records()})
    try:
        command(['systemctl', 'stop', CP_UNIT]); restore_files(identifier, project_only=True)
        config = cp_read()
        if state.get('ActiveState') == 'active':
            command(['systemctl', 'start', CP_UNIT]); time.sleep(1)
            cp_health(config, cp_records())
    except Exception:
        restore_deployment(TASK.name)
        raise
    return {'service': 'cliproxyapi', 'verified': 'configuration-and-auth' if state.get('ActiveState') == 'active' else 'configuration-restored-core-stopped'}


def cp_rollback():
    folder = CP_STATE / 'rollback'
    require(all((folder / name).is_file() for name in ['core', 'management.html', 'versions.json']), '尚无可恢复的升级版本。')
    require(unit_info(CP_UNIT).get('ActiveState') == 'active', '请先启动核心并检查后再回滚。')
    record = cp_records(); cp_health(cp_read(), record)
    versions = json.loads((folder / 'versions.json').read_text())
    old_binary = CP_BINARY.read_bytes(); page = CP_DATA / 'static/management.html'; old_page = page.read_bytes()
    account = pwd.getpwnam('cliproxy')
    command(['systemctl', 'stop', CP_UNIT])
    try:
        private_write(CP_BINARY, (folder / 'core').read_bytes(), 0o755)
        private_write(page, (folder / 'management.html').read_bytes(), 0o600); os.chown(page, account.pw_uid, account.pw_gid)
        command(['systemctl', 'start', CP_UNIT]); time.sleep(1)
        cp_health(cp_read(), record)
        require(cp_version() == versions['core'], '回滚后的版本检查失败。')
    except Exception:
        command(['systemctl', 'stop', CP_UNIT], check=False)
        private_write(CP_BINARY, old_binary, 0o755); private_write(page, old_page, 0o600); os.chown(page, account.pw_uid, account.pw_gid)
        command(['systemctl', 'start', CP_UNIT])
        raise
    write_json(CP_STATE / 'versions.json', versions)
    command(['systemctl', 'disable', '--now', CP_TIMERS[0]])
    # Avoid immediately reinstalling the version deliberately rolled back by the user.
    mark_installed('cliproxyapi', record | {'auto_update': False, 'version': versions['core'], 'panel_version': versions['panel']})
    write_json(CP_STATE / 'update-status.json', {'checked': now(), 'result': '手动回滚成功；自动更新已关闭', 'after': versions})
    return {'service': 'cliproxyapi', 'verified': 'rollback-and-health', 'version': versions['core']}


_cp_previous_manage = manage_service


def manage_service(params):
    if params.get('service') != 'cliproxyapi' or params.get('action') not in {'check_update', 'enable_update', 'disable_update', 'rollback_core'}:
        return _cp_previous_manage(params)
    require(cp_records() and not cp_records().get('uninstalled'), 'CLIProxyAPI 尚未安装。')
    action = params['action']
    if action == 'check_update':
        result = cp_update(force=True)
        require(result['result'] != '更新失败', result.get('reason', '更新检查失败。'))
        return {'service': 'cliproxyapi', 'update': result}
    if action == 'rollback_core': return cp_rollback()
    enabled = action == 'enable_update'
    command(['systemctl', 'enable' if enabled else 'disable', '--now', CP_TIMERS[0]])
    mark_installed('cliproxyapi', cp_records() | {'auto_update': enabled})
    return {'service': 'cliproxyapi', 'auto_update': enabled}


_cp_previous_uninstall = uninstall_project
_cp_previous_restore_uninstall = restore_uninstall


def uninstall_project(params):
    result = _cp_previous_uninstall(params)
    if params.get('service') == 'cliproxyapi':
        command(['nginx', '-t']); command(['systemctl', 'reload', 'nginx.service'])
    return result


def restore_uninstall(identifier):
    _cp_previous_restore_uninstall(identifier)
    manifest = json.loads((ROOT / 'tasks' / identifier / 'uninstall/manifest.json').read_text())
    if manifest.get('service') == 'cliproxyapi':
        command(['nginx', '-t']); command(['systemctl', 'reload', 'nginx.service'])
