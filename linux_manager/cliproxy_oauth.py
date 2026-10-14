"""Root-side OAuth bridge, embedded into the allowlisted SSH agent."""
import queue
import threading

CP_OAUTH_ACTIVE = {'starting', 'ready', 'exchanging', 'verifying'}
CP_OAUTH_TERMINAL = {'succeeded', 'failed', 'expired', 'cancelled'}


def cp_oauth_folder(identifier):
    return CP_STATE / 'oauth' / validate_task_id(identifier)


def cp_oauth_read_session(file):
    try:
        session = json.loads(file.read_text())
        if not isinstance(session, dict):
            raise ValueError()
        identifier = session.get('id')
        if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{24}', identifier) or identifier != file.parent.name:
            raise ValueError()
        if not isinstance(session.get('provider'), str) or session['provider'] not in OAUTH_PROVIDERS:
            raise ValueError()
        if session.get('mode') not in ['callback', 'observe', 'api-device', 'device', 'cli'] or session.get('phase') not in list(CP_OAUTH_ACTIVE | CP_OAUTH_TERMINAL):
            raise ValueError()
        expires = session.get('expires')
        if type(expires) not in (int, float) or not 0 < expires < float('inf'):
            raise ValueError()
        if session['mode'] == 'cli' and (type(session.get('callback_port')) is not int or not 1024 <= session['callback_port'] <= 65535):
            raise ValueError()
        return session
    except (OSError, ValueError):
        raise OperationError('授权会话记录无法读取；请先核对，不能同时维护核心。') from None


def cp_oauth_sessions():
    folder = CP_STATE / 'oauth'
    if folder.is_dir():
        for file in folder.glob('*/session.json'):
            yield cp_oauth_read_session(file)


def cp_oauth_busy():
    return any(s.get('cleanup_failed') or (s.get('phase') in CP_OAUTH_ACTIVE or s.get('cleanup_pending') or s.get('cancel_unconfirmed')) and s.get('expires', 0) > time.time() for s in cp_oauth_sessions())


def cp_oauth_http(path, key, *, method='GET', data=None, raw=False):
    config = cp_read()
    require(config and config['server']['host'] == '127.0.0.1', 'AI 核心未配置为环回监听。')
    headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}
    body = data if raw else json.dumps(data).encode() if data is not None else None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request('http://127.0.0.1:' + str(config['server']['port']) + path,
                                     data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=10) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
            require(len(payload) <= 2 * 1024 * 1024, '管理接口响应过长，已停止。')
            value = json.loads(payload)
            require(isinstance(value, dict), '管理接口返回格式无法识别。')
            return value
    except urllib.error.HTTPError as error:
        if method == 'DELETE' and error.code in {404, 409, 410}:
            return {'status': 'ok'}  # An already-ended session is an idempotent cancellation.
        message = {401: '管理 Key 无效，请补充现有管理 Key。', 403: '管理 Key 验证被拒绝。',
                   404: '当前核心不支持所需的授权接口或会话已过期。', 409: '授权会话已结束或过期，请重新登录。'}
        raise OperationError(message.get(error.code, '服务器授权接口未完成请求，请检查后台。')) from None
    except (OSError, ValueError):
        raise OperationError('服务器授权接口暂时不可达，请检查核心和网络。') from None


def cp_oauth_public(session):
    keys = ['phase', 'provider', 'mode', 'message', 'recognized', 'cleanup_failed', 'cancel_unconfirmed']
    if session.get('phase') == 'ready':
        keys.extend(['url', 'state', 'user_code'])
    return {key: session[key] for key in keys if key in session}


def cp_oauth_finish(folder, session, phase, message, **extra):
    session.update(phase=phase, message=message, **extra)
    for key in ['url', 'state', 'user_code']:
        session.pop(key, None)
    write_json(folder / 'session.json', session)
    return cp_oauth_public(session)


def cp_oauth_cancel(folder, session, key, *, phase='cancelled', message='本次授权已取消，可以重新登录。'):
    if session['phase'] == 'succeeded':
        return cp_oauth_public(session)
    state = session.get('cancel_state') or session.get('state')
    private_write(folder / 'cancel', '')
    if state and session['mode'] in {'callback', 'observe', 'api-device'}:
        session.update(cancel_state=state, cancel_unconfirmed=True)
    # End the bridge first so callbacks cannot be forwarded after a lost DELETE.
    cp_oauth_finish(folder, session, phase, message)
    if session.get('cancel_unconfirmed') and state:
        try:
            cp_oauth_http('/v8/management/oauth/session?state=' + urllib.parse.quote(state), key, method='DELETE')
            session.pop('cancel_state', None)
            session.pop('cancel_unconfirmed', None)
        except OperationError:
            session['message'] = '本次授权已结束；服务器清理暂未确认，下次登录会自动重试，请关闭旧网页。'
        write_json(folder / 'session.json', session)
    elif session.get('cancel_unconfirmed') and session.get('expires', 0) <= time.time():
        session.pop('cancel_unconfirmed', None)
        write_json(folder / 'session.json', session)
    return cp_oauth_public(session)


def cp_oauth_recover(key):
    """Retry cleanup only for terminal sessions; preserve other Macs' active logins."""
    for session in cp_oauth_sessions():
        if session.get('phase') not in CP_OAUTH_TERMINAL or not any(session.get(k) for k in ['cancel_unconfirmed', 'cleanup_failed', 'cleanup_pending']):
            continue
        folder = cp_oauth_folder(session['id'])
        with state_lock(folder, timeout=5):
            session = cp_oauth_read_session(folder / 'session.json')
            if session.get('cancel_unconfirmed'):
                cp_oauth_cancel(folder, session, key, phase=session['phase'])
            if session.get('cleanup_failed') or session.get('cleanup_pending'):
                if unit_info('linux-manager-oauth-' + session['id'] + '.service').get('ActiveState') in {'active', 'activating', 'deactivating'}:
                    continue
                try:
                    if session['mode'] == 'cli':
                        cp_oauth_firewall(session['id'], session['callback_port'], remove=True)
                    for temporary in CP_DATA.glob('.oauth-' + session['id'] + '-*'):
                        require(not temporary.is_symlink() and temporary.is_dir(), '临时授权目录类型不正确，未删除。')
                        shutil.rmtree(temporary)
                    (folder / 'private.json').unlink(missing_ok=True)
                    session.update(cleanup_pending=False, cleanup_failed=False)
                    write_json(folder / 'session.json', session)
                except (OperationError, OSError):
                    pass  # Keep the guard until the exact temporary resources are cleaned.


def cp_oauth_baseline():
    return {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in (CP_DATA / 'auth').glob('*.json') if file.is_file()}


def cp_oauth_recognized(session, key):
    # A browser login or a successful callback POST alone is not completion.
    changed = []
    for file in (CP_DATA / 'auth').glob('*.json'):
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        if session.get('baseline', {}).get(file.name) == digest:
            continue
        value = json.loads(file.read_text())
        if value.get('type', value.get('provider')) == session['provider'] and any(value.get(k) for k in OAUTH_PROVIDERS[session['provider']]['tokens']) and not value.get('disabled'):
            changed.append(file.name)
    if not changed:
        return False
    files = cp_oauth_http('/v8/management/credentials', key).get('files', [])
    return any(row.get('name') in changed and row.get('provider') == session['provider'] and not row.get('disabled') for row in files if isinstance(row, dict))


def cp_oauth_dispatch(request):
    require(os.geteuid() == 0, '授权桥接需要管理员权限。')
    identifier = request.get('session_id'); folder = cp_oauth_folder(identifier)
    provider = request.get('provider')
    require(provider in OAUTH_PROVIDERS, '授权服务不支持；插件和凭据导入请使用官方管理页面，不猜测回调地址。')
    key = request.get('management_key', '')
    register_secrets(request); password(key)
    require(cp_records().get('installed') and not cp_records().get('uninstalled'), 'CLIProxyAPI 尚未安装。')
    # Verify on every call; never return sensitive URLs to an invalid management key.
    cp_oauth_http('/v8/management/config', key)
    operation = request.get('oauth_operation')
    if operation == 'capabilities':
        return {'callback_port': OAUTH_PROVIDERS[provider]['port'] if provider != 'devin' else cp_read()['server']['port'],
                'flow': OAUTH_PROVIDERS[provider]['flow']}
    if operation == 'probe_port':
        require(provider == 'antigravity', '此服务不支持可变回调端口。')
        number = port(request.get('callback_port'))
        require(number >= 1024, '临时回调端口无效。')
        return {'available': not any(row['port'] == number and row['protocol'] == 'tcp' for row in listeners())}
    # Same submission lock as maintenance prevents auth/start races across Macs.
    with state_lock(ROOT / 'submission', timeout=5), state_lock(CP_STATE / 'oauth', timeout=5), state_lock(folder, timeout=5):
        file = folder / 'session.json'
        session = cp_oauth_read_session(file) if file.is_file() else None
        if operation == 'start':
            mode = request.get('mode'); number = request.get('callback_port')
            flow = OAUTH_PROVIDERS[provider]['flow']
            allowed = {flow} | ({'device'} if provider == 'codex' else {'cli'} if provider == 'antigravity' else {'observe'} if provider in {'claude', 'devin'} else set())
            require(mode in allowed, '授权方式不支持。')
            expected = OAUTH_PROVIDERS[provider]['port'] if provider != 'devin' else cp_read()['server']['port']
            require(number == expected if mode in {'callback', 'observe'} else number == 0 if mode in {'device', 'api-device'} else isinstance(number, int) and 1024 <= number <= 65535, '回调端口不符合官方授权约束。')
            if session:
                require((session['provider'], session['mode'], session['callback_port']) == (provider, mode, number), '授权编号已被其他流程使用。')
                return cp_oauth_public(session)
            cp_oauth_recover(key)
            require(not cp_oauth_busy(), '另一项授权尚未结束，请先完成或取消。')
            require(not any(t['state'] in {'queued', 'running', 'awaiting_verification', 'recovery_failed'} for t in task_list()), '服务器有未完成维护任务，暂不发起授权。')
            with (ROOT / 'operation.lock').open('a') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise OperationError('核心正在维护，请稍后登录。') from None
                session = {'id': identifier, 'provider': provider, 'mode': mode, 'callback_port': number,
                           'phase': 'starting', 'expires': time.time() + (900 if mode in {'device', 'api-device'} else 300),
                           'baseline': cp_oauth_baseline(), 'cleanup_pending': mode in {'device', 'cli'}}
                write_json(file, session)
                try:
                    write_json(folder / 'private.json', {'management_key': key})
                    if mode in {'callback', 'observe', 'api-device'}:
                        # is_webui=false avoids Linux's wildcard callback forwarder.
                        data = cp_oauth_http('/v8/management/oauth/auth-url?' + urllib.parse.urlencode({'provider': provider, 'is_webui': 'false'}), key)
                        require(data.get('status') == 'ok' and data.get('url') and data.get('state'), '核心没有返回有效授权会话。')
                        require((data.get('flow') == 'device') == (mode == 'api-device'), '核心返回的授权流程与提供商契约不一致。')
                        session.update(phase='ready', url=data['url'], state=data['state'], user_code=data.get('user_code', ''))
                        if mode == 'api-device' and isinstance(data.get('expires_in'), (int, float)):
                            session['expires'] = min(session['expires'], time.time() + max(1, data['expires_in']))
                        write_json(file, session)
                    private_write(folder / 'runner.py', globals().get('AGENT_SOURCE', ''))
                    command(['systemd-run', '--quiet', '--collect', '--unit=linux-manager-oauth-' + identifier,
                             '--property=RuntimeMaxSec=16min', '/usr/bin/python3', str(folder / 'runner.py'), 'cp-oauth', identifier])
                except Exception:
                    (folder / 'private.json').unlink(missing_ok=True)
                    session['cleanup_pending'] = False
                    cp_oauth_cancel(folder, session, key, phase='failed', message='授权启动未完成，请重新登录；旧网页不可继续使用。')
                    raise
            return cp_oauth_public(session)
        if operation == 'cancel' and session is None:
            return {'phase': 'cancelled', 'message': '服务器没有这个临时授权会话，可以重新登录。'}
        require(session is not None and session['provider'] == provider, '这不是当前服务器的授权会话。')
        if operation == 'cancel':
            return cp_oauth_cancel(folder, session, key, phase=session['phase'] if session['phase'] in CP_OAUTH_TERMINAL else 'cancelled')
        if session['phase'] in CP_OAUTH_TERMINAL:
            return cp_oauth_public(session)
        if time.time() >= session['expires']:
            return cp_oauth_cancel(folder, session, key, phase='expired', message='本次授权已过期，可以重新登录。')
        if operation == 'callback':
            state = request.get('state', ''); code = request.get('code', ''); error = request.get('error', '')
            require(isinstance(state, str) and hmac.compare_digest(state.encode(), session.get('state', '').encode()), '回调状态与本次授权不一致。')
            require(all(isinstance(v, str) and len(v) <= 4096 and not any(ord(c) < 32 for c in v) for v in [code, error]) and bool(code) != bool(error), '回调参数无效。')
            digest = hashlib.sha256(json.dumps([state, code, error]).encode()).hexdigest()
            if session.get('callback_digest'):
                require(hmac.compare_digest(digest, session['callback_digest']), '本次授权已经收到不同的回调，不重复提交。')
                return cp_oauth_public(session)
            session.update(callback_digest=digest, phase='exchanging')
            write_json(file, session)
            if session['mode'] in {'callback', 'observe'}:
                cp_oauth_http('/v8/management/oauth/callback', key, method='POST', data={'provider': OAUTH_PROVIDERS[provider].get('callback_provider', provider), 'state': state, 'code': code, 'error': error})
            elif session['mode'] == 'cli':
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                url = 'http://127.0.0.1:' + str(session['callback_port']) + '/oauth-callback?' + urllib.parse.urlencode({'state': state, 'code': code, 'error': error})
                try:
                    with opener.open(url, timeout=5) as response:
                        require(response.status == 200, '临时授权接收器拒绝回调。')
                except OSError:
                    raise OperationError('临时授权接收器不可达；请重新登录，不继续使用旧回调。') from None
            else:
                raise OperationError('设备码授权无需回调。')
            session.update(callback_digest=digest, phase='exchanging')
            write_json(file, session)
            return cp_oauth_public(session)
        require(operation == 'status', '不支持这个授权操作。')
        if session['mode'] in {'callback', 'observe', 'api-device'}:
            data = cp_oauth_http('/v8/management/oauth/status?state=' + urllib.parse.quote(session['state']), key)
            if data.get('status') == 'error':
                reason = str(data.get('error', '')).lower()
                text = '授权超时或已取消，请重新登录。' if any(w in reason for w in ['timeout', 'timed out', 'expired', 'cancel']) else '服务器未完成 Token 兑换或保存，请在后台检查网络与账号权限。'
                return cp_oauth_finish(folder, session, 'failed', text)
            if data.get('status') == 'ok':
                require(session['mode'] == 'api-device' or session.get('callback_digest'), '授权完成缺少本次回调证据。')
                if cp_oauth_recognized(session, key):
                    return cp_oauth_finish(folder, session, 'succeeded', '服务器已保存并识别授权。', recognized=True)
                session['phase'] = 'verifying'; write_json(file, session)
        return cp_oauth_public(session)


def cp_oauth_firewall(identifier, number, remove=False):
    # Official Antigravity CLI binds wildcard. Block only this new, otherwise-free
    # callback port on non-loopback interfaces before spawning it (IPv4 + IPv6).
    rules = ['!', '-i', 'lo', '-p', 'tcp', '--dport', str(number), '-m', 'comment', '--comment', 'lm-oauth-' + identifier, '-j', 'DROP']
    tools = ['iptables', 'ip6tables']
    if not remove:
        require(all(shutil.which(tool) for tool in tools), '缺少双栈回调端口保护工具，未启动临时授权。')
        for tool in tools:
            command([tool, '-w', '5', '-I', 'INPUT', '1', *rules])
        return
    failed = False
    for tool in tools:
        try:
            require(shutil.which(tool), '缺少回调端口保护工具。')
            exists = command([tool, '-w', '5', '-C', 'INPUT', *rules], check=False)
            require(exists.returncode in {0, 1}, '无法确认临时端口保护规则。')
            if exists.returncode == 0:
                command([tool, '-w', '5', '-D', 'INPUT', *rules])
        except (OperationError, OSError):
            failed = True  # Still clean the other stack; retry only this session.
    require(not failed, '临时端口保护规则未能全部清理，请核对服务器后重试。')


def cp_oauth_worker(identifier):
    folder = cp_oauth_folder(identifier); process = None; protected = False; temporary = None; success = False
    try:
        session = cp_oauth_read_session(folder / 'session.json')
        if session['phase'] in CP_OAUTH_TERMINAL:
            return
        key = json.loads((folder / 'private.json').read_text())['management_key']
        (folder / 'private.json').unlink()
        if session['mode'] in {'callback', 'observe', 'api-device'}:
            # Expire the exact core session as well, including native device flows.
            while time.time() < session['expires']:
                current = cp_oauth_read_session(folder / 'session.json')
                if current['phase'] in CP_OAUTH_TERMINAL:
                    return
                time.sleep(1)
            with state_lock(folder, timeout=5):
                current = cp_oauth_read_session(folder / 'session.json')
                if current['phase'] in CP_OAUTH_ACTIVE:
                    cp_oauth_cancel(folder, current, key, phase='expired', message='授权超时，可以重新登录。')
            return
        account = pwd.getpwnam('cliproxy')
        temporary = Path(tempfile.mkdtemp(prefix='.oauth-' + identifier + '-', dir=CP_DATA))
        os.chown(temporary, account.pw_uid, account.pw_gid)
        auth_dir = temporary / 'auth'; auth_dir.mkdir(mode=0o700); os.chown(auth_dir, account.pw_uid, account.pw_gid)
        config = cp_read(); config['oauth']['auth-dir'] = str(auth_dir)
        config.setdefault('observability', {})['logs'] = {'debug': False, 'logging-to-file': False, 'request-log': False}
        private_write(temporary / 'config.yaml', cp_yaml().safe_dump(config, sort_keys=False), owner=(account.pw_uid, account.pw_gid))
        args = [str(CP_BINARY), '-config', str(temporary / 'config.yaml'), '-no-browser']
        if session['mode'] == 'device':
            args.append('-codex-device-login')
        else:
            number = session['callback_port']
            ensure_port_available(number)
            protected = True  # Also remove a partial IPv4-only insertion on failure.
            cp_oauth_firewall(identifier, number)
            args.extend(['-antigravity-login', '-oauth-callback-port', str(number)])
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding='utf-8', errors='replace', start_new_session=True,
                                   user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                   env=os.environ | {'HOME': str(temporary)})
        lines = queue.Queue(maxsize=64)
        def read_output():
            for line in process.stdout:
                # Do not save CLI output: it may contain account names and tokens.
                try:
                    lines.put(line[:16384], timeout=1)
                except queue.Full:
                    continue
        thread = threading.Thread(target=read_output, daemon=True); thread.start()
        auth_url = ''; state = ''; user_code = ''
        while time.time() < session['expires']:
            with state_lock(folder, timeout=5):
                current = cp_oauth_read_session(folder / 'session.json')
                if current['phase'] in CP_OAUTH_TERMINAL or (folder / 'cancel').exists():
                    return
            try:
                line = lines.get(timeout=0.25)
                if session['mode'] == 'device':
                    match = re.search(r'Codex device code:\s*([A-Za-z0-9-]+)', line)
                    if match: user_code = match.group(1); auth_url = 'https://auth.openai.com/codex/device'
                else:
                    match = re.search(r'https://accounts\.google\.com/[^\s]+', line)
                    if match:
                        auth_url = match.group(0)
                        state = urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query).get('state', [''])[0]
                if auth_url:
                    with state_lock(folder, timeout=5):
                        current = cp_oauth_read_session(folder / 'session.json')
                        if current['phase'] == 'starting':
                            current.update(phase='ready', url=auth_url, state=state, user_code=user_code)
                            write_json(folder / 'session.json', current)
            except queue.Empty:
                pass
            if process.poll() is not None:
                thread.join(timeout=2)
                files = list(auth_dir.glob('*.json'))
                require(process.returncode == 0 and len(files) == 1, '官方授权流程未完成；请检查账号权限、设备码设置及服务器网络后重试。')
                file = files[0]; value = json.loads(file.read_text())
                require(value.get('type', value.get('provider')) == session['provider'] and value.get('access_token') and value.get('refresh_token'), '官方授权未返回完整凭据。')
                # Commit and cancellation serialize on the same lock.
                with state_lock(folder, timeout=5):
                    current = cp_oauth_read_session(folder / 'session.json')
                    if current['phase'] in CP_OAUTH_TERMINAL or (folder / 'cancel').exists():
                        return
                    require(current['phase'] in {'ready', 'exchanging'}, '授权状态无法识别，未保存。')
                    cp_oauth_http('/v8/management/credentials?name=' + urllib.parse.quote(file.name), key, method='POST', data=file.read_bytes(), raw=True)
                    current['phase'] = 'verifying'; write_json(folder / 'session.json', current)
                    for _ in range(10):
                        if cp_oauth_recognized(current, key):
                            success = True
                            return
                        time.sleep(0.5)
                    raise OperationError('授权已保存，但核心识别尚未确认；请在后台核对，不要重复授权。')
        raise OperationError('授权超时，请重新登录。')
    except Exception as error:
        with state_lock(folder, timeout=5):
            file = folder / 'session.json'
            if file.is_file():
                current = cp_oauth_read_session(file)
                if current['phase'] not in CP_OAUTH_TERMINAL:
                    cp_oauth_finish(folder, current, 'failed', str(error) if isinstance(error, OperationError) else '临时授权流程未完成；原有账号与配置未被清空。')
    finally:
        if process:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            for stream in [process.stdin, process.stdout]:
                if stream: stream.close()
        if protected:
            try:
                cp_oauth_firewall(identifier, session['callback_port'], remove=True)
            except OperationError:
                with state_lock(folder, timeout=5):
                    current = cp_oauth_read_session(folder / 'session.json')
                    current['message'] = '临时端口保护规则未能清理，请核对服务器；原服务和防火墙策略保留。'
                    current['cleanup_failed'] = True
                    write_json(folder / 'session.json', current)
        if temporary is not None and temporary.exists():
            try:
                shutil.rmtree(temporary)
            except OSError:
                with state_lock(folder, timeout=5):
                    current = cp_oauth_read_session(folder / 'session.json')
                    current.update(cleanup_failed=True, message='临时授权文件清理失败；文件仍受权限保护，请核对服务器。')
                    write_json(folder / 'session.json', current)
        (folder / 'private.json').unlink(missing_ok=True)
        with state_lock(folder, timeout=5):
            file = folder / 'session.json'
            if file.is_file():
                current = cp_oauth_read_session(file); current['cleanup_pending'] = False
                if success and current['phase'] not in CP_OAUTH_TERMINAL:
                    cp_oauth_finish(folder, current, 'failed' if current.get('cleanup_failed') else 'succeeded',
                                    current.get('message') if current.get('cleanup_failed') else '服务器已保存并识别授权。', recognized=not current.get('cleanup_failed'))
                else:
                    write_json(file, current)


_cp_oauth_previous_dispatch = dispatch


def dispatch(request):
    if request.get('action') == 'cliproxy_oauth':
        return cp_oauth_dispatch(request)
    return _cp_oauth_previous_dispatch(request)
