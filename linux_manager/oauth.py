"""Temporary loopback callbacks; credentials and PKCE stay on the selected Linux host."""
from __future__ import annotations

import errno
import hmac
import json
import shlex
import subprocess
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .models import ManagerError
from .transport import WaitingStopped
from .oauth_contract import OAUTH_PROVIDERS

PROVIDERS = {name: (spec['port'], spec['path'], spec['hosts'][0]) for name, spec in OAUTH_PROVIDERS.items()}


def open_authorization_browser(url):
    if sys.platform == 'darwin':
        # Launch Services resolves user-installed/moved apps by bundle ID. Normal
        # opening needs no Apple Events permission; send the URL through stdin.
        for arguments in (['/usr/bin/open', '-b', 'com.google.Chrome', url], ['/usr/bin/open', url]):
            try:
                result = subprocess.run(['/bin/sh'], input='exec ' + shlex.join(arguments) + '\n',
                                        text=True, capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0:
                return True
        raise ManagerError('无法打开授权浏览器；请设置可用的默认浏览器后重试。')
    return webbrowser.open(url)


class CallbackPortBusy(ManagerError):
    pass


class LoopbackCallback:
    def __init__(self, provider, port=None, lifetime=280, listen=True):
        if provider not in PROVIDERS:
            raise ManagerError('不支持这个授权服务。')
        self.provider = provider
        self.path = PROVIDERS[provider][1]
        self.state = ''
        self.payload = None
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.deadline = time.monotonic() + lifetime
        self.servers = []
        self.threads = []
        self.closed = False
        self.notice = ''
        requested = PROVIDERS[provider][0] if port is None else port
        owner = self
        if not listen:
            self.port = requested
            return

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(2)

            def log_message(self, *_):
                # HTTP's default access log includes the secret callback query.
                return

            def do_GET(self):
                status, text = owner.accept(self.path, self.headers.get('Host', ''))
                body = ('<!doctype html><meta charset="utf-8"><title>登录授权</title><p>' + text + '</p>').encode()
                try:
                    self.send_response(status)
                    for name, value in [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'),
                                        ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'none'"),
                                        ('Connection', 'close'), ('Content-Length', str(len(body)))]:
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, TimeoutError):
                    owner.notice = '浏览器连接提前关闭；已接收的回调仍会继续处理。'

        class Server(ThreadingHTTPServer):
            allow_reuse_address = False
            daemon_threads = True

            def handle_error(self, *_):
                owner.notice = '本机收到无法处理的 HTTP 请求，未转交授权。'

        class IPv6Server(Server):
            address_family = socket.AF_INET6

            def server_bind(self):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                super().server_bind()

        try:
            for attempt in range(10):
                ipv4 = Server(('127.0.0.1', requested), Handler)
                self.servers.append(ipv4)
                self.port = ipv4.server_address[1]
                try:
                    ipv6 = IPv6Server(('::1', self.port), Handler)
                    self.servers.append(ipv6)
                    break
                except OSError as error:
                    if error.errno in {errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT}:
                        break  # IPv6 is disabled on this system; IPv4 remains loopback-only.
                    ipv4.server_close(); self.servers.clear()
                    if error.errno == errno.EADDRINUSE and requested == 0 and attempt < 9:
                        continue
                    raise
            for server in self.servers:
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
                thread.start(); self.threads.append(thread)
        except OSError as error:
            for server in self.servers:
                server.server_close()
            if error.errno == errno.EADDRINUSE:
                raise CallbackPortBusy('本机回调端口已被其他程序使用，将采用替代授权方式。') from None
            raise ManagerError('无法建立本机环回回调接收器；没有抢占端口或开放公网入口。') from None

    def arm(self, state):
        if not isinstance(state, str) or not state or len(state) > 512 or not state.isascii():
            raise ManagerError('服务器返回的授权状态无法识别，已停止。')
        with self.lock:
            if self.closed:
                raise WaitingStopped('授权已取消。')
            self.state = state

    def accept(self, raw_path, authority):
        if len(raw_path) > 8192:
            return 414, '回调请求过长，未处理。'
        if authority not in {f'localhost:{self.port}', f'127.0.0.1:{self.port}', f'[::1]:{self.port}'}:
            return 400, '回调来源不正确，未处理。'
        parsed = urlsplit(raw_path)
        if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path != self.path:
            return 404, '这不是本次登录的回调入口。'
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=24)
        except ValueError:
            return 400, '回调参数无法识别。'
        if any(len(query.get(name, [])) != 1 for name in ['state']) or any(len(query.get(name, [])) > 1 for name in ['code', 'error', 'provider']):
            return 400, '回调参数不完整或重复。'
        state = query['state'][0]
        code = query.get('code', [''])[0]
        error = query.get('error', [''])[0]
        if bool(code) == bool(error) or len(code) > 4096 or len(error) > 512:
            return 400, '回调必须包含授权结果。'
        if any(ord(c) < 32 or ord(c) == 127 for c in state + code + error):
            return 400, '回调包含无效字符。'
        if query.get('provider', [self.provider])[0] != self.provider:
            return 400, '回调服务与本次登录不一致。'
        with self.lock:
            if self.closed or time.monotonic() >= self.deadline:
                return 410, '本次授权已结束，请在管理器重新发起。'
            if not self.state:
                return 503, '授权尚未就绪。'
            if not hmac.compare_digest(state.encode(), self.state.encode()):
                return 400, '回调不属于本次授权，未转交其他程序。'
            if self.payload is not None:
                return 409, '回调已经接收，请回管理器查看结果。'
            self.payload = {'state': state, 'code': code, 'error': 'access_denied' if error == 'access_denied' else 'authorization_failed' if error else ''}
            self.event.set()
        return 200, '回调已接收。请回服务器管理器确认授权结果；此页面不代表服务器已登录成功。'

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            self.state = ''
            self.payload = None
            self.event.set()
        for server in self.servers:
            server.shutdown(); server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


def chrome_callback_urls(host, port, path):
    if sys.platform != 'darwin':
        raise ManagerError('固定回调端口被占用，需要 Google Chrome 的回调兼容入口；未抢占其他程序。')
    prefix = f'http://{host}:{port}{path}?'
    source = ('tell application id "com.google.Chrome"\nset out to {}\nrepeat with w in windows\nrepeat with t in tabs of w\n'
              'if URL of t starts with ' + json.dumps(prefix) + ' then set end of out to URL of t\n'
              'end repeat\nend repeat\nset AppleScript\'s text item delimiters to linefeed\nreturn out as text\nend tell')
    try:
        result = subprocess.run(['/usr/bin/osascript', '-'], input=source, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        raise ManagerError('读取 Google Chrome 回调超时；没有向其他程序提交授权。') from None
    if result.returncode:
        raise ManagerError('无法读取 Google Chrome 的回调；请允许管理器控制 Chrome 后重试。')
    # Only matching loopback URLs leave Chrome, and only in this process memory.
    return [url for url in result.stdout.splitlines() if url.startswith(prefix)]


def validate_authorization(provider, data, port):
    url = data.get('url', '')
    if not isinstance(url, str) or len(url) > 8192:
        raise ManagerError('授权网址无法识别。')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in OAUTH_PROVIDERS[provider]['hosts'] or parsed.port not in {None, 443} or parsed.username or parsed.password or parsed.fragment:
        raise ManagerError('授权网址不是预期的官方 HTTPS 入口，已停止。')
    if data.get('mode') in {'device', 'api-device'}:
        if data.get('mode') == 'device' and (provider != 'codex' or parsed.path != '/codex/device' or parsed.query):
            raise ManagerError('设备码授权入口无法识别。')
        if data.get('mode') == 'api-device' and OAUTH_PROVIDERS[provider]['flow'] != 'api-device':
            raise ManagerError('提供商授权流程不一致。')
        code = data.get('user_code', '')
        if not isinstance(code, str) or len(code) > 64 or not code.isascii() or any(not (c.isalnum() or c == '-') for c in code) or data.get('mode') == 'device' and not code:
            raise ManagerError('服务器没有返回有效设备码。')
        return
    query = parse_qs(parsed.query, keep_blank_values=True)
    redirect = f"http://{OAUTH_PROVIDERS[provider]['redirect_host']}:{port}{PROVIDERS[provider][1]}"
    if query.get('redirect_uri') != [redirect] or query.get('state') != [data.get('state')] or not data.get('state'):
        raise ManagerError('授权回调地址或状态不一致，未打开浏览器。')
    if provider in {'codex', 'claude', 'devin'} and (provider == 'codex' and port != 1455 or query.get('code_challenge_method') != ['S256'] or len(query.get('code_challenge', [''])[0]) < 32):
        raise ManagerError('Codex 的固定回调地址或 PKCE 信息不正确。')


class OAuthLogin:
    """One immutable RPC destination; no auth URL, code, state or key in history."""
    def __init__(self, provider, rpc):
        if provider not in PROVIDERS:
            raise ManagerError('不支持这个授权服务。')
        self.provider = provider
        self.rpc = rpc
        self.identifier = secrets.token_hex(12)
        self.cancel_event = threading.Event()
        self.receiver = None
        self.finished = threading.Event()
        self.cleanup_pending = False

    def cancel(self):
        self.cancel_event.set()
        if self.receiver:
            self.receiver.close()

    def run(self, ready=lambda data: None, progress=lambda text: None):
        submitted = False
        succeeded = False
        mode = OAUTH_PROVIDERS[self.provider]['flow']
        observing = False
        try:
            if self.cancel_event.is_set():
                raise WaitingStopped('授权已取消。')
            if mode == 'callback':
                number = OAUTH_PROVIDERS[self.provider]['port']
                if number is None:
                    number = self.rpc('capabilities', session_id=self.identifier, provider=self.provider).get('callback_port')
                    if not isinstance(number, int) or not 1 <= number <= 65535:
                        raise ManagerError('服务器回调端口无法识别。')
                try:
                    self.receiver = LoopbackCallback(self.provider, **({'port': number} if self.provider == 'devin' else {}))
                except CallbackPortBusy:
                    mode = 'device' if self.provider == 'codex' else 'cli' if self.provider == 'antigravity' else 'observe'
                    progress('回调端口已占用；正在准备兼容授权入口…')
                    if mode == 'cli':
                        for _ in range(8):
                            self.receiver = LoopbackCallback(self.provider, port=0)
                            if self.rpc('probe_port', session_id=self.identifier, provider=self.provider, callback_port=self.receiver.port).get('available'):
                                break
                            self.receiver.close()
                        else:
                            raise ManagerError('未找到两端都可用的回调端口，未抢占任何已有程序。')
                    elif mode == 'observe':
                        chrome_callback_urls(OAUTH_PROVIDERS[self.provider]['redirect_host'], number, PROVIDERS[self.provider][1])
                        self.receiver = LoopbackCallback(self.provider, port=number, listen=False)
                        observing = True
            port = self.receiver.port if self.receiver else 0
            submitted = True  # A lost SSH response may still have created the remote session.
            data = self.rpc('start', session_id=self.identifier, provider=self.provider, mode=mode, callback_port=port)
            deadline = time.monotonic() + (880 if mode in {'device', 'api-device'} else 280)
            opened = False
            forwarded = False
            while time.monotonic() < deadline:
                if self.cancel_event.is_set():
                    raise WaitingStopped('授权已取消；正在结束本次服务器授权会话。')
                phase = data.get('phase')
                if data.get('cleanup_failed'):
                    raise ManagerError(data.get('message') or '服务器临时授权资源清理失败，请核对后重试。')
                if phase == 'succeeded':
                    if not opened or (self.receiver and not forwarded) or not data.get('recognized'):
                        raise ManagerError('服务器返回的授权完成证据不一致，请在后台核对。')
                    succeeded = True
                    return {'provider': self.provider, 'recognized': True}
                if phase in {'failed', 'expired', 'cancelled'}:
                    raise ManagerError(data.get('message') or '本次授权未完成，请重新发起。')
                if not opened and phase == 'ready':
                    validate_authorization(self.provider, data, port)
                    if self.receiver:
                        self.receiver.arm(data.get('state'))
                    ready({key: data.get(key, '') for key in ['url', 'user_code', 'mode']})
                    opened = True
                    progress('请在官方网页完成登录；回调会自动转交当前服务器。')
                if observing and opened and not forwarded:
                    for url in chrome_callback_urls(OAUTH_PROVIDERS[self.provider]['redirect_host'], port, self.receiver.path):
                        parsed = urlsplit(url)
                        self.receiver.accept(parsed.path + '?' + parsed.query, parsed.netloc)
                if self.receiver and opened and not forwarded and self.receiver.event.is_set():
                    payload = self.receiver.payload
                    if payload is None:
                        raise WaitingStopped('授权已取消。')
                    data = self.rpc('callback', session_id=self.identifier, provider=self.provider, **payload)
                    forwarded = True
                    self.receiver.close()
                    progress('回调已转交；正在核验服务器保存和识别授权…')
                if self.cancel_event.wait(1):
                    continue
                data = self.rpc('status', session_id=self.identifier, provider=self.provider)
            raise ManagerError('授权等待超时；本机接收器已关闭，请重新发起登录。')
        finally:
            try:
                if self.receiver:
                    self.receiver.close()
                if submitted and not succeeded:
                    self.cleanup_pending = True
                    try:
                        result = self.rpc('cancel', session_id=self.identifier, provider=self.provider)
                        self.cleanup_pending = bool(result.get('cancel_unconfirmed') or result.get('cleanup_failed'))
                    except ManagerError:
                        pass  # Preserve the original failure instead of hiding it with cleanup errors.
                    if self.cleanup_pending:
                        progress('本机授权已结束；关闭旧授权页后可重新登录，程序会先重试服务器清理。')
            finally:
                self.finished.set()
