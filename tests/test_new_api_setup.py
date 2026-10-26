"""Uses isolated Codex homes, disposable TLS keys, and synthetic login records."""
import base64
import contextlib
import datetime
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("new_api_setup", ROOT / "tools/new_api_setup.py")
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)
KEY = "fixture-only-not-a-real-api-key"


class Gateway:
    def __init__(self, root, mirror=None):
        executable = shutil.which("openssl")
        if not executable and os.name == "nt":
            possible = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
            executable = str(possible) if possible.is_file() else None
        if not executable:
            raise RuntimeError("test_requires_openssl")
        self.cert = root / "test-cert.pem"
        key = root / "test-key.pem"
        configuration = root / "cert.conf"
        configuration.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=New API Fixture Root CA\n[ext]\nbasicConstraints=critical,CA:TRUE\nsubjectKeyIdentifier=hash\nkeyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n")
        result = subprocess.run([executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
            "-config", str(configuration), "-keyout", str(key), "-out", str(self.cert)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError("test_certificate_generation_failed")
        # rustls correctly rejects a CA certificate used as the server leaf.
        # Sign a separate CA:FALSE leaf instead of relying on OpenSSL's tolerance.
        ca_key = root / "ca-private.pem"
        key.replace(ca_key)
        csr, leaf = root / "server.csr", root / "server-cert.pem"
        leaf_configuration = root / "leaf.conf"
        leaf_configuration.write_text("[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        for args in [["req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", str(configuration), "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr)],
                     ["x509", "-req", "-in", str(csr), "-CA", str(self.cert), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(leaf_configuration), "-extensions", "ext", "-out", str(leaf)]]:
            process = subprocess.run([executable, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if process.returncode:raise RuntimeError("test_leaf_certificate_failed")
        if os.name != "nt":
            key.chmod(0o600)
        self.requests = []
        self.downloads = []
        self.reject = False
        self.missing_model = False
        gateway = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args):
                pass
            def reply(self, value, status=200, content_type="application/json"):
                content = value.encode() if isinstance(value, str) else json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content)
            def allowed(self):
                return not gateway.reject and self.headers.get("Authorization") == "Bearer " + KEY
            def do_GET(self):
                if mirror is not None and self.path.startswith('/client-setup/'):
                    import urllib.parse
                    relative = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path[len('/client-setup/'):])
                    path = (mirror / relative).resolve()
                    if not path.is_relative_to(mirror.resolve()) or not path.is_file():
                        return self.reply({'error': 'missing_fixture_asset'}, 404)
                    gateway.downloads.append(relative)
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8' if path.suffix in ('.sh', '.ps1', '.py') else 'application/octet-stream')
                    self.send_header('Content-Length', str(path.stat().st_size))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    with path.open('rb') as stream:
                        try:
                            shutil.copyfileobj(stream, self.wfile, 1024 * 1024)
                        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                            pass
                    return
                if not self.allowed():
                    return self.reply({"error": {"message": "fixture rejected"}}, 401)
                models = ["gemini-3.8-flash-high"] if gateway.missing_model else ["gpt-6.1-sol", "gemini-3.8-flash-high", "gpt-image-2"]
                self.reply({"data": [{"id": item} for item in models]})
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                gateway.requests.append({"path": self.path, "correct_auth": self.headers.get("Authorization") == "Bearer " + KEY})
                if not self.allowed():
                    return self.reply({"error": {"message": "fixture rejected"}}, 401)
                response = {"id": "resp_fixture_" + str(time.time_ns()), "object": "response", "created_at": int(time.time()),
                    "status": "completed", "model": "gpt-6.1-sol", "output": [{"id": "msg_fixture", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "NEWAPI_OK", "annotations": []}]}],
                    "usage": {"input_tokens": 123, "input_tokens_details": {"cached_tokens": 23}, "output_tokens": 3, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 126}}
                if not body.get("stream"):
                    return self.reply(response)
                item = response["output"][0]
                events = [
                    {"type": "response.created", "response": dict(response, status="in_progress", output=[])},
                    {"type": "response.output_item.added", "output_index": 0, "item": dict(item, status="in_progress", content=[])},
                    {"type": "response.content_part.added", "output_index": 0, "item_id": item["id"], "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}},
                    {"type": "response.output_text.delta", "output_index": 0, "item_id": item["id"], "content_index": 0, "delta": "NEWAPI_OK"},
                    {"type": "response.output_text.done", "output_index": 0, "item_id": item["id"], "content_index": 0, "text": "NEWAPI_OK"},
                    {"type": "response.output_item.done", "output_index": 0, "item": item},
                    {"type": "response.completed", "response": response}]
                data = "".join("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n" for event in events)
                self.reply(data, content_type="text/event-stream")
        self.server = http.server.ThreadingHTTPServer(("localhost", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(leaf, key)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "https://localhost:" + str(self.server.server_address[1]) + "/v1"
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def login_fixture(kind):
    if kind == "api":
        return {"auth_mode": "apikey", "OPENAI_API_KEY": "fixture-old-openai-key"}
    if kind == "chatgpt":
        def b64(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
        jwt = b64({"alg": "none", "typ": "JWT"}) + "." + b64({"exp": 4102444800, "email": "fixture@example.invalid", "https://api.openai.com/auth": {"chatgpt_account_id": "fixture-account", "chatgpt_plan_type": "plus"}}) + ".fixture"
        return {"auth_mode": "chatgpt", "tokens": {"access_token": jwt, "id_token": jwt, "refresh_token": "fixture-refresh", "account_id": "fixture-account"}, "last_refresh": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    return None


class NewApiSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.local_proxy = mock.patch.dict(os.environ, {"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1"})
        cls.local_proxy.start()
        cls.temp = tempfile.TemporaryDirectory(prefix="newapi-tests-")
        cls.root = Path(cls.temp.name).resolve()
        cls.gateway = Gateway(cls.root)
        cls.command = setup.discover_codex()
    @classmethod
    def tearDownClass(cls):
        cls.gateway.close()
        cls.temp.cleanup()
        cls.local_proxy.stop()
    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.root)
        self.home = Path(self.case.name).resolve()
    def tearDown(self):
        self.case.cleanup()
    def configure(self):
        try:
            return setup.configure(self.home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
        except setup.SetupError as error:
            context = error.__context__
            reason = getattr(context, "reason", context)
            detail = (type(context).__name__, type(reason).__name__, getattr(reason, "verify_code", None),
                getattr(reason, "verify_message", None), getattr(reason, "errno", None))
            raise AssertionError("isolated_fixture_failure:" + str(detail)) from None
    def verify_cli(self):
        env = dict(os.environ)
        env.update(CODEX_HOME=str(self.home), SSL_CERT_FILE=str(self.gateway.cert), CODEX_CA_CERTIFICATE=str(self.gateway.cert), OPENAI_API_KEY="fixture-wrong-env-key")
        env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1,::1"
        work = self.home / "work"
        work.mkdir(exist_ok=True)
        args = self.command + ["exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "-C", str(work),
            "-c", 'web_search="disabled"', "-c", 'model_reasoning_effort="low"',
            "-c", "features.plugins=false",
            "-c", "model_providers.newapi_gateway.request_max_retries=0", "-c", "model_providers.newapi_gateway.stream_max_retries=0",
            "Reply only NEWAPI_OK. Do not use tools."]
        run = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        events = []
        for line in run.stdout.decode("utf-8", "replace").splitlines():
            try:events.append(json.loads(line))
            except ValueError:pass
        # Errors are never dumped: they can contain auth/config content.
        self.assertEqual(run.returncode, 0, "codex_fixture_inference_failed")
        self.assertTrue(any(e.get("type") == "turn.completed" for e in events), "codex_turn_not_completed")
        self.assertTrue(any(e.get("item", {}).get("text", "").strip() == "NEWAPI_OK" for e in events), "codex_fixture_answer_missing")
        self.assertTrue(self.gateway.requests[-1]["correct_auth"], "wrong_credential_selected")
    def test_fresh_and_existing_login_matrix(self):
        for existing in [False, True]:
            for login in ["none", "chatgpt", "api"]:
                with self.subTest(existing=existing, login=login):
                    home = self.home / (str(existing) + "-" + login)
                    home.mkdir()
                    before = None
                    if existing:
                        before = '# keep comment\nmodel="old"\nmodel_provider="old"\nmodel_reasoning_effort="high"\ncli_auth_credentials_store="file"\n[model_providers.old]\nname="Old"\nbase_url="https://old.example.invalid/v1"\n[plugins."fixture@local"]\nenabled=false\n'
                        (home / "config.toml").write_text(before)
                    state = login_fixture(login)
                    auth = home / "auth.json"
                    if state:
                        auth.write_text(json.dumps(state))
                    old_auth = auth.read_bytes() if auth.exists() else None
                    with mock.patch.object(self, "home", home):
                        self.configure()
                        got = tomllib.loads((home / "config.toml").read_text())
                        self.assertEqual(got["model_provider"], setup.PROVIDER)
                        if before:
                            parsed = tomllib.loads(before)
                            self.assertEqual(got["plugins"], parsed["plugins"])
                            self.assertEqual(got["model_providers"]["old"], parsed["model_providers"]["old"])
                            self.assertEqual(got["model_reasoning_effort"], "high")
                            self.assertIn("# keep comment", (home / "config.toml").read_text())
                        self.verify_cli()
                        self.assertEqual(auth.read_bytes() if auth.exists() else None, old_auth)
    def test_rejected_key_missing_model_tls_and_redirect_do_not_write(self):
        for mode in ["reject", "missing_model", "untrusted_tls"]:
            with self.subTest(mode=mode):
                self.gateway.reject = mode == "reject"
                self.gateway.missing_model = mode == "missing_model"
                try:
                    with self.assertRaises(setup.SetupError):
                        setup.configure(self.home, self.command, self.gateway.base, KEY, None if mode == "untrusted_tls" else str(self.gateway.cert))
                    self.assertFalse((self.home / "config.toml").exists())
                finally:
                    self.gateway.reject = self.gateway.missing_model = False
        self.assertIsNone(setup.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid"))
    def test_backup_restore_and_later_edits(self):
        original = 'model="previous"\n'
        target = self.home / "config.toml"
        target.write_text(original)
        result = self.configure()
        backup = self.home / "newapi-backups" / result["backup_id"]
        self.assertEqual((backup / "original").read_text(), original)
        configured = target.read_bytes()
        target.write_bytes(configured + b"\n# edited\n")
        with self.assertRaises(setup.SetupError):setup.restore(self.home)
        target.write_bytes(configured)
        setup.restore(self.home)
        self.assertEqual(target.read_text(), original)
    @unittest.skipIf(os.name == "nt", "Windows ACL case is separate")
    def test_nonroot_permissions_and_readonly_directory(self):
        self.assertNotEqual(os.geteuid(), 0, "run tests as ordinary user")
        self.configure()
        target = self.home / "config.toml"
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        readonly = self.home / "readonly"
        readonly.mkdir()
        readonly.chmod(0o500)
        try:
            with self.assertRaises(setup.SetupError):setup.preflight(readonly)
        finally:readonly.chmod(0o700)
    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_windows_acl_has_only_current_user_and_no_inheritance(self):
        self.configure()
        target = self.home / "config.toml"
        encoded = base64.b64encode(str(target).encode()).decode()
        script = "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));$a=Get-Acl -LiteralPath $p;$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;@{protected=$a.AreAccessRulesProtected;only_user=(@($a.Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $s}).Count -eq 0)}|ConvertTo-Json -Compress"
        result = setup.powershell(script)
        data = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertTrue(data["protected"] and data["only_user"])
        target.chmod(stat.S_IREAD)
        try:
            with self.assertRaises(setup.SetupError):setup.preflight(self.home)
        finally:target.chmod(stat.S_IREAD | stat.S_IWRITE)
    def test_url_rejections_and_symlink_are_non_destructive(self):
        for value in ["http://gateway.invalid", "https://u:p@gateway.invalid", "https://gateway.invalid/keys", "https://gateway.invalid/?key=bad"]:
            with self.assertRaises(setup.SetupError):setup.normalize_url(value)
        if os.name != "nt":
            original = self.home / "original"
            original.write_text("keep")
            (self.home / "config.toml").symlink_to(original)
            with self.assertRaises(setup.SetupError):setup.preflight(self.home)
            self.assertEqual(original.read_text(), "keep")
    def test_cancel_does_not_configure(self):
        with mock.patch.object(setup, "config_home", return_value=self.home), mock.patch.object(setup, "discover_codex", return_value=self.command), mock.patch.object(setup, "prompt_terminal", side_effect=setup.Cancelled()), mock.patch.object(sys, "argv", ["setup", "--terminal"]):
            with self.assertRaises(setup.Cancelled):setup.main()
        self.assertFalse((self.home / "config.toml").exists())
    def test_old_cli_stops_without_upgrading_or_writing(self):
        reply = subprocess.CompletedProcess([], 0, stdout=b"codex-cli 0.100.0\n", stderr=b"")
        with mock.patch.object(subprocess, "run", return_value=reply):
            with self.assertRaisesRegex(setup.SetupError, "版本过旧"):
                setup.discover_codex()
        self.assertFalse((self.home / "config.toml").exists())
    def test_policy_override_rolls_back_instead_of_claiming_success(self):
        target = self.home / "config.toml"
        original = b'# retained\nmodel="previous"\n'
        target.write_bytes(original)
        class PolicyRpc:
            def __init__(self, *args):pass
            def close(self):pass
            def call(self, method, params):
                if method == "config/read":return {"layers": []}
                target.write_bytes(b'model="gpt-6.1-sol"\n')
                return {"status": "okOverridden"}
        with mock.patch.object(setup, "Rpc", PolicyRpc):
            with self.assertRaisesRegex(setup.SetupError, "管理策略"):
                setup.configure(self.home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
        self.assertEqual(target.read_bytes(), original)

    def test_lost_write_reply_rolls_back_existing_and_fresh_config(self):
        real_rpc = setup.Rpc
        for existing in (False, True):
            with self.subTest(existing=existing):
                home = self.home / str(existing)
                home.mkdir()
                target = home / 'config.toml'
                original = b'# keep comment\nmodel="previous"\n' if existing else None
                if original is not None:
                    target.write_bytes(original)
                    if os.name != 'nt':
                        target.chmod(0o640)
                class LostReplyRpc(real_rpc):
                    def call(self, method, params):
                        result = super().call(method, params)
                        if method == 'config/batchWrite':
                            raise setup.SetupError('simulated_reply_lost_after_commit')
                        return result
                with mock.patch.object(setup, 'Rpc', LostReplyRpc):
                    with self.assertRaisesRegex(setup.SetupError, 'simulated_reply_lost'):
                        setup.configure(home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
                self.assertEqual(target.read_bytes() if target.exists() else None, original)
                if original is not None and os.name != 'nt':
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                states = list((home / 'newapi-backups').glob('*/state.json'))
                self.assertEqual(len(states), 1)
                self.assertTrue(json.loads(states[0].read_bytes())['restored'])

    def test_lost_reply_does_not_hide_previous_successful_backup(self):
        target = self.home / 'config.toml'
        original = b'model="original"\n'
        target.write_bytes(original)
        self.configure()
        configured = target.read_bytes()
        real_rpc = setup.Rpc
        class LostReplyRpc(real_rpc):
            def call(self, method, params):
                result = super().call(method, params)
                if method == 'config/batchWrite':
                    raise setup.SetupError('simulated_reply_lost_after_commit')
                return result
        with mock.patch.object(setup, 'Rpc', LostReplyRpc):
            with self.assertRaises(setup.SetupError):
                setup.configure(self.home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
        self.assertEqual(target.read_bytes(), configured)
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), original)

    def test_failed_rollback_after_lost_reply_leaves_restorable_backup(self):
        target = self.home / 'config.toml'
        original = b'model="previous"\n'
        target.write_bytes(original)
        real_rpc, real_write = setup.Rpc, setup.private_write
        class LostReplyRpc(real_rpc):
            def call(self, method, params):
                result = super().call(method, params)
                if method == 'config/batchWrite':
                    raise setup.SetupError('simulated_reply_lost_after_commit')
                return result
        def fail_rollback(path, content):
            if path == target:
                raise OSError('simulated_rollback_write_failure')
            return real_write(path, content)
        with mock.patch.object(setup, 'Rpc', LostReplyRpc), mock.patch.object(setup, 'private_write', side_effect=fail_rollback):
            with self.assertRaises(OSError):
                setup.configure(self.home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
        self.assertNotEqual(target.read_bytes(), original)
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), original)

    def test_lost_reply_does_not_overwrite_concurrent_config_changes(self):
        target = self.home / 'config.toml'
        real_rpc = setup.Rpc
        edited = None
        class ConcurrentEditRpc(real_rpc):
            def call(self, method, params):
                nonlocal edited
                result = super().call(method, params)
                if method == 'config/batchWrite':
                    edited = 'model_reasoning_effort="low"\n' + target.read_text()
                    target.write_text(edited)
                    raise setup.SetupError('simulated_reply_lost_after_external_edit')
                return result
        with mock.patch.object(setup, 'Rpc', ConcurrentEditRpc):
            with self.assertRaises(setup.SetupError):
                setup.configure(self.home, self.command, self.gateway.base, KEY, str(self.gateway.cert))
        self.assertEqual(target.read_text(), edited)

    def test_same_second_backups_restore_by_creation_time_including_legacy_records(self):
        target = self.home / 'config.toml'
        original = b'model="original"\n'
        target.write_bytes(original)
        with mock.patch.object(setup.os, 'urandom', side_effect=[b'\xff' * 4, b'\x00' * 4]):
            first = self.configure()
            first_config = target.read_bytes()
            second = self.configure()
        parent = self.home / 'newapi-backups'
        first_dir, second_dir = parent / first['backup_id'], parent / second['backup_id']
        first_dir.rename(parent / '20261025-120000-ffffffff')
        second_dir.rename(parent / '20261025-120000-00000000')
        for index, suffix in enumerate(('ffffffff', '00000000'), 1):
            directory = parent / ('20261025-120000-' + suffix)
            state = json.loads((directory / 'state.json').read_bytes())
            state.pop('created_ns')
            setup.private_write(directory / 'state.json', json.dumps(state).encode())
            timestamp = 1_700_000_000_000_000_000 + index * 1_000_000_000
            os.utime(directory, ns=(timestamp, timestamp))
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), first_config)
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), original)

    def test_new_backup_order_does_not_depend_on_random_suffix_or_directory_mtime(self):
        target = self.home / 'config.toml'
        original = b'model="original"\n'
        target.write_bytes(original)
        first = self.configure()
        first_config = target.read_bytes()
        self.configure()
        directory = self.home / 'newapi-backups' / first['backup_id']
        future = 4_000_000_000_000_000_000
        os.utime(directory, ns=(future, future))
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), first_config)
        setup.restore(self.home)
        self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
