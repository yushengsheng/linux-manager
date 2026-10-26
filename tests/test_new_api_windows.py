"""Native PS 5.1 + real installed Codex, temporary homes and synthetic keys only."""
import base64
import hashlib
import gzip
import http.server
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/new_api_bootstrap.ps1').read_text(encoding='utf-8')
LIBRARY = SOURCE.split('# Entry point.', 1)[0]
KEY = 'fixture-only-windows-key'
CODEX = os.environ.get('NEWAPI_CODEX_BINARY') or shutil.which('codex.exe')
MODEL = 'gpt-6.1-sol'
MODELS = [MODEL, 'claude-sonnet-4-6', 'gemini-3.8-flash-high']
OLD = '''# preserve this comment
model="old"
model_provider="old"
model_reasoning_effort="high"
instructions=''' + "'''\nmodel=\"keep inside multiline string\"\n'''\n" + '''
[model_providers.old]
name="Old"
base_url="https://old.invalid/v1"
[plugins."fixture@local"]
enabled=false
'''


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell(body, env=None, timeout=45, shell='powershell.exe'):
    code = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();\n" + body
    loader = '& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))))'
    encoded = base64.b64encode(loader.encode('utf-16-le')).decode()
    environment = {k: v for k, v in (env or os.environ).items() if k.upper() != 'PSMODULEPATH'}
    return subprocess.run([shell, '-NoProfile', '-NonInteractive', '-STA', '-EncodedCommand', encoded],
                          input=base64.b64encode(code.encode('utf-8')), env=environment, capture_output=True, timeout=timeout)


@unittest.skipUnless(os.name == 'nt' and CODEX, 'requires Windows and installed Codex')
class WindowsConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codex = CODEX

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='newapi-windows-')
        self.home = Path(self.temporary.name) / "用户 空格'配置"
        self.home.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def run_ps(self, body, expect_success=True):
        prelude = f'$env:CODEX_HOME={ps_quote(self.home)};$env:NEWAPI_CODEX_BINARY={ps_quote(self.codex)};\n. {{\n' + LIBRARY + '\n}\n'
        result = powershell(prelude + 'try {\n' + body + '\n}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}')
        if expect_success:
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace')[-1500:])
        else:
            self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(KEY.encode(), result.stdout + result.stderr)
        return result

    def configure_code(self, extra=''):
        models = ','.join(map(ps_quote, MODELS))
        return (f'$result=Set-NewApiConfiguration {ps_quote(self.home)} {ps_quote(self.codex)} '
                f"'https://fixture.invalid:2026/v1' '{KEY}' '{MODEL}' @({models})\n" + extra)

    def config(self):
        return tomllib.loads((self.home / 'config.toml').read_text(encoding='utf-8'))

    def test_fresh_existing_and_login_matrix_preserves_and_restores(self):
        for existing in (False, True):
            for login in ('none', 'chatgpt', 'api'):
                with self.subTest(existing=existing, login=login):
                    self.home = Path(self.temporary.name) / f'{existing}-{login}'
                    self.home.mkdir()
                    if existing:
                        (self.home / 'config.toml').write_bytes(OLD.encode())
                    auth = self.home / 'auth.json'
                    auth_bytes = None
                    if login != 'none':
                        auth_bytes = json.dumps({'auth_mode': login, 'fixture': 'keep-old-login'}).encode()
                        auth.write_bytes(auth_bytes)
                    self.run_ps(self.configure_code())
                    config = self.config()
                    self.assertEqual(config['model'], MODEL)
                    self.assertEqual(config['model_providers']['newapi_gateway']['experimental_bearer_token'], KEY)
                    self.assertFalse(config['model_providers']['newapi_gateway']['requires_openai_auth'])
                    catalog = json.loads(Path(config['model_catalog_json']).read_text())
                    self.assertEqual([r['slug'] for r in catalog['models']], MODELS)
                    if existing:
                        old = tomllib.loads(OLD)
                        self.assertEqual(config['model_providers']['old'], old['model_providers']['old'])
                        self.assertEqual(config['instructions'], old['instructions'])
                        self.assertEqual(config['plugins'], old['plugins'])
                        self.assertIn('# preserve this comment', (self.home / 'config.toml').read_text())
                    self.assertEqual(auth.read_bytes() if auth.exists() else None, auth_bytes)
                    self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
                    if existing:
                        self.assertEqual((self.home / 'config.toml').read_bytes(), OLD.encode())
                    else:
                        self.assertFalse((self.home / 'config.toml').exists())
                    self.assertEqual(auth.read_bytes() if auth.exists() else None, auth_bytes)

    def test_reconfiguration_and_lifo_restore(self):
        (self.home / 'config.toml').write_bytes(OLD.encode())
        self.run_ps(self.configure_code())
        first = (self.home / 'config.toml').read_bytes()
        self.run_ps(self.configure_code())
        self.assertEqual(len(list((self.home / 'newapi-backups').iterdir())), 2)
        self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
        self.assertEqual((self.home / 'config.toml').read_bytes(), first)
        self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
        self.assertEqual((self.home / 'config.toml').read_bytes(), OLD.encode())

    def test_same_second_backups_restore_by_creation_time_including_legacy_records(self):
        root = self.home
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                self.home = root / str(legacy)
                self.home.mkdir()
                target = self.home / 'config.toml'
                target.write_bytes(OLD.encode())
                self.run_ps(self.configure_code())
                first = target.read_bytes()
                original_directories = set((self.home / 'newapi-backups').iterdir())
                self.run_ps(self.configure_code())
                parent = self.home / 'newapi-backups'
                earlier = original_directories.pop()
                later = (set(parent.iterdir()) - {earlier}).pop()
                for index, (directory, suffix) in enumerate(((earlier, 'ffffffff'), (later, '00000000')), 1):
                    renamed = parent / ('20261026-120000-' + suffix)
                    directory.rename(renamed)
                    state = json.loads((renamed / 'state.json').read_text())
                    timestamp = 1_700_000_000_000_000_000 + index * 1_000_000_000
                    if legacy:
                        state.pop('created_ns')
                    else:
                        state['created_ns'] = timestamp
                    (renamed / 'state.json').write_text(json.dumps(state))
                    os.utime(renamed, ns=(timestamp, timestamp))
                self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
                self.assertEqual(target.read_bytes(), first)
                self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
                self.assertEqual(target.read_bytes(), OLD.encode())

    def test_empty_and_crlf_original_files_restore_exact_bytes(self):
        target = self.home / 'config.toml'
        for original in (b'', OLD.replace('\n', '\r\n').encode()):
            with self.subTest(length=len(original)):
                target.write_bytes(original)
                self.run_ps(self.configure_code())
                self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
                self.assertEqual(target.read_bytes(), original)

    def test_later_edits_block_restore(self):
        self.run_ps(self.configure_code())
        target = self.home / 'config.toml'
        content = target.read_bytes() + b'\n# external change\n'
        target.write_bytes(content)
        self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}', expect_success=False)
        self.assertEqual(target.read_bytes(), content)

    def test_invalid_existing_toml_is_not_overwritten(self):
        target = self.home / 'config.toml'
        target.write_bytes(b'[[[invalid')
        self.run_ps(self.configure_code(), expect_success=False)
        self.assertEqual(target.read_bytes(), b'[[[invalid')
        self.assertFalse((self.home / 'newapi-backups').exists())

    def test_prepare_only_uses_installed_cli_without_runtime_or_connection_changes(self):
        env = dict(os.environ, CODEX_HOME=str(self.home), NEWAPI_CODEX_BINARY=self.codex)
        result = powershell('& {\n' + SOURCE + '\n} -PrepareOnly', env=env)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace')[-1000:])
        self.assertFalse((self.home / 'config.toml').exists())
        self.assertFalse((self.home / 'auth.json').exists())
        self.assertFalse((self.home / 'newapi-runtime').exists())

    def test_url_normalization_and_rejection(self):
        code = "foreach($p in @('','/v1','/keys','/keys/')){if((Get-NewApiBase ('https://fixture.invalid:2026'+$p)) -ne 'https://fixture.invalid:2026/v1'){throw 'url_normalization_failed'}}\n"
        code += "foreach($u in @('http://fixture.invalid','https://u:p@fixture.invalid','https://fixture.invalid/?key=x','https://fixture.invalid/admin')){$bad=$false;try{[void](Get-NewApiBase $u)}catch{$bad=$true};if(!$bad){throw 'unsafe_url_allowed'}}"
        self.run_ps(code)

    def test_parser_and_native_only_source(self):
        self.run_ps('$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput(' + ps_quote(SOURCE) + ',[ref]$tokens,[ref]$errors);if($errors){throw "parse_error"}')
        self.assertNotIn('python install', SOURCE)
        self.assertNotIn('Invoke-WebRequest', SOURCE)
        self.assertNotIn('DownloadFile', SOURCE)

    def test_embedded_command_matches_source_and_needs_no_bootstrap_download(self):
        from tools.build_new_api_guide import windows_native_command
        for options in ({}, {'restore': True}, {'prepare_only': True}):
            command = windows_native_command(**options)
            payload = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
            self.assertEqual(gzip.decompress(base64.b64decode(payload)), SOURCE.encode())
            self.assertNotIn('Invoke-RestMethod', command)
        environment = dict(os.environ, CODEX_HOME=str(self.home), NEWAPI_CODEX_BINARY=self.codex)
        result = powershell(windows_native_command(prepare_only=True), env=environment)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace')[-1000:])
        self.assertFalse((self.home / 'config.toml').exists())

    def test_lost_write_reply_rolls_back_only_exact_owned_content(self):
        target = self.home / 'config.toml'
        target.write_bytes(OLD.encode())
        wrapper = '$realRpc=${function:Invoke-NewApiRpc}\nfunction Invoke-NewApiRpc($Rpc,$Method,$Params){$r=& $realRpc $Rpc $Method $Params;'
        wrapper += "if($Method -eq 'config/batchWrite' -and $Params.filePath -eq " + ps_quote(target) + "){throw 'fixture_lost_reply'};return $r}\n"
        self.run_ps(wrapper + self.configure_code(), expect_success=False)
        self.assertEqual(target.read_bytes(), OLD.encode())
        state = json.loads(next((self.home / 'newapi-backups').glob('*/state.json')).read_text())
        self.assertTrue(state['restored'])
        self.assertFalse(list((self.home / 'newapi-backups').glob('*/.preview.*')))

    def test_lost_reply_preserves_concurrent_comment_edits(self):
        target = self.home / 'config.toml'
        target.write_bytes(OLD.encode())
        wrapper = '$realRpc=${function:Invoke-NewApiRpc}\nfunction Invoke-NewApiRpc($Rpc,$Method,$Params){$r=& $realRpc $Rpc $Method $Params;'
        wrapper += "if($Method -eq 'config/batchWrite' -and $Params.filePath -eq " + ps_quote(target) + "){[IO.File]::AppendAllText($Params.filePath,\"`n# concurrent edit\");throw 'fixture_lost_reply'};return $r}\n"
        self.run_ps(wrapper + self.configure_code(), expect_success=False)
        self.assertIn(b'# concurrent edit', target.read_bytes())
        self.assertEqual(self.config()['model'], MODEL)
        backup = next((self.home / 'newapi-backups').glob('*/original'))
        self.assertEqual(backup.read_bytes(), OLD.encode())

    def test_change_between_read_and_commit_blocks_write(self):
        target = self.home / 'config.toml'
        target.write_bytes(OLD.encode())
        wrapper = '$realRpc=${function:Invoke-NewApiRpc};$script:changed=$false\nfunction Invoke-NewApiRpc($Rpc,$Method,$Params){$r=& $realRpc $Rpc $Method $Params;'
        wrapper += "if(!$script:changed -and $Method -eq 'config/read' -and $Rpc.process.StartInfo.WorkingDirectory -eq " + ps_quote(self.home) + "){$script:changed=$true;[IO.File]::AppendAllText(" + ps_quote(target) + ",\"`n# external change\")};return $r}\n"
        self.run_ps(wrapper + self.configure_code(), expect_success=False)
        self.assertEqual(target.read_bytes(), OLD.encode() + b'\n# external change')

    def test_corrupt_original_backup_blocks_restore(self):
        (self.home / 'config.toml').write_bytes(OLD.encode())
        self.run_ps(self.configure_code())
        current = (self.home / 'config.toml').read_bytes()
        next((self.home / 'newapi-backups').glob('*/original')).write_bytes(b'corrupt')
        self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}', expect_success=False)
        self.assertEqual((self.home / 'config.toml').read_bytes(), current)

    def test_old_python_backup_format_can_be_restored(self):
        target = self.home / 'config.toml';target.write_bytes(b'model="configured"\n')
        backup = self.home / 'newapi-backups/20261025-120000-aaaaaaaa';backup.mkdir(parents=True)
        (backup / 'original').write_bytes(OLD.encode())
        (backup / 'state.json').write_text(json.dumps({'existed': True, 'mode': 384, 'installed_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}))
        self.run_ps(f'Restore-NewApiConfiguration {ps_quote(self.home)}')
        self.assertEqual(target.read_bytes(), OLD.encode())

    def test_catalog_reuses_only_exact_model_metadata_and_acl_is_private(self):
        (self.home / 'models_cache.json').write_text(json.dumps({'models': [{'slug': MODEL, 'context_window': 262144, 'input_modalities': ['text', 'image']}, {'slug': MODEL.upper(), 'context_window': 1048576}]}))
        checks = "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;foreach($p in @((Join-Path $env:CODEX_HOME 'config.toml'),(Join-Path $env:CODEX_HOME 'newapi-backups'))){$a=Get-Acl -LiteralPath $p;foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.IdentityReference.Value -ne $sid -or $r.IsInherited){throw 'broad_acl'}}}"
        self.run_ps(self.configure_code(checks))
        catalog = json.loads(Path(self.config()['model_catalog_json']).read_text())['models']
        self.assertEqual(catalog[0]['context_window'], 262144)
        self.assertEqual(catalog[1]['context_window'], 32768)
        self.assertEqual(catalog[1]['supported_reasoning_levels'], [])
        for state in (self.home / 'newapi-backups').glob('*/state.json'):
            self.assertNotIn(KEY, state.read_text())

    def test_codex_model_list_reads_generated_gateway_catalog(self):
        code = f"$rpc=New-NewApiRpc {ps_quote(self.codex)} {ps_quote(self.home)};try{{$list=Invoke-NewApiRpc $rpc 'model/list' @{{includeHidden=$true;limit=100}};[Console]::WriteLine(($list.data.model|ConvertTo-Json -Compress))}}finally{{Stop-NewApiRpc $rpc}}"
        result = self.run_ps(self.configure_code(code))
        self.assertEqual(set(json.loads(result.stdout.decode('utf-8'))), set(MODELS))

    def test_official_user_installer_layouts_are_discovered_without_path(self):
        for index, layout in enumerate(('OpenAI/Codex/bin/version-fixture/codex.exe', 'Programs/OpenAI/Codex/bin/codex.exe', 'Programs/Codex/resources/codex.exe')):
            with self.subTest(layout=layout):
                local = self.home / str(index)
                target = local / layout;target.parent.mkdir(parents=True)
                target.write_bytes(b'fixture-placeholder')
                code = f"$env:NEWAPI_CODEX_BINARY=$null;$env:LOCALAPPDATA={ps_quote(local)};function Get-Command {{}};function Invoke-NewApiProcess {{'codex-cli 0.164.0'}};if((Find-NewApiCodex) -ne {ps_quote(target)}){{throw 'installer_layout_not_found'}}"
                self.run_ps(code)

    def test_store_installation_is_discovered_without_path(self):
        package = self.home / 'store-app';target = package / 'app/resources/codex.exe'
        target.parent.mkdir(parents=True);target.write_bytes(b'fixture-placeholder')
        code = "$env:NEWAPI_CODEX_BINARY=$null;$env:LOCALAPPDATA=" + ps_quote(self.home / 'empty-local') + ";function Invoke-NewApiProcess {'codex-cli 0.164.0'};function Get-Command($Name){if($Name -eq 'Get-AppxPackage'){return $true}};function Get-AppxPackage{[pscustomobject]@{InstallLocation=" + ps_quote(package) + "}};if((Find-NewApiCodex) -ne " + ps_quote(target) + "){throw 'store_layout_not_found'}"
        self.run_ps(code)

    @unittest.skipUnless(shutil.which('pwsh.exe'), 'PowerShell 7 not installed')
    def test_powershell_7_can_configure_and_restore(self):
        body = '. {\n' + LIBRARY + '\n}\ntry {\n' + self.configure_code() + f'\nRestore-NewApiConfiguration {ps_quote(self.home)}' + '\n}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}'
        result = powershell(body, shell=shutil.which('pwsh.exe'))
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace')[-1000:])
        self.assertFalse((self.home / 'config.toml').exists())

    def test_real_codex_uses_gateway_key_with_existing_api_login(self):
        from tests.test_new_api_setup import Gateway, login_fixture, KEY as GATEWAY_KEY
        gateway = Gateway(Path(self.temporary.name))
        try:
            auth = self.home / 'auth.json';auth.write_text(json.dumps(login_fixture('api')))
            original_auth = auth.read_bytes()
            code = f"$result=Set-NewApiConfiguration {ps_quote(self.home)} {ps_quote(self.codex)} {ps_quote(gateway.base)} '{GATEWAY_KEY}' '{MODEL}' @('{MODEL}')"
            self.run_ps(code)
            work = self.home / 'work';work.mkdir()
            env = dict(os.environ, CODEX_HOME=str(self.home), SSL_CERT_FILE=str(gateway.cert), CODEX_CA_CERTIFICATE=str(gateway.cert),
                       OPENAI_API_KEY='fixture-wrong-env-key', NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1')
            args = [self.codex, 'exec', '--ephemeral', '--skip-git-repo-check', '--sandbox', 'read-only', '--json', '-C', str(work),
                    '-c', 'web_search="disabled"', '-c', 'features.plugins=false', '-c', 'analytics.enabled=false',
                    '-c', 'model_providers.newapi_gateway.request_max_retries=0', '-c', 'model_providers.newapi_gateway.stream_max_retries=0',
                    'Reply only NEWAPI_OK. Do not use tools.']
            result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, 'isolated_codex_inference_failed')
            events = [json.loads(line) for line in result.stdout.decode('utf-8', 'replace').splitlines() if line.startswith('{')]
            self.assertTrue(any(e.get('item', {}).get('text', '').strip() == 'NEWAPI_OK' for e in events))
            self.assertTrue(gateway.requests and all(r['correct_auth'] for r in gateway.requests))
            self.assertEqual(auth.read_bytes(), original_auth)
        finally:
            gateway.close()


@unittest.skipUnless(os.name == 'nt', 'requires Windows PowerShell')
class WindowsGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reject = False;cls.redirect = False;cls.response_supported = True;cls.hits = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def send(self, body, status=200):
                data=json.dumps(body).encode();self.send_response(status)
                if status == 302:self.send_header('Location','/forbidden')
                self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def do_GET(self):
                cls.hits.append(self.path)
                if cls.reject or self.headers.get('Authorization') != 'Bearer ' + KEY:return self.send({},401)
                if cls.redirect:return self.send({},302)
                self.send({'data':[{'id':m} for m in MODELS+['gpt-image-2','gemini-3.1-flash-image','codex-auto-review','tts-1','',MODEL,MODEL.upper()]]})
            def do_POST(self):
                cls.hits.append(self.path)
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if not cls.response_supported:return self.send({},404)
                cls.request=body
                self.send({'object':'response','status':'completed','output':[]})
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)+'/v1'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=5)

    def setUp(self):
        type(self).reject=False;type(self).redirect=False;type(self).response_supported=True;self.hits.clear()

    def call(self, command):
        result=powershell('. {\n'+LIBRARY+'\n}\ntry{'+command+'}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}')
        self.assertNotIn(KEY.encode(),result.stdout+result.stderr)
        return result

    def test_live_model_list_is_filtered_deduplicated_and_responses_checked(self):
        result=self.call(f"$m=Get-NewApiModels '{self.base}' '{KEY}';[Console]::WriteLine(($m|ConvertTo-Json -Compress));Test-NewApiResponses '{self.base}' '{KEY}' '{MODEL}'")
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        self.assertEqual(json.loads(result.stdout.decode('utf-8').splitlines()[0]),sorted(MODELS+[MODEL.upper()]))
        self.assertEqual(self.request['model'],MODEL)
        self.assertFalse(self.request['store'])
        self.assertEqual(self.request['max_output_tokens'],32)

    def test_invalid_key_stops_without_echoing_key(self):
        type(self).reject=True
        result=self.call(f"Get-NewApiModels '{self.base}' '{KEY}'|Out-Null")
        self.assertNotEqual(result.returncode,0)

    def test_redirect_never_forwards_bearer_key(self):
        type(self).redirect=True
        result=self.call(f"Get-NewApiModels '{self.base}' '{KEY}'|Out-Null")
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('/forbidden',self.hits)

    def test_responses_missing_is_detected(self):
        type(self).response_supported=False
        result=self.call(f"Test-NewApiResponses '{self.base}' '{KEY}' '{MODEL}'")
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'HTTP 404',result.stderr)

    @unittest.skipUnless(CODEX, 'requires installed Codex')
    def test_complete_entry_checks_gateway_before_configuring(self):
        with tempfile.TemporaryDirectory(prefix='newapi-entry-') as folder:
            home=Path(folder)
            prefix,entry=SOURCE.split('# Entry point.',1)
            stubs=(f"\nfunction Find-NewApiCodex {{{ps_quote(CODEX)}}}\n"
                   f"function Get-NewApiBase {{{ps_quote(self.base)}}}\n"
                   f"function Read-NewApiConnection {{@{{origin='https://fixture.invalid';key='{KEY}'}}}}\n"
                   f"function Select-NewApiModel {{'{MODEL}'}}\n")
            result=powershell('$env:CODEX_HOME='+ps_quote(home)+'\n& {\n'+prefix+stubs+'\n# Entry point.'+entry+'\n}')
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace')[-1000:])
            self.assertEqual(tomllib.loads((home/'config.toml').read_text())['model'],MODEL)
            self.assertEqual(self.hits,['/v1/models','/v1/responses'])
            self.assertFalse((home/'auth.json').exists())
            self.assertFalse((home/'newapi-runtime').exists())
            self.assertNotIn(KEY.encode(),result.stdout+result.stderr)

    def test_entry_failure_keeps_interactive_host_alive_and_config_untouched(self):
        type(self).reject=True
        with tempfile.TemporaryDirectory(prefix='newapi-entry-error-') as folder:
            home=Path(folder);target=home/'config.toml';target.write_bytes(OLD.encode())
            prefix,entry=SOURCE.split('# Entry point.',1)
            stubs=("\nfunction Find-NewApiCodex {'unused-fixture'}\n"
                   f"function Get-NewApiBase {{{ps_quote(self.base)}}}\n"
                   f"function Read-NewApiConnection {{@{{origin='https://fixture.invalid';key='{KEY}'}}}}\n")
            code='$env:CODEX_HOME='+ps_quote(home)+'\ntry{& {\n'+prefix+stubs+'\n# Entry point.'+entry+'\n}}catch{};[Console]::WriteLine("HOST_STILL_RUNNING")'
            result=powershell(code)
            self.assertEqual(result.returncode,0)
            self.assertIn(b'HOST_STILL_RUNNING',result.stdout)
            self.assertNotIn(KEY.encode(),result.stdout+result.stderr)
            self.assertEqual(target.read_bytes(),OLD.encode())
            self.assertFalse((home/'newapi-backups').exists())


if __name__ == '__main__':
    unittest.main()
