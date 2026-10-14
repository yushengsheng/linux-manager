import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock
import urllib.error

from linux_manager.client_config import CLIENTS, PROVIDER, ClientConfigurator, gateway_connection, gateway_models, _NoRedirect
from linux_manager.models import ManagerError

BASE = "https://fixture.invalid:9229/v1"
KEY = "fixture-client-key"
MODEL = "gpt-fixture"


class ClientConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.configurator = ClientConfigurator(self.root / "backups", self.root / "home", {})

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, content, mode=0o640):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        path.chmod(mode)

    def configure(self, client, **kwargs):
        return self.configurator.configure(client, kwargs.get("base", BASE), kwargs.get("key", KEY),
                                           kwargs.get("model", MODEL), kwargs.get("models", [MODEL]))

    def test_mac_home_environment_and_saved_directories_with_spaces_and_quotes(self):
        home = self.root / "另一位用户 空格'中文"
        env = {'CODEX_HOME': '$HOME/GPT 配置', 'CLAUDE_CONFIG_DIR': '~/Claude 配置',
               'PI_CODING_AGENT_DIR': str(home / 'Pi 配置'), 'XDG_CONFIG_HOME': '${HOME}/自定义配置'}
        configurator = ClientConfigurator(self.root / 'custom-backups', home, env)
        self.assertEqual(configurator.directories['codex'], home / 'GPT 配置')
        self.assertEqual(configurator.directories['claude'], home / 'Claude 配置')
        self.assertEqual(configurator.directories['opencode'], home / '自定义配置/opencode')
        for client in CLIENTS:
            with self.subTest(client=client):
                result = configurator.configure(client, BASE, KEY, MODEL, [MODEL])
                if client == 'codex':
                    import subprocess
                    data = tomllib.loads(configurator.paths(client)[0].read_text())['model_providers'][PROVIDER]['auth']
                    self.assertEqual(subprocess.check_output([data['command'], *data['args']], text=True), KEY)
                configurator.restore(client, result['backup_id'])
                self.assertFalse(any(p.exists() for p in configurator.paths(client)))
        custom = home / 'Finder 选择的配置'; custom.mkdir(parents=True)
        configurator.set_directory('codex', custom)
        reopened = ClientConfigurator(self.root / 'custom-backups', home, env)
        self.assertEqual(reopened.directories['codex'], custom)
        self.assertEqual(reopened.directory_settings.stat().st_mode & 0o777, 0o600)

    def test_relative_environment_directory_is_rejected_before_writing(self):
        with self.assertRaisesRegex(ManagerError, '绝对路径'):
            ClientConfigurator(self.root / 'backups', self.root / 'home', {'CODEX_HOME': 'relative-config'})

    def test_codex_preserves_comments_other_providers_plugins_and_auth(self):
        paths = self.configurator.paths("codex")
        original = '''# original settings
model = "old"
model_provider = "local"
model_reasoning_effort = "high"
instructions = ''' + "'''\nmodel = \"keep this in a multiline string\"\n[model_providers.linux-manager-cliproxyapi]\n'''\n" + '''
[model_providers.local]
base_url = "http://127.0.0.1:8317/v1"
[model_providers.local.auth]
command = "/usr/bin/ruby"
args = ["original-helper"]
[plugins."fixture@local"]
enabled = true
'''
        self.write(paths[0], original)
        auth = paths[0].parent / "auth.json"
        self.write(auth, '{"tokens":"original-account"}')
        result = self.configure("codex")
        parsed = tomllib.loads(paths[0].read_text())
        previous = tomllib.loads(original)
        self.assertEqual(parsed["model"], MODEL)
        self.assertEqual(parsed["model_provider"], PROVIDER)
        self.assertEqual(parsed["instructions"], previous["instructions"])
        self.assertEqual(parsed["model_providers"]["local"], previous["model_providers"]["local"])
        self.assertEqual(parsed["plugins"], previous["plugins"])
        self.assertIn("# original settings", paths[0].read_text())
        self.assertNotIn(KEY, paths[0].read_text())
        self.assertEqual(paths[1].read_text(), KEY)
        self.assertEqual(auth.read_text(), '{"tokens":"original-account"}')
        self.configurator.restore("codex", result["backup_id"])
        self.assertEqual(paths[0].read_text(), original)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o640)
        self.assertFalse(paths[1].exists())

    def test_codex_repeated_configuration_replaces_only_owned_provider(self):
        self.configure("codex")
        self.configure("codex", model="second", models=["second"], key="second-key")
        config, token, catalog = self.configurator.paths("codex")
        parsed = tomllib.loads(config.read_text())
        self.assertEqual(parsed["model"], "second")
        self.assertEqual(parsed["model_providers"][PROVIDER]["base_url"], BASE)
        self.assertEqual(token.read_text(), "second-key")
        self.assertEqual([r["slug"] for r in json.loads(catalog.read_text())["models"]], ["second"])
        self.assertEqual(len(self.configurator.backups_for("codex")), 2)

    def test_claude_preserves_permissions_and_routes_all_model_aliases(self):
        path = self.configurator.paths("claude")[0]
        old = {"permissions": {"allow": ["Read"]}, "env": {"CUSTOM": "keep", "ANTHROPIC_API_KEY": "old"}, "apiKeyHelper": "old-helper"}
        self.write(path, json.dumps(old))
        self.configure("claude", model="claude-fixture", models=["claude-fixture"])
        new = json.loads(path.read_text())
        self.assertEqual(new["permissions"], old["permissions"])
        self.assertEqual(new["env"]["CUSTOM"], "keep")
        self.assertEqual(new["env"]["ANTHROPIC_BASE_URL"], "https://fixture.invalid:9229")
        self.assertEqual(new["env"]["ANTHROPIC_AUTH_TOKEN"], KEY)
        self.assertEqual(new["env"]["ANTHROPIC_API_KEY"], "")
        self.assertNotIn("apiKeyHelper", new)
        for alias in ("HAIKU", "SONNET", "OPUS"):
            self.assertEqual(new["env"]["ANTHROPIC_DEFAULT_" + alias + "_MODEL"], "claude-fixture")

    def test_pi_preserves_extensions_providers_and_model_filters(self):
        models, settings, token = self.configurator.paths("pi")
        self.write(models, '{"providers":{"local":{"baseUrl":"http://localhost"}}}')
        self.write(settings, '{"extensions":["original"],"enabledModels":["local/*"]}')
        self.configure("pi")
        new = json.loads(models.read_text())
        self.assertIn("local", new["providers"])
        self.assertEqual(new["providers"][PROVIDER]["models"], [{"id": MODEL}])
        self.assertTrue(new["providers"][PROVIDER]["apiKey"].startswith("!/bin/cat "))
        self.assertEqual(token.read_text(), KEY)
        new = json.loads(settings.read_text())
        self.assertEqual(new["extensions"], ["original"])
        self.assertEqual(new["defaultProvider"], PROVIDER)
        self.assertEqual(new["defaultModel"], MODEL)
        self.assertEqual(new["enabledModels"], ["local/*", PROVIDER + "/" + MODEL])

    def test_opencode_preserves_other_providers_and_enables_selected_provider(self):
        path = self.configurator.paths("opencode")[0]
        self.write(path, json.dumps({"provider": {"old": {"name": "Original"}}, "plugin": ["keep"],
                                    "enabled_providers": ["old"], "disabled_providers": [PROVIDER]}))
        self.configure("opencode")
        data = json.loads(path.read_text())
        self.assertEqual(data["provider"]["old"], {"name": "Original"})
        self.assertEqual(data["plugin"], ["keep"])
        self.assertEqual(data["model"], PROVIDER + "/" + MODEL)
        self.assertIn(PROVIDER, data["enabled_providers"])
        self.assertNotIn(PROVIDER, data["disabled_providers"])

    def test_all_clients_restore_original_missing_files_and_can_undo_restore(self):
        for client in CLIENTS:
            with self.subTest(client=client):
                result = self.configure(client)
                configured = {p: p.read_bytes() for p in self.configurator.paths(client)}
                restored = self.configurator.restore(client, result["backup_id"])
                self.assertTrue(all(not p.exists() for p in configured))
                self.configurator.restore(client, restored["backup_id"])
                self.assertEqual({p: p.read_bytes() for p in configured}, configured)

    def test_write_failure_after_first_file_is_automatically_rolled_back(self):
        models, settings, token = self.configurator.paths("pi")
        self.write(models, '{"providers":{"old":{}}}', 0o644)
        self.write(settings, '{"defaultModel":"old"}', 0o640)
        old = {p: self.configurator._read(p) for p in (models, settings, token)}
        write = self.configurator._write
        count = 0
        def fail_once(path, state):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("fixture failure with secret " + KEY)
            write(path, state)
        with mock.patch.object(self.configurator, "_write", side_effect=fail_once):
            with self.assertRaisesRegex(ManagerError, "已自动恢复") as raised:
                self.configure("pi")
        self.assertNotIn(KEY, str(raised.exception))
        self.assertEqual({p: self.configurator._read(p) for p in old}, old)

    def test_restore_write_failure_keeps_configuration_before_restore(self):
        result = self.configure("pi")
        before = self.configurator._snapshot("pi")
        write = self.configurator._write
        count = 0
        def fail_once(path, state):
            nonlocal count
            count += 1
            if count == 2: raise OSError()
            write(path, state)
        with mock.patch.object(self.configurator, "_write", side_effect=fail_once):
            with self.assertRaisesRegex(ManagerError, "已自动恢复"):
                self.configurator.restore("pi", result["backup_id"])
        self.assertEqual(self.configurator._snapshot("pi"), before)

    def test_invalid_original_files_are_not_overwritten_or_backed_up(self):
        for client in CLIENTS:
            with self.subTest(client=client):
                path = self.configurator.paths(client)[0]
                self.write(path, "invalid configuration")
                with self.assertRaises(ManagerError): self.configure(client)
                self.assertEqual(path.read_text(), "invalid configuration")
                self.assertEqual(self.configurator.backups_for(client), [])

    def test_backup_contains_exact_content_private_permissions_and_no_key_in_manifest(self):
        path = self.configurator.paths("claude")[0]
        original = '{"env":{"ANTHROPIC_AUTH_TOKEN":"' + KEY + '"}}'
        self.write(path, original)
        result = self.configure("claude")
        directory = self.root / "backups/claude" / result["backup_id"]
        self.assertEqual((directory / "0.bin").read_text(), original)
        self.assertNotIn(KEY, (directory / "manifest.json").read_text())
        for file in directory.iterdir(): self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_corrupted_backup_is_rejected_before_writing(self):
        self.write(self.configurator.paths("claude")[0], '{"model":"original"}')
        result = self.configure("claude")
        before = self.configurator._snapshot("claude")
        (self.root / "backups/claude" / result["backup_id"] / "0.bin").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ManagerError, "备份缺失、损坏"):
            self.configurator.restore("claude", result["backup_id"])
        self.assertEqual(self.configurator._snapshot("claude"), before)

    def test_backup_cannot_restore_to_another_file_or_use_path_traversal(self):
        result = self.configure("pi")
        directory = self.root / "backups/pi" / result["backup_id"]
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][0]["path"] = str(self.root / "other")
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ManagerError): self.configurator.restore("pi", result["backup_id"])
        with self.assertRaises(ManagerError): self.configurator.restore("pi", "../../other")
        self.assertFalse((self.root / "other").exists())

    def test_concurrent_change_during_backup_is_not_overwritten(self):
        path = self.configurator.paths("claude")[0]
        self.write(path, "{}")
        save = self.configurator._save
        def change(*args, **kwargs):
            result = save(*args, **kwargs)
            path.write_text('{"model":"changed elsewhere"}')
            return result
        with mock.patch.object(self.configurator, "_save", side_effect=change):
            with self.assertRaisesRegex(ManagerError, "被其他程序修改"): self.configure("claude")
        self.assertEqual(json.loads(path.read_text())["model"], "changed elsewhere")

    def test_symbolic_link_is_not_replaced(self):
        path = self.configurator.paths("claude")[0]
        path.parent.mkdir(parents=True)
        target = self.root / "target"
        target.write_text("{}")
        path.symlink_to(target)
        with self.assertRaisesRegex(ManagerError, "符号链接"): self.configure("claude")
        self.assertTrue(path.is_symlink())
        self.assertEqual(target.read_text(), "{}")

    def test_nondefault_client_directories_are_respected(self):
        env = {"CODEX_HOME": str(self.root / "custom-codex"), "CLAUDE_CONFIG_DIR": str(self.root / "custom-claude"),
               "PI_CODING_AGENT_DIR": str(self.root / "custom-pi"), "XDG_CONFIG_HOME": str(self.root / "custom-xdg")}
        configurator = ClientConfigurator(self.root / "backups", self.root / "home", env)
        for client in CLIENTS:
            self.assertTrue(str(configurator.paths(client)[0]).startswith(str(self.root / "custom")))

    def test_active_codex_profile_is_not_silently_ignored(self):
        path = self.configurator.paths("codex")[0]
        self.write(path, 'profile = "original"\n[profiles.original]\nmodel = "old"\n')
        with self.assertRaisesRegex(ManagerError, "独立 profile"): self.configure("codex")
        self.assertIn('profile = "original"', path.read_text())

    def test_opencode_jsonc_priority_is_not_silently_overwritten(self):
        path = self.configurator.paths("opencode")[0]
        self.write(path.with_suffix(".jsonc"), "// keep comments\n{}")
        with self.assertRaisesRegex(ManagerError, "JSONC"): self.configure("opencode")
        self.assertFalse(path.exists())

    def test_pi_existing_credential_does_not_silently_override_new_key(self):
        self.write(self.configurator.directories["pi"] / "auth.json", json.dumps({PROVIDER: {"type": "api_key", "key": "old"}}))
        with self.assertRaisesRegex(ManagerError, "同名提供商授权"): self.configure("pi")
        self.assertFalse(self.configurator.paths("pi")[0].exists())

    def test_model_and_key_validation_prevents_partial_writes(self):
        for kwargs in ({"model": "missing"}, {"key": "bad\nkey"}, {"base": "http://fixture.invalid/v1"}):
            with self.assertRaises(ManagerError): self.configure("codex", **kwargs)
        self.assertTrue(all(not p.exists() for p in self.configurator.paths("codex")))

    def test_backups_order_by_creation_time_when_ids_share_a_second(self):
        with mock.patch("linux_manager.client_config.secrets.token_hex", side_effect=["ffffffff", "00000000"]):
            first = self.configure("claude")
            second = self.configure("claude")
        self.assertEqual([r["id"] for r in self.configurator.backups_for("claude")], [second["backup_id"], first["backup_id"]])

    def test_every_chat_model_is_selectable_and_nonchat_models_are_excluded(self):
        choices = [MODEL, "gpt-second", "claude-fixture", "gemini-fixture"]
        server = choices + ["gpt-image-fixture", "grok-tts", "codex-auto-review"]
        for client in ("codex", "pi", "opencode"):
            self.configure(client, models=server)
        config, key, catalog = self.configurator.paths("codex")
        self.assertEqual([r["slug"] for r in json.loads(catalog.read_text())["models"]], choices)
        self.assertEqual(tomllib.loads(config.read_text())["model_catalog_json"], str(catalog))
        pi = json.loads(self.configurator.paths("pi")[0].read_text())
        self.assertEqual([r["id"] for r in pi["providers"][PROVIDER]["models"]], choices)
        opencode = json.loads(self.configurator.paths("opencode")[0].read_text())
        self.assertEqual(list(opencode["provider"][PROVIDER]["models"]), choices)
        self.assertEqual(opencode["model"], PROVIDER + "/" + MODEL)

    def test_existing_catalog_metadata_is_preserved_only_for_exact_model_names(self):
        config = self.configurator.paths("codex")[0]
        original_catalog = config.parent / "original-catalog.json"
        original = {"models": [{"slug": MODEL, "display_name": "Original display name", "context_window": 100000,
                                "input_modalities": ["text", "image"], "base_instructions": "original model instructions"}]}
        self.write(original_catalog, json.dumps(original))
        self.write(config, 'model_catalog_json = ' + json.dumps(str(original_catalog)) + '\nmodel = "old"\n')
        result = self.configure("codex", models=[MODEL, "unknown-alias"])
        rows = json.loads(self.configurator.paths("codex")[2].read_text())["models"]
        self.assertEqual(rows[0]["display_name"], "Original display name")
        self.assertEqual(rows[0]["context_window"], 100000)
        self.assertEqual(rows[0]["base_instructions"], "original model instructions")
        self.assertEqual(rows[1]["input_modalities"], ["text"])
        self.assertEqual(rows[1]["supported_reasoning_levels"], [])
        self.assertEqual(json.loads(original_catalog.read_text()), original)
        self.configurator.restore("codex", result["backup_id"])
        self.assertEqual(tomllib.loads(config.read_text())["model_catalog_json"], str(original_catalog))

    def test_legacy_codex_backups_restore_after_adding_the_model_catalog(self):
        result = self.configure("codex")
        directory = self.root / "backups/codex" / result["backup_id"]
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["files"] = manifest["files"][:2]
        (directory / "manifest.json").write_text(json.dumps(manifest))
        self.configurator.restore("codex", result["backup_id"])
        self.assertTrue(all(not p.exists() for p in self.configurator.paths("codex")))

    def test_pi_model_filter_keeps_all_new_models_available(self):
        settings = self.configurator.paths("pi")[1]
        self.write(settings, '{"enabledModels":["original/*"]}')
        self.configure("pi", models=[MODEL, "second"])
        self.assertEqual(json.loads(settings.read_text())["enabledModels"], ["original/*", PROVIDER + "/" + MODEL, PROVIDER + "/second"])

    def test_claude_aliases_can_switch_between_server_sonnet_and_opus(self):
        choices = ["claude-sonnet-fixture", "claude-opus-fixture"]
        self.configure("claude", model=choices[0], models=choices)
        env = json.loads(self.configurator.paths("claude")[0].read_text())["env"]
        self.assertEqual(env["ANTHROPIC_DEFAULT_SONNET_MODEL"], choices[0])
        self.assertEqual(env["ANTHROPIC_DEFAULT_OPUS_MODEL"], choices[1])
        self.assertEqual(env["CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY"], "1")

    def test_corrupt_backup_metadata_does_not_hide_valid_restore_versions(self):
        result = self.configure("claude")
        valid = self.configurator.backups_for("claude")[0]
        for number, field, value in [(1, "created", []), (2, "created", "invalid-date"), (3, "model", {}), (4, "action", "unknown")]:
            directory = self.root / "backups/claude" / ("20261013-000000-" + f"{number:08x}")
            directory.mkdir()
            row = dict(valid, id=directory.name)
            row[field] = value
            (directory / "manifest.json").write_text(json.dumps(row))
        self.assertEqual([row["id"] for row in self.configurator.backups_for("claude")], [result["backup_id"]])
        self.configurator.restore("claude", result["backup_id"])
        self.assertFalse(self.configurator.paths("claude")[0].exists())


class GatewayConnectionTests(unittest.TestCase):
    def test_gateway_uses_current_client_keys_and_public_address(self):
        info = {"service": "cliproxyapi", "data": {"installed": True, "api_keys": [KEY]},
                "rows": [("API 基础地址", BASE), ("管理 Key", "management-key")]}
        result = gateway_connection(info)
        self.assertEqual(result, {"base_url": BASE, "api_keys": [KEY]})

    def test_missing_gateway_information_is_rejected(self):
        with self.assertRaises(ManagerError): gateway_connection({})

    def test_models_request_checks_gateway_key_without_inference(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":[{"id":"second"},{"id":"first"},{"id":"first"}]}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch("linux_manager.client_config.urllib.request.build_opener", return_value=opener):
            self.assertEqual(gateway_models(BASE, KEY), ["first", "second"])
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, BASE + "/models")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(request.get_method(), "GET")

    def test_authentication_errors_do_not_echo_secret_response(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(BASE, 401, "secret " + KEY, {}, None)
        with mock.patch("linux_manager.client_config.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ManagerError, "勿使用管理 Key") as result: gateway_models(BASE, KEY)
        self.assertNotIn(KEY, str(result.exception))

    def test_empty_models_does_not_report_configuration_ready(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":[]}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch("linux_manager.client_config.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ManagerError, "模型列表为空"): gateway_models(BASE, KEY)

    def test_redirect_is_never_followed_with_gateway_key(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid"))


if __name__ == "__main__":
    unittest.main()
