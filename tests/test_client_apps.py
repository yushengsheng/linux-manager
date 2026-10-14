from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

from linux_manager.client_apps import installed_applications, resolve_application
from linux_manager.client_config import ClientConfigurator
from linux_manager.models import ManagerError


class ClientApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def application(self, path, identifier='com.openai.codex', name='Codex'):
        (path / 'Contents').mkdir(parents=True)
        (path / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': identifier, 'CFBundleDisplayName': name}))
        return path

    def test_application_location_and_name_do_not_determine_configuration_location(self):
        app = self.application(self.root / "任意安装 空格'中文/随意名称.app")
        selected = resolve_application(app)
        self.assertEqual(selected.client, 'codex')
        home = self.root / '另一台 Mac 用户'
        config = ClientConfigurator(self.root / 'backups', home, {})
        self.assertEqual(config.directories[selected.client], home / '.codex')
        moved = self.root / '移动后的名称.app'; app.rename(moved)
        self.assertEqual(config.directories[resolve_application(moved).client], home / '.codex')
        self.assertFalse((home / '.codex').exists())

    def test_known_environment_and_historical_directory_remain_usable(self):
        app = self.application(self.root / 'Codex.app')
        custom = self.root / '历史配置'; custom.mkdir()
        config = ClientConfigurator(self.root / 'backups', self.root / 'home', {'CODEX_HOME': '~/环境配置'})
        self.assertEqual(config.directories[resolve_application(app).client], self.root / 'home/环境配置')
        config.set_directory('codex', custom)
        reopened = ClientConfigurator(self.root / 'backups', self.root / 'home', {})
        self.assertEqual(reopened.directories[resolve_application(app).client], custom)

    def test_inventory_searches_application_roots_one_group_and_exact_metadata(self):
        system = self.root / '系统应用'; user = self.root / '个人应用'
        expected = [self.application(system / 'Codex.app'), self.application(user / '分组/OpenCode.app', 'ai.opencode.desktop', 'OpenCode'),
                    self.application(self.root / '其他位置/客户端.app')]
        self.application(system / '更深/分组/不遍历.app')
        self.application(system / 'Claude.app', 'com.anthropic.claudefordesktop', 'Claude')
        result = subprocess.CompletedProcess([], 0, str(expected[2]) + '\n' + str(expected[0]) + '\n', '')
        with mock.patch('linux_manager.client_apps.subprocess.run', return_value=result) as command:
            rows = installed_applications(self.root, [system, user])
        self.assertEqual({row.path for row in rows}, set(expected))
        self.assertEqual(command.call_args.args[0][0], '/usr/bin/mdfind')
        self.assertIn('com.openai.codex', command.call_args.args[0][1])

    def test_spotlight_failure_does_not_hide_apps_in_known_folders(self):
        app = self.application(self.root / 'Apps/Codex.app')
        with mock.patch('linux_manager.client_apps.subprocess.run', side_effect=subprocess.TimeoutExpired('mdfind', 3)):
            self.assertEqual(installed_applications(roots=[self.root / 'Apps'])[0].path, app)

    def test_unrelated_or_missing_apps_are_not_assigned_a_configuration(self):
        for name, identifier in [('Claude.app', 'com.anthropic.claudefordesktop'), ('ChatGPT.app', 'com.openai.chat'), ('Codex.app', 'com.unrelated.app')]:
            with self.subTest(name=name), self.assertRaises(ManagerError):
                resolve_application(self.application(self.root / name, identifier))
        with self.assertRaises(ManagerError): resolve_application(self.root / 'missing.app')

    def test_icon_conversion_failure_keeps_the_app_selectable(self):
        app = self.application(self.root / 'Apps/Codex.app')
        resources = app / 'Contents/Resources'; resources.mkdir(); (resources / 'App.icns').write_bytes(b'fixture')
        info = app / 'Contents/Info.plist'; data = plistlib.loads(info.read_bytes()); data['CFBundleIconFile'] = 'App'; info.write_bytes(plistlib.dumps(data))
        def run(command, **kwargs):
            if command[0].endswith('mdfind'): return subprocess.CompletedProcess(command, 0, '', '')
            raise subprocess.CalledProcessError(1, command)
        with mock.patch('linux_manager.client_apps.subprocess.run', side_effect=run):
            rows = installed_applications(roots=[self.root / 'Apps'])
        self.assertEqual(rows[0].path, app); self.assertIsNone(rows[0].icon)

    def test_malformed_application_metadata_does_not_hide_other_apps(self):
        valid = self.application(self.root / 'Apps/Codex.app')
        malformed = self.application(self.root / 'Apps/Broken.app', ['invalid'])
        with mock.patch('linux_manager.client_apps.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            self.assertEqual([row.path for row in installed_applications(roots=[valid.parent])], [valid])
        with self.assertRaises(ManagerError): resolve_application(malformed)
