"""Mirror routing checks never use real servers or credentials."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mirror_setup', ROOT / 'tools/new_api_setup.py')
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


class NewApiMirrorTests(unittest.TestCase):
    def test_every_supported_platform_has_pinned_uv_python_and_codex_assets(self):
        assets = json.loads((ROOT / 'tools/new_api_mirror_assets.json').read_text(encoding='utf-8'))['assets']
        self.assertEqual(len(assets), 20)
        for target, digest in setup.CODEX_DIGESTS.items():
            for prefix in ('uv/', 'codex/'):
                matches = [a for a in assets if a['path'].startswith(prefix) and target in a['path']]
                self.assertEqual(len(matches), 1)
                self.assertRegex(matches[0]['sha256'], r'^[a-f0-9]{64}$')
                if prefix == 'codex/':
                    self.assertEqual(matches[0]['sha256'], digest)
        self.assertEqual(len([a for a in assets if a['path'].startswith('python/')]), 8)

    def test_missing_or_unsafe_mirror_stops_before_network_access(self):
        for base in ('', 'http://mirror.example/client-setup', 'https://u:p@mirror.example/client-setup', 'https://mirror.example/?key=fixture'):
            with self.subTest(base=base), tempfile.TemporaryDirectory() as temporary, mock.patch.dict(setup.os.environ, {'NEWAPI_DOWNLOAD_BASE': base}), mock.patch.object(setup, 'discover_codex', side_effect=setup.SetupError('fixture_missing_cli')), mock.patch.object(setup.urllib.request, 'build_opener') as opener:
                with self.assertRaises(setup.SetupError):
                    setup.prepare_codex(Path(temporary))
                opener.assert_not_called()

    def test_cli_download_stays_on_mirror_and_rejects_bad_digest(self):
        opener = mock.Mock()
        opener.open.return_value = io.BytesIO(b'fixture-corrupt-download')
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(setup.os.environ, {'NEWAPI_DOWNLOAD_BASE': 'https://mirror.example/client-setup'}), mock.patch.object(setup, 'discover_codex', side_effect=setup.SetupError('fixture_missing_cli')), mock.patch.object(setup.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(setup.SetupError, '校验失败'):
                setup.prepare_codex(Path(temporary))
            self.assertTrue(opener.open.call_args.args[0].startswith('https://mirror.example/client-setup/codex/0.164.0/'))
            self.assertFalse(list(Path(temporary).rglob('codex.exe')))
            self.assertFalse(list(Path(temporary).rglob('codex')))

    def test_bootstrap_templates_have_no_external_download_url(self):
        for suffix in ('sh', 'ps1'):
            text = (ROOT / ('tools/new_api_bootstrap.' + suffix)).read_text(encoding='utf-8')
            self.assertNotIn('github.com', text)
            self.assertNotIn('astral.sh', text)
            self.assertIn('--offline', text)
            self.assertIn('--mirror', text)
            self.assertIn('__SETUP_SHA256__', text)


if __name__ == '__main__':
    unittest.main()
