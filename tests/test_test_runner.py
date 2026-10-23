import importlib
from pathlib import Path
import unittest
from unittest import mock


class TestRunnerPrivacyTests(unittest.TestCase):
    def test_import_does_not_read_local_profiles_or_credentials(self):
        from tools import run_tests
        with mock.patch.object(Path, 'read_text', side_effect=AssertionError('unexpected local read')):
            importlib.reload(run_tests)

    def test_local_paths_and_addresses_are_redacted_without_saved_profiles(self):
        from tools import run_tests
        output = f'{run_tests.base}/tests/fixture.py {Path.home()}/fixture 192.0.2.40'
        result = run_tests.redact(output)
        self.assertNotIn(str(run_tests.base), result)
        self.assertNotIn(str(Path.home()), result)
        self.assertNotIn('192.0.2.40', result)


class LiveTestPrivacyTests(unittest.TestCase):
    def test_missing_explicit_profile_stops_before_loading_saved_credentials(self):
        from tools import live_direct_download_regression as live
        with mock.patch.dict(live.os.environ, {}, clear=True), mock.patch.object(live, 'Store') as store, mock.patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError, 'authorized test profile required'):
                live.main()
        store.assert_not_called()


if __name__ == '__main__':
    unittest.main()
