import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from tools import ci_proxy_integration as ci


class IsolatedRealityOriginTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='lm-ci-origin-')
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / 'config.json'
        self.original = {'inbounds':[{'tag':'manager-reality', 'settings':{'clients':[{'id':'synthetic-id'}]}}],
                         'outbounds':[{'tag':'direct', 'protocol':'freedom', 'settings':{'domainStrategy':'AsIs'}},
                                      {'tag':'other', 'protocol':'blackhole'}]}
        self.content = (json.dumps(self.original, indent=2) + '\n').encode()
        self.path.write_bytes(self.content); self.path.chmod(0o640)
        def write(path, content, mode=0o600):
            path = Path(path)
            path.write_bytes(content.encode() if isinstance(content, str) else content)
            path.chmod(mode)
        self.remote = types.SimpleNamespace(REALITY_CONFIG=str(self.path), REALITY_BINARY='/synthetic/xray',
                                            REALITY_UNIT='synthetic-reality.service',
                                            private_write=mock.Mock(side_effect=write), command=mock.Mock())
        guard = mock.patch.object(ci, 'require_disposable_runner')
        self.guard = guard.start(); self.addCleanup(guard.stop)

    def assert_restored(self):
        self.assertEqual(self.path.read_bytes(), self.content)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_exception_allows_only_one_loopback_tcp_port_and_restores_original(self):
        with ci.reality_test_origin(self.remote, 34567):
            config = json.loads(self.path.read_bytes())
            expected = copy.deepcopy(self.original)
            expected['outbounds'][0]['settings']['finalRules'] = [
                {'action':'allow', 'network':'tcp', 'ip':['127.0.0.1/32'], 'port':'34567'}]
            self.assertEqual(config, expected)
            self.assertEqual(self.remote.command.call_args.args[0],
                             ['systemctl', 'restart', 'synthetic-reality.service'])
        self.assert_restored()
        self.assertEqual(self.remote.command.call_count, 3)

    def test_probe_failure_still_removes_the_exception(self):
        with self.assertRaisesRegex(RuntimeError, 'synthetic probe failure'):
            with ci.reality_test_origin(self.remote, 34567):
                raise RuntimeError('synthetic probe failure')
        self.assert_restored()

    def test_invalid_candidate_never_changes_running_node(self):
        self.remote.command.side_effect = RuntimeError('synthetic validation failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic validation failure'):
            with ci.reality_test_origin(self.remote, 34567):
                self.fail('invalid candidate was used')
        self.assert_restored()
        self.remote.command.assert_called_once()

    def test_startup_failure_restores_original_before_retrying_service(self):
        self.remote.command.side_effect = [None, RuntimeError('synthetic startup failure'), None]
        with self.assertRaisesRegex(RuntimeError, 'synthetic startup failure'):
            with ci.reality_test_origin(self.remote, 34567):
                self.fail('failed service was used')
        self.assert_restored()

    def test_missing_runner_guard_stops_before_reading_or_writing_config(self):
        self.guard.side_effect = SystemExit('not a disposable runner')
        with mock.patch.object(Path, 'read_bytes') as read:
            with self.assertRaises(SystemExit):
                with ci.reality_test_origin(self.remote, 34567):
                    self.fail('fixture used outside runner')
        read.assert_not_called(); self.remote.private_write.assert_not_called()

    def test_invalid_ports_cannot_create_a_broader_exception(self):
        for port in [0, 65536, True, '1-65535', '34567']:
            with self.subTest(port=port), self.assertRaises(ValueError):
                with ci.reality_test_origin(self.remote, port):
                    self.fail('invalid port accepted')
        self.remote.private_write.assert_not_called()
        self.assert_restored()


if __name__ == '__main__':
    unittest.main()
