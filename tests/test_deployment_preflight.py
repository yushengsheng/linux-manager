import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.models import Connection,Store,ManagerError
from linux_manager.project_info import credential_alias

spec=importlib.util.spec_from_file_location('deployment_remote',Path(__file__).resolve().parents[1]/'linux_manager/remote_agent.py')
REMOTE=importlib.util.module_from_spec(spec);spec.loader.exec_module(REMOTE)


class DeploymentPreflightTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.base=Path(self.folder.name)
        original=Path
        def path(value):
            return self.base/str(value).lstrip('/') if str(value).startswith('/') else original(value)
        patch=mock.patch.object(REMOTE,'Path',side_effect=path);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(REMOTE,'unit_info',return_value={'LoadState':'not-found'});patch.start();self.addCleanup(patch.stop)

    def test_retry_only_before_units_or_runtime_data_and_exact_parameters(self):
        params={'host':'fixture.invalid','version':'v1.1.85','port':26483,'backend_port':18880}
        root=self.base/'opt/xiaojun-exchange';root.mkdir(parents=True)
        marker=root/'.install-incomplete.json';marker.write_text(json.dumps(params|{'phase':'bootstrap'}))
        self.assertTrue(REMOTE.exchange_retry_allowed(params))
        self.assertFalse(REMOTE.exchange_retry_allowed(params|{'port':26484}))
        data=self.base/'var/lib/xiaojun-exchange';data.mkdir(parents=True);(data/'account.db').touch()
        self.assertFalse(REMOTE.exchange_retry_allowed(params));(data/'account.db').unlink()
        units=self.base/'etc/systemd/system';units.mkdir(parents=True);(units/'xiaojun-exchange-web.service').touch()
        self.assertFalse(REMOTE.exchange_retry_allowed(params))

    def test_existing_install_is_preserved_before_download_or_mutation(self):
        folder=self.base/'etc/x-ui';folder.mkdir(parents=True);database=folder/'x-ui.db';database.write_text('fixture-data')
        with mock.patch.object(REMOTE.platform,'freedesktop_os_release',return_value={'ID':'ubuntu','VERSION_ID':'24.04'}),mock.patch.object(REMOTE.platform,'machine',return_value='x86_64'),mock.patch.object(REMOTE.shutil,'disk_usage',return_value=mock.Mock(free=2*1024**3)),mock.patch.object(REMOTE,'command') as command:
            with self.assertRaises(REMOTE.OperationError):REMOTE.deployment_preflight({'service':'xui','host':'fixture.invalid','port':2053})
            command.assert_not_called()
        self.assertEqual(database.read_text(),'fixture-data')

    def test_old_panel_information_is_read_only_and_hash_is_never_returned(self):
        folder=self.base/'etc/x-ui';folder.mkdir(parents=True);database=folder/'x-ui.db'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE users(username TEXT,password TEXT)');db.execute('INSERT INTO users VALUES(?,?)',('fixture','hash-must-stay-on-server'))
            db.execute('CREATE TABLE settings(key TEXT,value TEXT)')
            db.executemany('INSERT INTO settings VALUES(?,?)',[('webPort','2054'),('webBasePath','/fixture/'),('subEnable','true'),('subPort','2096'),('subPath','/sub/')])
        before=database.read_bytes();data=REMOTE.connection_details({'service':'xui','host':'fixture.invalid'})
        self.assertEqual(data['panel_username'],'fixture');self.assertEqual(data['scheme'],'http');self.assertEqual(data['port'],2054)
        self.assertEqual(data['subscription_base'],'http://fixture.invalid:2096/sub/')
        self.assertNotIn('hash-must-stay-on-server',json.dumps(data));self.assertEqual(before,database.read_bytes())

    def test_certificate_validation_failure_has_actionable_message(self):
        with mock.patch.object(REMOTE,'listeners',return_value=[]),mock.patch.object(REMOTE,'apt'),mock.patch.object(REMOTE,'allow_port'),mock.patch.object(REMOTE,'private_write'),mock.patch.object(REMOTE,'command',side_effect=REMOTE.OperationError('Timeout during connect (likely firewall problem)')):
            with self.assertRaisesRegex(REMOTE.OperationError,'TCP 80'):
                # Existing executable avoids dependency preparation in this fixture.
                exe=self.base/'opt/linux-server-manager/certbot/bin/certbot';exe.parent.mkdir(parents=True);exe.touch()
                REMOTE.ensure_certificate('fixture.invalid')

    def test_https_probe_connects_loopback_but_verifies_real_hostname(self):
        context=mock.MagicMock();secured=mock.MagicMock();context.wrap_socket.return_value.__enter__.return_value=secured
        response=mock.Mock(status=200)
        with mock.patch.object(REMOTE.ssl,'create_default_context',return_value=context),mock.patch.object(REMOTE.socket,'create_connection') as connection,mock.patch.object(REMOTE.http.client,'HTTPResponse',return_value=response):
            REMOTE.verify_local_https('fixture.invalid',26483)
            connection.assert_called_once_with(('127.0.0.1',26483),timeout=20)
            self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'],'fixture.invalid')
            self.assertIn(b'Host: fixture.invalid:26483',secured.sendall.call_args.args[0])

    def test_expired_or_wrong_hostname_certificate_is_not_ignored(self):
        context=mock.Mock();context.wrap_socket.side_effect=REMOTE.ssl.SSLCertVerificationError('fixture failure')
        with mock.patch.object(REMOTE.ssl,'create_default_context',return_value=context),mock.patch.object(REMOTE.socket,'create_connection'):
            with self.assertRaises(REMOTE.OperationError):REMOTE.verify_local_https('fixture.invalid',26483)


if __name__=='__main__':unittest.main()
