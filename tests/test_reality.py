import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import sys
import types
import unittest
from unittest import mock
import urllib.parse
import zipfile

from linux_manager.models import Connection, ManagerError
from linux_manager.official_packages import download_project
from linux_manager.project_info import information_rows, node_links
from linux_manager.qr import is_node_link, qr_png
import test_uninstallation as fixtures
REMOTE = fixtures.REMOTE


PRIVATE = base64.urlsafe_b64encode(bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')).decode().rstrip('=')
PUBLIC = base64.urlsafe_b64encode(bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')).decode().rstrip('=')


def configuration():
    return {'log':{'loglevel':'warning'}, 'inbounds':[{'tag':'manager-reality','listen':'::','port':443,'protocol':'vless','settings':{'decryption':'none','clients':[{'id':'fe9f599c-25e2-4a3c-bddb-708630d6ead1','flow':'xtls-rprx-vision'}]},'streamSettings':{'network':'raw','security':'reality','realitySettings':{'target':'www.microsoft.com:443','serverNames':['www.microsoft.com'],'privateKey':PRIVATE,'shortIds':['0123456789abcdef']}}}], 'outbounds':[{'protocol':'freedom'}]}


class RealitySandboxTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.UninstallSandboxTests(methodName='runTest')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.write(str(self.fixture.task/'status.json'),json.dumps({'state':'running','events':[]}))
        if sys.platform == 'darwin':
            self.fixture.stack.enter_context(mock.patch.object(REMOTE.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=bytes.fromhex('302a300506032b656e032100')+base64.urlsafe_b64decode(PUBLIC+'='),stderr=b'')))
        self.fixture.write(REMOTE.REALITY_BINARY, 'fixture-xray', 0o755)
        self.fixture.write(REMOTE.REALITY_CONFIG, json.dumps(configuration()))
        self.fixture.records['reality'].update(port=443, server_name='www.microsoft.com')
        self.fixture.write('/var/lib/linux-server-manager/installed.json', json.dumps(self.fixture.records))
        original_command = self.fixture.command
        def command(args, **kwargs):
            if args[-1:] == ['version'] and 'xray' in args[0]:return types.SimpleNamespace(returncode=0,stdout='Xray 26.3.27 (Xray)',stderr='')
            return original_command(args, **kwargs)
        self.fixture.stack.enter_context(mock.patch.object(REMOTE, 'command', side_effect=command))
        self.fixture.stack.enter_context(mock.patch.object(REMOTE.platform,'freedesktop_os_release',return_value={'ID':'ubuntu','VERSION_ID':'24.04'}))
        self.fixture.stack.enter_context(mock.patch.object(REMOTE.platform,'machine',return_value='x86_64'))
        self.fixture.stack.enter_context(mock.patch.object(REMOTE.shutil,'disk_usage',return_value=types.SimpleNamespace(free=3*1024**3)))

    def params(self, **values):
        return {'service':'reality','host':'fixture.invalid','port':443,'version_policy':'keep'} | values

    def test_private_key_derivation_matches_rfc7748_vector_and_never_returns_private_key(self):
        data = REMOTE.connection_details({'service':'reality','host':'fixture.invalid'})
        self.assertEqual(data['public_key'],PUBLIC)
        self.assertNotIn(PRIVATE,json.dumps(data))
        self.assertNotIn(PRIVATE,REMOTE.clean('private='+PRIVATE))
        self.assertNotIn(data['uuid'],REMOTE.clean('uuid='+data['uuid']))

    def test_unchanged_and_port_only_changes_keep_credentials(self):
        with mock.patch.object(REMOTE,'ensure_port_available') as available:
            self.assertEqual(REMOTE.deployment_preflight(self.params())['action'],'unchanged')
            plan = REMOTE.deployment_preflight(self.params(port=8443))
        self.assertEqual(plan['action'],'reconfigure');self.assertFalse(plan['requires_archive'])
        available.assert_called_once_with(8443,'tcp')
        with mock.patch.object(REMOTE,'ensure_port_available'),mock.patch.object(REMOTE,'listeners',return_value=[{'port':8443,'protocol':'tcp','local_only':False,'processes':['xray']}]),mock.patch.object(REMOTE,'allow_port'),mock.patch.object(REMOTE,'_reality_target_check') as target:
            REMOTE.deploy(self.params(port=8443, deployment_fingerprint=plan['fingerprint']))
        target.assert_not_called()
        changed = json.loads(self.fixture.path(REMOTE.REALITY_CONFIG).read_text())
        original = configuration();original['inbounds'][0]['port']=8443
        self.assertEqual(changed,original)
        self.assertTrue((self.fixture.task/'backup/manifest.json').is_file())

    def test_key_or_config_change_invalidates_preview(self):
        plan = REMOTE.deployment_preflight(self.params(port=8443))
        changed=configuration();changed['inbounds'][0]['streamSettings']['realitySettings']['shortIds']=['abcdef0123456789']
        self.fixture.write(REMOTE.REALITY_CONFIG,json.dumps(changed))
        with self.assertRaises(REMOTE.OperationError):REMOTE.deploy(self.params(port=8443,deployment_fingerprint=plan['fingerprint']))
        self.assertFalse((self.fixture.task/'backup/manifest.json').exists())

    def test_unknown_installation_and_custom_nodes_are_not_overwritten(self):
        self.fixture.records.pop('reality');self.fixture.write('/var/lib/linux-server-manager/installed.json',json.dumps(self.fixture.records))
        with self.assertRaises(REMOTE.OperationError):REMOTE.deployment_preflight(self.params())
        config=configuration();config['inbounds'].append({'protocol':'socks'})
        self.fixture.write(REMOTE.REALITY_CONFIG,json.dumps(config))
        with self.assertRaises(REMOTE.OperationError):REMOTE.connection_details({'service':'reality'})

    def test_failed_first_install_restore_removes_new_service_and_credentials(self):
        self.fixture.path(REMOTE.REALITY_CONFIG).unlink()
        self.fixture.path('/etc/systemd/system/'+REMOTE.REALITY_UNIT).unlink()
        REMOTE._deployment_backup('reality','install')
        self.fixture.write(REMOTE.REALITY_CONFIG,json.dumps(configuration()))
        self.fixture.write('/etc/systemd/system/'+REMOTE.REALITY_UNIT,self.fixture.unit_text(REMOTE.REALITY_UNIT))
        self.fixture.active[REMOTE.REALITY_UNIT]='active';self.fixture.enabled[REMOTE.REALITY_UNIT]='enabled'
        REMOTE.restore_deployment(self.fixture.task.name)
        self.assertFalse(self.fixture.path(REMOTE.REALITY_CONFIG).exists())
        self.assertFalse(self.fixture.path('/etc/systemd/system/'+REMOTE.REALITY_UNIT).exists())
        self.assertIn(['systemctl','disable',REMOTE.REALITY_UNIT],self.fixture.calls)

    def test_uninstall_and_reinstall_preserve_configuration_and_other_proxy(self):
        original=self.fixture.path(REMOTE.REALITY_CONFIG).read_bytes()
        hy2=self.fixture.path('/etc/sing-box/config.json').read_bytes()
        REMOTE.uninstall_project(self.fixture.prepare('reality'))
        self.assertEqual(self.fixture.path(REMOTE.REALITY_CONFIG).read_bytes(),original)
        self.assertEqual(self.fixture.path('/etc/sing-box/config.json').read_bytes(),hy2)
        plan=REMOTE.deployment_preflight(self.params(version='v26.3.27',version_policy='specific'))
        self.assertEqual(plan['action'],'repair');self.assertTrue(plan['reinstall'])

    def test_zip_paths_and_duplicate_binary_rejected_before_write(self):
        for names in [['../xray'],['xray','xray']]:
            with self.subTest(names=names):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with zipfile.ZipFile(self.fixture.task/'release.tar.gz','w') as z:
                        for name in names:z.writestr(name,b'fixture')
                with self.assertRaises(REMOTE.OperationError):REMOTE._reality_install_binary()


class RealityLinksAndPackagesTests(unittest.TestCase):
    def test_node_uri_contains_required_fields_and_ipv6_without_private_key(self):
        data={'service':'reality','installed':True,'host':'2001:db8::1','port':8443,'uuid':'fixture-uuid','server_name':'www.microsoft.com','public_key':PUBLIC,'short_id':'0123456789abcdef','privateKey':PRIVATE}
        rows=dict(information_rows(data,Connection(host='fixture.invalid')))
        uri=rows['VLESS 节点链接'];parsed=urllib.parse.urlsplit(uri)
        self.assertEqual(parsed.hostname,'2001:db8::1');self.assertEqual(parsed.port,8443)
        query=urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query['flow'],['xtls-rprx-vision']);self.assertEqual(query['fp'],['chrome'])
        self.assertEqual(query['pbk'],[PUBLIC]);self.assertEqual(query['security'],['reality'])
        self.assertNotIn(PRIVATE,uri)
        self.assertEqual(node_links(data|{'public_key':''},'fixture.invalid'),[])

    def test_architecture_specific_official_zip_download_is_verified(self):
        for architecture,name in [('x86_64','Xray-linux-64.zip'),('aarch64','Xray-linux-arm64-v8a.zip')]:
            payload=b'fixture-zip';digest=hashlib.sha256(payload).hexdigest();version='v26.3.27'
            release={'assets':[{'name':name,'size':len(payload),'digest':'sha256:'+digest,'browser_download_url':'https://github.com/XTLS/Xray-core/releases/download/'+version+'/'+name}]}
            with self.subTest(architecture=architecture),tempfile.TemporaryDirectory() as folder,mock.patch('linux_manager.official_packages.official_release',return_value=release),mock.patch('linux_manager.official_packages.urllib.request.urlopen',return_value=io.BytesIO(payload)):
                self.assertEqual(download_project('reality',version,architecture,Path(folder)/'zip'),digest)


class NodeQrTests(unittest.TestCase):
    def test_decoded_qr_matches_complete_node_link(self):
        try:
            from PIL import Image
            import zxingcpp
        except ImportError:self.skipTest('QR decoder is a development/CI dependency')
        links=[node_links({'service':'hysteria2','host':'fixture.invalid','port':51752,'proxy_password':'a@b:/?中文'},'fixture.invalid')[0][1],node_links({'service':'reality','host':'2001:db8::1','port':8443,'uuid':'fixture-id','server_name':'www.microsoft.com','public_key':PUBLIC,'short_id':'0123456789abcdef'},'fixture.invalid')[0][1]]
        for link in links:
            with self.subTest(protocol=link.split(':')[0]):
                png=qr_png(link);picture=Image.open(io.BytesIO(png))
                self.assertLessEqual(picture.width,380)
                decoded=zxingcpp.read_barcode(picture)
                self.assertIsNotNone(decoded);self.assertEqual(decoded.text,link)

    def test_non_nodes_and_oversized_values_are_rejected(self):
        for value in ['https://fixture.invalid','password','vless://'+'x'*4097]:
            with self.assertRaises(ManagerError):qr_png(value)
        self.assertFalse(is_node_link(None))


if __name__=='__main__':unittest.main()
