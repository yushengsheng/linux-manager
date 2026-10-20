import base64
import json
from pathlib import Path
import tempfile
import tkinter as tk
from types import SimpleNamespace
import unittest
from unittest import mock

from linux_manager.gui import App
from linux_manager.controller import Controller
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.project_info import information_rows, node_links, server_key, credential_alias
from linux_manager.vault import LocalVault


class ProjectInformationTests(unittest.TestCase):
    def test_keychain_denial_keeps_builtin_snapshot_and_detail_available(self):
        data = {'service': 'xui', 'installed': True, 'port': 2053, 'scheme': 'http', 'path': '/panel/'}
        connection = Connection(host='fixture.invalid')
        for action in ('snapshot', 'details'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                vault = mock.Mock(); vault.get.side_effect = ManagerError('fixture denial')
                controller = Controller(Store(Path(folder), vault))
                transport = mock.Mock(); controller.transport = mock.Mock(return_value=transport)
                transport.call.return_value = {'project_details': {'xui': dict(data)}} if action == 'snapshot' else dict(data)
                if action == 'snapshot':
                    information = controller.inspect(connection)['project_information']['xui']
                else:
                    information = controller.project_information(connection, 'xui')
                rows = dict(information['rows'])
                self.assertEqual(rows['后台网址'], 'http://fixture.invalid:2053/panel/')
                self.assertIn('本机登录记录', rows)
                self.assertNotIn('fixture denial', str(rows))
                vault.put.assert_not_called(); vault.delete.assert_not_called()

    def test_exchange_origin_without_explicit_port_uses_its_web_scheme(self):
        from test_linux_manager import REMOTE
        for origin, expected in [('http://fixture.invalid', 80), ('https://fixture.invalid', 443), ('http://fixture.invalid:8080', 8080)]:
            with self.subTest(origin=origin), \
                 mock.patch.object(REMOTE.Path, 'exists', return_value=False), \
                 mock.patch.object(REMOTE.Path, 'is_file', lambda path: str(path) == '/etc/xiaojun-exchange/server.env'), \
                 mock.patch.object(REMOTE.Path, 'read_text', return_value='XIAOJUN_PUBLIC_ORIGIN=' + origin), \
                 mock.patch.object(REMOTE, 'unit_info', return_value={'LoadState': 'loaded'}), \
                 mock.patch.object(REMOTE, 'command', return_value=SimpleNamespace(stdout='')):
                self.assertEqual(REMOTE.connection_details({'service': 'exchange'})['port'], expected)

    def test_existing_panel_uses_http_and_exact_base_path_without_password_hash(self):
        conn=Connection(host='fixture.invalid',label='fixture')
        rows=dict(information_rows({'service':'xui','installed':True,'port':2054,'scheme':'http','path':'/fixture/','panel_username':'owner'},conn))
        self.assertEqual(rows['后台网址'],'http://fixture.invalid:2054/fixture/')
        self.assertEqual(rows['后台账号'],'owner')
        self.assertIn('未在本机保存',rows['后台密码'])
        saved=dict(information_rows({'service':'xui','installed':True},conn,{'panel_password':'fictional-password'}))
        self.assertEqual(saved['后台密码'],'fictional-password')

    def test_hysteria_password_escaped_and_ipv6_bracketed(self):
        links=node_links({'service':'hysteria2','port':12345,'host':'2001:db8::1','proxy_password':'a@b:/?','sni':'fixture.invalid'},'unused.invalid')
        self.assertIn('a%40b%3A%2F%3F@[2001:db8::1]:12345',links[0][1])
        self.assertIn('sni=fixture.invalid',links[0][1])

    def test_vless_reality_nodes_and_subscriptions_exclude_disabled_clients(self):
        data={'service':'xui','subscription_base':'https://fixture.invalid:2096/sub/','inbounds':[{'port':10001,'protocol':'vless','enable':True,'settings':{'clients':[{'email':'fixture','id':'fictional-id','subId':'fictional-sub','flow':'xtls-rprx-vision'},{'id':'disabled','enable':False}]},'stream_settings':{'network':'tcp','security':'reality','realitySettings':{'serverNames':['example.org'],'shortIds':['ab'],'settings':{'publicKey':'public-fixture'}}}}]}
        links=node_links(data,'fixture.invalid')
        self.assertEqual(len(links),2)
        node=next(value for name,value in links if name.startswith('节点：'))
        self.assertIn('pbk=public-fixture',node);self.assertIn('sni=example.org',node)
        self.assertIn(('订阅：fixture','https://fixture.invalid:2096/sub/fictional-sub'),links)

    def test_vmess_payload_preserves_websocket_path(self):
        data={'inbounds':[{'port':10002,'protocol':'vmess','settings':{'clients':[{'id':'fictional-id'}]},'stream_settings':{'network':'ws','security':'tls','wsSettings':{'path':'/fixture','headers':{'Host':'example.org'}}}}]}
        uri=node_links(data,'fixture.invalid')[0][1]
        payload=json.loads(base64.b64decode(uri.removeprefix('vmess://')))
        self.assertEqual(payload['path'],'/fixture');self.assertEqual(payload['host'],'example.org')

    def test_same_user_on_different_servers_and_ports_has_separate_namespaces(self):
        one=Connection(host='one.invalid',username='fixture');two=one.changed(host='two.invalid');port=one.changed(port=2222)
        self.assertNotEqual(server_key(one),server_key(two));self.assertNotEqual(credential_alias(one,'xui'),credential_alias(two,'xui'))
        self.assertNotEqual(server_key(one),server_key(port))
        self.assertEqual(server_key(one),server_key(one.changed(username='another')))

    def test_stale_account_list_cannot_be_used_for_deletion(self):
        app=object.__new__(App);app.current=Connection(host='two.invalid')
        app.report_server_key=server_key(Connection(host='one.invalid'))
        app.account_tree=mock.Mock();app.account_tree.selection.return_value=['selected'];app.account_map={'selected':'fixture'}
        with self.assertRaises(ManagerError):app._selected_account()

    def test_late_account_detail_cannot_cross_servers(self):
        app=object.__new__(App);old=Connection(host='one.invalid');app.current=old
        app._ready=mock.Mock(return_value=True);app._selected_account=mock.Mock(return_value='fixture')
        app._run=mock.Mock();app.controller=mock.Mock();app._show_account_detail=mock.Mock();app.account_detail=None
        app._account_details();callback=app._run.call_args.args[1]
        app.current=Connection(host='two.invalid');callback({'username':'fixture'})
        self.assertIsNone(app.account_detail);app._show_account_detail.assert_not_called()

    def test_late_project_response_is_cached_under_original_server_only(self):
        app=object.__new__(App);old=Connection(host='one.invalid');app.current=old
        app._ready=mock.Mock(return_value=True);app.manage_choice=mock.Mock();app.manage_choice.get.return_value='代理管理面板'
        app._service_key=mock.Mock(return_value='xui');app._run=mock.Mock();app.controller=mock.Mock();app.status=mock.Mock();app._project_changed=mock.Mock();app.project_details={}
        app._refresh_project_info();callback=app._run.call_args.args[1]
        app.current=Connection(host='two.invalid');callback({'rows':[('后台账号','fixture')]})
        self.assertIn((server_key(old),'xui'),app.project_details);app._project_changed.assert_not_called()

    def test_vault_cached_read_does_not_call_native_or_share_mutable_dictionary(self):
        vault=LocalVault();vault.cache['a'*16]={'panel_password':'fictional-password'}
        with mock.patch.object(vault,'_initialize',side_effect=AssertionError('unexpected native call')):
            values=vault.get('a'*16);values['panel_password']='changed'
            self.assertEqual(vault.get('a'*16)['panel_password'],'fictional-password')


if __name__=='__main__':unittest.main()
