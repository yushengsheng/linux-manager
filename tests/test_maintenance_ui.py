import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest
from unittest import mock
from linux_manager.gui import App
from linux_manager.models import Connection,SERVICES
from linux_manager.project_info import server_key


class MaintenancePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=tk.Tk();cls.root.withdraw()
    @classmethod
    def tearDownClass(cls):cls.root.destroy()
    def setUp(self):
        self.page=ttk.Frame(self.root);self.app=object.__new__(App)
        app=self.app;app.pages={'日常维护':SimpleNamespace(content=self.page)}
        app.privacy=tk.BooleanVar(self.root,value=False);app.buttons=[];app.private_entries=[]
        app.current=Connection(host='one.invalid');app.project_details={};app.project_logs={}
        app._maintenance_page();app._copy=mock.Mock()
    def tearDown(self):self.page.destroy()
    def test_switch_project_uses_cached_matching_information_and_logs_only(self):
        app=self.app;identity=server_key(app.current)
        app.project_details[(identity,'xui')]={'rows':[('后台网址','https://one.invalid:2053/fixture/'),('后台密码','fictional-password')]}
        app.project_logs[(identity,'xui')]='fixture panel log'
        app.project_details[(identity,'hysteria2')]={'rows':[('服务端口','51752')]}
        app.manage_choice.set(SERVICES['xui'][0]);app._project_changed()
        self.assertIn('后台密码',dict(app.project_rows));self.assertIn('fixture panel log',app.maintenance_text.get('1.0','end'))
        app.manage_choice.set(SERVICES['hysteria2'][0]);app._project_changed()
        self.assertNotIn('后台密码',dict(app.project_rows));self.assertNotIn('fixture panel log',app.maintenance_text.get('1.0','end'))
        app.current=app.current.changed(host='two.invalid');app._project_changed()
        self.assertFalse(app.project_rows)
    def test_copy_full_node_while_hidden_does_not_truncate_the_value(self):
        app=self.app;value='vless://fictional-id@one.invalid:1234?type=tcp'
        app.project_details[(server_key(app.current),'exchange')]={'rows':[('节点：fixture',value)]}
        app.privacy.set(True);app._project_changed();app.project_info_tree.selection_set('0')
        app._select_project_info();self.assertNotEqual(app.project_info_value.get(),value)
        app._copy_project_item();app._copy.assert_called_once_with(value)
    def test_account_server_selector_deduplicates_same_server_accounts(self):
        app=self.app;app.account_server_box=ttk.Combobox(self.page,state='readonly')
        app.profiles=[app.current,app.current.changed(username='second'),app.current.changed(host='two.invalid')]
        app._account_servers();self.assertEqual(len(app.account_server_map),2)
        self.assertEqual(app.account_server_box.current(),0)


if __name__=='__main__':unittest.main()
