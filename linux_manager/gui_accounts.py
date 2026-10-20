"""Page layout and presentation; actions use the shared App controller."""
import datetime
import tkinter as tk
from tkinter import ttk

from .gui_common import INK
from .models import ManagerError, Redactor
from .project_info import server_key
from .widgets import sync_tree


class AccountsPage:
    def _accounts_page(self):
        page = self.pages["账号与登录"].content
        self._description(page, "账号、密码和连接方式", "变更连接配置前备份；新连接通过验证后才完成切换。超级管理员账号保持不变，可创建普通管理员后切换使用。")
        server_row = ttk.Frame(page); server_row.pack(fill="x", pady=(0, 12))
        self._help_label(server_row, "账号所属服务器").pack(side="left", padx=(0, 12))
        self.account_server_box = ttk.Combobox(server_row, state="readonly", width=36)
        self.account_server_box.pack(side="left", fill="x", expand=True)
        self.account_server_box.bind("<<ComboboxSelected>>", self._choose_account_server)
        self.account_server_status = ttk.Label(page, text="先连接服务器，再查看这台服务器的用户。", style="Muted.TLabel")
        self.account_server_status.pack(anchor="w", pady=(0, 8))
        counts = ttk.Frame(page); counts.pack(fill="x", pady=6)
        self.account_count = ttk.Label(counts, text="连接后统计全部本机用户。")
        self.account_count.pack(side="left")
        self.show_system_accounts = tk.BooleanVar(value=False)
        self._check(counts, "显示系统账号", self.show_system_accounts, command=self._render_accounts).pack(side="right")
        self.account_tree = self._tree(page, [("name", "账号", 180), ("role", "权限", 140), ("keys", "登录密钥", 120), ("password", "系统密码", 130), ("access", "SSH 登录", 170)], height=6)
        self.account_tree.bind("<<TreeviewSelect>>", self._select_account)
        actions = ttk.Frame(page); actions.pack(fill="x", pady=8)
        self._button(actions, "刷新用户列表", self._refresh_accounts).pack(side="left")
        self._button(actions, "查看选中账号详情", self._account_details).pack(side="left", padx=6)
        self._button(actions, "复制选中账号信息", self._copy_account).pack(side="left")
        self._button(page, "删除选中用户（保留文件）", self._delete_user).pack(anchor="w", pady=(0, 6))
        self.account_detail_text = tk.Text(page, height=10, wrap="word", bg="white", foreground=INK, font="TkDefaultFont", relief="flat", padx=14, pady=10, state="disabled")
        self.account_detail_text.pack(fill="x", pady=6)
        self._replace_text(self.account_detail_text, "选中账号可以查看登录名、权限、登录策略和本机私钥位置。系统服务账号默认折叠，不能删除。")
        forms = ttk.Frame(page)
        forms.pack(fill="x", pady=14)
        left = ttk.LabelFrame(forms, text="账号管理", padding=12)
        right = ttk.LabelFrame(forms, text="SSH 连接设置", padding=12)
        left.grid(row=0, column=0, sticky="nsew", pady=(0, 14))
        right.grid(row=1, column=0, sticky="nsew")
        forms.columnconfigure(0, weight=1)
        self.account_user = tk.StringVar()
        self.account_password = tk.StringVar()
        self.account_confirmation = tk.StringVar()
        self.new_username = tk.StringVar()
        self.install_key = tk.BooleanVar(value=True)
        self._field(left, 0, "账号名", self.account_user, True, 24)
        self._field(left, 1, "新密码", self.account_password, True, 24)
        self._field(left, 2, "再次输入", self.account_confirmation, True, 24)
        self._button(left, "生成密码", lambda: self._generate_password(self.account_password, self.account_confirmation)).grid(row=1, column=2, padx=12)
        self._field(left, 3, "改名后的账号", self.new_username, True, 24)
        self._check(left, "创建账号时配置本机专用密钥", self.install_key).grid(row=4, columnspan=2, sticky="w", pady=6)
        row = ttk.Frame(left); row.grid(row=5, columnspan=2, sticky="w", pady=10)
        self._button(row, "创建管理员", lambda: self._account_operation("create_admin")).pack(side="left")
        self._button(row, "修改密码", lambda: self._account_operation("password")).pack(side="left", padx=6)
        self._button(row, "账号改名", lambda: self._account_operation("rename_user")).pack(side="left")
        access = ttk.Frame(left); access.grid(row=6, columnspan=2, sticky="w", pady=8)
        self._button(access, "禁止用户登录", lambda: self._account_access(True)).pack(side="left")
        self._button(access, "恢复用户登录", lambda: self._account_access(False)).pack(side="left", padx=8)
        self.ssh_port = tk.StringVar(value="22")
        self.ssh_account = tk.StringVar()
        self.allow_password = tk.BooleanVar(value=False)
        self.allow_root = tk.BooleanVar(value=False)
        self.replace_key = tk.BooleanVar(value=True)
        self._field(right, 0, "验证登录账号", self.ssh_account, True, 24)
        self._field(right, 1, "SSH 端口（TCP）", self.ssh_port, False, 24)
        self._check(right, "允许密码登录", self.allow_password).grid(row=2, columnspan=2, sticky="w", pady=7)
        self._check(right, "允许超级管理员直接登录", self.allow_root).grid(row=3, columnspan=2, sticky="w", pady=7)
        self._check(right, "添加本机专用密钥并验证", self.replace_key).grid(row=4, columnspan=2, sticky="w", pady=7)
        self._button(right, "检查并应用 SSH 设置", self._apply_ssh, True).grid(row=5, columnspan=2, sticky="w", pady=10)

    def _account_servers(self):
        groups = {}
        for profile in self.profiles:
            groups.setdefault(server_key(profile), profile)
        if self.current and self.current.host:
            groups[server_key(self.current)] = self.current
        self.account_server_map = list(groups.values())
        self.account_server_box["values"] = [f"{index + 1}. {profile.label}" + ("" if self.privacy.get() else " · " + profile.host) for index,profile in enumerate(self.account_server_map)]
        if self.current:
            for index,profile in enumerate(self.account_server_map):
                if server_key(profile)==server_key(self.current):
                    self.account_server_box.current(index);break

    def _clear_account_view(self):
        self.account_map = {}; self.account_detail = None
        sync_tree(self.account_tree, [])
        self.account_count.configure(text="尚未读取这台服务器的用户。")
        self.account_server_status.configure(text="请连接所选服务器后读取用户。")
        self._replace_text(self.account_detail_text, "每次只显示所选服务器的账号；切换后不会沿用上一台服务器的用户或权限信息。")

    def _select_account(self, _=None):
        selection = self.account_tree.selection()
        if selection and selection[0] in self.account_map:
            self.account_user.set(self.account_map[selection[0]])
            self._show_account_detail()

    def _render_accounts(self):
        if not self.report: return
        if self.report_server_key != server_key(self.current):
            self._clear_account_view(); return
        self.account_server_status.configure(text="当前服务器：" + (self.current.label if self.privacy.get() else self.current.label + " · " + self.current.host))
        selected = self.account_map.get(next(iter(self.account_tree.selection()), ""))
        self.account_map = {}
        tree_rows = []
        selected_id = None
        rows = self.report["accounts"]
        system_count = sum(u.get("system", u["uid"] != 0 and not 1000 <= u["uid"] < 65534) for u in rows)
        self.account_count.configure(text=f"全部 {len(rows)} 个用户 · 系统账号 {system_count} 个 · 管理员 {sum(u['admin'] for u in rows)} 个")
        for i, account in enumerate(rows):
            system = account.get("system", account["uid"] != 0 and not 1000 <= account["uid"] < 65534)
            if system and not self.show_system_accounts.get(): continue
            name = f"账号 {i + 1}" if self.privacy.get() else account["username"]
            role = "超级管理员" if account["uid"] == 0 else "系统服务账号" if system else "普通管理员" if account["admin"] else "普通账号"
            access = "本程序已禁止" if account.get("managed_blocked") else "配置已禁止" if account.get("ssh_denied") else "详见账号策略"
            row_id = self.report_server_key + ":" + str(i)
            tree_rows.append((row_id, (name, role, str(account["key_count"]) + " 把", {"set": "已设置", "locked": "已锁定", "empty": "未设置"}.get(account["password_state"], "未知"), access)))
            self.account_map[row_id] = account["username"]
            if selected == account["username"]: selected_id = row_id
        sync_tree(self.account_tree, tree_rows)
        if selected_id is not None:
            if self.account_tree.selection() != (selected_id,): self.account_tree.selection_set(selected_id)
        elif self.account_tree.selection():
            self.account_tree.selection_remove(*self.account_tree.selection())
        self._show_account_detail()

    def _selected_account(self):
        if self.report_server_key != server_key(self.current):
            raise ManagerError("请先刷新所选服务器的用户列表。")
        selected = self.account_tree.selection()
        if not selected or selected[0] not in self.account_map:
            raise ManagerError("请先在用户列表里选中一个账号。")
        return self.account_map[selected[0]]

    def _account_info(self, account):
        row = next(u for u in self.report["accounts"] if u["username"] == account)
        detail = self.account_detail if self.account_detail and self.account_detail.get("username") == account and self.account_detail.get("server_id") == self.current.identifier else None
        data = detail or row
        ssh = data.get("ssh", self.report.get("ssh", {}))
        policy = "按所选账号查询" if detail else "全局概览；点击查看详情核对账号条件"
        def value(key):
            translations = {"yes": "允许", "no": "禁止", "publickey": "密钥", "any": "任一已开启方式", "prohibit-password": "禁止密码（仍可用密钥）", "without-password": "禁止密码（仍可用密钥）", "force-commands-only": "仅限指定命令", "local": "仅本地隧道", "remote": "仅远端隧道"}
            return " / ".join(translations.get(v, v) for v in ssh.get(key, [])) or "未单独限制"
        paths = data.get("local_private_keys", [p.key_path for p in self.profiles if p.host == self.current.host and p.username == account and p.auth == "key" and p.key_path])
        text = f"登录名：{account}\nUID / GID：{data['uid']} / {data.get('gid', '未知')}\n用户组：{', '.join(data.get('groups', [])) or '未知'}\n家目录：{data.get('home', '未知')}\n登录 Shell：{data.get('shell', '未知')}\n系统密码：" + {"set": "已设置", "locked": "已锁定（不等于禁用所有密钥）", "empty": "空密码"}.get(data["password_state"], "未知")
        text += "\n权限：" + data.get("sudo_policy", "管理员组成员" if data["admin"] else "普通或系统账号")
        text += f"\nSSH 策略（{policy}）：\n密码认证：{value('passwordauthentication')}；交互认证：{value('kbdinteractiveauthentication')}；密钥认证：{value('pubkeyauthentication')}\n认证组合要求：{value('authenticationmethods')}；超级管理员登录：{value('permitrootlogin')}\n允许账号：{value('allowusers')}；禁止账号：{value('denyusers')}\n允许用户组：{value('allowgroups')}；禁止用户组：{value('denygroups')}\n公钥文件：{value('authorizedkeysfile')}\n认证次数：{value('maxauthtries')}；等待秒数：{value('logingracetime')}；隧道转发：{value('allowtcpforwarding')}"
        text += "\n本程序登录禁用：" + ("是" if data.get("managed_blocked") else "否")
        if detail:
            expiry = str(detail.get("account_expiry", "未设定"))
            if expiry.isdigit():
                try:
                    expiry = (datetime.date(1970, 1, 1) + datetime.timedelta(days=int(expiry))).isoformat()
                except (ValueError, OverflowError):
                    expiry = "日期超出可显示范围，请核对账号配置"
            text += "\n查询范围：" + detail.get("policy_scope", "") + "\n账号过期日期：" + expiry
            text += "\n公钥指纹：" + ("；".join(data.get("public_key_fingerprints", [])) or "标准公钥文件未发现钥匙")
        key_lines = []
        for path in paths:
            state = self.key_encryption.get(path)
            key_lines.append(path + "（" + ("已加密" if state is True else "未加密，可用一键方案更换" if state is False else "点击查看详情检查加密状态") + "）")
        text += "\n本机保存的私钥：\n" + ("\n".join(key_lines) if paths else "这台电脑没有该账号的私钥记录。服务器只有公钥，无法得知其他电脑的私钥位置。")
        text += "\n密码、私钥内容及私钥口令不包含在可复制信息中。登录能否成功还取决于账号状态、公钥选项、防火墙和云平台规则。"
        return text

    def _show_account_detail(self):
        if not self.report: return
        try:
            account = self._selected_account()
            text = self._account_info(account)
            if self.privacy.get():
                secrets_to_hide = [self.current.host]
                for row in self.report["accounts"]:
                    secrets_to_hide += [row["username"], row.get("home", "")]
                secrets_to_hide += [p.key_path for p in self.profiles if p.key_path]
                text = Redactor(*secrets_to_hide).text(text)
                text = "信息已隐藏；关闭右上角隐藏开关可查看真实账号和本机私钥位置。\n" + text
        except ManagerError:
            text = "先选中账号；可点击查看详情、复制信息或删除选中用户。"
        self._replace_text(self.account_detail_text, text)
