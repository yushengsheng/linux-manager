"""Page layout and presentation; actions use the shared App controller."""
import tkinter as tk
from tkinter import ttk

from .widgets import sync_tree


class ConnectionPages:
    def _connection_page(self):
        page = self.pages["连接服务器"].content
        self._description(page, "填写必要信息，其余交给程序", "首次连接确认服务器身份；连接后自动检查系统、服务和安全配置。已有服务会保持原样。")
        form = ttk.Frame(page)
        form.pack(anchor="w", fill="x")
        form.columnconfigure(1, weight=1)
        self.profile_choice = tk.StringVar()
        self._help_label(form, "保存的服务器").grid(row=0, column=0, sticky="e", padx=(0, 12), pady=6)
        self.profile_box = ttk.Combobox(form, textvariable=self.profile_choice, state="readonly", width=39)
        self.profile_box.grid(row=0, column=1, sticky="w", pady=6)
        self.profile_box.bind("<<ComboboxSelected>>", self._choose_profile)
        self._button(form, "添加新服务器", self._new_profile).grid(row=0, column=2, padx=12)
        self.label_var = tk.StringVar(value="我的服务器")
        self.host_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.auth_var = tk.StringVar(value="密码登录")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.passphrase_var = tk.StringVar()
        self.sudo_var = tk.StringVar()
        self.remember_var = tk.BooleanVar(value=True)
        self._field(form, 1, "服务器备注", self.label_var)
        self._field(form, 2, "服务器地址", self.host_var, True)
        self._field(form, 3, "登录账号", self.user_var, True)
        self._field(form, 4, "SSH 端口（TCP）", self.port_var)
        self._help_label(form, "登录方式").grid(row=5, column=0, sticky="e", padx=(0, 12))
        auth_box = ttk.Combobox(form, textvariable=self.auth_var, values=["密码登录", "密钥登录"], state="readonly")
        auth_box.grid(row=5, column=1, sticky="w", pady=6)
        auth_box.bind("<<ComboboxSelected>>", lambda event: self._auth_fields())
        self.password_entry = self._field(form, 6, "登录密码", self.password_var, True)
        self.key_entry = self._field(form, 7, "SSH 私钥", self.key_var, True)
        self.key_button = self._button(form, "选择文件", lambda: self._select_file(self.key_var, "选择 SSH 私钥"))
        self.key_button.grid(row=7, column=2, padx=12)
        self.passphrase_entry = self._field(form, 8, "私钥口令（如有）", self.passphrase_var, True)
        self._field(form, 9, "管理员密码（如不同）", self.sudo_var, True)
        self._check(form, "记住登录信息（仅本机）", self.remember_var).grid(row=10, column=1, sticky="w", pady=6)
        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(18, 10))
        self._button(actions, "连接并检查", self._connect, True).pack(side="left")
        self._button(actions, "保存连接档案", self._save_profile).pack(side="left", padx=12)
        self._button(actions, "VNC 登录排查", self._vnc_help).pack(side="left")
        self._button(actions, "重新确认服务器身份", self._reconfirm_identity).pack(side="left", padx=12)
        ttk.Label(page, text="这里填写已有密码和旧私钥口令，不生成替换。新系统密码可在“账号与登录”一键生成；新私钥口令在“安全防护”生成。", style="Muted.TLabel", wraplength=1000).pack(anchor="w", pady=8)
        self._auth_fields()

    def _auth_fields(self):
        key = self.auth_var.get() == "密钥登录"
        self.password_entry.configure(state="disabled" if key else "normal")
        for entry in [self.key_entry, self.passphrase_entry, self.key_button]:
            entry.configure(state="normal" if key else "disabled")

    def _fleet_page(self):
        page = self.pages["服务器列表"].content
        self._description(page, "多台服务器，各自保存登录信息", "同一台服务器的不同账号也能分别保存。先选中档案，再切换并连接；操作只针对当前已连接的服务器。")
        row = ttk.Frame(page); row.pack(fill="x", pady=(0, 16))
        self._button(row, "检查全部服务器", self._check_fleet).pack(side="left")
        self._button(row, "切换到选中服务器", self._switch_fleet).pack(side="left", padx=10)
        self._button(row, "移除本机档案", self._remove_profile).pack(side="left")
        self.fleet_tree = self._tree(page, [("label", "备注", 150), ("address", "服务器 / 账号", 230), ("auth", "登录方式", 100), ("state", "检查状态", 170), ("os", "系统", 230), ("time", "检查时间", 100)], height=10)
        self.fleet_tree.bind("<Double-1>", lambda event: self._switch_fleet())

    def _render_fleet(self):
        rows = []
        for profile in self.profiles:
            state, when = self.fleet_states.get(profile.identifier, ("尚未检查", "—"))
            report = self.fleet_reports.get(profile.identifier, {})
            address = "已隐藏" if self.privacy.get() else profile.host + " / " + profile.username
            rows.append((profile.identifier, (profile.label, address, "密钥" if profile.auth == "key" else "密码", state, report.get("os", "—"), when)))
        sync_tree(self.fleet_tree, rows)
        self._render_sidebar()
