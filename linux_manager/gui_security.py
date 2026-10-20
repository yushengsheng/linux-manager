"""Page layout and presentation; actions use the shared App controller."""
import tkinter as tk
from tkinter import ttk


class SecurityPage:
    def _security_page(self):
        page = self.pages["安全防护"].content
        self._help_label(page, "常用安全设置").pack(anchor="w", pady=(0, 8))
        self.protection_status = ttk.Label(page, text="先连接并检查服务器。", style="Muted.TLabel", wraplength=1000)
        self.protection_status.pack(anchor="w", pady=(0, 8))
        preset = ttk.LabelFrame(page, text="一键登录安全方案", padding=12); preset.pack(fill="x", pady=(0, 8))
        ttk.Label(preset, text="推荐", style="Recommended.TLabel").grid(row=0, column=2, sticky="ne", padx=(24, 0))
        preset.columnconfigure(2, weight=1)
        self.plan_mode = tk.StringVar(value="修改现有用户名和密钥")
        self.plan_username = tk.StringVar()
        self.plan_password = tk.StringVar()
        self.plan_phrase = tk.StringVar()
        self._help_label(preset, "安全方案类型").grid(row=0, column=0, sticky="e", padx=(0, 12))
        modes = ttk.Combobox(preset, textvariable=self.plan_mode, values=["修改现有用户名和密钥", "新增管理员和密钥"], state="readonly", width=32)
        modes.grid(row=0, column=1, sticky="w", pady=6)
        modes.bind("<<ComboboxSelected>>", self._plan_mode_changed)
        self._field(preset, 1, "目标账号名", self.plan_username, True, 32)
        self._field(preset, 2, "系统新密码（可留空）", self.plan_password, True, 32)
        self._field(preset, 3, "加密私钥口令（可留空）", self.plan_phrase, True, 32)
        self._button(preset, "生成密码", lambda: self._generate_password(self.plan_password)).grid(row=2, column=2, sticky="w", padx=12)
        self._button(preset, "生成口令", lambda: self._generate_password(self.plan_phrase, private_key=True)).grid(row=3, column=2, sticky="w", padx=12)
        self.plan_retire = tk.BooleanVar(value=True)
        self.plan_fail2ban = tk.BooleanVar(value=True)
        self.plan_updates = tk.BooleanVar(value=True)
        self.plan_checks = {}
        options = ttk.Frame(preset)
        options.grid(row=4, columnspan=3, sticky="ew", pady=(8, 0))
        options.columnconfigure(0, weight=1); options.columnconfigure(1, weight=1)
        for i, (label, variable) in enumerate([("验证后撤销原档案旧钥匙", self.plan_retire), ("方案中启用防猜密码保护", self.plan_fail2ban), ("方案中启用自动安全更新", self.plan_updates)]):
            check = self._check(options, label, variable)
            check.grid(row=i // 2, column=i % 2, sticky="w", pady=3, padx=(0, 20))
            self.plan_checks[label] = check.checkbox
        self.plan_hint = ttk.Label(preset, text="修改当前普通管理员，并全局禁止 SSH 密码登录；名称相同则保留用户名。", style="Muted.TLabel", wraplength=930)
        self.plan_hint.grid(row=5, columnspan=3, sticky="w", pady=(6, 4))
        self.plan_policy_hint = ttk.Label(preset, text="私钥与口令仅存本机 · 保留端口与现有地址规则", style="Muted.TLabel", wraplength=930)
        self.plan_policy_hint.grid(row=6, columnspan=3, sticky="w", pady=(0, 6))
        self.plan_apply = self._button(preset, "预览并应用一键安全方案", self._apply_security_plan, True)
        self.plan_apply.grid(row=7, columnspan=2, sticky="w", pady=(0, 3))
        custom_header = ttk.Frame(page, padding=(0, 8, 0, 8)); custom_header.pack(fill="x")
        self.custom_security_open = False
        self.custom_security_toggle = self._button(custom_header, "自定义设置", self._toggle_custom_security, track=False)
        self.custom_security_toggle.pack(side="left")
        ttk.Label(custom_header, text="按需调整防火墙、SSH 连接及封禁规则", style="Muted.TLabel").pack(side="left", padx=14)
        self.custom_security_frame = ttk.Frame(page)
        custom = self.custom_security_frame
        row = ttk.Frame(custom); row.pack(fill="x", pady=(12, 14))
        self._button(row, "启用防火墙并保留现有规则", self._firewall).pack(side="left")
        self._button(row, "开启自动安全更新", self._updates).pack(side="left", padx=10)
        ssh = ttk.LabelFrame(custom, text="SSH 连接防护", padding=12); ssh.pack(fill="x", pady=8)
        self.auth_tries = tk.StringVar(value="3")
        self.login_grace = tk.StringVar(value="120")
        self.alive_interval = tk.StringVar(value="0")
        self.tcp_forwarding = tk.BooleanVar(value=True)
        self.x11_forwarding = tk.BooleanVar(value=False)
        self.agent_forwarding = tk.BooleanVar(value=False)
        for index, (label, variable) in enumerate([("单次连接允许尝试次数", self.auth_tries), ("完成登录的等待秒数", self.login_grace), ("断线检查间隔秒数", self.alive_interval)]):
            self._field(ssh, index, label, variable, width=18)
        for index, (label, variable) in enumerate([("允许 SSH 隧道转发", self.tcp_forwarding), ("允许图形界面转发", self.x11_forwarding), ("允许转交本机密钥代理", self.agent_forwarding)], start=3):
            self._check(ssh, label, variable).grid(row=index, columnspan=2, sticky="w", pady=5)
        self._button(ssh, "应用 SSH 防护设置", self._harden_ssh, True).grid(row=6, columnspan=2, sticky="w", pady=10)
        jail = ttk.LabelFrame(custom, text="防猜密码保护", padding=12); jail.pack(fill="x", pady=8)
        self.ban_attempts = tk.StringVar(value="5")
        self.ban_window = tk.StringVar(value="10")
        self.ban_duration = tk.StringVar(value="60")
        for index, (label, variable) in enumerate([("连续失败次数", self.ban_attempts), ("统计时间（分钟）", self.ban_window), ("封禁时长（分钟）", self.ban_duration)]):
            self._field(jail, index, label, variable, width=18)
        actions = ttk.Frame(jail); actions.grid(row=3, columnspan=2, sticky="w", pady=10)
        self._button(actions, "启用防猜密码保护", lambda: self._fail2ban(True)).pack(side="left")
        self._button(actions, "关闭本程序的防猜密码保护", lambda: self._fail2ban(False)).pack(side="left", padx=10)

    def _toggle_custom_security(self):
        self.custom_security_open = not self.custom_security_open
        if self.custom_security_open:
            self.custom_security_frame.pack(fill="x", pady=(0, 8))
        else:
            self.custom_security_frame.pack_forget()
        self.custom_security_toggle.button.configure(text="收起自定义设置" if self.custom_security_open else "自定义设置")

    def _plan_mode_changed(self, event=None):
        create = self.plan_mode.get() == "新增管理员和密钥"
        if event is not None:
            self.plan_username.set(self.current.username if self.current and not create and self.current.username != "root" else "")
        self.plan_checks["验证后撤销原档案旧钥匙"].configure(state="disabled" if create or not self.current or self.current.auth != "key" else "normal")
        for label in ("方案中启用防猜密码保护", "方案中启用自动安全更新"):
            self.plan_checks[label].configure(state="disabled" if create else "normal")
        self.plan_hint.configure(text="仅新管理员使用密钥登录；原账号与其他账号的登录方式保持不变。" if create else "修改当前普通管理员，并全局禁止 SSH 密码登录；名称相同则保留用户名。")
        self.plan_policy_hint.configure(text="新增模式不调整全局防猜密码保护或自动更新 · 私钥与口令仅存本机" if create else "验证新密钥后，全局禁止密码及超级管理员直接登录 · 保留端口与现有地址规则")
