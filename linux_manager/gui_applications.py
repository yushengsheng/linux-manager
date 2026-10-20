"""Page layout and presentation; actions use the shared App controller."""
import secrets
import tkinter as tk
from tkinter import ttk
import webbrowser

from .client_config import CLIENTS
from .gui_common import INK
from .models import SERVICES
from .oauth_contract import OAUTH_PROVIDERS
from .project_info import SERVICE_PROTOCOLS, credential_alias, deployment_network_hint, server_key
from .qr import is_node_link
from .releases import KEEP_CURRENT, LATEST_STABLE, SPECIFIC_VERSION
from .widgets import sync_tree


class ApplicationPages:
    def _deployment_page(self):
        page = self.pages["一键部署"].content
        self._description(page, "选择项目，点击部署", "首次安装自动准备依赖与证书；已有项目先比对条件，只调整变化的配置，版本切换先备份并保留数据。")
        form = ttk.Frame(page); form.pack(fill="x")
        form.columnconfigure(0, minsize=190)
        self.deploy_choice = tk.StringVar(value="小军交易系统")
        self._help_label(form, "要安装的项目").grid(row=0, column=0, sticky="e", padx=(0, 12))
        box = ttk.Combobox(form, textvariable=self.deploy_choice, values=[v[0] for v in SERVICES.values()], state="readonly", width=37)
        box.grid(row=0, column=1, sticky="w", pady=6); box.bind("<<ComboboxSelected>>", self._deploy_defaults)
        self.deploy_host = tk.StringVar()
        self.deploy_port = tk.StringVar(value="26483")
        self.deploy_backend = tk.StringVar(value="18880")
        self.deploy_username = tk.StringVar(value="manager")
        self.deploy_password = tk.StringVar()
        self.deploy_api_key = tk.StringVar()
        self.deploy_auto_update = tk.BooleanVar(value=True)
        self.deploy_server_name = tk.StringVar(value="www.cloudflare.com")
        self.version_mode = tk.StringVar(value=LATEST_STABLE)
        self.deploy_version = tk.StringVar(value="部署前自动获取")
        self.deploy_rows = {}
        for index, (name, label, variable, private) in enumerate([
            ("port", "服务端口", self.deploy_port, False),
            ("username", "面板账号（代理面板）", self.deploy_username, True),
            ("proxy_password", "服务密码（代理服务）", self.deploy_password, True),
            ("panel_password", "面板密码", self.deploy_password, True),
            ("management_key", "管理 Key（后台登录）", self.deploy_password, True),
            ("api_key", "客户端 API Key", self.deploy_api_key, True),
        ], start=1):
            row = ttk.Frame(form); row.grid(row=index, column=0, columnspan=2, sticky="w")
            row.columnconfigure(0, minsize=190)
            self._field(row, 0, label, variable, private)
            if name == "port":
                self.deploy_port_protocol = ttk.Label(row, text="TCP（网页入口）")
                self.deploy_port_protocol.grid(row=0, column=2, sticky="w", padx=12)
            if name.endswith("password"):
                self._button(row, "生成密码", lambda: self._generate_password(self.deploy_password)).grid(row=0, column=2, padx=12)
            if name in {"management_key", "api_key"}:
                self._button(row, "生成 Key", lambda v=variable: self._generate_password(v)).grid(row=0, column=2, padx=12)
            self.deploy_rows[name] = row
        self.deploy_optional_open = False
        self.deploy_optional_header = ttk.Frame(page)
        self.deploy_optional_header.pack(fill="x", pady=(14, 0))
        self.deploy_optional_toggle = self._button(self.deploy_optional_header, "可选设置", self._toggle_deploy_optional, track=False)
        self.deploy_optional_toggle.pack(side="left")
        ttk.Label(self.deploy_optional_header, text="使用域名、调整内部端口或指定版本时展开", style="Muted.TLabel").pack(side="left", padx=14)
        self.deploy_optional_frame = ttk.Frame(page)
        self.deploy_optional_rows = {}
        for index, (name, label, variable, private) in enumerate([
            ("host", "访问域名（可留空）", self.deploy_host, True),
            ("backend", "内部端口", self.deploy_backend, False),
            ("server_name", "REALITY 目标域名", self.deploy_server_name, False),
        ]):
            row = ttk.Frame(self.deploy_optional_frame); row.grid(row=index, column=0, sticky="w")
            row.columnconfigure(0, minsize=190)
            self._field(row, 0, label, variable, private)
            if name == "backend":
                ttk.Label(row, text="TCP · 仅本机，不向公网开放", style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=12)
            self.deploy_optional_rows[name] = row
        auto_row = ttk.Frame(self.deploy_optional_frame); auto_row.grid(row=5, column=0, sticky="w")
        ttk.Checkbutton(auto_row, text="CLIProxyAPI 自动更新核心和管理页面（每 30 分钟）", variable=self.deploy_auto_update).pack(anchor="w")
        self.deploy_optional_rows["auto_update"] = auto_row
        version_row = ttk.Frame(self.deploy_optional_frame); version_row.grid(row=3, column=0, sticky="w")
        version_row.columnconfigure(0, minsize=190)
        self.deploy_optional_rows["version_mode"] = version_row
        self._help_label(version_row, "版本选择").grid(row=0, column=0, sticky="e", padx=(0, 12), pady=6)
        self.version_box = ttk.Combobox(version_row, textvariable=self.version_mode, values=[LATEST_STABLE, SPECIFIC_VERSION], state="readonly", width=37)
        self.version_box.grid(row=0, column=1, sticky="w", pady=6)
        self.version_box.bind("<<ComboboxSelected>>", self._version_fields)
        version_entry_row = ttk.Frame(self.deploy_optional_frame); version_entry_row.grid(row=4, column=0, sticky="w")
        version_entry_row.columnconfigure(0, minsize=190)
        self.deploy_optional_rows["version"] = version_entry_row
        self.version_entry = self._field(version_entry_row, 0, "安装版本", self.deploy_version)
        self.version_entry.configure(state="disabled")
        self.deploy_hint = ttk.Label(page, text="只需确认服务端口。程序密码在首次打开交易系统网页时设置；内部端口使用默认值，安装版本自动获取官方最新稳定版。", style="Muted.TLabel", wraplength=1000)
        self.deploy_hint.pack(anchor="w", pady=18)
        actions = ttk.Frame(page); actions.pack(fill="x")
        self._button(actions, "预览并部署", self._deploy, True).pack(side="left")
        self._button(actions, "查看访问 / 连接信息", self._details).pack(side="left", padx=12)
        self.deploy_network_hint = ttk.Label(page, style="Muted.TLabel", wraplength=1000, justify="left")
        self.deploy_network_hint.pack(anchor="w", pady=18)
        self.deploy_port.trace_add("write", self._deploy_network_changed)
        self.deploy_backend.trace_add("write", self._deploy_network_changed)
        self._deployment_fields()

    def _maintenance_page(self):
        page = self.pages["日常维护"].content
        self._description(page, "管理已安装的服务", "每次只操作选中的项目。交易系统停止或重启前，需要确认交易任务已经停止并完成清理。")
        top = ttk.Frame(page); top.pack(fill="x")
        self.manage_choice = tk.StringVar(value="小军交易系统")
        self._help_label(top, "要管理的项目").pack(side="left", padx=(0, 10))
        project_box = self.manage_project_box = ttk.Combobox(top, textvariable=self.manage_choice, values=[v[0] for v in SERVICES.values()], state="readonly", width=36)
        project_box.pack(side="left")
        project_box.bind("<<ComboboxSelected>>", self._project_changed)
        self._button(top, "刷新读取全部项目", self._external_projects).pack(side="left", padx=(12, 0))
        actions = ttk.Frame(page); actions.pack(fill="x", pady=(12, 0))
        self._button(actions, "刷新项目信息", self._refresh_project_info).pack(side="left")
        self._button(actions, "查看运行日志", self._logs).pack(side="left", padx=12)
        self.manage_config_button = self._button(actions, "安装 / 调整配置", self._configure_project)
        self.manage_config_button.pack(side="left")
        self._button(actions, "登记项目目录", self._register_external_directory).pack(side="left", padx=12)
        self.manage_forget_button = self._button(actions, "移除本机登记", self._forget_external_directory)
        self.manage_forget_button.pack(side="left")
        information = ttk.LabelFrame(page, text="项目信息 · 可直接复制使用", padding=12); information.pack(fill="x", pady=(12, 8))
        self.project_info_tree = self._tree(information, [("name", "信息", 240), ("value", "内容", 660), ("qr", "扫码", 60)], height=9)
        self.project_info_tree.column("qr", width=60, minwidth=60, stretch=False, anchor="center")
        self.project_info_tree.bind("<<TreeviewSelect>>", self._select_project_info)
        self.project_info_tree.bind("<ButtonRelease-1>", self._node_qr_clicked)
        self.project_info_value = tk.StringVar()
        link_row = ttk.Frame(information); link_row.pack(fill="x", pady=8)
        ttk.Entry(link_row, textvariable=self.project_info_value, state="readonly").pack(side="left", fill="x", expand=True)
        self.node_qr_icon = tk.PhotoImage(master=link_row, width=21, height=21)
        self.node_qr_icon.put("white", to=(0, 0, 21, 21))
        for x, y in [(1, 1), (13, 1), (1, 13)]:
            self.node_qr_icon.put(INK, to=(x, y, x+7, y+7)); self.node_qr_icon.put("white", to=(x+1, y+1, x+6, y+6)); self.node_qr_icon.put(INK, to=(x+2, y+2, x+5, y+5))
        for x, y in [(10, 9), (13, 12), (17, 10), (10, 16), (16, 16), (18, 19)]:self.node_qr_icon.put(INK, to=(x, y, x+2, y+2))
        self.node_qr_button = self._button(link_row, "展示节点二维码", self._show_selected_node_qr, track=False)
        self.node_qr_button.button.configure(image=self.node_qr_icon, text="", width=3, state="disabled")
        self.node_qr_button.pack(side="left", padx=(8, 0))
        actions = ttk.Frame(information); actions.pack(fill="x")
        self._button(actions, "复制选中项", self._copy_project_item).pack(side="left")
        self._button(actions, "复制全部项目信息", self._copy_project_information).pack(side="left", padx=10)
        self._button(actions, "打开项目网址", self._open_project_url).pack(side="left")
        self._button(actions, "补充登录信息", self._save_project_credentials).pack(side="left", padx=10)
        row = ttk.Frame(page); row.pack(fill="x", pady=18)
        self.manage_service_buttons = {}
        for title, action in [("启动", "start"), ("停止", "stop"), ("重启", "restart"), ("开启开机启动", "enable"), ("关闭开机启动", "disable")]:
            button = self._button(row, title, lambda a=action: self._service(a))
            button.pack(side="left", padx=(0, 9)); self.manage_service_buttons[action] = button
        self.ai_maintenance = ttk.Frame(page)
        for title, action in [("检查并更新 AI", "check_update"), ("开启 AI 自动更新", "enable_update"), ("关闭 AI 自动更新", "disable_update"), ("回滚 AI 核心", "rollback_core")]:
            self._button(self.ai_maintenance, title, lambda a=action: self._service(a)).pack(side="left", padx=(0, 9))
        self.ai_oauth = ttk.Frame(page)
        for title, provider in [("登录 Codex", "codex"), ("登录 Antigravity", "antigravity")]:
            self._button(self.ai_oauth, title, lambda p=provider: self._oauth(p)).pack(side="left", padx=(0, 9))
        self.oauth_choices = {spec['label']: name for name, spec in OAUTH_PROVIDERS.items() if name not in {'codex', 'antigravity'}}
        self.oauth_provider = tk.StringVar(value="Claude")
        ttk.Combobox(self.ai_oauth, textvariable=self.oauth_provider, values=list(self.oauth_choices), state="readonly", width=16).pack(side="left", padx=(4, 9))
        self._button(self.ai_oauth, "登录所选提供商", lambda: self._oauth(self.oauth_choices[self.oauth_provider.get()])).pack(side="left")
        self.ai_clients = ttk.LabelFrame(page, text="本机客户端 · 配置与恢复", padding=12)
        client_actions = ttk.Frame(self.ai_clients); client_actions.pack(fill="x")
        for client, title in CLIENTS.items():
            label = "一键配置 GPT" if client == "codex" else "一键配置 " + title
            self._button(client_actions, label, lambda name=client: self._configure_local_client(name)).pack(side="left", padx=(0, 9))
        restore_clients = ttk.Frame(self.ai_clients); restore_clients.pack(fill="x", pady=(10, 0))
        self.local_client_choice = tk.StringVar(value=CLIENTS["codex"])
        ttk.Combobox(restore_clients, textvariable=self.local_client_choice, values=list(CLIENTS.values()), state="readonly", width=19).pack(side="left", padx=(0, 9))
        self._button(restore_clients, "恢复原客户端配置", self._restore_local_client).pack(side="left")
        self._button(restore_clients, "选择已安装应用", self._choose_local_client_application).pack(side="left", padx=(9, 0))
        ttk.Label(self.ai_clients, text="只配置这台电脑；自动备份，可恢复到首次配置前或任一历史版本。配置后需重启客户端。", style="Muted.TLabel", wraplength=920).pack(anchor="w", pady=(8, 0))
        removal = ttk.Frame(page); self.maintenance_removal = removal; removal.pack(fill="x", pady=(0, 8))
        self.manage_uninstall_button = self._button(removal, "卸载所选项目", self._uninstall)
        self.manage_uninstall_button.pack(side="left")
        ttk.Label(removal, text="移除程序和专属服务，默认保留配置、账号及业务数据。", style="Muted.TLabel", wraplength=640).pack(side="left", padx=12)
        security = ttk.LabelFrame(page, text="安全与配置备份", padding=12); security.pack(fill="x", pady=8)
        self.manage_backup_button = self._button(security, "备份所选服务配置", self._backup)
        self.manage_backup_button.grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 8))
        self._button(security, "备份安全配置", lambda: self._backup("security")).grid(row=0, column=1, sticky="w", pady=(0, 8))
        self._button(security, "启用防火墙并保留现有规则", self._firewall).grid(row=1, column=0, sticky="w", padx=(0, 10))
        self._button(security, "开启自动安全更新", self._updates).grid(row=1, column=1, sticky="w")
        restore = ttk.Frame(page); restore.pack(fill="x", pady=18)
        self._help_label(restore, "备份编号").pack(side="left", padx=(0, 10))
        self.restore_id = tk.StringVar()
        ttk.Entry(restore, textvariable=self.restore_id, width=32).pack(side="left")
        self._button(restore, "预览并恢复配置", self._restore).pack(side="left", padx=12)
        self.maintenance_text = tk.Text(page, height=11, wrap="word", bg="white", foreground=INK, font="TkDefaultFont", relief="flat", padx=14, pady=14, state="disabled")
        self.maintenance_text.pack(fill="both", expand=True)
        self._replace_text(self.maintenance_text, "服务日志会在这里显示。\n备份保存在服务器，仅管理员可读取。恢复前会再备份当前配置。\n业务系统的账号、交易账本及运行数据使用其自身备份机制。")

    def _service_key(self, choice):
        builtin = next((key for key, value in SERVICES.items() if value[0] == choice), "")
        if builtin: return builtin
        identity = server_key(self.current) if self.current else ""
        if self.__dict__.get("manage_catalog_identity") == identity:
            return self.__dict__.get("manage_project_labels", {}).get(choice, "")
        return ""

    def _restore_project_snapshots(self, snapshots):
        if not isinstance(snapshots, dict): return
        from .external_projects import ExternalProjects
        for identity, result in snapshots.get("servers", {}).items():
            c = next((p for p in self.profiles if server_key(p) == identity), None)
            if not c: continue
            for project in result["projects"]:
                info = {"project": project, "fingerprint": ExternalProjects.fingerprint(project), "saved_at": result.get("saved_at", "")}
                self._cache_external_information(c, info)
            for key, info in result.get("builtin_information", {}).items():
                info["rows"] = list(info.get("rows", [])) + [("保存时间", result.get("saved_at", "")), ("信息来源", "本机保存的上次读取结果；刷新可更新状态。")]
                self.project_details[(identity, key)] = info
        self.project_cache_warnings = snapshots.get("warnings", [])

    def _sync_manage_projects(self):
        from .external_projects_gui import KINDS
        identity = server_key(self.current) if self.current else ""
        projects = self.__dict__.get("external_catalogs", {}).get(identity, {})
        selected = self._service_key(self.manage_choice.get())
        labels = {value[0]: key for key, value in SERVICES.items()}
        hidden = self.privacy.get()
        for index, (key, project) in enumerate(projects.items(), 1):
            name = project.get("product") or ("外部项目 " + str(index) if hidden else project["name"])
            base = name + " · " + KINDS.get(project["kind"], "外部项目")
            label = base
            if not hidden and project.get("product") and project["name"] != project["product"]:
                label += "（" + project["name"] + "）"
            number = 2
            while label in labels:
                label = base + "（" + str(number) + "）"; number += 1
            labels[label] = key
        self.manage_catalog_identity = identity
        self.manage_project_labels = labels
        self.manage_project_box.configure(values=list(labels))
        label = next((label for label, key in labels.items() if key == selected), next(iter(labels)))
        self.manage_choice.set(label)

    def _cache_external_information(self, connection, information):
        from .external_projects_gui import information_rows
        key = information["project"]["id"]
        identity = server_key(connection)
        self.project_details[(identity, key)] = {"external": information, "rows": information_rows(information, connection)}
        self.__dict__.setdefault("external_catalogs", {}).setdefault(identity, {})[key] = information["project"]

    def _manage_action_states(self):
        key = self._service_key(self.manage_choice.get())
        identity = server_key(self.current) if self.current else ""
        info = self.project_details.get((identity, key), {}).get("external", {})
        builtin = key in SERVICES
        available = not self.__dict__.get("busy", False)
        for action, button in self.__dict__.get("manage_service_buttons", {}).items():
            enabled = available and (builtin or action in info.get("project", {}).get("capabilities", []))
            button.configure(state="normal" if enabled else "disabled")
        for name in ("manage_config_button", "manage_uninstall_button", "manage_backup_button"):
            if name in self.__dict__:
                self.__dict__[name].configure(state="normal" if builtin and available else "disabled")
        if "manage_forget_button" in self.__dict__:
            enabled = available and info.get("project", {}).get("registered_local")
            self.manage_forget_button.configure(state="normal" if enabled else "disabled")

    def _deploy_defaults(self, _=None):
        key = self._service_key(self.deploy_choice.get())
        defaults = {"exchange": (26483, "部署前自动获取"), "hysteria2": (51752, "v1.14.2"), "reality": (443, "v26.3.27"), "xui": (2053, "v3.9.0"), "nginx": (80, "系统软件包"), "cliproxyapi": (9229, "部署前自动获取")}
        number, version = defaults[key]; self.deploy_port.set(str(number)); self.deploy_version.set(version)
        self.version_mode.set(LATEST_STABLE)
        current = self._deployment_current(key)
        if current:
            self.deploy_port.set(str(current.get("port", number)))
            self.deploy_host.set(current.get("host", ""))
            self.deploy_version.set(current.get("version") or "预览时读取现有版本")
            self.version_mode.set(KEEP_CURRENT)
            if key == "exchange": self.deploy_backend.set(str(current.get("backend_port", 18880)))
            if key == "cliproxyapi":
                self.deploy_backend.set(str(current.get("backend_port", 8317)))
                self.deploy_password.set(self.store.vault.cache.get(credential_alias(self.current, key), {}).get("management_key", ""))
                self.deploy_api_key.set(next(iter(current.get("api_keys", [])), ""))
                self.deploy_auto_update.set(current.get("timers", {}).get("linux-manager-cliproxyapi-update.timer", {}).get("UnitFileState") == "enabled")
            if key == "reality": self.deploy_server_name.set(current.get("server_name", "www.cloudflare.com"))
            if key == "hysteria2": self.deploy_password.set(current.get("proxy_password", ""))
            if key == "xui":
                self.deploy_username.set(current.get("panel_username", ""))
                values = self.store.vault.cache.get(credential_alias(self.current, key), {})
                self.deploy_password.set(values.get("panel_password", ""))
        else:
            self.deploy_host.set("")
            self.deploy_password.set("")
            self.deploy_username.set("manager")
            self.deploy_backend.set("8317" if key == "cliproxyapi" else "18880")
            if key == "cliproxyapi":
                self.deploy_password.set(secrets.token_urlsafe(32))
                self.deploy_api_key.set(secrets.token_urlsafe(32))
                self.deploy_auto_update.set(True)
            self.deploy_server_name.set("www.cloudflare.com")
        self._deployment_fields()
        hints = {"exchange": "确认 TCP 网页端口即可。已有项目先比对条件，只调整改变的配置；版本变化会备份并切换版本，保留业务数据。", "hysteria2": "填写 UDP 节点端口和服务密码；HY2 不使用 TCP 节点端口。已有项目会按新条件调整；原密码不变时可以留空。", "reality": "只填 TCP 节点端口；连接凭据自动生成，无需自有域名和证书。部署后在运行与备份复制 VLESS 节点链接，或点击二维码图标扫码导入。已有节点调整端口或版本时保留原凭据。", "xui": "填写 TCP 面板端口、面板账号和密码；节点端口另按各自协议放行。已有项目的密码不变时可留空；节点和订阅保持。", "nginx": "默认 TCP 80，可填写其他端口。版本使用系统软件源；已有配置会先备份，网站文件保留。"}
        hints["cliproxyapi"] = "默认使用 IP＋HTTPS，无需域名。管理 Key 用于后台登录；客户端 Key 可供多设备共用。添加上游账号后才能调用模型。自动更新运行在服务器上。"
        self.deploy_hint.configure(text=hints[key])

    def _deployment_current(self, key):
        c = self.__dict__.get("current")
        if c is None or self.__dict__.get("report_server_key") != server_key(c): return {}
        information = self.__dict__.get("project_details", {}).get((server_key(c), key), {})
        data = information.get("data", {})
        return data if (data.get("installed") or data.get("uninstalled")) and (key != "nginx" or data.get("config_file")) else {}

    def _sync_deployment_server(self, c):
        if "deploy_choice" in self.__dict__ and self.__dict__.get("deployment_context") != server_key(c):
            self.deployment_context = server_key(c)
            self._deploy_defaults()

    def _deployment_fields(self):
        key = self._service_key(self.deploy_choice.get())
        visible = {"exchange": {"port"}, "hysteria2": {"port", "proxy_password"}, "reality": {"port"}, "xui": {"port", "username", "panel_password"}, "nginx": {"port"}, "cliproxyapi": {"port", "management_key", "api_key"}}[key]
        for name, row in self.deploy_rows.items():
            row.grid() if name in visible else row.grid_remove()
        for name, row in self.deploy_optional_rows.items():
            shown = name == "host" and key != "nginx" or name == "backend" and key in {"exchange", "cliproxyapi"} or name == "server_name" and key == "reality" or name == "version_mode" or name == "auto_update" and key == "cliproxyapi"
            if name != "version":
                row.grid() if shown else row.grid_remove()
        self.deploy_optional_header.pack(fill="x", pady=(14, 0), before=self.deploy_hint)
        if self.deploy_optional_open:
            self.deploy_optional_frame.pack(fill="x", pady=(8, 0), before=self.deploy_hint)
        self.deploy_network_hint.pack(anchor="w", pady=18)
        self._deploy_network_changed()
        self._version_fields()

    def _deploy_network_changed(self, *_):
        key = self._service_key(self.deploy_choice.get())
        purpose = "HY2 节点" if key == "hysteria2" else "REALITY 节点" if key == "reality" else "面板网页" if key == "xui" else "网页入口"
        self.deploy_port_protocol.configure(text=SERVICE_PROTOCOLS[key]+"（"+purpose+"）")
        self.deploy_network_hint.configure(text=deployment_network_hint(key, self.deploy_port.get().strip(), self.deploy_backend.get().strip()))

    def _toggle_deploy_optional(self):
        self.deploy_optional_open = not self.deploy_optional_open
        if self.deploy_optional_open:
            self.deploy_optional_frame.pack(fill="x", pady=(8, 0), before=self.deploy_hint)
        else:
            self.deploy_optional_frame.pack_forget()
        self.deploy_optional_toggle.button.configure(text="收起可选设置" if self.deploy_optional_open else "可选设置")

    def _version_fields(self, _=None):
        key = self._service_key(self.deploy_choice.get())
        automatic = self.version_mode.get() == LATEST_STABLE
        keeping = self.version_mode.get() == KEEP_CURRENT
        choices = [LATEST_STABLE, SPECIFIC_VERSION]
        if self._deployment_current(key): choices.insert(0, KEEP_CURRENT)
        self.version_box.configure(state="readonly", values=choices)
        self.version_entry.configure(state="disabled" if automatic or keeping else "normal")
        if automatic:
            self.deploy_version.set("部署前自动获取" if key != "nginx" else "预览时读取系统仓库版本")
        elif not keeping and key != "nginx" and not self.deploy_version.get().startswith("v"):
            self.deploy_version.set({"exchange":"v1.1.85", "hysteria2":"v1.14.3", "reality":"v26.3.27", "xui":"v3.9.0", "cliproxyapi":"v8.0.27"}[key])
        elif not keeping and key == "nginx" and self.deploy_version.get().startswith(("预览", "系统")):
            self.deploy_version.set("")
        if "deploy_optional_rows" in self.__dict__:
            row = self.deploy_optional_rows["version"]
            row.grid_remove() if automatic else row.grid()

    def _project_changed(self, _=None):
        if "manage_project_box" in self.__dict__: self._sync_manage_projects()
        key = self._service_key(self.manage_choice.get())
        identity = server_key(self.current) if self.current else ""
        information = self.project_details.get((identity,key), {})
        if "ai_maintenance" in self.__dict__:
            if key == "cliproxyapi": self.ai_maintenance.pack(fill="x", pady=(0, 10), before=self.maintenance_removal)
            else: self.ai_maintenance.pack_forget()
        if "ai_oauth" in self.__dict__:
            if key == "cliproxyapi": self.ai_oauth.pack(fill="x", pady=(0, 10), before=self.maintenance_removal)
            else: self.ai_oauth.pack_forget()
        if "ai_clients" in self.__dict__:
            if key == "cliproxyapi": self.ai_clients.pack(fill="x", pady=(0, 10), before=self.maintenance_removal)
            else: self.ai_clients.pack_forget()
        self.project_rows = list(information.get("rows", []))
        hidden = self.privacy.get()
        sync_tree(self.project_info_tree, [(str(i),(name,"已隐藏；关闭右上角隐藏开关可查看" if hidden and name not in {"项目状态","安装版本","端口协议"} else value, "▦" if is_node_link(value) else "")) for i,(name,value) in enumerate(self.project_rows)])
        self.project_info_value.set("")
        if "node_qr_button" in self.__dict__: self.node_qr_button.configure(state="disabled")
        if not self.project_rows:
            sync_tree(self.project_info_tree, [("placeholder",("项目信息","连接服务器后点击刷新；只显示当前服务器的项目。"))])
        self._replace_text(self.maintenance_text,self.project_logs.get((identity,key),"所选项目的运行日志会在这里显示。点击「查看运行日志」读取。"))
        self._manage_action_states()
        if "service_tree" in self.__dict__: self._render_overview_projects()

    def _select_project_info(self, _=None):
        selected = self.project_info_tree.selection()
        if selected and selected[0].isdigit() and int(selected[0])<len(self.project_rows):
            value = self.project_rows[int(selected[0])][1]
            self.project_info_value.set("已隐藏" if self.privacy.get() else value)
            if "node_qr_button" in self.__dict__: self.node_qr_button.configure(state="normal" if is_node_link(value) else "disabled")

    def _node_qr_clicked(self, event):
        if self.project_info_tree.identify_column(event.x) != "#3":return
        row = self.project_info_tree.identify_row(event.y)
        if row.isdigit() and int(row) < len(self.project_rows) and is_node_link(self.project_rows[int(row)][1]):
            self.project_info_tree.selection_set(row)
            self._show_node_qr(self.project_rows[int(row)][1])

    def _show_selected_node_qr(self):
        selected = self.project_info_tree.selection()
        if selected and selected[0].isdigit() and int(selected[0]) < len(self.project_rows):
            value = self.project_rows[int(selected[0])][1]
            if is_node_link(value):self._show_node_qr(value)

    def _copy_project_item(self):
        selected = self.project_info_tree.selection()
        if selected and selected[0].isdigit() and int(selected[0])<len(self.project_rows):
            self._copy(self.project_rows[int(selected[0])][1])
        else:
            self.status.configure(text="请先选中需要复制的信息。")

    def _copy_project_information(self):
        if self.project_rows:
            self._copy("\n".join(name+"："+value for name,value in self.project_rows))

    def _open_project_url(self):
        url = next((value for name,value in self.project_rows if name in {"后台网址","软件网址","项目管理网址"}),"")
        if url.startswith(("https://","http://")):
            webbrowser.open(url)
        else:
            self.status.configure(text="所选项目没有网页入口；请复制节点或订阅链接使用。")
