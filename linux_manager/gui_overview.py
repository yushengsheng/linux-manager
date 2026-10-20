"""Page layout and presentation; actions use the shared App controller."""
from tkinter import ttk

from .gui_common import readable_size
from .models import SERVICES
from .project_info import server_key
from .widgets import sync_tree


class OverviewPage:
    def _overview_page(self):
        page = self.pages["服务器总览"].content
        top = ttk.Frame(page)
        top.pack(fill="x")
        self._button(top, "重新检查", self._refresh).pack(side="right")
        self.system_label = ttk.Label(top, text="连接后显示服务器信息", style="Heading.TLabel")
        self.system_label.pack(side="left", pady=10)
        cards = ttk.Frame(page)
        cards.pack(fill="x", pady=(10, 14))
        self.statistics = {}
        for index, (key, label) in enumerate([("disk", "可用磁盘"), ("memory", "可用内存"), ("services", "运行中的项目"), ("security", "SSH 登录方式")]):
            card = ttk.Frame(cards, style="Card.TFrame", padding=12)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 10, 0))
            cards.columnconfigure(index, weight=1)
            ttk.Label(card, text=label, style="Card.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="—", style="Stat.TLabel")
            value.pack(anchor="w", pady=(8, 2))
            self.statistics[key] = value
        ttk.Label(page, text="项目与配套服务", style="Heading.TLabel").pack(anchor="w", pady=(0, 12))
        services = ttk.Frame(page); services.pack(fill="x")
        self.service_tree = self._tree(services, [("name", "项目", 185), ("status", "运行状态", 130), ("startup", "开机启动", 130), ("purpose", "作用", 460)], height=5)
        self.service_tree.pack_configure(side="left", expand=True)
        scrollbar = ttk.Scrollbar(services, orient="vertical", command=self.service_tree.yview)
        scrollbar.pack(side="right", fill="y"); self.service_tree.configure(yscrollcommand=scrollbar.set)
        self.service_tree.bind("<Double-1>", self._open_selected_project)
        self.service_tree.bind("<Return>", self._open_selected_project)
        self._button(page, "管理选中项目", self._open_selected_project).pack(anchor="w", pady=(12, 0))
        self.security_summary = ttk.Label(page, text="安全状态将在连接检查后显示。", style="Muted.TLabel", wraplength=1000, justify="left")
        self.security_summary.pack(anchor="w", pady=18)

    def _open_selected_project(self, _=None):
        if self.busy:
            return
        selection = self.service_tree.selection()
        identity = server_key(self.current) if self.current else ""
        projects = self.__dict__.get("external_catalogs", {}).get(identity, {})
        if selection and selection[0] in projects:
            self._sync_manage_projects()
            label = next((label for label, key in self.manage_project_labels.items() if key == selection[0]), None)
            if label:
                self.manage_choice.set(label)
                self._project_changed()
                self.notebook.select(self.pages["日常维护"])
            return
        if not selection or selection[0] not in SERVICES:
            self.status.configure(text="先在项目列表中选择要管理的项目。")
            return
        kind = selection[0]
        self.manage_choice.set(SERVICES[kind][0])
        self._project_changed()
        data = self.project_details.get((identity, kind), {}).get("data")
        if data is None: data = (self.report or {}).get("project_information", {}).get(kind, {}).get("data", {})
        installed = data.get("installed", any(unit.get("LoadState") == "loaded" for unit in (self.report or {}).get("services", {}).get(kind, [])))
        if data.get("uninstalled"):
            installed = False
        if installed:
            self.notebook.select(self.pages["日常维护"])
        else:
            self._configure_project()

    def _render_report(self):
        if not self.report: return
        r = self.report
        self.system_label.configure(text=r["os"] + " · " + r["architecture"])
        self.statistics["disk"].configure(text=readable_size(r["disk_free"]))
        self.statistics["memory"].configure(text=readable_size(r["memory"].get("MemAvailable", 0)))
        self._render_overview_projects()
        password_enabled = "yes" in r["ssh"].get("passwordauthentication", [])
        self.statistics["security"].configure(text="密码 / 密钥" if password_enabled else "密钥")
        self.allow_password.set(password_enabled)
        self.allow_root.set("yes" in r["ssh"].get("permitrootlogin", []))
        self._render_accounts()
        root_allowed = "yes" in r["ssh"].get("permitrootlogin", [])
        summary = "防火墙：" + ("已启用" if r["firewall"]["active"] else "未启用") + "    安全更新：" + ("已启用" if r["automatic_updates"] else "未就绪") + "    超级管理员 SSH 密码登录：" + ("允许" if root_allowed and password_enabled else "禁止")
        self.security_summary.configure(text=summary + ("\n当前系统暂不支持自动部署；仍可检查已安装服务。" if not r["supported"] else ""))
        self.protection_status.configure(text=summary + "    防猜密码：" + ("已启用" if r.get("fail2ban", {}).get("active") else "未启用本程序保护"))
        for variable, field, default in [(self.auth_tries, "maxauthtries", "3"), (self.login_grace, "logingracetime", "120"), (self.alive_interval, "clientaliveinterval", "0")]:
            variable.set(r["ssh"].get(field, [default])[0])
        for variable, field in [(self.tcp_forwarding, "allowtcpforwarding"), (self.x11_forwarding, "x11forwarding"), (self.agent_forwarding, "allowagentforwarding")]:
            variable.set(r["ssh"].get(field, ["no"])[0] != "no")
        self._show_tasks(r.get("tasks", []))

    def _render_overview_projects(self):
        from .external_projects_gui import KINDS, STATES
        identity = server_key(self.current) if self.current else ""
        report = self.__dict__.get("report") or {}
        if self.__dict__.get("report_server_key") != identity: report = {}
        details = self.__dict__.get("project_details", {})
        rows = []; count = 0; unknown = False
        purposes = {"exchange": "币安多账号交易、资产查询和资金管理", "hysteria2": "Hysteria2 网络代理服务", "reality": "独立 VLESS + REALITY + Vision 节点", "xui": "代理账号与节点的网页管理", "nginx": "网页入口、HTTPS 和后端转发", "cliproxyapi": "AI 接口转发、账号管理与自动更新"}
        for key, (name, _) in SERVICES.items():
            information = details.get((identity, key), report.get("project_information", {}).get(key, {}))
            if key not in report.get("services", {}) and not information: continue
            data = information.get("data", {})
            units = data.get("units", report.get("services", {}).get(key, []))
            installed = [unit for unit in units if unit.get("LoadState") == "loaded"]
            running = any(unit.get("ActiveState") == "active" for unit in installed)
            state = "运行中" if running else "已停止" if installed else "尚未安装"
            startup = "已开启" if any(unit.get("UnitFileState") == "enabled" for unit in installed) else "未开启" if installed else "—"
            if data.get("uninstalled"):
                state = "独立站点已卸载" if key == "nginx" else "已卸载（数据保留）"
                startup = "—"; running = False
            elif data.get("installed") is False:
                state = "尚未安装"; startup = "—"; running = False
            elif data.get("installed") and not installed:
                state = "已安装（运行状态未保存）"; startup = "未读取"; unknown = True
            if any(label == "保存时间" for label, _ in information.get("rows", [])):
                state += "（上次读取）"
            count += running
            rows.append((key, (name, state, startup, purposes[key])))
        hidden = self.privacy.get()
        for index, (key, project) in enumerate(self.__dict__.get("external_catalogs", {}).get(identity, {}).items(), 1):
            kind = project.get("kind", "")
            name = (project.get("product") or "外部项目 " + str(index)) if hidden else project["name"]
            state = STATES.get(project.get("state"), "未知")
            info = details.get((identity, key), {}).get("external", {})
            if info.get("saved_at"): state += "（上次读取）"
            startup = "—"
            if kind in {"systemd", "systemd-user"}:
                startup = {"enabled": "已开启", "enabled-runtime": "临时开启", "disabled": "未开启", "static": "随依赖启动",
                           "indirect": "间接启用", "masked": "已屏蔽"}.get(project.get("startup"), "未读取")
            elif kind == "docker":
                startup = {"always": "自动重启", "unless-stopped": "自动重启（手动停止除外）", "on-failure": "失败时重启", "no": "未开启"}.get(project.get("startup"), "未读取")
            elif kind == "pm2": startup = "已保存，自启待确认"
            purpose = KINDS.get(kind, "外部项目")
            if not hidden and project.get("description"): purpose += " · " + project["description"]
            rows.append((key, (name, state, startup, purpose)))
            count += project.get("state") in {"active", "running"}
            unknown = unknown or project.get("state") == "unknown"
        sync_tree(self.service_tree, rows)
        self.statistics["services"].configure(text=("至少 " if unknown else "") + str(count) if rows else "—")
