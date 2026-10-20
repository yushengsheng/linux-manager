from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, font, messagebox, simpledialog, ttk
import webbrowser

from . import APP_NAME, VERSION
from .controller import Controller
from .models import Connection, ManagerError, Redactor, SERVICES, Store, validate_password, validate_port, validate_user
from .releases import LATEST_STABLE, SPECIFIC_VERSION, KEEP_CURRENT, exchange_version
from .help_texts import HELP
from .widgets import HelpAction, ScrollPage, install_check_style, sync_tree
from .key_info import encrypted_key
from .project_info import server_key, credential_alias, deployment_network_hint
from .qr import qr_png
from .transport import WaitingStopped
from .oauth_contract import OAUTH_PROVIDERS
from .client_config import CLIENTS, ClientConfigurator, chat_models, gateway_connection, gateway_models
from .client_apps import installed_applications, resolve_application

from .gui_common import BG, INK, MUTED, BLUE
from .gui_connections import ConnectionPages
from .gui_overview import OverviewPage
from .gui_accounts import AccountsPage
from .gui_security import SecurityPage
from .gui_applications import ApplicationPages
from .gui_history import HistoryPage

BASE = Path(__file__).resolve().parents[1]
NAVIGATION = {
    "服务器总览": "服务器概览",
    "日常维护": "应用管理",
    "账号与登录": "账号与登录",
    "安全防护": "安全防护",
    "命令行": "命令行",
    "操作记录": "操作记录",
    "连接服务器": "连接设置",
    "服务器列表": "服务器档案",
}


def data_directory():
    if getattr(sys, "frozen", False) or "--desktop-data" in sys.argv:
        return Path.home() / "Library/Application Support/linux服务器管理"
    return BASE / "data/linux-manager"


def answer_askpass():
    """Frozen helper mode: answer OpenSSH without starting another window."""
    endpoint = os.environ.get("LM_ASKPASS_SOCKET", "")
    if not endpoint or not Path(endpoint).name == "askpass.sock":
        return 1
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(endpoint)
        data = b""
        while chunk := client.recv(4096):
            data += chunk
            if len(data) > 4096:
                return 1
    os.write(1, data)
    return 0


class App(ConnectionPages, OverviewPage, AccountsPage, SecurityPage, ApplicationPages, HistoryPage, tk.Tk):
    def __init__(self, development_profile=False):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x820")
        self.minsize(1080, 760)
        self.configure(bg=BG)
        self.store = Store(data_directory())
        self.controller = Controller(self.store)
        self.profiles = []
        self.current = None
        self.report = None
        self.busy = False
        self.events = queue.Queue()
        self._worker_contexts = []
        self.controller.connection_listener = lambda state: self.events.put(("connection", state, None))
        self.buttons = []
        self.sessions = {}
        self.privacy = tk.BooleanVar(value=True)
        self.private_entries = []
        self.account_map = {}
        self.account_detail = None
        self.latest_tasks = []
        self.input_states = []
        self.fleet_reports = {}
        self.fleet_states = {}
        self.key_encryption = {}
        self.profiles_loaded = False
        self.profile_load_stage = "pending"
        self.project_details = {}
        self.project_logs = {}
        self.project_rows = []
        self.account_server_map = []
        self.report_server_key = None
        self._style()
        self._build()
        self._manage_action_states()
        self._profile_options()
        self._cache_inputs()
        if development_profile:
            path = Path("/private/tmp/linux-manager-development/current.json")
            if path.is_file():
                self._load_profile(Connection(**json.loads(path.read_text())))
        self.protocol("WM_DELETE_WINDOW", self._close)
        if sys.platform == "darwin":
            self.tk.createcommand("::tk::mac::Quit", self._close)
        self.after(100, self._drain)
        self.after(750, self._record_window_state)
        self.after(0, self._load_saved_profiles)

    def _record_window_state(self):
        from .models import atomic_private
        atomic_private(self.store.directory / "window-state.json", json.dumps({"pid": os.getpid(), "title": self.title(), "mapped": bool(self.winfo_ismapped()), "width": self.winfo_width(), "height": self.winfo_height(), "profiles_loaded": self.profiles_loaded, "profile_load_stage": self.profile_load_stage, "busy": self.busy, "pending_events": self.events.qsize()}))

    def _check_ui(self):
        """Development-only checks on this existing window; no server operations."""
        from .models import atomic_private
        if self.busy:
            deadline = self.__dict__.setdefault("ui_check_deadline", time.monotonic() + 30)
            if time.monotonic() < deadline:
                self.after(200, self._check_ui)
                return
        result = {"version": VERSION, "mapped": bool(self.winfo_ismapped()), "pages": len(self.pages), "horizontal_overflow": [], "help_dialog": False, "tab_switch_ms": {}, "privacy_enabled": self.privacy.get()}
        style = ttk.Style(self)
        result["caption_line_height"] = font.nametofont("TkCaptionFont", root=self).metrics("linespace")
        result["font_line_heights"] = {
            name: font.Font(root=self, font=style.lookup(name, "font")).metrics("linespace")
            for name in ["Title.TLabel", "Heading.TLabel", "TLabel", "TButton", "Treeview", "Navigation.Treeview"]
        }
        selected = self.notebook.select()
        for name, page in self.pages.items():
            started = time.perf_counter()
            self.notebook.select(page); self.update_idletasks()
            result["tab_switch_ms"][name] = round((time.perf_counter() - started) * 1000, 2)
            content = page.content
            def inspect(widget):
                for child in widget.winfo_children():
                    if isinstance(child, (ttk.Button, ttk.Entry, ttk.Combobox, ttk.Checkbutton)):
                        offset = child.winfo_rootx() - content.winfo_rootx()
                        if offset < 0 or offset + child.winfo_width() > content.winfo_width():
                            result["horizontal_overflow"].append(name)
                    inspect(child)
            inspect(content)
        result["deployment_optional_initially_collapsed"] = not self.deploy_optional_frame.winfo_manager()
        result["deployment_required_fields"] = {}
        for key in SERVICES:
            self.deploy_choice.set(SERVICES[key][0]); self._deploy_defaults()
            result["deployment_required_fields"][key] = sorted(name for name, row in self.deploy_rows.items() if row.winfo_manager())
        self.deploy_choice.set(SERVICES["exchange"][0]); self._deploy_defaults()
        self.notebook.select(self.pages["安全防护"]); self.update_idletasks()
        result["custom_settings_initially_collapsed"] = not self.custom_security_frame.winfo_manager()
        before = [v.get() for v in [self.plan_retire, self.plan_fail2ban, self.plan_updates, self.auth_tries, self.login_grace, self.alive_interval]]
        self._toggle_custom_security(); self.update_idletasks()
        result["custom_settings_expand"] = bool(self.custom_security_frame.winfo_ismapped())
        self._toggle_custom_security(); self.update_idletasks()
        result["custom_settings_preserve_values"] = before == [v.get() for v in [self.plan_retire, self.plan_fail2ban, self.plan_updates, self.auth_tries, self.login_grace, self.alive_interval]]
        result["green_check_indicator"] = self._check_images[1].get(8, 13) == (22, 163, 74)
        for name, widget in [("preset_button_visible", self.plan_apply.button), ("custom_toggle_visible", self.custom_security_toggle.button)]:
            canvas = self.pages["安全防护"].canvas
            result[name] = widget.winfo_rooty() + widget.winfo_height() <= canvas.winfo_rooty() + canvas.winfo_height()
        previous = set(self.winfo_children())
        self._help("禁止用户登录"); self.update_idletasks()
        dialogs = [child for child in self.winfo_children() if isinstance(child, tk.Toplevel) and child not in previous]
        result["help_dialog"] = bool(dialogs and dialogs[0].winfo_ismapped())
        for dialog in dialogs:
            dialog.destroy()
        self.notebook.select(self.pages["安全防护"])
        self.pages["安全防护"].canvas.yview_moveto(0)
        result["visible_page"] = "安全防护"
        result["profiles_ready"] = self.profiles_loaded and not self.busy
        result["saved_login_information_ready"] = result["profiles_ready"] and not self.store.last_warning and all(
            profile.identifier in self.store.vault.cache and all(
                getattr(profile, key) == self.store.vault.cache[profile.identifier].get(key, "")
                for key in ["password", "key_passphrase", "sudo_password"]
            ) for profile in self.profiles if profile.remember
        )
        result["horizontal_overflow"] = sorted(set(result["horizontal_overflow"]))
        atomic_private(self.store.directory / "ui-check.json", json.dumps(result, ensure_ascii=False))
        self._record_window_state()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        # Tk system fonts match the native caption; point sizes are enlarged by Tk's DPI scaling.
        self.option_add("*Font", "TkDefaultFont")
        style.configure("TFrame", background="white")
        style.configure("Chrome.TFrame", background=BG)
        style.configure("Card.TFrame", background="white")
        style.configure("TLabel", background="white", foreground=INK, font="TkDefaultFont")
        style.configure("Chrome.TLabel", background=BG, foreground=MUTED, font="TkDefaultFont")
        style.configure("Muted.TLabel", foreground=MUTED, font="TkDefaultFont")
        style.configure("Title.TLabel", font="TkCaptionFont", background=BG)
        style.configure("Heading.TLabel", font="TkCaptionFont")
        style.configure("Card.TLabel", background="white")
        style.configure("Stat.TLabel", background="white", font="TkCaptionFont", foreground=BLUE)
        style.configure("TButton", font="TkDefaultFont", padding=(10, 5), background="#f4f7fc", foreground=INK, bordercolor="#dde5f0", relief="flat", borderwidth=1)
        style.map("TButton", background=[("active", "#eaf0fa"), ("pressed", "#e0e9f8")], foreground=[("disabled", "#9aa8ba")])
        style.configure("Help.TButton", foreground=MUTED, background="white", borderwidth=0, padding=(3, 3))
        style.map("Help.TButton", background=[("active", "#eef4ff")], foreground=[("active", BLUE)])
        style.configure("Primary.TButton", background=BLUE, foreground="white", borderwidth=0, padding=(12, 6))
        style.map("Primary.TButton", background=[("active", "#2656c3"), ("disabled", "#ccd3e1")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", font="TkDefaultFont", padding=(12, 6), background=BG, foreground=MUTED, borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", "white"), ("active", "#eaf0fa")], foreground=[("selected", BLUE), ("active", INK)])
        style.configure("TEntry", font="TkDefaultFont", padding=(8, 5), fieldbackground="white", bordercolor="#dbe3ee", lightcolor="#dbe3ee", darkcolor="#dbe3ee", relief="flat")
        style.map("TEntry", bordercolor=[("focus", BLUE)])
        style.configure("TCombobox", font="TkDefaultFont", padding=(7, 5), fieldbackground="white", background="#f5f8fd", bordercolor="#dbe3ee", arrowsize=14)
        style.configure("Treeview", rowheight=24, font="TkDefaultFont", background="white", fieldbackground="white", borderwidth=0)
        style.configure("Treeview.Heading", font="TkCaptionFont", padding=6, background="#f4f7fc", foreground=MUTED, relief="flat")
        style.map("Treeview", background=[("selected", "#eaf2ff")], foreground=[("selected", "#1e40af")])
        style.configure("TCheckbutton", background="white", font="TkDefaultFont", padding=(0, 2))
        style.map("TCheckbutton", background=[("active", "white")], foreground=[("disabled", "#9aa8ba")])
        install_check_style(style, self)
        style.configure("TLabelframe", background="white", bordercolor="#e1e7f0", relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background="white", foreground=INK, font="TkCaptionFont")
        style.configure("Recommended.TLabel", background="#eaf9f0", foreground="#168249", font="TkSmallCaptionFont", padding=(8, 3))
        style.configure("TProgressbar", background=BLUE, troughcolor="#e8edf6", borderwidth=0)
        style.configure("Sidebar.Treeview", rowheight=26, font="TkDefaultFont", background="white", fieldbackground="white")
        style.configure("Navigation.Treeview", rowheight=26, font="TkDefaultFont", background="white", fieldbackground="white")
        style.configure("Workspace.TNotebook", background=BG, borderwidth=0, tabmargins=0)
        style.layout("Workspace.TNotebook.Tab", [])

    def _build(self):
        header = ttk.Frame(self, padding=(16, 10, 16, 8), style="Chrome.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        edition = "本地桌面版" if getattr(sys, "frozen", False) else "本地源码版"
        ttk.Label(header, text=f"  {VERSION} · {edition}", style="Chrome.TLabel").pack(side="left")
        self._check(header, "隐藏连接与账号信息", self.privacy, self._privacy_changed).pack(side="right")
        self._button(header, "使用说明", lambda: self._help()).pack(side="right", padx=10)
        self._button(header, "断开连接", self._disconnect).pack(side="right")

        body = ttk.Frame(self, style="Chrome.TFrame")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        sidebar = ttk.Frame(body, padding=12, width=216)
        sidebar.pack(side="left", fill="y", padx=(0, 12))
        sidebar.pack_propagate(False)
        self._help_label(sidebar, "我的服务器").pack(anchor="w", pady=(0, 10))
        self.server_count = ttk.Label(sidebar, text="尚未保存服务器", style="Muted.TLabel")
        self.server_count.pack(anchor="w", pady=(0, 8))
        servers = ttk.Frame(sidebar); servers.pack(fill="x")
        self.server_tree = ttk.Treeview(servers, columns=("name", "state"), show="headings", height=5, selectmode="browse", style="Sidebar.Treeview")
        self.server_tree.heading("name", text="服务器")
        self.server_tree.heading("state", text="连接")
        self.server_tree.column("name", width=130, minwidth=80)
        self.server_tree.column("state", width=54, minwidth=54, stretch=False, anchor="center")
        scrollbar = ttk.Scrollbar(servers, orient="vertical", command=self.server_tree.yview)
        self.server_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y"); self.server_tree.pack(fill="x")
        self.server_tree.bind("<ButtonRelease-1>", self._choose_sidebar_server)
        self.server_tree.bind("<Return>", self._choose_sidebar_server)
        self.server_tree.bind("<space>", self._choose_sidebar_server)
        self._button(sidebar, "添加新服务器", self._new_profile).pack(fill="x", pady=(8, 12))
        ttk.Separator(sidebar).pack(fill="x", pady=(0, 10))
        ttk.Label(sidebar, text="管理当前服务器", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.navigation_tree = ttk.Treeview(sidebar, show="tree", height=len(NAVIGATION), selectmode="browse", style="Navigation.Treeview")
        self.navigation_tree.column("#0", width=180, minwidth=80)
        for page, title in NAVIGATION.items():
            self.navigation_tree.insert("", "end", iid=page, text="  " + title)
        self.navigation_tree.pack(fill="x")
        self.navigation_tree.bind("<<TreeviewSelect>>", self._navigate)

        workspace = ttk.Frame(body, style="Chrome.TFrame")
        workspace.pack(side="left", fill="both", expand=True)
        context = ttk.Frame(workspace, padding=(4, 4, 4, 6), style="Chrome.TFrame")
        context.pack(fill="x")
        self.connection_badge = ttk.Label(context, text="● 尚未连接", style="Chrome.TLabel")
        self.connection_badge.pack(side="right", padx=(16, 0))
        self.current_server_label = ttk.Label(context, text="先添加或选择一台服务器", style="Heading.TLabel", background=BG, wraplength=600)
        self.current_server_label.pack(side="left", fill="x", expand=True)
        self.workspace_title = ttk.Label(workspace, text="连接设置", style="Title.TLabel")
        self.workspace_title.pack(anchor="w", padx=4, pady=(0, 6))
        self.application_tabs = ttk.Frame(workspace, style="Chrome.TFrame")
        self.application_install = self._button(self.application_tabs, "安装与配置", lambda: self.notebook.select(self.pages["一键部署"]), track=False)
        self.application_install.pack(side="left", padx=(0, 10))
        self.application_manage = self._button(self.application_tabs, "运行与备份", lambda: self.notebook.select(self.pages["日常维护"]), track=False)
        self.application_manage.pack(side="left")
        self.notebook = ttk.Notebook(workspace, style="Workspace.TNotebook")
        self.notebook.pack(fill="both", expand=True)
        self.pages = {}
        for name in ["连接服务器", "服务器列表", "服务器总览", "账号与登录", "安全防护", "一键部署", "日常维护", "操作记录"]:
            frame = ScrollPage(self.notebook, BG)
            self.notebook.add(frame, text=name)
            self.pages[name] = frame
        self._connection_page()
        self._fleet_page()
        self._overview_page()
        self._accounts_page()
        self._security_page()
        self._deployment_page()
        self._maintenance_page()
        self._history_page()
        self.notebook.bind("<<NotebookTabChanged>>", self._page_changed)
        self._page_changed()
        footer = ttk.Frame(self, padding=(16, 2, 16, 10), style="Chrome.TFrame")
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="登录信息仅保存在本机；密码由 Mac 钥匙串保护。点击 ？ 查看大白话说明。", style="Chrome.TLabel", wraplength=830)
        self.status.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(footer, length=200, maximum=100)
        self.progress.pack(side="right", padx=(15, 0))
        stop = self._button(footer, "停止等待", self._stop_waiting, track=False)
        stop.pack(side="right", padx=(10, 0))
        self.stop_waiting_button = stop.button
        self.stop_waiting_button.configure(state="disabled")

    def _navigate(self, _=None):
        selection = self.navigation_tree.selection()
        if not selection:
            return
        page = selection[0]
        if page == "命令行":
            self._page_changed()
            self._open_terminal()
            return
        current = self.notebook.select()
        if page == "日常维护" and current in {str(self.pages["一键部署"]), str(self.pages["日常维护"])}:
            return
        if current != str(self.pages[page]):
            self.notebook.select(self.pages[page])

    def _page_changed(self, _=None):
        selected = self.notebook.select()
        page = next((name for name, frame in self.pages.items() if str(frame) == selected), "连接服务器")
        group = "日常维护" if page == "一键部署" else page
        if self.navigation_tree.selection() != (group,):
            self.navigation_tree.selection_set(group)
        self.workspace_title.configure(text=NAVIGATION[group])
        if group == "日常维护":
            self.application_tabs.pack(fill="x", padx=4, pady=(0, 8), before=self.notebook)
            self.application_install.button.configure(style="Primary.TButton" if page == "一键部署" else "TButton")
            self.application_manage.button.configure(style="Primary.TButton" if page == "日常维护" else "TButton")
        else:
            self.application_tabs.pack_forget()

    def _render_sidebar(self):
        if "server_tree" not in self.__dict__:
            return
        names = {"连接保持中": "在线", "连接正常": "在线", "正在自动重连": "重连", "正在连接": "连接中",
                 "需核实服务器身份": "核实", "登录信息需检查": "认证", "连接未建立": "失败", "已手动断开": "断开"}
        rows = [(p.identifier, (p.label, names.get(self.fleet_states.get(p.identifier, ("", ""))[0], "—"))) for p in self.profiles]
        sync_tree(self.server_tree, rows)
        hosts = len({server_key(p) for p in self.profiles})
        self.server_count.configure(text=f"{hosts} 台服务器 · {len(self.profiles)} 个登录档案" if self.profiles else "尚未保存服务器")
        identifier = self.current.identifier if self.current else None
        if identifier and self.server_tree.exists(identifier):
            if self.server_tree.selection() != (identifier,):
                self.server_tree.selection_set(identifier)
                self.server_tree.see(identifier)
        elif self.server_tree.selection():
            self.server_tree.selection_remove(*self.server_tree.selection())
        self._server_context()

    def _server_context(self):
        if "current_server_label" not in self.__dict__:
            return
        c = self.current
        text = c.label if c and c.host else "先添加或选择一台服务器"
        if c and c.host and not self.privacy.get():
            text += f" · {c.host}:{c.port} · {c.username}"
        self.current_server_label.configure(text=text)

    def _choose_sidebar_server(self, event=None):
        if event is not None and event.type == tk.EventType.ButtonRelease and not self.server_tree.identify_row(event.y):
            return
        if self.busy:
            self._render_sidebar()
            self.status.configure(text="当前操作尚未结束，完成后再切换服务器。")
            return
        selection = self.server_tree.selection()
        if selection:
            self._activate_profile(selection[0])

    def _activate_profile(self, identifier):
        if self.busy:
            return
        profile = next((p for p in self.profiles if p.identifier == identifier), None)
        if profile is None:
            return
        self._load_profile(self.sessions.get(identifier, profile))
        kept = self._restore_connection_view(self.current)
        if kept and self.report:
            self.notebook.select(self.pages["服务器总览"])
        else:
            self.notebook.select(self.pages["连接服务器"])
            self._connect()

    def _clear_server_view(self):
        self.report = None
        self.report_server_key = None
        self._clear_account_view()
        if "statistics" not in self.__dict__:
            return
        self.system_label.configure(text="尚未读取当前服务器信息")
        for value in self.statistics.values():
            value.configure(text="—")
        sync_tree(self.service_tree, [])
        self.security_summary.configure(text="连接并检查后显示当前服务器的安全状态。")
        self.protection_status.configure(text="连接并检查后显示当前服务器的安全状态。")
        self._show_tasks([])
        self._replace_text(self.task_text, "连接后查看当前服务器的操作记录。")
        self.restore_id.set("")
        for variable in [self.account_password, self.account_confirmation, self.new_username, self.plan_password, self.plan_phrase]:
            variable.set("")

    def _configure_project(self):
        if self.busy:
            return
        if self._service_key(self.manage_choice.get()) not in SERVICES:
            self.status.configure(text="外部项目请使用原有安装方式调整配置。")
            return
        self.deploy_choice.set(self.manage_choice.get())
        self._deploy_defaults()
        self.notebook.select(self.pages["一键部署"])


    def _button(self, parent, text, action, primary=False, track=True):
        button = HelpAction(parent, text, action, lambda: self._help(text), "Primary.TButton" if primary else "TButton")
        if track:
            self.buttons.append(button.button)
        return button

    def _help_label(self, parent, label):
        frame = ttk.Frame(parent)
        ttk.Label(frame, text=label).pack(side="left")
        ttk.Button(frame, text="？", width=2, style="Help.TButton", command=lambda: self._help(label)).pack(side="left", padx=(3, 0))
        return frame

    def _check(self, parent, text, variable, command=None):
        frame = ttk.Frame(parent)
        frame.checkbox = ttk.Checkbutton(frame, text=text, variable=variable, command=command)
        frame.checkbox.pack(side="left", padx=(0, 5))
        if variable is self.privacy:
            self.privacy_control = frame.checkbox
        ttk.Button(frame, text="？", width=2, style="Help.TButton", command=lambda: self._help(text)).pack(side="left")
        return frame

    def _help(self, topic=None):
        dialog = tk.Toplevel(self); dialog.title("大白话使用说明"); dialog.geometry("760x520"); dialog.transient(self)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        self._description_plain(frame, "点功能旁的 ？ 就能查看对应说明")
        choice = tk.StringVar(value=topic if topic in HELP else "使用说明")
        box = ttk.Combobox(frame, textvariable=choice, values=sorted(HELP), state="readonly", width=55)
        box.pack(fill="x", pady=15)
        content = tk.Text(frame, wrap="word", relief="flat", padx=12, pady=12, font="TkDefaultFont", bg="white")
        content.pack(fill="both", expand=True)
        def show(_=None):
            self._replace_text(content, choice.get() + "\n\n" + HELP[choice.get()])
        box.bind("<<ComboboxSelected>>", show); show()

    def _description_plain(self, parent, title):
        ttk.Label(parent, text=title, style="Heading.TLabel").pack(anchor="w")

    def _field(self, parent, row, label, variable, private=False, width=32):
        self._help_label(parent, label).grid(row=row, column=0, sticky="e", padx=(0, 10), pady=4)
        entry = ttk.Entry(parent, textvariable=variable, width=width, show="•" if private and self.privacy.get() else "")
        entry.grid(row=row, column=1, sticky="ew", pady=4)
        if private:
            self.private_entries.append(entry)
        return entry

    def _generate_password(self, variable, confirmation=None, private_key=False):
        if self.__dict__.get("busy", False):
            return
        value = secrets.token_urlsafe(36 if private_key else 30)
        variable.set(value)
        if confirmation is not None:
            confirmation.set(value)
        if "status" in self.__dict__:
            self.status.configure(text="已生成强随机口令，仅填入表单；确认执行后才生效。")

    def _description(self, parent, title, text):
        self._help_label(parent, title).pack(anchor="w")
        ttk.Label(parent, text=text, style="Muted.TLabel", wraplength=1000, justify="left").pack(anchor="w", pady=(5, 10))


    def _switch_fleet(self):
        if self.busy: return
        selection = self.fleet_tree.selection()
        if selection:
            self._activate_profile(selection[0])

    def _check_fleet(self):
        profiles = [self.sessions.get(c.identifier, c) for c in self.profiles]
        if not profiles:
            messagebox.showinfo("先保存档案", "请先添加并保存服务器登录档案。", parent=self); return
        def worker():
            result = {}
            for index, profile in enumerate(profiles):
                self.events.put(("progress", {"message": f"正在检查第 {index + 1} / {len(profiles)} 台服务器…", "progress": index * 100 / len(profiles)}, None))
                try:
                    profile.validate()
                    if not self.controller.transport(profile).trusted():
                        result[profile.identifier] = ("需要首次确认身份", None)
                    else:
                        result[profile.identifier] = ("连接正常", self.controller.inspect(profile))
                except ManagerError:
                    result[profile.identifier] = ("连接失败，请单独检查", None)
                except Exception:
                    result[profile.identifier] = ("未完成，请单独检查", None)
            return result
        def done(result):
            when = datetime.datetime.now().strftime("%H:%M:%S")
            for identifier, (state, report) in result.items():
                self.fleet_states[identifier] = (state, when)
                if report:
                    self.fleet_reports[identifier] = report
                else:
                    self.fleet_reports.pop(identifier, None)
            self._render_fleet(); self.progress.configure(value=100)
            self.status.configure(text="已逐台检查，只读取状态。需要处理的服务器请单独连接。")
        self._run(worker, done, "逐台检查服务器…")

    def _remove_profile(self):
        selection = self.fleet_tree.selection()
        if not selection: return
        if not messagebox.askyesno("移除本机档案", "删除选中档案及它在本机钥匙串中保存的登录信息。\n服务器上的账号、项目和文件保持原样，本机私钥保留。是否移除？", parent=self): return
        identifier = selection[0]
        def done(_):
            self.profiles = [c for c in self.profiles if c.identifier != identifier]
            self.sessions.pop(identifier, None)
            self.fleet_reports.pop(identifier, None); self.fleet_states.pop(identifier, None)
            self._profile_options()
            if self.current and self.current.identifier == identifier:
                self._new_profile()
            self.status.configure(text="已移除本机档案和保存的登录信息。")
        def worker():
            self.controller.disconnect_connection(identifier)
            self.store.remove(identifier)
        self._run(worker, done, "正在移除本机档案…")


    def _tree(self, parent, columns, height):
        tree = ttk.Treeview(parent, columns=[c[0] for c in columns], show="headings", height=height)
        for key, title, width in columns:
            tree.heading(key, text=title); tree.column(key, width=width, minwidth=75, anchor="w")
        tree.pack(fill="x")
        return tree

    def _profile_options(self):
        self.profile_box["values"] = [f"{i + 1}. {c.label}" for i, c in enumerate(self.profiles)]
        self._render_fleet()
        if "account_server_box" in self.__dict__:
            self._account_servers()


    def _choose_account_server(self, _=None):
        if self.busy:return
        index = self.account_server_box.current()
        if not 0<=index<len(self.account_server_map):return
        c = self.account_server_map[index]
        if self.current and server_key(c)==server_key(self.current) and self.report:return
        self._load_profile(c)
        self.report = None; self.connection_badge.configure(text="● 尚未连接",foreground=MUTED)
        if not self.controller.transport(c).trusted():
            self.notebook.select(self.pages["连接服务器"])
            self.status.configure(text="请先连接并确认这台服务器的身份。")
            return
        profiles = list(self.profiles)
        self._run(lambda:self._inspect_and_save(c,profiles),lambda report:self._connected(c,report,select_page=False),"正在读取所选服务器的用户和策略…")

    def _choose_profile(self, _=None):
        if self.busy:
            return
        index = self.profile_box.current()
        if 0 <= index < len(self.profiles):
            self._load_profile(self.sessions.get(self.profiles[index].identifier, self.profiles[index]))
            if not self._restore_connection_view(self.current):
                self.status.configure(text="已切换连接档案，请点击“连接并检查”。")

    def _show_connection_state(self, state):
        labels = {"connecting": ("● 正在连接", MUTED), "connected": ("● 连接保持中", "#27805e"),
                  "reconnecting": ("● 正在自动重连", "#ae731d"), "identity_changed": ("● 需核实服务器身份", "#b91c1c"),
                  "authentication_failed": ("● 登录信息需检查", "#b91c1c"), "failed": ("● 连接未建立", "#b91c1c"),
                  "disconnected": ("● 已断开", MUTED)}
        text, color = labels.get(state, ("● 尚未连接", MUTED))
        self.connection_badge.configure(text=text, foreground=color)

    def _restore_connection_view(self, c):
        state = self.controller.connection_status(c)
        self.report = None
        if state["state"] in {"connected", "reconnecting"}:
            self.report = self.fleet_reports.get(c.identifier)
            if self.report:
                self.report_server_key = server_key(c)
                self._render_report()
                self._project_changed()
                self._sync_deployment_server(c)
            self._show_connection_state(state["state"])
            self.status.configure(text=state["message"])
            return True
        self.connection_badge.configure(text="● 尚未连接", foreground=MUTED)
        return False

    def _connection_changed(self, value):
        profile = next((p for p in self.profiles if p.identifier == value["identifier"]), None)
        if self.current and self.current.identifier == value["identifier"]:
            profile = self.current
        if profile is None or self.controller.connection_status(profile).get("token") != value["token"]:
            return
        names = {"connected": "连接保持中", "reconnecting": "正在自动重连", "connecting": "正在连接",
                 "identity_changed": "需核实服务器身份", "authentication_failed": "登录信息需检查", "failed": "连接未建立"}
        self.fleet_states[profile.identifier] = (names.get(value["state"], "已断开"), datetime.datetime.now().strftime("%H:%M:%S"))
        self._render_fleet()
        if self.current and self.current.identifier == profile.identifier:
            self._show_connection_state(value["state"])
            if not self.busy:
                self.status.configure(text=value["message"])

    def _disconnect(self):
        if self.current is None:
            return
        identifier = self.current.identifier
        self.controller.disconnect_connection(identifier)
        self._clear_server_view()
        if "project_info_tree" in self.__dict__:
            self._project_changed()
        self.fleet_states[identifier] = ("已手动断开", datetime.datetime.now().strftime("%H:%M:%S"))
        self._render_fleet()
        self._show_connection_state("disconnected")
        self.status.configure(text="已断开所选服务器，不会自动重连。其他服务器连接仍保持；需要时点击“连接并检查”。")

    def _load_profile(self, c):
        previous = self.current
        if previous is None or server_key(previous) != server_key(c) or previous.identifier != c.identifier:
            self._clear_server_view()
        self.current = c
        for variable, value in [(self.label_var, c.label), (self.host_var, c.host), (self.user_var, c.username), (self.port_var, str(c.port)), (self.key_var, c.key_path), (self.password_var, c.password), (self.passphrase_var, c.key_passphrase), (self.sudo_var, c.sudo_password)]:
            variable.set(value)
        self.auth_var.set("密钥登录" if c.auth == "key" else "密码登录")
        self.remember_var.set(c.remember)
        self._auth_fields()
        self.ssh_account.set(c.username); self.ssh_port.set(str(c.port)); self.account_user.set(c.username)
        self.plan_username.set(c.username if c.username != "root" and self.plan_mode.get() != "新增管理员和密钥" else "")
        self._plan_mode_changed()
        self.account_detail = None
        if "account_server_box" in self.__dict__:
            self._account_servers()
            self._project_changed()
        for index, saved in enumerate(self.profiles):
            if saved.identifier == c.identifier:
                self.profile_box.current(index)
                break
        self._sync_deployment_server(c)
        if not self.report:
            self.deployment_context = None
        self._render_sidebar()

    def _new_profile(self):
        if self.busy:
            return
        self._load_profile(Connection())
        self.profile_choice.set("")
        self.report = None
        self.connection_badge.configure(text="● 尚未连接", foreground=MUTED)
        self.notebook.select(self.pages["连接服务器"])

    def _connection(self):
        c = Connection(label=self.label_var.get().strip() or "我的服务器", host=self.host_var.get(), username=self.user_var.get().strip(), port=validate_port(self.port_var.get()), auth="key" if self.auth_var.get() == "密钥登录" else "password", password=self.password_var.get(), key_path=self.key_var.get(), key_passphrase=self.passphrase_var.get(), sudo_password=self.sudo_var.get(), identifier=self.current.identifier if self.current else Connection().identifier, remember=self.remember_var.get())
        c.validate()
        return c

    def _save_profile(self):
        try:
            c = self._connection()
            if self.current and (c.host, c.username, c.port, c.auth, c.key_path) != (self.current.host, self.current.username, self.current.port, self.current.auth, self.current.key_path):
                self.report = None
                self.connection_badge.configure(text="● 尚未连接", foreground=MUTED)
            profiles = list(self.profiles)
            def done(_):
                self._persist_profile(c)
                self.status.configure(text="连接档案已保存。" + ("登录口令已存入本机钥匙串。" if c.remember and not self.store.last_warning else "本次运行可继续使用已填写的口令。"))
            self._run(lambda: self._save_connection(c, profiles, force=True), done, "正在安全保存到本机钥匙串…")
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)

    def _persist_profile(self, c):
        existing = next((index for index, p in enumerate(self.profiles) if p.identifier == c.identifier), None)
        if existing is None:
            self.profiles.append(c)
            existing = len(self.profiles) - 1
        else:
            self.profiles[existing] = c
        self.sessions[c.identifier] = c
        self.current = c
        self._profile_options()
        self.profile_box.current(existing)
        if self.store.last_warning:
            messagebox.showwarning("登录信息尚未保存", self.store.last_warning, parent=self)

    def _select_file(self, variable, title):
        path = filedialog.askopenfilename(title=title, parent=self)
        if path:
            variable.set(path)

    def _save_connection(self, c, profiles, force=False):
        existing = next((p for p in profiles if p.identifier == c.identifier), None)
        if not force and existing == c:
            self.store.last_warning = ""
            return
        updated = [c if p.identifier == c.identifier else p for p in profiles]
        if existing is None: updated.append(c)
        self.store.save(updated, update_identifiers={c.identifier})

    def _inspect_and_save(self, c, profiles):
        self.controller.keep_connection(c)
        report = self.controller.inspect(c)
        self._save_connection(c, profiles)
        return report

    def _load_saved_profiles(self):
        def worker():
            self.profile_load_stage = "profiles"
            profiles = self.store.profiles()
            self._saved_project_snapshots = self.controller.cached_projects(profiles)
            self.profile_load_stage = "key_metadata"
            keys = {p.key_path: encrypted_key(p.key_path) for p in profiles if p.key_path}
            self.profile_load_stage = "queued"
            return profiles, keys
        def done(data):
            self.profiles, self.key_encryption = data
            self._restore_project_snapshots(self.__dict__.pop("_saved_project_snapshots", {}))
            self.profiles_loaded = True
            self.profile_load_stage = "ready"
            self._profile_options()
            if self.profiles and self.current is None:
                self._load_profile(self.profiles[0])
            else:
                self._plan_mode_changed()
            saved = bool(self.__dict__.get("external_catalogs"))
            self.status.configure(text=("本机档案与上次项目信息已恢复；需要更新时手动刷新。" if saved else "本机档案已就绪。选择服务器后连接，或查看功能说明。") +
                                  " ".join(self.__dict__.get("project_cache_warnings", [])))
            if self.store.last_warning:
                messagebox.showwarning("本机登录信息", self.store.last_warning, parent=self)
            self._record_window_state()
            if "--ui-check" in sys.argv:
                self.after(0, self._check_ui)
        self._run(worker, done, "正在读取本机保存的登录档案…")

    def _cache_inputs(self):
        self.inputs = []
        def collect(parent):
            for widget in parent.winfo_children():
                if isinstance(widget, tk.Toplevel): continue
                if isinstance(widget, (ttk.Entry, ttk.Combobox, ttk.Checkbutton)) and widget is not self.__dict__.get("privacy_control"):
                    self.inputs.append(widget)
                collect(widget)
        collect(self)

    def _stop_waiting(self):
        cancel = self.__dict__.get("wait_cancel")
        if cancel is not None:
            cancel.set()
            self.stop_waiting_button.configure(state="disabled")
            self.status.configure(text="正在停止本机等待；已提交的 Linux 后台任务继续执行…")

    def _run(self, worker, callback=None, message="正在检查…", wait_cancel=None):
        if self.busy:
            return
        self.busy = True
        self.wait_cancel = wait_cancel
        if self.__dict__.get("stop_waiting_button"):
            self.stop_waiting_button.configure(state="normal" if wait_cancel is not None else "disabled")
        for button in self.buttons:
            button.configure(state="disabled")
        self.input_states = []
        def freeze(parent):
            for widget in parent.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    continue
                if isinstance(widget, (ttk.Entry, ttk.Combobox, ttk.Checkbutton)):
                    self.input_states.append((widget, widget.cget("state")))
                    widget.configure(state="disabled")
                freeze(widget)
        inputs = self.__dict__.get("inputs")
        if inputs is None:
            freeze(self)
        else:
            for widget in inputs:
                if widget.winfo_exists():
                    self.input_states.append((widget, widget.cget("state")))
                    widget.configure(state="disabled")
        self.status.configure(text=message)
        self.progress.configure(value=0)
        def work():
            try:
                data = worker()
                self.events.put(("done", data, callback))
            except Exception as error:
                if isinstance(error, ManagerError):
                    text = str(error)
                else:
                    text = "操作未完成。已保留记录，请检查连接或查看任务状态。"
                self.events.put(("stopped" if isinstance(error, WaitingStopped) else "error", text, None))
        thread = threading.Thread(target=work, daemon=True)
        # A worker may capture Tk Variables through dialog callbacks. Keep its
        # closure until the UI thread reaps it, so their finalizers never run
        # while threading.Thread deletes its target on the background thread.
        self.__dict__.setdefault('_worker_contexts', []).append((thread, work))
        thread.start()

    def _reap_workers(self):
        contexts = self.__dict__.get('_worker_contexts', [])
        self._worker_contexts = [(thread, work) for thread, work in contexts if thread.is_alive()]

    def _drain(self):
        self._reap_workers()
        latest_progress = None
        deadline = time.perf_counter() + 0.008
        def show_progress(value):
            self.status.configure(text=self._redactor().text(value.get("message", "正在执行…")))
            self.progress.configure(value=value.get("progress", 0))
        try:
            while time.perf_counter() < deadline:
                kind, value, callback = self.events.get_nowait()
                if kind == "connection":
                    self._connection_changed(value)
                    continue
                if kind == "progress":
                    latest_progress = value
                    continue
                if kind == "oauth_ready":
                    callback(value)
                    continue
                if latest_progress is not None:
                    show_progress(latest_progress); latest_progress = None
                self.busy = False
                self.wait_cancel = None
                if self.__dict__.get("stop_waiting_button"):
                    self.stop_waiting_button.configure(state="disabled")
                for button in self.buttons:
                    button.configure(state="normal")
                for widget, state in self.input_states:
                    if widget.winfo_exists():
                        widget.configure(state=state)
                self.input_states = []
                self._auth_fields()
                if kind == "stopped":
                    self.status.configure(text=value)
                elif kind == "error":
                    self.status.configure(text=value)
                    messagebox.showerror("操作未完成", value, parent=self)
                elif callback:
                    callback(value)
                if "manage_project_box" in self.__dict__:
                    self._manage_action_states()
        except queue.Empty:
            pass
        finally:
            # Tk reports callback failures; keep processing later task results.
            self.after(40 if self.busy or not self.events.empty() else 100, self._drain)
        if latest_progress is not None: show_progress(latest_progress)

    def report_callback_exception(self, exception, value, traceback):
        # Record locations only: exception values and source lines can contain secrets.
        from traceback import extract_tb
        from .models import atomic_private
        diagnostic = {"type": exception.__name__, "frames": [
            {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in extract_tb(traceback)
        ]}
        note = "诊断已保存到本机 ui-error.json（不含账号或口令）。"
        try:
            atomic_private(self.store.directory / "ui-error.json", json.dumps(diagnostic, ensure_ascii=False))
        except OSError:
            note = "本机诊断未能保存，请检查数据目录权限。"
        messagebox.showerror("操作未完成", "界面操作未完成，请重新检查输入或查看任务状态。\n\n" + note, parent=self)

    def _redactor(self):
        c = self.current
        return Redactor(*(c.__dict__[key] for key in ["host", "username", "password", "key_path", "key_passphrase", "sudo_password"])) if c else Redactor()

    def _connect(self):
        if self.busy:
            return
        try:
            c = self._connection()
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self); return
        ssh = self.controller.transport(c)
        if not ssh.trusted():
            def trust_result(data):
                fingerprint, keys = data
                if messagebox.askyesno("首次连接", "程序已自动获取服务器身份，后续连接会自动比对。\n\n公开指纹：\n" + fingerprint + "\n\n请确认你填写的地址属于自己的服务器。是否记住此身份并连接？\n如需进一步核实，可在云平台控制台查看指纹。", parent=self):
                    ssh.trust(keys)
                    profiles = list(self.profiles)
                    self._run(lambda: self._inspect_and_save(c, profiles), lambda r: self._connected(c, r))
            self._run(ssh.fingerprint, trust_result, "读取服务器身份指纹…")
        else:
            profiles = list(self.profiles)
            self._run(lambda: self._inspect_and_save(c, profiles), lambda r: self._connected(c, r))

    def _connected(self, c, report, select_page=True):
        self._persist_profile(c)
        self._load_profile(c)
        self.report = report
        self.report_server_key = server_key(c)
        for kind, information in report.get("project_information", {}).items():
            self.project_details[(server_key(c), kind)] = information
        self.fleet_reports[c.identifier] = report
        self.fleet_states[c.identifier] = ("连接正常", datetime.datetime.now().strftime("%H:%M:%S"))
        self._render_fleet()
        self.connection_badge.configure(text="● 连接保持中", foreground="#27805e")
        self.status.configure(text="连接与管理员权限已验证。连接会保持到手动断开或关闭程序，短暂掉线后自动重连。")
        self._render_report()
        self._project_changed()
        self._sync_deployment_server(c)
        if select_page:
            self.notebook.select(self.pages["服务器总览"])

    def _reconfirm_identity(self):
        try:
            c = self._connection()
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self); return
        ssh = self.controller.transport(c)
        def result(data):
            fingerprint, keys = data
            if messagebox.askyesno("服务器身份发生变化", "仅当你确认这台服务器刚重装、重建，或已通过云平台核实身份时使用。\n\n当前公开指纹：\n" + fingerprint + "\n\n是否保存新身份并重新连接？旧记录会保留。", parent=self):
                ssh.replace_trust(keys)
                self.controller.disconnect_connection(c.identifier)
                profiles = list(self.profiles)
                self._run(lambda: self._inspect_and_save(c, profiles), lambda report: self._connected(c, report))
        self._run(ssh.fingerprint, result, "获取服务器当前公开指纹…")

    def _refresh(self):
        if not self._ready(): return
        c = self.current
        profiles = list(self.profiles)
        self._run(lambda: self._inspect_and_save(c, profiles), lambda r: self._connected(c, r))

    def _ready(self):
        if self.current and (self.host_var.get().strip(), self.user_var.get().strip(), self.port_var.get().strip(), self.auth_var.get(), self.key_var.get()) != (self.current.host, self.current.username, str(self.current.port), "密钥登录" if self.current.auth == "key" else "密码登录", self.current.key_path):
            self.report = None
            self.connection_badge.configure(text="● 连接信息已修改", foreground=MUTED)
        if not self.current or not self.report:
            messagebox.showinfo("先连接服务器", "请在连接页点击“连接并检查”，确认账号及管理员权限。", parent=self)
            self.notebook.select(self.pages["连接服务器"])
            return False
        state = self.controller.connection_status(self.current)
        if state["state"] != "connected":
            self._show_connection_state(state["state"])
            messagebox.showinfo("等待连接恢复", state.get("message", "请先连接服务器。") + "\n\n请勿重复提交已经执行的任务。", parent=self)
            return False
        return True

    def _open_terminal(self):
        if self.busy or not self._ready():
            return
        connection = self.current

        def done(_):
            self.status.configure(text="已打开当前服务器的命令行窗口，可连续输入或粘贴多行代码。退出请输入 exit。")

        self._run(lambda: self.controller.open_terminal(connection), done,
                  "正在打开当前服务器的命令行…")


    def _refresh_accounts(self):
        if not self._ready(): return
        c = self.current
        def done(report):
            if server_key(self.current) != server_key(c): return
            self.report = report; self.report_server_key = server_key(c)
            self.account_detail = None; self._render_report()
            self.status.configure(text="用户列表及安全策略已刷新。")
        self._run(lambda: self.controller.inspect(c), done, "读取全部本机用户…")

    def _account_details(self):
        if not self._ready(): return
        try:
            account = self._selected_account(); c = self.current
        except ManagerError as error:
            messagebox.showinfo("选中账号", str(error), parent=self); return
        def done(data):
            if not self.current or server_key(self.current) != server_key(c): return
            self.account_detail = data | {"server_id": c.identifier}
            self.key_encryption.update(data.get("local_key_encryption", {}))
            self._show_account_detail()
        self._run(lambda: self.controller.account_details(c, account), done, "读取所选账号的实际安全策略…")

    def _copy_account(self):
        if not self._ready(): return
        try:
            text = self._account_info(self._selected_account())
        except ManagerError as error:
            messagebox.showinfo("选中账号", str(error), parent=self); return
        self._copy(text)
        self.status.configure(text="账号信息已复制到本机剪贴板（不含密码、口令或私钥内容）。")

    def _apply_security_plan(self):
        if not self._ready(): return
        try:
            target = validate_user(self.plan_username.get().strip())
            mode = "create" if self.plan_mode.get() == "新增管理员和密钥" else "rename"
            if target == "root" or (mode == "rename" and self.current.username == "root"):
                raise ManagerError("超级管理员不能改名，请选择新增管理员。")
            value = self.plan_password.get()
            if value: validate_password(value)
            phrase = self.plan_phrase.get()
            if phrase and (len(phrase) < 16 or any(c in phrase for c in "\r\n\x00")):
                raise ManagerError("私钥口令至少 16 位；留空可以自动生成。")
        except ManagerError as error:
            messagebox.showerror("检查方案输入", str(error), parent=self); return
        c = self.current
        options = {"mode": mode, "username": target, "new_password": value, "key_passphrase": phrase, "retire_old_key": mode == "rename" and self.plan_retire.get(), "fail2ban": mode == "rename" and self.plan_fail2ban.get(), "updates": mode == "rename" and self.plan_updates.get()}
        steps = ["新增并验证普通管理员：" + target if mode == "create" else "修改当前账号为：" + target + "（名称相同则保留用户名）", "生成加密私钥，私钥和口令仅存本机，并开启记住登录信息", "验证新密钥及 sudo 后，仅新账号使用密钥登录，其他账号及全局登录策略保持不变" if mode == "create" else "验证新密钥及 sudo 后，全局禁止 SSH 密码、交互密码及超级管理员直接登录", "保留 SSH 端口、现有地址规则及 SSH 隧道设置"]
        if mode == "create": steps.append("新账号 sudo 密码：" + ("使用已填写的新密码" if value else "自动生成并保存到本机钥匙串"))
        elif value: steps.append("修改当前账号的系统密码")
        if mode == "rename" and options["retire_old_key"] and c.auth == "key": steps.append("验证后撤销当前档案原公钥；其他钥匙保留")
        if options["fail2ban"]: steps.append("启用临时封禁：10 分钟内失败 5 次，封禁 60 分钟")
        if options["updates"]: steps.append("启用系统安全更新，不自动重启")
        impact = "仅调整新管理员的登录策略，保留原账号和其他账号的密码／密钥登录。" if mode == "create" else "全局关闭密码入口会影响仍使用密码的账号和管理工具。改名会关闭原账号的登录会话。"
        if not messagebox.askyesno("预览一键安全方案", "\n".join("• " + s for s in steps) + "\n\n" + impact + "\n每个连接变更分别验证和保护；后续步骤失败时，已完成步骤保留并列出结果。\n是否开始？", parent=self): return
        def progress(status): self.events.put(("progress", status, None))
        def done(result):
            updated = result["connection"]
            self.profiles = result["local_profiles"]
            self.key_encryption.update(result["local_key_encryption"])
            self.sessions = {p.identifier: self.sessions.get(p.identifier, p) if p.host != c.host else p for p in self.profiles}
            self._profile_options(); self._load_profile(updated)
            self.report = None; self.account_detail = None
            for p in self.profiles:
                if p.host == c.host:
                    self.fleet_reports.pop(p.identifier, None)
                    self.fleet_states[p.identifier] = ("请重新检查", "—")
            self.plan_password.set(""); self.plan_phrase.set("")
            self.connection_badge.configure(text="● 方案已完成" if result["complete"] else "● 方案未全部完成", foreground="#27805e" if result["complete"] else "#ae731d")
            self.status.configure(text=result["message"])
            show = messagebox.showinfo if result["complete"] else messagebox.showwarning
            show("安全方案结果", result["message"] + "\n\n已完成：\n" + ("\n".join(s["step"] for s in result["stages"]) or "暂无远程步骤完成") + "\n\n本机已保留最后验证成功的连接档案，可重新连接检查实际状态。", parent=self)
            self.notebook.select(self.pages["连接服务器"])
        def work():
            result = self.controller.security_plan(c, options, progress)
            result["local_profiles"] = self.store.profiles()
            result["local_key_encryption"] = {p.key_path: encrypted_key(p.key_path) for p in result["local_profiles"] if p.key_path}
            return result
        self._run(work, done, "检查兼容性并准备本机加密密钥…")

    def _privacy_changed(self):
        for entry in self.private_entries:
            entry.configure(show="•" if self.privacy.get() else "")
        self._render_accounts()
        self._render_fleet()
        if "account_server_box" in self.__dict__:
            self._account_servers()
        if "project_info_tree" in self.__dict__:
            self._project_changed()

    def _execute(self, params, description):
        if not self._ready(): return
        if not messagebox.askyesno("确认本次操作", description + "\n\n仅执行本次所列改动。是否开始？", parent=self): return
        c = self.current
        wait_cancel = threading.Event() if params["operation"] == "deploy" else None
        def progress(status):
            self.events.put(("progress", status, None))
        def done(data):
            status, updated = data
            self.key_encryption.update(status.get("local_key_encryption", {}))
            self.profiles, _ = self.controller.synchronize_profiles(self.profiles, c, updated, params)
            sessions, _ = self.controller.synchronize_profiles(list(self.sessions.values()), c, updated, params)
            self.sessions = {profile.identifier: profile for profile in sessions}
            for profile in self.profiles:
                if profile.host == c.host:
                    self.fleet_reports.pop(profile.identifier, None)
                    self.fleet_states[profile.identifier] = ("配置已变更，请重新检查", "—")
            if params["operation"] == "uninstall":
                identities = {server_key(profile) for profile in [c, updated, *self.profiles] if profile.host == c.host}
                for identity in identities:
                    self.project_details.pop((identity, params["service"]), None)
                    self.project_logs.pop((identity, params["service"]), None)
                self.deployment_context = None
            self._persist_profile(updated); self._load_profile(updated)
            self.report = None
            self.connection_badge.configure(text="● 已验证，待刷新", foreground="#27805e")
            self.account_password.set(""); self.account_confirmation.set("")
            self.status.configure(text="操作完成，验证已通过。")
            self.progress.configure(value=100)
            result = status.get("result", {})
            if result.get("backup_id") and params["operation"] != "deploy":
                self.restore_id.set(result["backup_id"])
            self._show_tasks([status] + self.latest_tasks)
            self.notebook.select(self.pages["操作记录"])
            messagebox.showinfo("操作完成", "项目已卸载，配置、账号和业务数据保留。共享依赖与防火墙规则未删除；移除文件的恢复备份仍占磁盘空间。" if params["operation"] == "uninstall" else "操作已完成。可以刷新总览，或查看访问 / 连接信息。", parent=self)
            profiles = list(self.profiles)
            if params["operation"] == "deploy": self.deployment_context = None
            self._run(lambda: self._inspect_and_save(updated, profiles), lambda report: self._connected(updated, report), "刷新配置后的状态…")
        def work():
            if params.pop("local_generate_key", False):
                phrase = secrets.token_urlsafe(36)
                key, public = self.controller.generate_key(c, phrase)
                params.update(local_key_path=key, local_key_passphrase=phrase, public_key=public)
            result = self.controller.execute(c, params, progress, **({"cancel_event": wait_cancel} if wait_cancel is not None else {}))
            updated = result[1]
            if updated.key_path:
                result[0]["local_key_encryption"] = {updated.key_path: encrypted_key(updated.key_path)}
            return result
        self._run(work, done, "提交后台任务…", wait_cancel=wait_cancel)

    def _account_operation(self, operation):
        if not self._ready(): return
        try:
            account = validate_user(self.account_user.get().strip())
            params = {"operation": operation, "username": account}
            if operation in {"create_admin", "password"}:
                value = validate_password(self.account_password.get())
                if value != self.account_confirmation.get(): raise ManagerError("两次输入的新密码不一致。")
                params["new_password"] = value
            if operation == "create_admin" and self.install_key.get():
                params["local_generate_key"] = True
            if operation == "rename_user":
                if account != self.current.username:
                    raise ManagerError("账号改名需先以该账号连接，程序才能自动验证新登录身份。")
                params.update(old_username=account, new_username=validate_user(self.new_username.get().strip()))
            description = {"create_admin": "创建普通管理员，设置系统密码和本机密钥，验证可登录及使用 sudo。", "password": "修改所选账号的系统密码；SSH 登录方式保持原设置。", "rename_user": "原地修改普通账号名和家目录，保留 UID、权限和密钥。若该账号运行业务进程，程序会停止改名。"}[operation]
            if operation in {"create_admin", "password"}:
                description += "\n本次新密码副本单独保存到本机钥匙串（不受记住登录开关影响），可在操作记录查看；保存失败不执行。"
            self._execute(params, description)
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)

    def _apply_ssh(self):
        if not self._ready(): return
        try:
            account = validate_user(self.ssh_account.get().strip())
            if account != self.current.username:
                raise ManagerError("请先切换到验证账号并连接，再修改 SSH 设置。")
            params = {"operation": "ssh", "username": account, "port": validate_port(self.ssh_port.get()), "old_port": self.current.port, "allow_password": self.allow_password.get(), "allow_root": self.allow_root.get()}
            if self.replace_key.get():
                params["local_generate_key"] = True
            self._execute(params, "修改 SSH 登录策略和端口。先保留原端口，验证新连接；验证失败将在保护时限内恢复。")
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)

    def _guard_account(self, selected=False):
        account = validate_user(self._selected_account() if selected else self.account_user.get().strip())
        target = next((item for item in self.report["accounts"] if item["username"] == account), None)
        admin = next((item for item in self.report["accounts"] if item["username"] == self.current.username), None)
        if not target:
            raise ManagerError("请选中服务器中存在的普通账号。")
        if account == self.current.username or not (1000 <= target["uid"] < 65534):
            raise ManagerError("不能禁用或删除当前账号、超级管理员及系统账号。先创建并切换到自己的管理员。")
        if not admin or not admin["admin"] or not (1000 <= admin["uid"] < 65534):
            raise ManagerError("请先使用另一个普通管理员连接并检查。")
        return account

    def _account_access(self, blocked):
        if not self._ready(): return
        try:
            account = self._guard_account()
            self._execute({"operation": "account_access", "username": account, "blocked": blocked}, "所选账号：" + account + "\n" + ("禁止所选账号的 SSH 登录并锁住系统密码，保留文件和运行服务。" if blocked else "撤销本程序对所选账号设置的登录限制，保留其他原有限制。"))
        except ManagerError as error:
            messagebox.showerror("检查账号", str(error), parent=self)

    def _delete_user(self):
        if not self._ready(): return
        try:
            account = self._guard_account(selected=True)
            self._execute({"operation": "delete_user", "username": account}, "本次要删除的账号：" + account + "\n默认保留家目录和文件。\n若存在运行进程、系统服务或定时任务，将拒绝删除。\n同一服务器这个账号的已保存登录口令也会清除。")
        except ManagerError as error:
            messagebox.showerror("检查账号", str(error), parent=self)

    def _integer(self, variable, minimum, maximum, label):
        try:
            value = int(variable.get())
        except ValueError:
            raise ManagerError(label + "必须是整数。") from None
        if not minimum <= value <= maximum:
            raise ManagerError(label + f"需在 {minimum} 至 {maximum} 之间。")
        return value

    def _harden_ssh(self):
        if not self._ready(): return
        try:
            params = {"operation": "ssh_hardening", "max_auth_tries": self._integer(self.auth_tries, 2, 20, "认证尝试次数"), "login_grace": self._integer(self.login_grace, 15, 600, "登录等待秒数"), "alive_interval": self._integer(self.alive_interval, 0, 3600, "断线检查秒数"), "tcp_forwarding": self.tcp_forwarding.get(), "x11_forwarding": self.x11_forwarding.get(), "agent_forwarding": self.agent_forwarding.get()}
            forwarding = self.report["ssh"].get("allowtcpforwarding", ["yes"])[0]
            if params["tcp_forwarding"] and forwarding in {"local", "remote"}:
                params["tcp_forwarding"] = forwarding
            self._execute(params, "应用填写的认证次数、登录等待、断线检查及转发设置，禁止空密码，启用详细 SSH 认证日志。\n保留端口和账号登录策略，验证失败时尝试恢复。")
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)

    def _fail2ban(self, enabled):
        if not self._ready(): return
        try:
            params = {"operation": "fail2ban", "enabled": enabled, "ssh_port": self.current.port, "attempts": self._integer(self.ban_attempts, 3, 20, "失败次数"), "window_minutes": self._integer(self.ban_window, 1, 1440, "统计分钟数"), "ban_minutes": self._integer(self.ban_duration, 1, 10080, "封禁分钟数")}
            self._execute(params, f"启用 SSH 防猜密码保护：{params['window_minutes']} 分钟内失败 {params['attempts']} 次，暂时封禁 {params['ban_minutes']} 分钟。\n首次启用会安装 Fail2ban，保留其他配置。" if enabled else "关闭本程序管理的 SSH 防猜密码保护，保留其他已有配置。")
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)


    def _external_projects(self):
        if self.busy or not self._ready(): return
        from .external_projects import ExternalProjects
        c = self.current; identity = server_key(c)
        selected = self._service_key(self.manage_choice.get())
        def done(result):
            if not self.current or server_key(self.current) != identity: return
            projects = {p["id"]: p for p in result["projects"] if p["kind"] != "builtin"}
            previous = self.__dict__.setdefault("external_catalogs", {}).get(identity, {})
            if result.get("warnings"): projects = dict(previous, **projects)
            for removed in previous.keys() - projects.keys():
                self.project_details.pop((identity, removed), None)
                self.project_logs.pop((identity, removed), None)
            self.external_catalogs[identity] = projects
            for key, information in result.get("builtin_information", {}).items():
                self.project_details[(identity, key)] = information
            for project in result["projects"]:
                if project["kind"] == "builtin":
                    self.project_details[(identity, project["service"])] = project["information"]
                else:
                    cached = self.project_details.get((identity, project["id"]), {}).get("external", {})
                    self._cache_external_information(c, dict(cached, project=project, fingerprint=ExternalProjects.fingerprint(project), saved_at=""))
            self._sync_manage_projects()
            label = next((label for label, key in self.manage_project_labels.items() if key == selected), None)
            if label: self.manage_choice.set(label)
            self._project_changed()
            self.status.configure(text="已读取 " + str(len(result["projects"])) + " 个已安装项目，已更新项目下拉列表。" + " ".join(dict.fromkeys(result.get("warnings", []))))
        self._run(lambda: self.controller.external_projects(c, include_builtin=True), done, "刷新读取服务器项目，更新下拉列表…")

    def _register_external_directory(self):
        if self.busy or not self._ready(): return
        c = self.current
        path = simpledialog.askstring("登记安装目录", "填写服务器上的项目目录（例如 /opt/my-app）；只读取目录与公开版本信息。", parent=self)
        if not path: return
        def done(project):
            if not self.current or server_key(self.current) != server_key(c): return
            from .external_projects import ExternalProjects
            self._cache_external_information(c, {"project": project, "fingerprint": ExternalProjects.fingerprint(project)})
            self._sync_manage_projects()
            self.manage_choice.set(next(label for label, key in self.manage_project_labels.items() if key == project["id"]))
            self._project_changed()
        self._run(lambda: self.controller.register_external_directory(c, path), done, "核对服务器项目目录…")

    def _forget_external_directory(self):
        if self.busy or not self._ready(): return
        c = self.current; key = self._service_key(self.manage_choice.get()); identity = server_key(c)
        info = self.project_details.get((identity, key), {}).get("external", {})
        if not info.get("project", {}).get("registered_local"): return
        if not messagebox.askyesno("移除本机登记", "仅移除本机目录登记；服务器项目、数据与本机凭据记录均保留。是否继续？", parent=self): return
        def done(_):
            self.__dict__.get("external_catalogs", {}).get(identity, {}).pop(key, None)
            self.project_details.pop((identity, key), None)
            if self.current and server_key(self.current) == identity:
                self._project_changed()
                self.status.configure(text="已移除本机登记；服务器文件和本机凭据均保留。")
        self._run(lambda: self.controller.forget_external_directory(c, key), done, "移除本机目录登记…")


    def _deploy(self):
        if not self._ready(): return
        try:
            key = self._service_key(self.deploy_choice.get())
            params = {"operation": "deploy", "service": key, "host": self.deploy_host.get().strip() or self.current.host, "port": validate_port(self.deploy_port.get())}
            if key != "nginx" or self.version_mode.get() == SPECIFIC_VERSION: params["version"] = self.deploy_version.get().strip()
            if self.version_mode.get() == KEEP_CURRENT: params["version_policy"] = "keep"
            if key == "exchange": params["backend_port"] = validate_port(self.deploy_backend.get())
            if key == "cliproxyapi":
                params.update(backend_port=validate_port(self.deploy_backend.get()), auto_update=self.deploy_auto_update.get())
                if self.deploy_password.get(): params["management_key"] = validate_password(self.deploy_password.get())
                if self.deploy_api_key.get(): params["api_key"] = validate_password(self.deploy_api_key.get())
            if key == "reality": params["server_name"] = self.deploy_server_name.get().strip() or "www.cloudflare.com"
            existing = bool(self._deployment_current(key))
            if key == "hysteria2": params["proxy_password"] = validate_password(self.deploy_password.get()) if self.deploy_password.get() or not existing else ""
            if key == "xui": params.update(panel_username=validate_user(self.deploy_username.get()), panel_password=validate_password(self.deploy_password.get()) if self.deploy_password.get() or not existing else "")
            if key != "nginx" and self.version_mode.get() == LATEST_STABLE:
                params.pop("version", None)
            self._preview_deployment(params)
        except ManagerError as error:
            messagebox.showerror("检查输入", str(error), parent=self)

    def _preview_deployment(self, params):
        c = self.current
        wait_cancel = threading.Event()
        def done(plan):
            params["version"] = plan["version"]
            params["deployment_fingerprint"] = plan["fingerprint"]
            self.deploy_version.set(plan["version"])
            names = {"install":"首次安装", "reconfigure":"调整现有配置", "update":"切换软件版本", "repair":"保留数据并修复安装", "retry":"重新准备未完成的首次安装", "unchanged":"条件相同，无需重复安装"}
            lines = [SERVICES[params["service"]][0] + "：" + ("重新安装（沿用保留的数据）" if plan.get("reinstall") else names[plan["action"]]), "目标版本：" + plan["version"]]
            if params["service"] == "cliproxyapi":
                lines.extend(["管理页面版本：" + plan["panel_version"], "自动更新：" + ("开启（每 30 分钟检查）" if plan["auto_update"] else "关闭"), "后台：https://" + plan["host"] + ":" + str(plan["port"]) + "/management.html"])
            for item in plan["changes"]:
                lines.append(item["name"] + "：" + str(item["before"] or "未设置") + " → " + str(item["after"]))
            if plan["installed"] and plan["action"] != "unchanged": lines.append("先备份原配置；保留现有账号、节点和业务数据。新配置验证失败时恢复原项目。")
            if params["service"] == "exchange" and plan["installed"] and plan["action"] not in {"unchanged", "retry"}:
                lines.append("开始即确认：你已在交易网页停止交易并完成撤单与清理，再进行本次维护。")
                params["maintenance_confirmed"] = True
            lines.append(deployment_network_hint(params["service"], params["port"], params.get("backend_port")))
            self._execute(params, "\n".join(lines))
        self._run(lambda:self.controller.deployment_preview(c, params, cancel_event=wait_cancel), done, "Linux 正在查询官方版本并比对部署条件…", wait_cancel=wait_cancel)

    def _details(self):
        if not self._ready(): return
        self.manage_choice.set(self.deploy_choice.get())
        self._project_changed()
        self.notebook.select(self.pages["日常维护"])
        self._refresh_project_info()

    def _secret_dialog(self, title, value, open_url=False):
        dialog = tk.Toplevel(self); dialog.title(title); dialog.geometry("620x180"); dialog.transient(self)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=title, style="Heading.TLabel").pack(anchor="w")
        variable = tk.StringVar(dialog, value=value)
        entry = ttk.Entry(frame, textvariable=variable, show="•", width=70); entry.pack(fill="x", pady=16)
        entry.variable = variable
        actions = ttk.Frame(frame); actions.pack(fill="x")
        self._button(actions, "显示 / 隐藏", lambda: entry.configure(show="" if entry.cget("show") else "•"), track=False).pack(side="left")
        self._button(actions, "复制", lambda: self._copy(value), track=False).pack(side="left", padx=10)
        if open_url: self._button(actions, "打开管理网页", lambda: webbrowser.open(value), track=False).pack(side="left")

    def _copy(self, value):
        self.clipboard_clear(); self.clipboard_append(value)
        self.status.configure(text="已复制到本机剪贴板。")

    def _service(self, action):
        key = self._service_key(self.manage_choice.get())
        if key.startswith("external:"):
            if self.busy or not self._ready(): return
            c = self.current; identity = server_key(c)
            info = self.project_details.get((identity, key), {}).get("external", {})
            project = info.get("project", {})
            if action not in project.get("capabilities", []) or not info.get("fingerprint"):
                self.status.configure(text="该项目暂不支持此操作，请使用原有启动方式。")
                return
            labels = {"start": "启动", "stop": "停止", "restart": "重启", "enable": "开启自启", "disable": "关闭自启"}
            if not messagebox.askyesno("确认项目操作", "服务器：" + c.label + "\n项目：" + project["name"] +
                                      "\n操作：" + labels[action] + "\n\n停止或重启会中断该项目的连接；是否执行？", parent=self): return
            params = {"operation": "service", "service": key, "action": action, "external_fingerprint": info["fingerprint"]}
            def done(result):
                status, _ = result
                updated = status.get("result", {}).get("external_project")
                if updated and self.current and server_key(self.current) == identity:
                    self._cache_external_information(c, dict(info, project=updated))
                    self._project_changed()
                    self.status.configure(text="项目操作已完成，已核对状态；记录已保存到操作记录。")
            self._run(lambda: self.controller.execute(c, params), done, "执行已确认的项目操作…")
            return
        if key not in SERVICES: return
        params = {"operation": "service", "service": key, "action": action}
        if key == "exchange" and action in {"stop", "restart"}:
            if not messagebox.askyesno("确认维护条件", "请先在交易网页停止任务并确认撤单及清理完成。\n是否已经完成？", parent=self): return
            params["maintenance_confirmed"] = True
        description = "对“" + SERVICES[key][0] + "”执行所选服务管理操作。"
        if key == "cliproxyapi" and action == "check_update":
            description += "\n查询官方稳定版；发现新版后会备份、下载并升级核心和管理页面。升级重启会短暂中断模型请求，失败自动恢复原版本。"
        if key == "cliproxyapi" and action == "rollback_core":
            description += "\n恢复最近一次升级前的核心和页面，保留当前配置与授权；成功后关闭自动更新。"
        if key == "nginx":
            description += "\n仅操作 nginx.service 共享核心，会影响该核心下的其他网站；不操作交易系统的专属网页入口。"
        self._execute(params, description)

    def _uninstall(self):
        if self.busy or not self._ready(): return
        c = self.current; kind = self._service_key(self.manage_choice.get())
        if kind not in SERVICES:
            self.status.configure(text="外部项目请使用原有卸载方式；本程序不会删除其文件或数据。")
            return
        params = {"operation": "uninstall", "service": kind, "keep_data": True}
        def done(plan):
            if not self.current or server_key(self.current) != server_key(c):
                self.status.configure(text="服务器已切换，请重新预览卸载。")
                return
            if plan["action"] == "unchanged":
                messagebox.showinfo("卸载项目", "这个项目已经卸载，保留的数据不会清空。", parent=self)
                return
            params["uninstall_fingerprint"] = plan["fingerprint"]
            lines = ["目标服务器：" + c.label, "卸载项目：" + SERVICES[kind][0], plan["message"], "移除范围：\n" + "\n".join(plan["remove_paths"]), "保留目录：\n" + "\n".join(plan["retained_paths"]), "不删除 SSH 账号、本机口令、共享证书与续期工具、系统依赖或防火墙规则。", "移除文件保存在服务器管理员专用任务目录，用于失败恢复，仍占磁盘空间；重要业务数据须单独安全备份。"]
            if kind == "exchange":
                lines.append("确认开始即表示：已在交易网页停止所有交易，完成撤单和清理。本程序不能代替你核对订单；无法确认请取消。")
                params["maintenance_confirmed"] = True
            self._replace_text(self.maintenance_text, "\n\n".join(lines))
            unit_paths = [name for name in plan["remove_paths"] if name.startswith("/etc/systemd/system/")]
            files = [name for name in plan["remove_paths"] if name not in unit_paths]
            summary = lines[:3] + ["移除文件 / 目录：\n" + "\n".join(files), "同时移除 " + str(len(unit_paths)) + " 项专属服务 / 定时器定义，完整范围见下方预览。", "保留目录：\n" + "\n".join(plan["retained_paths"]), lines[5], lines[6]]
            if kind == "exchange": summary.append(lines[-1])
            self._execute(params, "\n".join(summary))
        self._run(lambda: self.controller.uninstall_preview(c, params), done, "检查所选项目的卸载范围与共享依赖…")

    def _logs(self):
        if not self._ready(): return
        key = self._service_key(self.manage_choice.get()); c = self.current
        if not key: return
        redactor = self._redactor()
        info = self.project_details.get((server_key(c),key), {})
        for name,value in info.get("rows",[]):
            if any(word in name for word in ("密码", "Key", "初始化码", "节点", "订阅")):
                redactor.add(value)
        def done(data):
            text = redactor.text(data["logs"])
            self.project_logs[(server_key(c),key)] = text
            if self.current and server_key(self.current)==server_key(c) and self._service_key(self.manage_choice.get())==key:
                self._replace_text(self.maintenance_text, text)
        request = {"action": "external_logs", "identifier": key} if key.startswith("external:") else {"action": "logs", "service": key}
        self._run(lambda: self.controller.transport(c).call(request), done)


    def _refresh_project_info(self):
        if not self._ready(): return
        c = self.current; key = self._service_key(self.manage_choice.get())
        if not key: return
        def done(information):
            if key.startswith("external:"):
                if not self.current or server_key(self.current) != server_key(c): return
                self._cache_external_information(c, information)
            else: self.project_details[(server_key(c),key)] = information
            if self.current and server_key(self.current)==server_key(c) and self._service_key(self.manage_choice.get())==key:
                self._project_changed()
            self.status.configure(text="项目信息已刷新；选中一项可复制完整内容。")
        worker = (lambda: self.controller.external_project_information(c, key)) if key.startswith("external:") else (lambda: self.controller.project_information(c, key))
        self._run(worker, done, "读取项目端口、网址及连接信息…")


    def _show_node_qr(self, value):
        try:
            png = qr_png(value)
        except ManagerError as error:
            messagebox.showerror("节点二维码", str(error), parent=self)
            return
        dialog = tk.Toplevel(self); dialog.title("扫码导入节点"); dialog.transient(self); dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="使用代理客户端扫码导入", style="Heading.TLabel").pack()
        dialog.qr_image = tk.PhotoImage(master=dialog, data=base64.b64encode(png).decode())
        ttk.Label(frame, image=dialog.qr_image).pack(pady=12)
        ttk.Label(frame, text="二维码包含完整节点凭据，请仅供自己的设备扫描。", wraplength=380, justify="center").pack()
        self._button(frame, "复制节点链接", lambda:self._copy(value), track=False).pack(pady=(12, 0))


    def _client_configurator(self):
        return ClientConfigurator(self.store.directory / "client-config-backups")

    def _choose_local_client_application(self):
        if self.busy: return
        self._run(installed_applications, self._local_client_application_dialog, "识别已安装的客户端应用…")

    def _local_client_application_dialog(self, applications):
        dialog = tk.Toplevel(self); dialog.title("选择已安装应用"); dialog.transient(self)
        body = ttk.Frame(dialog, padding=20); body.pack(fill="both", expand=True)
        ttk.Label(body, text="选择要配置的 App", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(body, text="点击应用图标，程序自动识别当前用户的配置，无需选择路径。", wraplength=550).pack(anchor="w", pady=(8, 14))
        grid = ttk.Frame(body); grid.pack(fill="both", expand=True)
        dialog.icons = []
        def select(application):
            try:
                current = resolve_application(application.path)
                configurator = self._client_configurator()
                directory = configurator.directories[current.client]
                self.local_client_choice.set(CLIENTS[current.client])
                self.status.configure(text="已选择 " + current.name + "；已自动定位本机配置：" + str(directory))
                dialog.destroy()
            except (ManagerError, OSError) as error:
                messagebox.showerror("选择已安装应用", str(error) if isinstance(error, ManagerError) else "本机配置暂时无法识别，请刷新后重试。", parent=dialog)
        for index, application in enumerate(applications):
            icon = None
            if application.icon:
                try:
                    icon = tk.PhotoImage(master=dialog, data=base64.b64encode(application.icon).decode())
                    dialog.icons.append(icon)
                except tk.TclError:
                    pass
            label = application.name
            if sum(item.name == application.name for item in applications) > 1:
                label += "\n" + ("系统安装" if application.path.parent == Path('/Applications') else "个人安装" if application.path.parent == Path.home() / 'Applications' else application.path.parent.name)
            ttk.Button(grid, text=label if icon else "◎\n" + label, image=icon or "", compound="top", width=19,
                       command=lambda item=application: select(item)).grid(row=index // 3, column=index % 3, padx=8, pady=10)
        if not applications:
            ttk.Label(grid, text="未发现支持配置的桌面客户端，请先安装 GPT / Codex 或 OpenCode，再刷新。", wraplength=550).pack(anchor="w", pady=12)
        ttk.Label(body, text="Claude Code、Pi 命令行版使用原有一键配置按钮，程序会自动定位；Claude 桌面聊天应用不在此列表中。",
                  wraplength=550, style="Muted.TLabel").pack(anchor="w", pady=(10, 14))
        actions = ttk.Frame(body); actions.pack(fill="x")
        self._button(actions, "刷新应用列表", lambda: (dialog.destroy(), self._choose_local_client_application()), track=False).pack(side="left")
        self._button(actions, "取消", dialog.destroy, track=False).pack(side="right")

    def _configure_local_client(self, client):
        if self.busy or not self._ready(): return
        c = self.current.changed()
        def done(information):
            if not self.current or server_key(self.current) != server_key(c) or self._service_key(self.manage_choice.get()) != "cliproxyapi":
                self.status.configure(text="服务器或项目已切换，请重新配置客户端。")
                return
            self.project_details[(server_key(c), "cliproxyapi")] = information
            self._project_changed()
            try:
                connection = gateway_connection(information)
            except ManagerError as error:
                messagebox.showerror("配置客户端", str(error), parent=self); return
            self._local_client_dialog(client, c, connection)
        self._run(lambda: self.controller.project_information(c, "cliproxyapi"), done, "读取所选服务器的接口地址和客户端 Key…")

    def _local_client_dialog(self, client, connection, gateway):
        try:
            configurator = self._client_configurator()
        except (ManagerError, OSError) as error:
            messagebox.showerror("配置客户端", str(error) if isinstance(error, ManagerError) else "本机目录设置未能读取，请检查目录权限。", parent=self); return
        dialog = tk.Toplevel(self); dialog.title("配置本机 · " + CLIENTS[client]); dialog.transient(self)
        dialog.geometry("740x520"); dialog.minsize(700, 500)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=CLIENTS[client] + " → " + connection.label, style="Heading.TLabel").pack(anchor="w")
        ttk.Label(frame, text=gateway["base_url"], wraplength=650).pack(anchor="w", pady=(8, 12))
        key_labels = ["客户端 Key " + str(i + 1) for i in range(len(gateway["api_keys"]))]
        key_choice = tk.StringVar(dialog, value=key_labels[0])
        ttk.Label(frame, text="客户端 Key（使用服务器当前有效值）").pack(anchor="w")
        key_box = ttk.Combobox(frame, textvariable=key_choice, values=key_labels, state="readonly", width=32); key_box.pack(anchor="w", pady=6)
        ttk.Label(frame, text="默认模型").pack(anchor="w")
        model = tk.StringVar(dialog)
        model_box = ttk.Combobox(frame, textvariable=model, state="disabled", width=58); model_box.pack(anchor="w", pady=6)
        hint = tk.StringVar(dialog, value="正在从这台电脑验证 HTTPS、客户端 Key 和模型目录…")
        ttk.Label(frame, textvariable=hint, wraplength=650, justify="left").pack(anchor="w", pady=8)
        ttk.Label(frame, text="将备份并修改：\n" + "\n".join(str(p) for p in configurator.paths(client)), style="Muted.TLabel", wraplength=650, justify="left").pack(anchor="w")
        state = {"models": [], "key": None}
        actions = ttk.Frame(frame); actions.pack(anchor="w", pady=12)
        apply_button = self._button(actions, "备份并应用配置", lambda: apply(), track=False); apply_button.pack(side="left")
        apply_button.configure(state="disabled")
        self._button(actions, "取消", dialog.destroy, track=False).pack(side="left", padx=12)
        def refresh(_=None):
            if self.busy or not dialog.winfo_exists(): return
            state.update(models=[], key=None); model.set(""); model_box.configure(state="disabled")
            apply_button.configure(state="disabled"); key_box.configure(state="disabled")
            index = key_labels.index(key_choice.get()); token = gateway["api_keys"][index]
            def loaded(models):
                if not dialog.winfo_exists(): return
                state.update(models=models, key=token)
                choices = chat_models(models)
                if client == "claude":
                    choices = [m for m in choices if "claude" in m.lower()]
                if not choices:
                    hint.set("服务器没有可用于 Claude Code 的 Claude 模型，请先在后台添加授权或模型。" if client == "claude" else "服务器没有可用于对话的模型，请先在后台添加授权或模型。")
                    key_box.configure(state="readonly"); return
                preferred = next((m for m in choices if "gpt" in m.lower()), choices[0]) if client != "claude" else choices[0]
                model_box.configure(values=choices, state="readonly"); model.set(preferred)
                hint.set("将配置模型发现及 Sonnet／Opus 别名，所选项作为默认模型。应用前请关闭客户端。" if client == "claude" else "将写入 " + str(len(chat_models(models))) + " 个对话模型；所选项仅作为默认模型，GPT 下拉框、Pi /model 可继续切换。应用前请关闭客户端。")
                apply_button.configure(state="normal"); key_box.configure(state="readonly")
            self._run(lambda: gateway_models(gateway["base_url"], token), loaded, "验证本机到服务器的客户端连接…")
            def retry_controls():
                if not dialog.winfo_exists(): return
                if self.busy: self.after(100, retry_controls)
                else: key_box.configure(state="readonly")
            self.after(100, retry_controls)
        def apply():
            if self.busy or state["key"] is None: return
            if gateway["api_keys"][key_labels.index(key_choice.get())] != state["key"]:
                refresh(); return
            if not self.current or server_key(self.current) != server_key(connection) or self._service_key(self.manage_choice.get()) != "cliproxyapi":
                messagebox.showerror("配置客户端", "服务器或项目已切换，请重新打开配置窗口。", parent=dialog); return
            selected_model = model.get(); token = state["key"]; models = list(state["models"])
            def worker():
                # Recheck the selected credential and model immediately before writing.
                fresh = gateway_models(gateway["base_url"], token)
                if selected_model not in fresh or selected_model not in models:
                    raise ManagerError("服务器模型列表已改变；请重新选择模型。未改动本地配置。")
                return configurator.configure(client, gateway["base_url"], token, selected_model, fresh)
            def applied(result):
                if dialog.winfo_exists(): dialog.destroy()
                self.status.configure(text=CLIENTS[client] + " 本机配置已保存；重启客户端后使用。")
                messagebox.showinfo("本机客户端已配置", CLIENTS[client] + " 已配置。\n请完全退出并重新打开客户端，新建会话验证模型调用。\n\n原配置备份：" + result["backup_id"] + "\n可使用「恢复原客户端配置」回退。", parent=self)
            self._run(worker, applied, "备份并写入本机客户端配置…")
        key_box.bind("<<ComboboxSelected>>", refresh)
        self._button(actions, "重新读取模型", refresh, track=False).pack(side="left")
        refresh()

    def _restore_local_client(self):
        if self.busy: return
        client = next(name for name, title in CLIENTS.items() if title == self.local_client_choice.get())
        try:
            configurator = self._client_configurator()
        except (ManagerError, OSError) as error:
            messagebox.showerror("恢复客户端配置", str(error) if isinstance(error, ManagerError) else "本机目录设置未能读取，请检查目录权限。", parent=self); return
        rows = configurator.backups_for(client)
        if not rows:
            messagebox.showinfo("恢复客户端配置", "这个客户端还没有本程序创建的配置备份。", parent=self); return
        dialog = tk.Toplevel(self); dialog.title("恢复本机 · " + CLIENTS[client]); dialog.transient(self)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        original = next((r["id"] for r in reversed(rows) if r["action"] == "configure"), rows[-1]["id"])
        labels = [r["created"][:19].replace("T", " ") + " · " + ("首次配置前" if r["id"] == original else "恢复前" if r["action"] == "restore" else "配置前") + (" · " + r["model"] if r["model"] else "") + " · " + r["id"][-8:] for r in rows]
        choice = tk.StringVar(dialog, value=labels[next(i for i, r in enumerate(rows) if r["id"] == original)])
        ttk.Label(frame, text="选择要恢复的版本；默认选中首次配置前的原配置。", wraplength=680).pack(anchor="w")
        ttk.Combobox(frame, textvariable=choice, values=labels, state="readonly", width=85).pack(fill="x", pady=14)
        ttk.Label(frame, text="请先关闭对应客户端。恢复会覆盖上述客户端配置，原本不存在的文件会删除；当前配置会先另存备份。\n恢复本机配置无需连接服务器。", wraplength=680, justify="left").pack(anchor="w")
        def restore():
            if self.busy: return
            identifier = rows[labels.index(choice.get())]["id"]
            def done(result):
                if dialog.winfo_exists(): dialog.destroy()
                self.status.configure(text=CLIENTS[client] + " 原配置已恢复；请重启客户端。")
                messagebox.showinfo("客户端配置已恢复", "已恢复所选版本，请重启 " + CLIENTS[client] + "。\n\n恢复前配置已备份：" + result["backup_id"], parent=self)
            self._run(lambda: configurator.restore(client, identifier), done, "备份当前配置并恢复所选客户端版本…")
        actions = ttk.Frame(frame); actions.pack(anchor="w", pady=14)
        self._button(actions, "备份当前配置并恢复", restore, track=False).pack(side="left")
        self._button(actions, "取消", dialog.destroy, track=False).pack(side="left", padx=12)

    def _oauth(self, provider):
        if self.busy or not self._ready(): return
        c = self.current
        try:
            login = self.controller.oauth_login(c, provider)
        except ManagerError as error:
            messagebox.showerror("登录授权", str(error), parent=self); return
        dialog = tk.Toplevel(self); dialog.title("登录授权 · " + OAUTH_PROVIDERS[provider]['label'])
        dialog.transient(self); dialog.geometry("620x230")
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="正在为“" + c.label + "”准备登录…", wraplength=570).pack(anchor="w")
        hint = tk.StringVar(dialog, value="请保持管理器打开；回调会自动转交这台服务器。")
        ttk.Label(frame, textvariable=hint, wraplength=570, justify="left").pack(anchor="w", pady=12)
        code = tk.StringVar(dialog)
        entry = ttk.Entry(frame, textvariable=code, state="readonly", width=30)
        actions = ttk.Frame(frame); actions.pack(anchor="w", pady=12)
        self._button(actions, "取消本次授权", login.cancel, track=False).pack(side="left")
        dialog.protocol("WM_DELETE_WINDOW", login.cancel)
        def ready(data):
            acknowledgement = threading.Event(); errors = []
            def open_browser(value):
                try:
                    if login.cancel_event.is_set() or not self.current or server_key(self.current) != server_key(c):
                        raise ManagerError("授权已取消或服务器已切换，未打开旧授权页。")
                    if value.get("mode") in {"device", "api-device"}:
                        hint.set("请在官方网页完成设备授权；如网页要求输入设备码，请使用下面的码。服务器会自动取得授权结果，无需本机回调端口。")
                        if value.get("user_code"):
                            code.set(value["user_code"]); entry.pack(anchor="w", before=actions)
                    elif value.get("mode") == "observe":
                        hint.set("固定回调端口被占用，将仅从 Chrome 读取属于本次登录的回调。回调页可能显示连接错误，不需复制网址，请以管理器的最终结果为准。")
                    else:
                        hint.set("请在新打开的官方网页完成登录；不需要复制回调网址。以管理器的最终结果为准。")
                except Exception as error:
                    errors.append(error if isinstance(error, ManagerError) else ManagerError("打开浏览器未完成，授权已停止。"))
                finally:
                    acknowledgement.set()
            self.events.put(("oauth_ready", data, open_browser))
            while not acknowledgement.wait(0.1):
                if login.cancel_event.is_set():
                    raise ManagerError("授权已取消，未继续打开网页。")
            if errors: raise errors[0]
            if login.cancel_event.is_set():
                raise ManagerError("授权已取消，未继续打开网页。")
            from .oauth import open_authorization_browser
            # AppleScript/system permission waits must not freeze Tk cancellation.
            if not open_authorization_browser(data["url"]):
                raise ManagerError("无法打开授权浏览器；授权已停止，请检查浏览器后重试。")
        def progress(text):
            self.events.put(("progress", {"message": text}, None))
        def done(_):
            self.status.configure(text="服务器已保存并识别本次授权；实际模型可用性以后台查询为准。")
            self._refresh_project_info()
        def close_dialog():
            if login.finished.is_set():
                if dialog.winfo_exists(): dialog.destroy()
            elif self.winfo_exists():
                self.after(100, close_dialog)
        self._run(lambda: login.run(ready, progress), done, "正在准备服务器登录授权…")
        self.after(100, close_dialog)

    def _save_project_credentials(self):
        if not self._ready(): return
        key = self._service_key(self.manage_choice.get()); c = self.current
        if key.startswith("external:"):
            if self.busy: return
            from .external_projects_gui import credentials_dialog
            def show(information):
                if not self.current or server_key(self.current) != server_key(c) or self._service_key(self.manage_choice.get()) != key: return
                self._cache_external_information(c, information)
                def saved(values):
                    if not self.current or server_key(self.current) != server_key(c): return
                    current = self.project_details.get((server_key(c), key), {}).get("external", information)
                    self._cache_external_information(c, dict(current, credentials=values, credentials_warning=""))
                    self._project_changed()
                    self.status.configure(text="登录记录已保存到本机钥匙串；服务器账号未修改。")
                credentials_dialog(self, c, information, saved)
            information = self.project_details.get((server_key(c), key), {}).get("external", {})
            if "credentials" in information and not information.get("credentials_warning"): show(information)
            else: self._run(lambda: self.controller.external_project_information(c, key), show, "读取当前项目的本机登录记录…")
            return
        if key == "cliproxyapi":
            secret = simpledialog.askstring("补充管理 Key", "填写现有管理 Key；验证后保存到本机钥匙串，不修改服务器。", show="•", parent=self)
            if not secret: return
            def save_key():
                result = self.controller.transport(c).call({"action": "verify_cliproxy_key", "management_key": secret})
                if not result.get("verified"): raise ManagerError("管理 Key 验证失败，未保存。")
                self.store.vault.put(credential_alias(c, key), {"management_key": secret})
            self._run(save_key, lambda _: self._refresh_project_info(), "验证并保存管理 Key…")
            return
        if key != "xui":
            messagebox.showinfo("登录信息", "代理面板的旧密码无法从服务器反推，可在这里补充本机记录。其他项目的信息直接从服务器读取。",parent=self); return
        dialog = tk.Toplevel(self); dialog.title("补充代理面板登录信息"); dialog.transient(self)
        frame = ttk.Frame(dialog,padding=20);frame.pack(fill="both",expand=True)
        ttk.Label(frame,text="仅保存到本机钥匙串；不会修改服务器密码。",wraplength=480).pack(anchor="w")
        username=tk.StringVar(dialog); password=tk.StringVar(dialog)
        for label,variable,secret in [("后台账号",username,False),("后台密码",password,True)]:
            ttk.Label(frame,text=label).pack(anchor="w",pady=(12,4))
            ttk.Entry(frame,textvariable=variable,show="•" if secret else "",width=48).pack(fill="x")
        def save():
            values={"panel_username":username.get().strip(),"panel_password":password.get()}
            if not all(values.values()):return
            def done(_):
                dialog.destroy()
                if self.current and server_key(self.current)==server_key(c):self._refresh_project_info()
            self._run(lambda:self.store.vault.put(credential_alias(c,key),values),done,"保存到本机钥匙串…")
        self._button(frame,"保存本机记录",save,track=False).pack(anchor="w",pady=(16,0))

    def _firewall(self):
        if not self._ready(): return
        ports = [{"port": x["port"], "protocol": x["protocol"]} for x in self.report["listeners"] if not x["local_only"] and x["port"] in {self.current.port, 80, 443, 26483, 51752, 2053, 30043, 9229}]
        rules = sorted({(self.current.port, "tcp")} | {(item["port"], item["protocol"]) for item in ports})
        listing = "\n".join(f"• {protocol.upper()} {number}" for number, protocol in rules)
        self._execute({"operation": "firewall", "ssh_port": self.current.port, "ports": ports}, "开启服务器防火墙，保留现有规则，本次放行：\n"+listing+"\n未列出的自定义端口需已有放行规则；云平台安全组需按对应协议另行设置。\n新连接验证失败会自动恢复原防火墙配置。")

    def _updates(self):
        self._execute({"operation": "updates", "enabled": True}, "开启系统自动安全更新并验证定时调度；从下一次计划开始，不立即补跑升级，自动重启保持关闭。")

    def _backup(self, kind=None):
        key = kind or self._service_key(self.manage_choice.get())
        if key not in SERVICES and key != "security":
            self.status.configure(text="外部项目请使用原有备份方式。")
            return
        self._execute({"operation": "backup", "service": key}, "备份所选服务配置到服务器的管理员专用目录。不会删除业务数据。")

    def _restore(self):
        identifier = self.restore_id.get().strip()
        self._execute({"operation": "restore", "backup_id": identifier}, "恢复所选配置备份，并先保存当前配置。\n只恢复该备份包含的配置，不恢复交易账本。")

    def _tasks(self):
        if not self._ready(): return
        c = self.current
        self._run(lambda: self.controller.tasks(c), lambda data: self._show_tasks(data["tasks"]))


    def _task_password(self):
        if self.busy or not self.current:
            return
        selected = self.task_tree.selection()
        if not selected:
            c = self.current
            def listed(data):
                self._show_tasks(data["tasks"])
                self.status.configure(text="已列出本机保存的新密码记录；选中一条后再次点击「查看本次新密码」。" if data["tasks"] else "当前服务器没有可查看的新密码副本。旧版本记录不会补生成密码。")
            self._run(lambda: self.controller.saved_password_tasks(c), listed, "读取当前服务器的本机密码记录…")
            return
        task = next((item for item in self.latest_tasks if item["id"] == selected[0]), None)
        if not task or task.get("operation") not in {"create_admin", "password"}:
            messagebox.showinfo("本次新密码", "请选中创建管理员或修改密码的操作记录。", parent=self)
            return
        identifier = task["id"]; c = self.current
        def worker():
            from .vault import vault_alias
            saved = self.store.vault.get(vault_alias("task-password", identifier))
            return saved.get("password", "") if saved.get("host") == c.host else ""
        def done(value):
            if not value:
                messagebox.showinfo("本次新密码", "这条操作没有本机口令副本，或账号已删除。旧版本的记录不会补生成密码。", parent=self)
                return
            self._secret_dialog("本次设置的新密码（是否生效请核对任务结果）", value)
        self._run(worker, done, "读取本机钥匙串中的本次新密码…")

    def _recover(self):
        if not self._ready(): return
        selection = self.task_tree.selection()
        if not selection: return
        identifier = selection[0]; c = self.current
        task = next((item for item in self.latest_tasks if item["id"] == identifier), {})
        if task.get("operation") == "uninstall":
            description = "恢复异常中断或恢复未完成的卸载，找回移除的项目文件并恢复原服务状态；不会覆盖新安装或清空业务数据。已完成卸载不能用此按钮撤销。"
        elif task.get("operation") == "deploy":
            description = "仅对异常中断或恢复未完成的部署，按原任务备份恢复项目、配置和服务状态；可能短暂停机。交易系统请先停止交易并完成撤单与清理。已完成部署不能用此按钮撤销。"
        else:
            description = "恢复该任务变更前的配置，仅适用于等待验证的连接变更。"
        if not messagebox.askyesno("恢复变更", description, parent=self): return
        self._run(lambda: self.controller.transport(c).call({"action": "recover", "task_id": identifier}), lambda task: self._show_tasks([task] + self.latest_tasks))

    def _replace_text(self, widget, text):
        widget.configure(state="normal"); widget.delete("1.0", "end"); widget.insert("end", text); widget.configure(state="disabled")

    def _vnc_help(self):
        command = "sudo /usr/sbin/sshd -T | awk '$1==\"permitrootlogin\" || $1==\"passwordauthentication\" || $1==\"authenticationmethods\"'"
        dialog = tk.Toplevel(self); dialog.title("VNC 登录排查"); dialog.geometry("760x240"); dialog.transient(self)
        frame = ttk.Frame(dialog, padding=20); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="控制台登录与 SSH 使用不同的登录策略", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(frame, text="先核实云镜像提供的登录账号。密码正确但账号不匹配也会被拒绝。\n可在 VNC 中执行下面的只读检查，查看是否禁止密码登录或超级管理员登录。", wraplength=700).pack(anchor="w", pady=12)
        text = tk.Text(frame, height=3, wrap="word", relief="flat"); text.pack(fill="x"); text.insert("end", command); text.configure(state="disabled")
        self._button(frame, "复制只读检查命令", lambda: self._copy(command), track=False).pack(anchor="w", pady=12)

    def _close(self):
        if self.busy and not messagebox.askyesno("后台任务进行中", "服务器已提交的任务会继续执行。关闭后可重新连接并查看记录。\n是否关闭窗口？", parent=self):
            return
        self.controller.close_connections()
        (self.store.directory / "window-state.json").unlink(missing_ok=True)
        self.destroy()


def main():
    if "--askpass" in sys.argv:
        raise SystemExit(answer_askpass())
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--development-profile", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--desktop-data", action="store_true", help="源码运行时使用原桌面版的本机档案和钥匙串")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--check-release", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ui-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--vault-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--key-check", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.key_check:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="lm-key-check-", dir="/private/tmp") as folder:
            store = Store(Path(folder)); controller = Controller(store)
            try:
                conn = Connection(host="fictional.invalid", username="fixture")
                phrase = secrets.token_urlsafe(36)
                key, public = controller.generate_key(conn, phrase)
                checked = controller.public_key(conn.changed(key_path=key, key_passphrase=phrase))
                if not encrypted_key(key) or checked.split()[:2] != public.split()[:2]:
                    raise ManagerError("加密私钥验证失败。")
            finally:
                for meta in (Path(folder) / "keys").rglob("*.json"):
                    store.vault.delete(json.loads(meta.read_text())["vault_alias"])
        print("加密私钥、本机钥匙串及独立验证进程检查通过。")
        return
    if args.vault_check:
        from .vault import LocalVault
        vault = LocalVault(); identifier = secrets.token_hex(8)
        values = {"password": "fictional-local-keychain-check"}
        try:
            vault.put(identifier, values)
            if vault.get(identifier) != values:
                raise SystemExit("本机钥匙串验证失败。")
        finally:
            vault.delete(identifier)
        print("本机钥匙串保存、读取和删除验证通过。")
        return
    if args.check_release:
        try:
            print("官方稳定版查询通过：" + exchange_version())
        except ManagerError as error:
            raise SystemExit(str(error))
        return
    if args.self_check:
        import shutil
        missing = [name for name in ["ssh", "ssh-keygen", "ssh-keyscan"] if not shutil.which(name)]
        if missing:
            raise SystemExit("缺少 OpenSSH 工具。")
        try:
            import segno
            segno.make('linux-manager-runtime-check')
            root = tk.Tk(); root.withdraw(); root.update_idletasks(); root.destroy()
        except (ImportError, tk.TclError):
            raise SystemExit("图形界面或二维码运行环境不可用；未读取本机登录档案。") from None
        print(APP_NAME + "：环境检查通过。")
        return
    import fcntl
    directory = data_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "application.lock").open("a") as instance:
        os.chmod(directory / "application.lock", 0o600)
        try:
            fcntl.flock(instance, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            messagebox.showinfo(APP_NAME, "程序已在运行，请切换到现有窗口。")
            return
        app = App(development_profile=args.development_profile)
        import signal
        signal.signal(signal.SIGTERM, lambda *_: app.after(0, app.destroy))
        if args.ui_check:
            app.after(1200, app._check_ui)
        try:
            app.mainloop()
        finally:
            app.controller.close_connections()
            (app.store.directory / "window-state.json").unlink(missing_ok=True)
