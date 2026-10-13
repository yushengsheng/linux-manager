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
from tkinter import filedialog, font, messagebox, ttk
import urllib.parse
import webbrowser

from . import APP_NAME, VERSION
from .controller import Controller
from .models import Connection, ManagerError, Redactor, SERVICES, Store, validate_password, validate_port, validate_user
from .releases import LATEST_STABLE, SPECIFIC_VERSION, KEEP_CURRENT, exchange_version
from .help_texts import HELP
from .widgets import HelpAction, ScrollPage, install_check_style, sync_tree
from .key_info import encrypted_key
from .project_info import server_key, credential_alias, SERVICE_PROTOCOLS, deployment_network_hint
from .qr import is_node_link, qr_png
from .transport import WaitingStopped

BASE = Path(__file__).resolve().parents[1]
BG = "#f4f6fa"
INK = "#17243d"
MUTED = "#718096"
BLUE = "#2563eb"
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


def readable_size(value):
    return f"{value / 1024 ** 3:.1f} GB"


class App(tk.Tk):
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
        before = [v.get() for v in [self.plan_retire, self.plan_block, self.plan_fail2ban, self.plan_updates, self.auth_tries, self.login_grace, self.alive_interval]]
        self._toggle_custom_security(); self.update_idletasks()
        result["custom_settings_expand"] = bool(self.custom_security_frame.winfo_ismapped())
        self._toggle_custom_security(); self.update_idletasks()
        result["custom_settings_preserve_values"] = before == [v.get() for v in [self.plan_retire, self.plan_block, self.plan_fail2ban, self.plan_updates, self.auth_tries, self.login_grace, self.alive_interval]]
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
        self.deploy_choice.set(self.manage_choice.get())
        self._deploy_defaults()
        self.notebook.select(self.pages["一键部署"])

    def _open_selected_project(self, _=None):
        if self.busy:
            return
        selection = self.service_tree.selection()
        if not selection or selection[0] not in SERVICES:
            self.status.configure(text="先在项目列表中选择要管理的项目。")
            return
        kind = selection[0]
        self.manage_choice.set(SERVICES[kind][0])
        self._project_changed()
        installed = any(unit.get("LoadState") == "loaded" for unit in (self.report or {}).get("services", {}).get(kind, []))
        if (self.report or {}).get("project_information", {}).get(kind, {}).get("data", {}).get("uninstalled"):
            installed = False
        if installed:
            self.notebook.select(self.pages["日常维护"])
        else:
            self._configure_project()

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
        self.service_tree = self._tree(page, [("name", "项目", 185), ("status", "运行状态", 130), ("startup", "开机启动", 130), ("purpose", "作用", 460)], height=5)
        self.service_tree.bind("<Double-1>", self._open_selected_project)
        self.service_tree.bind("<Return>", self._open_selected_project)
        self._button(page, "管理选中项目", self._open_selected_project).pack(anchor="w", pady=(12, 0))
        self.security_summary = ttk.Label(page, text="安全状态将在连接检查后显示。", style="Muted.TLabel", wraplength=1000, justify="left")
        self.security_summary.pack(anchor="w", pady=18)

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
        self.plan_block = tk.BooleanVar(value=True)
        self.plan_fail2ban = tk.BooleanVar(value=True)
        self.plan_updates = tk.BooleanVar(value=True)
        self.plan_checks = {}
        options = ttk.Frame(preset)
        options.grid(row=4, columnspan=3, sticky="ew", pady=(8, 0))
        options.columnconfigure(0, weight=1); options.columnconfigure(1, weight=1)
        for i, (label, variable) in enumerate([("验证后撤销原档案旧钥匙", self.plan_retire), ("新增后禁止原账号登录", self.plan_block), ("方案中启用防猜密码保护", self.plan_fail2ban), ("方案中启用自动安全更新", self.plan_updates)]):
            check = self._check(options, label, variable)
            check.grid(row=i // 2, column=i % 2, sticky="w", pady=3, padx=(0, 20))
            self.plan_checks[label] = check.checkbox
        self.plan_hint = ttk.Label(preset, text="修改当前普通管理员；填写相同名字时，只更换加密密钥。", style="Muted.TLabel", wraplength=930)
        self.plan_hint.grid(row=5, columnspan=3, sticky="w", pady=(6, 4))
        ttk.Label(preset, text="仅允许密钥登录 · 私钥与口令仅存本机 · 保留端口与现有地址规则", style="Muted.TLabel", wraplength=930).grid(row=6, columnspan=3, sticky="w", pady=(0, 6))
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
        self.plan_checks["新增后禁止原账号登录"].configure(state="normal" if create else "disabled")
        self.plan_hint.configure(text="创建独立管理员与加密密钥，验证后保存为另一条本机档案。" if create else "修改当前普通管理员；填写相同名字时，只更换加密密钥。")

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
        self.deploy_server_name = tk.StringVar(value="www.cloudflare.com")
        self.version_mode = tk.StringVar(value=LATEST_STABLE)
        self.deploy_version = tk.StringVar(value="部署前自动获取")
        self.deploy_rows = {}
        for index, (name, label, variable, private) in enumerate([
            ("port", "服务端口", self.deploy_port, False),
            ("username", "面板账号（代理面板）", self.deploy_username, True),
            ("proxy_password", "服务密码（代理服务）", self.deploy_password, True),
            ("panel_password", "面板密码", self.deploy_password, True),
        ], start=1):
            row = ttk.Frame(form); row.grid(row=index, column=0, columnspan=2, sticky="w")
            row.columnconfigure(0, minsize=190)
            self._field(row, 0, label, variable, private)
            if name == "port":
                self.deploy_port_protocol = ttk.Label(row, text="TCP（网页入口）")
                self.deploy_port_protocol.grid(row=0, column=2, sticky="w", padx=12)
            if name.endswith("password"):
                self._button(row, "生成密码", lambda: self._generate_password(self.deploy_password)).grid(row=0, column=2, padx=12)
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
            ("backend", "内部端口（交易系统）", self.deploy_backend, False),
            ("server_name", "REALITY 目标域名", self.deploy_server_name, False),
        ]):
            row = ttk.Frame(self.deploy_optional_frame); row.grid(row=index, column=0, sticky="w")
            row.columnconfigure(0, minsize=190)
            self._field(row, 0, label, variable, private)
            if name == "backend":
                ttk.Label(row, text="TCP · 仅本机，不向公网开放", style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=12)
            self.deploy_optional_rows[name] = row
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
        project_box = ttk.Combobox(top, textvariable=self.manage_choice, values=[v[0] for v in SERVICES.values()], state="readonly", width=28)
        project_box.pack(side="left")
        project_box.bind("<<ComboboxSelected>>", self._project_changed)
        actions = ttk.Frame(page); actions.pack(fill="x", pady=(12, 0))
        self._button(actions, "刷新项目信息", self._refresh_project_info).pack(side="left")
        self._button(actions, "查看运行日志", self._logs).pack(side="left", padx=12)
        self._button(actions, "安装 / 调整配置", self._configure_project).pack(side="left")
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
        for title, action in [("启动", "start"), ("停止", "stop"), ("重启", "restart"), ("开启开机启动", "enable"), ("关闭开机启动", "disable")]:
            self._button(row, title, lambda a=action: self._service(a)).pack(side="left", padx=(0, 9))
        removal = ttk.Frame(page); removal.pack(fill="x", pady=(0, 8))
        self._button(removal, "卸载所选项目", self._uninstall).pack(side="left")
        ttk.Label(removal, text="移除程序和专属服务，默认保留配置、账号及业务数据。", style="Muted.TLabel", wraplength=640).pack(side="left", padx=12)
        security = ttk.LabelFrame(page, text="安全与配置备份", padding=12); security.pack(fill="x", pady=8)
        self._button(security, "备份所选服务配置", self._backup).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 8))
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

    def _history_page(self):
        page = self.pages["操作记录"].content
        self._description(page, "进度、结果与恢复记录", "后台任务在服务器执行。重新连接后可以刷新记录，查看上次任务的结果；断线时请勿重复部署。")
        row = ttk.Frame(page); row.pack(fill="x", pady=(0, 12))
        self._button(row, "刷新记录", self._tasks).pack(side="left")
        self._button(row, "查看任务详情", self._task_detail).pack(side="left", padx=10)
        self._button(row, "恢复待验证变更", self._recover).pack(side="left")
        self._button(row, "查看本次新密码", self._task_password).pack(side="left", padx=10)
        self.task_tree = self._tree(page, [("id", "任务编号", 235), ("operation", "操作", 145), ("state", "状态", 160), ("message", "结果", 440)], height=7)
        self.task_text = tk.Text(page, height=9, wrap="word", bg="white", foreground=INK, font="TkDefaultFont", relief="flat", padx=14, pady=14, state="disabled")
        self.task_text.pack(fill="both", expand=True, pady=(15, 0))

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
            self.profile_load_stage = "project_credentials"
            for profile in profiles:
                for kind in ["exchange", "hysteria2", "xui"]:
                    self.store.vault.get(credential_alias(profile, kind))
                    if kind in {"hysteria2", "xui"}:
                        from .vault import vault_alias
                        self.store.vault.get(vault_alias("service-pending", credential_alias(profile, kind)))
            self.profile_load_stage = "key_metadata"
            keys = {p.key_path: encrypted_key(p.key_path) for p in profiles if p.key_path}
            self.profile_load_stage = "queued"
            return profiles, keys
        def done(data):
            self.profiles, self.key_encryption = data
            self.profiles_loaded = True
            self.profile_load_stage = "ready"
            self._profile_options()
            if self.profiles and self.current is None:
                self._load_profile(self.profiles[0])
            else:
                self._plan_mode_changed()
            self.status.configure(text="本机档案已就绪。选择服务器后连接，或查看功能说明。")
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
        threading.Thread(target=work, daemon=True).start()

    def _drain(self):
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

    def _render_report(self):
        if not self.report: return
        r = self.report
        self.system_label.configure(text=r["os"] + " · " + r["architecture"])
        self.statistics["disk"].configure(text=readable_size(r["disk_free"]))
        self.statistics["memory"].configure(text=readable_size(r["memory"].get("MemAvailable", 0)))
        count = sum(any(u.get("ActiveState") == "active" for u in units) and not r.get("project_information", {}).get(key, {}).get("data", {}).get("uninstalled") for key, units in r["services"].items())
        self.statistics["services"].configure(text=str(count))
        password_enabled = "yes" in r["ssh"].get("passwordauthentication", [])
        self.statistics["security"].configure(text="密码 / 密钥" if password_enabled else "密钥")
        self.allow_password.set(password_enabled)
        self.allow_root.set("yes" in r["ssh"].get("permitrootlogin", []))
        service_rows = []
        purposes = {"exchange": "币安多账号交易、资产查询和资金管理", "hysteria2": "Hysteria2 网络代理服务", "reality": "独立 VLESS + REALITY + Vision 节点", "xui": "代理账号与节点的网页管理", "nginx": "网页入口、HTTPS 和后端转发"}
        for key, units in r["services"].items():
            installed = [u for u in units if u.get("LoadState") == "loaded"]
            state = "运行中" if any(u.get("ActiveState") == "active" for u in installed) else "已停止" if installed else "尚未安装"
            startup = "已开启" if any(u.get("UnitFileState") == "enabled" for u in installed) else "未开启" if installed else "—"
            if r.get("project_information", {}).get(key, {}).get("data", {}).get("uninstalled"):
                state = "独立站点已卸载" if key == "nginx" else "已卸载（数据保留）"
                startup = "—"
            service_rows.append((key, (SERVICES[key][0], state, startup, purposes[key])))
        sync_tree(self.service_tree, service_rows)
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
        options = {"mode": mode, "username": target, "new_password": value, "key_passphrase": phrase, "retire_old_key": self.plan_retire.get(), "block_original": self.plan_block.get(), "fail2ban": self.plan_fail2ban.get(), "updates": self.plan_updates.get()}
        steps = ["新增并验证普通管理员：" + target if mode == "create" else "修改当前账号为：" + target + "（名称相同则只更换密钥）", "生成加密私钥，私钥和口令仅存本机，并开启记住登录信息", "验证新密钥及 sudo 后，只允许 SSH 密钥登录，禁止密码和超级管理员直接登录", "保留 SSH 端口、现有地址规则及 SSH 隧道设置"]
        if mode == "create": steps.append("新账号 sudo 密码：" + ("使用已填写的新密码" if value else "自动生成并保存到本机钥匙串"))
        elif value: steps.append("修改当前账号的系统密码")
        if mode == "rename" and options["retire_old_key"] and c.auth == "key": steps.append("验证后撤销当前档案原公钥；其他钥匙保留")
        if mode == "create" and options["block_original"] and c.username != "root": steps.append("新账号验证成功后，禁止原账号 SSH 登录；账号和文件保留")
        if options["fail2ban"]: steps.append("启用临时封禁：10 分钟内失败 5 次，封禁 60 分钟")
        if options["updates"]: steps.append("启用系统安全更新，不自动重启")
        if not messagebox.askyesno("预览一键安全方案", "\n".join("• " + s for s in steps) + "\n\n关闭密码入口会影响本机以外仍使用密码的管理工具。改名会关闭原账号的登录会话。\n每个连接变更分别验证和保护；后续步骤失败时，已完成步骤保留并列出结果。\n是否开始？", parent=self): return
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

    def _service_key(self, choice):
        return next(key for key, value in SERVICES.items() if value[0] == choice)

    def _deploy_defaults(self, _=None):
        key = self._service_key(self.deploy_choice.get())
        defaults = {"exchange": (26483, "部署前自动获取"), "hysteria2": (51752, "v1.14.2"), "reality": (443, "v26.3.27"), "xui": (2053, "v3.9.0"), "nginx": (80, "系统软件包")}
        number, version = defaults[key]; self.deploy_port.set(str(number)); self.deploy_version.set(version)
        self.version_mode.set(LATEST_STABLE)
        current = self._deployment_current(key)
        if current:
            self.deploy_port.set(str(current.get("port", number)))
            self.deploy_host.set(current.get("host", ""))
            self.deploy_version.set(current.get("version") or "预览时读取现有版本")
            self.version_mode.set(KEEP_CURRENT)
            if key == "exchange": self.deploy_backend.set(str(current.get("backend_port", 18880)))
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
            self.deploy_backend.set("18880")
            self.deploy_server_name.set("www.cloudflare.com")
        self._deployment_fields()
        hints = {"exchange": "确认 TCP 网页端口即可。已有项目先比对条件，只调整改变的配置；版本变化会备份并切换版本，保留业务数据。", "hysteria2": "填写 UDP 节点端口和服务密码；HY2 不使用 TCP 节点端口。已有项目会按新条件调整；原密码不变时可以留空。", "reality": "只填 TCP 节点端口；连接凭据自动生成，无需自有域名和证书。部署后在运行与备份复制 VLESS 节点链接，或点击二维码图标扫码导入。已有节点调整端口或版本时保留原凭据。", "xui": "填写 TCP 面板端口、面板账号和密码；节点端口另按各自协议放行。已有项目的密码不变时可留空；节点和订阅保持。", "nginx": "默认 TCP 80，可填写其他端口。版本使用系统软件源；已有配置会先备份，网站文件保留。"}
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
        visible = {"exchange": {"port"}, "hysteria2": {"port", "proxy_password"}, "reality": {"port"}, "xui": {"port", "username", "panel_password"}, "nginx": {"port"}}[key]
        for name, row in self.deploy_rows.items():
            row.grid() if name in visible else row.grid_remove()
        for name, row in self.deploy_optional_rows.items():
            shown = name == "host" and key != "nginx" or name == "backend" and key == "exchange" or name == "server_name" and key == "reality" or name == "version_mode"
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
            self.deploy_version.set({"exchange":"v1.1.85", "hysteria2":"v1.14.3", "reality":"v26.3.27", "xui":"v3.9.0"}[key])
        elif not keeping and key == "nginx" and self.deploy_version.get().startswith(("预览", "系统")):
            self.deploy_version.set("")
        if "deploy_optional_rows" in self.__dict__:
            row = self.deploy_optional_rows["version"]
            row.grid_remove() if automatic else row.grid()

    def _deploy(self):
        if not self._ready(): return
        try:
            key = self._service_key(self.deploy_choice.get())
            params = {"operation": "deploy", "service": key, "host": self.deploy_host.get().strip() or self.current.host, "port": validate_port(self.deploy_port.get())}
            if key != "nginx" or self.version_mode.get() == SPECIFIC_VERSION: params["version"] = self.deploy_version.get().strip()
            if self.version_mode.get() == KEEP_CURRENT: params["version_policy"] = "keep"
            if key == "exchange": params["backend_port"] = validate_port(self.deploy_backend.get())
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
        params = {"operation": "service", "service": key, "action": action}
        if key == "exchange" and action in {"stop", "restart"}:
            if not messagebox.askyesno("确认维护条件", "请先在交易网页停止任务并确认撤单及清理完成。\n是否已经完成？", parent=self): return
            params["maintenance_confirmed"] = True
        description = "对“" + SERVICES[key][0] + "”执行所选服务管理操作。"
        if key == "nginx":
            description += "\n仅操作 nginx.service 共享核心，会影响该核心下的其他网站；不操作交易系统的专属网页入口。"
        self._execute(params, description)

    def _uninstall(self):
        if self.busy or not self._ready(): return
        c = self.current; kind = self._service_key(self.manage_choice.get())
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
        redactor = self._redactor()
        info = self.project_details.get((server_key(c),key), {})
        for name,value in info.get("rows",[]):
            if any(word in name for word in ("密码", "初始化码", "节点", "订阅")):
                redactor.add(value)
        def done(data):
            text = redactor.text(data["logs"])
            self.project_logs[(server_key(c),key)] = text
            if self.current and server_key(self.current)==server_key(c) and self._service_key(self.manage_choice.get())==key:
                self._replace_text(self.maintenance_text, text)
        self._run(lambda: self.controller.transport(c).call({"action": "logs", "service": key}), done)

    def _project_changed(self, _=None):
        key = self._service_key(self.manage_choice.get())
        identity = server_key(self.current) if self.current else ""
        information = self.project_details.get((identity,key), {})
        self.project_rows = list(information.get("rows", []))
        hidden = self.privacy.get()
        sync_tree(self.project_info_tree, [(str(i),(name,"已隐藏；关闭右上角隐藏开关可查看" if hidden and name not in {"项目状态","安装版本","端口协议"} else value, "▦" if is_node_link(value) else "")) for i,(name,value) in enumerate(self.project_rows)])
        self.project_info_value.set("")
        if "node_qr_button" in self.__dict__: self.node_qr_button.configure(state="disabled")
        if not self.project_rows:
            sync_tree(self.project_info_tree, [("placeholder",("项目信息","连接服务器后点击刷新；只显示当前服务器的项目。"))])
        self._replace_text(self.maintenance_text,self.project_logs.get((identity,key),"所选项目的运行日志会在这里显示。点击「查看运行日志」读取。"))

    def _refresh_project_info(self):
        if not self._ready(): return
        c = self.current; key = self._service_key(self.manage_choice.get())
        def done(information):
            self.project_details[(server_key(c),key)] = information
            if self.current and server_key(self.current)==server_key(c) and self._service_key(self.manage_choice.get())==key:
                self._project_changed()
            self.status.configure(text="项目信息已刷新；选中一项可复制完整内容。")
        self._run(lambda:self.controller.project_information(c,key),done,"读取项目端口、网址及连接信息…")

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
        url = next((value for name,value in self.project_rows if name in {"后台网址","软件网址"}),"")
        if url.startswith(("https://","http://")):
            webbrowser.open(url)
        else:
            self.status.configure(text="所选项目没有网页入口；请复制节点或订阅链接使用。")

    def _save_project_credentials(self):
        if not self._ready(): return
        key = self._service_key(self.manage_choice.get()); c = self.current
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
        ports = [{"port": x["port"], "protocol": x["protocol"]} for x in self.report["listeners"] if not x["local_only"] and x["port"] in {self.current.port, 80, 443, 26483, 51752, 2053, 30043}]
        rules = sorted({(self.current.port, "tcp")} | {(item["port"], item["protocol"]) for item in ports})
        listing = "\n".join(f"• {protocol.upper()} {number}" for number, protocol in rules)
        self._execute({"operation": "firewall", "ssh_port": self.current.port, "ports": ports}, "开启服务器防火墙，保留现有规则，本次放行：\n"+listing+"\n未列出的自定义端口需已有放行规则；云平台安全组需按对应协议另行设置。\n新连接验证失败会自动恢复原防火墙配置。")

    def _updates(self):
        self._execute({"operation": "updates", "enabled": True}, "开启系统自动安全更新并验证定时调度；从下一次计划开始，不立即补跑升级，自动重启保持关闭。")

    def _backup(self, kind=None):
        key = kind or self._service_key(self.manage_choice.get())
        self._execute({"operation": "backup", "service": key}, "备份所选服务配置到服务器的管理员专用目录。不会删除业务数据。")

    def _restore(self):
        identifier = self.restore_id.get().strip()
        self._execute({"operation": "restore", "backup_id": identifier}, "恢复所选配置备份，并先保存当前配置。\n只恢复该备份包含的配置，不恢复交易账本。")

    def _tasks(self):
        if not self._ready(): return
        c = self.current
        self._run(lambda: self.controller.tasks(c), lambda data: self._show_tasks(data["tasks"]))

    def _show_tasks(self, tasks):
        seen = set(); self.latest_tasks = []
        rows = []
        for task in tasks:
            if task["id"] in seen: continue
            seen.add(task["id"]); self.latest_tasks.append(task)
            names = {"deploy": "服务部署", "uninstall": "项目卸载（保留数据）", "create_admin": "创建管理员", "rename_user": "账号改名", "password": "修改密码", "ssh": "SSH 设置", "firewall": "防火墙", "updates": "安全更新", "backup": "配置备份", "restore": "配置恢复", "service": "服务管理", "account_access": "账号登录限制", "delete_user": "删除用户并保留文件", "ssh_hardening": "SSH 连接防护", "fail2ban": "防猜密码保护"}
            names.update(prepare_key="安装并验证加密密钥", login_policy="仅密钥登录策略", retire_key="撤销原档案旧钥匙")
            states = {"queued": "排队中", "running": "执行中", "awaiting_verification": "等待连接验证", "succeeded": "已完成", "failed": "未完成", "rolled_back": "已恢复原配置", "recovery_failed": "恢复未完成，需处理", "submission_unknown": "提交未确认"}
            rows.append((task["id"], (task["id"], names.get(task["operation"], task["operation"]), states.get(task["state"], task["state"]), self._redactor().text(task["message"]))))
        sync_tree(self.task_tree, rows)

    def _task_detail(self):
        selected = self.task_tree.selection()
        if not selected: return
        task = next(t for t in self.latest_tasks if t["id"] == selected[0])
        text = "\n".join(event["message"] for event in task.get("events", []))
        text += "\n\n" + task["message"]
        if task.get("diagnostic"): text += "\n" + task["diagnostic"]
        self._replace_text(self.task_text, self._redactor().text(text))

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
