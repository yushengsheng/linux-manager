#!/usr/bin/env python3
"""Double-clickable local UI for safely renaming the audited Linux login."""

from __future__ import annotations

import queue
import re
import shlex
import subprocess
import threading
import time
import json
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


DEFAULT_HOST = ""
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
SCHEDULE_GRACE_SECONDS = 9
VERIFY_ATTEMPTS = 18
VERIFY_RETRY_SECONDS = 4
STATE_FILE = Path(__file__).resolve().parent / ".rename_account_gui_state.json"


class RenameAccountApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Linux 账户改名工具")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        script_dir = Path(__file__).resolve().parent
        saved_state = self._load_connection_state()
        self.host_var = tk.StringVar(value=saved_state.get("host", DEFAULT_HOST))
        self.key_var = tk.StringVar(value=saved_state.get("key_path", ""))
        self.ssh_user_var = tk.StringVar(value=saved_state.get("ssh_user", "ubuntu"))
        self.old_user_var = tk.StringVar(value="ubuntu")
        self.old_password_var = tk.StringVar()
        self.new_user_var = tk.StringVar()
        self.new_password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.status_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self.running = False

        self._build_ui()
        self.after(100, self._drain_status_queue)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=16)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(1, weight=1)

        ttk.Label(
            frame,
            text=(
                "此工具原地重命名服务器账户，不会创建第二个账户。\n"
                "SSH 已启用密钥登录；原密码仅用于服务器端验证和设置新密码。"
            ),
            justify="left",
            wraplength=530,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        fields = (
            ("服务器", self.host_var, False),
            ("恢复密钥", self.key_var, False),
            ("当前 SSH 账户", self.ssh_user_var, False),
            ("原账户名", self.old_user_var, False),
            ("原账户密码", self.old_password_var, True),
            ("新账户名", self.new_user_var, False),
            ("新账户密码", self.new_password_var, True),
            ("确认新密码", self.confirm_password_var, True),
        )
        for row, (label, variable, secret) in enumerate(fields, start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="e", padx=(0, 8), pady=4)
            entry = ttk.Entry(frame, textvariable=variable, width=54, show="•" if secret else "")
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            if label == "恢复密钥":
                ttk.Button(frame, text="选择…", command=self._choose_key).grid(row=row, column=2, padx=(8, 0), pady=4)

        action_frame = ttk.Frame(frame)
        action_frame.grid(row=9, column=1, sticky="e", pady=(12, 8))
        self.open_terminal_button = ttk.Button(action_frame, text="打开服务器终端", command=self._open_terminal)
        self.open_terminal_button.grid(row=0, column=0, padx=(0, 8))
        self.rename_button = ttk.Button(action_frame, text="确认并改名", command=self._start_rename)
        self.rename_button.grid(row=0, column=1)

        ttk.Label(
            frame,
            text="改名期间 SSH 会短暂断开；完成后工具会用新账户名和同一把密钥自动验证登录。",
            foreground="#555555",
            wraplength=530,
            justify="left",
        ).grid(row=10, column=0, columnspan=3, sticky="w")

        self.output = tk.Text(frame, width=74, height=12, state="disabled", wrap="word")
        self.output.grid(row=11, column=0, columnspan=3, sticky="nsew", pady=(12, 0))

    def _choose_key(self) -> None:
        selected = filedialog.askopenfilename(title="选择 SSH 私钥")
        if selected:
            self.key_var.set(selected)

    def _open_terminal(self) -> None:
        host = self.host_var.get().strip()
        key_path = Path(self.key_var.get().strip()).expanduser()
        ssh_user = self.ssh_user_var.get().strip()
        if not HOST_RE.fullmatch(host):
            messagebox.showerror("输入错误", "服务器地址只能包含字母、数字、点和连字符。")
            return
        if not USERNAME_RE.fullmatch(ssh_user):
            messagebox.showerror("输入错误", "当前 SSH 账户名格式不正确。")
            return
        if not key_path.is_file():
            messagebox.showerror("输入错误", "找不到 SSH 私钥文件。")
            return

        self._save_connection_state(host, key_path, ssh_user)

        ssh_command = self._terminal_ssh_command(key_path, ssh_user, host)
        applescript = self._terminal_applescript(ssh_command)
        try:
            subprocess.run(["osascript", "-e", applescript], check=True, capture_output=True, text=True)
        except FileNotFoundError:
            messagebox.showerror("不支持", "该功能仅支持 macOS 的 Terminal 应用。")
            return
        except subprocess.CalledProcessError as exc:
            messagebox.showerror("启动失败", f"无法打开 Terminal：{exc.stderr.strip() or exc}")
            return
        self._append(f"已打开 Terminal，并使用账户 {ssh_user} 连接服务器。\n")

    @staticmethod
    def _terminal_ssh_command(key_path: Path, ssh_user: str, host: str) -> str:
        return " ".join(
            (
                "ssh",
                "-i",
                shlex.quote(str(key_path)),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ServerAliveInterval=60",
                shlex.quote(f"{ssh_user}@{host}"),
            )
        )

    @staticmethod
    def _terminal_applescript(ssh_command: str) -> str:
        # Construct the AppleScript as a parameter to osascript, never by
        # invoking a shell. Escape the command for AppleScript string syntax.
        escaped = ssh_command.replace("\\", "\\\\").replace('"', '\\"')
        return f'tell application "Terminal" to do script "{escaped}"'

    @staticmethod
    def _load_connection_state() -> dict[str, str]:
        try:
            value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        if not isinstance(value, dict):
            return {}
        return {
            key: value[key]
            for key in ("host", "key_path", "ssh_user")
            if isinstance(value.get(key), str)
        }

    @staticmethod
    def _save_connection_state(host: str, key_path: Path, ssh_user: str) -> None:
        # Passwords are intentionally never stored. Write atomically with
        # owner-only permissions so reopening the GUI restores only connection
        # metadata after a successful account rename.
        payload = json.dumps(
            {"host": host, "key_path": str(key_path), "ssh_user": ssh_user},
            ensure_ascii=False,
            indent=2,
        ) + "\n"
        temporary = STATE_FILE.with_suffix(".tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(STATE_FILE)
        os.chmod(STATE_FILE, 0o600)

    def _validate(self) -> tuple[str, Path, str, str, str, str] | None:
        host = self.host_var.get().strip()
        key_path = Path(self.key_var.get().strip()).expanduser()
        old_user = self.old_user_var.get().strip()
        old_password = self.old_password_var.get()
        new_user = self.new_user_var.get().strip()
        new_password = self.new_password_var.get()
        confirmation = self.confirm_password_var.get()

        if not HOST_RE.fullmatch(host):
            messagebox.showerror("输入错误", "服务器地址只能包含字母、数字、点和连字符。")
            return None
        if not key_path.is_file():
            messagebox.showerror("输入错误", "找不到 SSH 私钥文件。")
            return None
        if not USERNAME_RE.fullmatch(old_user) or not USERNAME_RE.fullmatch(new_user):
            messagebox.showerror("输入错误", "账户名只能使用小写字母、数字、下划线或连字符，长度不超过 32。")
            return None
        if old_user == new_user:
            messagebox.showerror("输入错误", "新账户名必须与原账户名不同。")
            return None
        if not old_password:
            messagebox.showerror("输入错误", "必须输入原账户密码。")
            return None
        if len(new_password) < 16:
            messagebox.showerror("输入错误", "新密码至少需要 16 个字符。")
            return None
        if new_password != confirmation:
            messagebox.showerror("输入错误", "两次输入的新密码不一致。")
            return None
        return host, key_path, old_user, old_password, new_user, new_password

    def _start_rename(self) -> None:
        values = self._validate()
        if values is None:
            return
        if not messagebox.askyesno(
            "确认改名",
            "将原地修改服务器账户名、家目录、sudo/SSH/cloud-init 配置。\n"
            "x-ui 与 30043 代理不会被修改。是否继续？",
        ):
            return

        self.running = True
        self.rename_button.configure(state="disabled")
        self.open_terminal_button.configure(state="disabled")
        self._append("开始执行账户改名，请不要关闭窗口。\n")

        host, key_path, old_user, old_password, new_user, new_password = values
        self.old_password_var.set("")
        self.new_password_var.set("")
        self.confirm_password_var.set("")
        thread = threading.Thread(
            target=self._rename_worker,
            args=(host, key_path, old_user, old_password, new_user, new_password),
            daemon=True,
        )
        thread.start()

    @staticmethod
    def _ssh_base(key_path: Path) -> list[str]:
        known_hosts = Path.home() / ".ssh" / "known_hosts"
        return [
            "ssh",
            "-T",
            "-i",
            str(key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ConnectTimeout=25",
        ]

    def _rename_worker(
        self,
        host: str,
        key_path: Path,
        old_user: str,
        old_password: str,
        new_user: str,
        new_password: str,
    ) -> None:
        try:
            command = self._ssh_base(key_path) + [
                f"{old_user}@{host}",
                "sudo",
                "/usr/local/sbin/rename-login-user",
                "--old-user",
                old_user,
                "--new-user",
                new_user,
                "--stdin-secrets",
            ]
            # No secret is part of command arguments. The remote script reads
            # this four-line payload from stdin with no allocated TTY.
            payload = f"{old_password}\n{new_password}\n{new_password}\nRENAME\n"
            completed = subprocess.run(
                command,
                input=payload,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=180,
                check=False,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            if completed.returncode != 0:
                self.status_queue.put(("error", self._safe_output(output, "服务器拒绝了改名操作。")))
                return
            if "Rename scheduled:" not in output:
                self.status_queue.put(("error", self._safe_output(output, "服务器没有确认改名任务。")))
                return

            self.status_queue.put(("info", self._safe_output(output, "改名任务已提交，正在等待旧会话关闭…")))
            time.sleep(SCHEDULE_GRACE_SECONDS)
            verification = self._ssh_base(key_path) + [
                f"{new_user}@{host}",
                "id; sudo -n true; printf '\\nNEW_LOGIN_VERIFIED\\n'",
            ]
            last_output = ""
            for attempt in range(VERIFY_ATTEMPTS):
                verified = subprocess.run(
                    verification,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    timeout=45,
                    check=False,
                )
                last_output = (verified.stdout or "") + (verified.stderr or "")
                if verified.returncode == 0 and "NEW_LOGIN_VERIFIED" in last_output:
                    self.status_queue.put(("success", "改名完成，已验证新账户可通过 SSH 密钥登录并使用 sudo。"))
                    return
                if attempt < VERIFY_ATTEMPTS - 1:
                    time.sleep(VERIFY_RETRY_SECONDS)
            self.status_queue.put(
                (
                    "error",
                    "服务器端已提交改名任务，但新账户登录验证超时。请勿重复提交；使用恢复密钥检查 "
                    "systemd 的 account-rename 日志：\n"
                    + self._safe_output(last_output, "没有收到验证输出。"),
                )
            )
        except subprocess.TimeoutExpired:
            self.status_queue.put(("error", "操作超时。请勿重复执行；先用恢复密钥检查服务器账户状态。"))
        except OSError as exc:
            self.status_queue.put(("error", f"无法启动 SSH：{exc}"))
        finally:
            old_password = ""
            new_password = ""

    @staticmethod
    def _safe_output(output: str, fallback: str) -> str:
        cleaned = output.strip()
        return cleaned if cleaned else fallback

    def _drain_status_queue(self) -> None:
        try:
            while True:
                kind, message = self.status_queue.get_nowait()
                self._append(message + "\n")
                if kind in {"success", "error"}:
                    self.running = False
                    self.rename_button.configure(state="normal")
                    self.open_terminal_button.configure(state="normal")
                    if kind == "success":
                        self.ssh_user_var.set(self.new_user_var.get().strip())
                        self._save_connection_state(
                            self.host_var.get().strip(),
                            Path(self.key_var.get().strip()).expanduser(),
                            self.ssh_user_var.get().strip(),
                        )
                        messagebox.showinfo("完成", message)
                    else:
                        messagebox.showerror("需要检查", message)
        except queue.Empty:
            pass
        self.after(100, self._drain_status_queue)

    def _append(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _on_close(self) -> None:
        if self.running:
            messagebox.showwarning("操作进行中", "账户改名仍在执行，请等待服务器返回结果。")
            return
        host = self.host_var.get().strip()
        key_path = Path(self.key_var.get().strip()).expanduser()
        ssh_user = self.ssh_user_var.get().strip()
        if HOST_RE.fullmatch(host) and USERNAME_RE.fullmatch(ssh_user) and key_path.is_file():
            self._save_connection_state(host, key_path, ssh_user)
        self.destroy()


if __name__ == "__main__":
    RenameAccountApp().mainloop()
