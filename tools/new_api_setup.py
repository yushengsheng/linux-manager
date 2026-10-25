"""One-command New API setup, embedded directly in the tutorial's shell commands.

Python 3.11+ standard library only. Uses Codex's native atomic config API.
No Keychain reads, account login/logout, execution-policy bypass, or elevation.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

PROVIDER = "newapi_gateway"
MODEL = "gpt-6.1-sol"
MIN_VERSION = (0, 164, 0)
LIMIT = 4 * 1024 * 1024


class SetupError(Exception):
    pass


class Cancelled(Exception):
    pass


def powershell(code, timeout=30):
    command = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not command:
        raise SetupError("未找到 PowerShell；请在原生 Windows PowerShell 中运行。")
    encoded = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
    return subprocess.run([command, "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", encoded],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def restrict(path, directory=False):
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    # A fresh DACL removes inherited AND explicit broad access before secrets are written.
    body = r'''
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PATH'))
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.KIND
$acl.SetAccessRuleProtection($true,$false)
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','INHERIT','None','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $p -AclObject $acl
'''.replace("PATH", base64.b64encode(str(path).encode()).decode()).replace("KIND", "DirectorySecurity" if directory else "FileSecurity").replace("INHERIT", "ContainerInherit,ObjectInherit" if directory else "None")
    if powershell(body).returncode:
        raise SetupError("无法设置仅当前用户可读写的权限；未继续保存密钥。不要盲目使用管理员窗口。")


def private_write(path, content):
    descriptor, name = tempfile.mkstemp(prefix=".newapi-write-", dir=path.parent)
    temporary = Path(name)
    try:
        restrict(temporary)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def config_home():
    result = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser()
    if not result.is_absolute():
        raise SetupError("CODEX_HOME 必须是绝对路径；请与桌面版使用同一目录。")
    return result.resolve()


def preflight(home):
    target = home / "config.toml"
    if target.is_symlink():
        raise SetupError("配置文件是符号链接；为避免写错目标，已停止，请先确认真实配置位置。")
    try:
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(prefix=".newapi-permission-", dir=home)
        os.close(descriptor)
        Path(name).unlink()
        if target.exists():
            if not target.is_file() or target.stat().st_size > LIMIT:
                raise SetupError("配置文件类型或大小异常；未覆盖。")
            with target.open("r+b"):
                pass
            if os.name != "nt" and target.stat().st_uid != os.getuid():
                raise PermissionError()
    except PermissionError:
        raise SetupError("当前用户不能修改 Codex 配置。请让管理员修复该用户目录的所有权或访问权限；不要用 sudo/管理员身份重跑本命令。") from None
    return target


def discover_codex():
    override = os.environ.get("NEWAPI_CODEX_BINARY")
    candidates = [Path(override)] if override else []
    for name in (["codex.exe", "codex.cmd", "codex"] if os.name == "nt" else ["codex"]):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    if sys.platform == "darwin":
        for root in [Path("/Applications"), Path.home() / "Applications"]:
            for app in ["Codex.app", "ChatGPT.app"]:
                for suffix in ["Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex", "Contents/Resources/codex"]:
                    candidates.append(root / app / suffix)
    elif os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        candidates += [local / "Programs/OpenAI/Codex/bin/codex.exe", local / "Programs/Codex/resources/codex.exe"]
        # Store apps may not expose their bundled CLI on PATH; ask the package registry.
        registered = powershell("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();Get-AppxPackage '*Codex*' | ForEach-Object { Join-Path $_.InstallLocation 'app/resources/codex.exe'; Join-Path $_.InstallLocation 'app/resources/codex-cli/codex.exe' }")
        if not registered.returncode:
            candidates += [Path(p) for p in registered.stdout.decode("utf-8-sig", "replace").splitlines() if p.strip()]
    else:
        candidates += [Path.home() / ".local/bin/codex", Path("/opt/Codex/resources/codex"), Path("/opt/codex/resources/codex")]
    old = False
    for candidate in dict.fromkeys(candidates):
        if not candidate.is_file() or candidate.suffix.lower() == ".ps1":
            continue
        command = cli_command(candidate)
        try:
            result = subprocess.run(command + ["--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            match = re.search(rb"codex-cli\s+(\d+)\.(\d+)\.(\d+)", result.stdout)
            if not result.returncode and match:
                if tuple(map(int, match.groups())) >= MIN_VERSION:
                    return command
                old = True
        except (OSError, subprocess.TimeoutExpired):
            continue
    if old:
        raise SetupError("Codex CLI 版本过旧；请先更新到 0.164.0 或以上，再运行配置命令。不会自动升级或覆盖已安装程序。")
    raise SetupError("未找到可用 Codex CLI。桌面版未暴露 CLI 时，请按教程安装官方用户版 CLI 后重试。")


def cli_command(path):
    if os.name == "nt" and path.suffix.lower() in {".cmd", ".bat"}:
        # Avoid PowerShell .ps1 execution-policy problems with npm's command shim.
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(path)]
    return [str(path)]


def normalize_url(value):
    value = value.strip().rstrip("/")
    try:
        parts = urllib.parse.urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/v1"} or parts.port == 0:
            raise ValueError()
    except ValueError:
        raise SetupError("地址须为 HTTPS 网站根地址或 /v1 地址，保留 2026 等自定义端口；不要粘贴 /keys 等后台页面路径。") from None
    return value if parts.path == "/v1" else value + "/v1"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_gateway(base, key, ca_file=None):
    if not key or len(key) > 4096 or any(c.isspace() for c in key):
        raise SetupError("密钥为空、过长或包含空白字符。")
    context = ssl.create_default_context(cafile=ca_file)
    if ca_file is None and Path("/etc/ssl/cert.pem").is_file():
        context.load_verify_locations("/etc/ssl/cert.pem")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(base + "/models", headers={"Authorization": "Bearer " + key})
    try:
        with opener.open(request, timeout=20) as response:
            content = response.read(LIMIT + 1)
        if len(content) > LIMIT:
            raise ValueError()
        models = {row["id"] for row in json.loads(content)["data"] if isinstance(row, dict) and isinstance(row.get("id"), str)}
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            raise SetupError("密钥被拒绝；请使用个人 API 密钥，不是管理员登录密码或管理密钥。") from None
        raise SetupError("读取模型失败（HTTP " + str(error.code) + "）；未改动配置。") from None
    except (OSError, ValueError, KeyError, TypeError):
        raise SetupError("无法验证 HTTPS 接口，请检查网络、证书和地址；不会跳过证书验证。") from None
    if MODEL not in models:
        raise SetupError("这把密钥没有 gpt-6.1-sol 权限，或渠道停用/模型未定价；未切换配置。")


class Rpc:
    def __init__(self, command, home):
        env = dict(os.environ)
        env["CODEX_HOME"] = str(home)  # Intended Codex data-root setting, scoped to this child.
        self.process = subprocess.Popen(command + ["-c", "features.plugins=false", "app-server", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", cwd=home, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.timer = threading.Timer(35, self.process.kill)
        self.timer.daemon = True
        self.timer.start()
        self.index = 0
        try:
            self.call("initialize", {"clientInfo": {"name": "newapi_setup", "version": "1.0"}})
            self.send({"method": "initialized", "params": {}})
        except Exception:
            self.close()
            raise

    def send(self, value):
        self.process.stdin.write(json.dumps(value, ensure_ascii=True) + "\n")
        self.process.stdin.flush()

    def call(self, method, params):
        self.index += 1
        self.send({"id": self.index, "method": method, "params": params})
        for line in self.process.stdout:
            answer = json.loads(line)
            if answer.get("id") != self.index:
                continue
            if "error" in answer:
                # Server errors may echo config values; never print them.
                raise SetupError("Codex 拒绝配置写入，请检查版本或企业管理策略；未输出敏感信息。")
            return answer["result"]
        raise SetupError("Codex 配置接口超时或退出，请检查安装状态。")

    def close(self):
        self.timer.cancel()
        # EOF allows the config-only server to release database/file handles cleanly.
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.process.stdout.close()


def configure(home, command, url, key, ca_file=None):
    base = normalize_url(url)
    validate_gateway(base, key, ca_file)
    target = preflight(home)
    original = target.read_bytes() if target.exists() else None
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
    backup = home / "newapi-backups" / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + os.urandom(4).hex())
    backup.parent.mkdir(exist_ok=True, mode=0o700)
    if backup.parent.is_symlink():
        raise SetupError("备份目录是符号链接；未修改配置。")
    restrict(backup.parent, True)
    backup.mkdir(mode=0o700)
    restrict(backup, True)
    if original is not None:
        private_write(backup / "original", original)
        restrict(target)
    manifest = {"existed": original is not None, "mode": mode}
    private_write(backup / "state.json", json.dumps(manifest).encode())
    written = None
    rpc = Rpc(command, home)
    try:
        before = rpc.call("config/read", {"includeLayers": True})
        layers = before.get("layers") or []
        layer = next((x for x in layers if x.get("name", {}).get("type") == "user" and x.get("name", {}).get("profile") is None), None)
        if (target.read_bytes() if target.exists() else None) != original:
            raise SetupError("配置被其他程序修改；已停止，请重试。")
        provider = {"name": "New API", "base_url": base, "wire_api": "responses", "experimental_bearer_token": key, "supports_websockets": False}
        edits = {"model": MODEL, "model_provider": PROVIDER, "model_providers." + PROVIDER: provider}
        params = {"filePath": str(target), "reloadUserConfig": False,
                  "edits": [{"keyPath": k, "value": v, "mergeStrategy": "replace"} for k, v in edits.items()]}
        if layer:
            params["expectedVersion"] = layer["version"]
        result = rpc.call("config/batchWrite", params)
        written = target.read_bytes()
        restrict(target)
        if result.get("status") != "ok":
            raise SetupError("企业管理策略覆盖了服务商配置；不能通过提权绕过，请联系管理员。")
        checked = rpc.call("config/read", {"includeLayers": False})["config"]
        actual = checked.get("model_providers", {}).get(PROVIDER, {})
        if checked.get("model_provider") != PROVIDER or actual.get("base_url") != base or actual.get("experimental_bearer_token") != key:
            raise SetupError("写入后配置未生效，已停止。")
        manifest["installed_sha256"] = hashlib.sha256(written).hexdigest()
        private_write(backup / "state.json", json.dumps(manifest).encode())
    except Exception:
        if written is not None and target.read_bytes() == written:
            if original is None:
                target.unlink()
            else:
                private_write(target, original)
                if os.name != "nt":
                    target.chmod(mode)
        raise
    finally:
        rpc.close()
    return {"model": MODEL, "backup_id": backup.name, "authentication": "personal_gateway_key"}


def restore(home):
    target = preflight(home)
    parent = home / "newapi-backups"
    if parent.is_symlink():
        raise SetupError("备份目录无效。")
    for directory in sorted(parent.glob("????????-??????-????????"), reverse=True):
        if directory.is_symlink():
            continue
        state = json.loads((directory / "state.json").read_bytes())
        if state.get("restored") or not state.get("installed_sha256"):
            continue
        current = target.read_bytes() if target.exists() else b""
        if hashlib.sha256(current).hexdigest() != state["installed_sha256"]:
            raise SetupError("配置后来已被修改，已停止自动恢复，避免覆盖其他设置。")
        original = (directory / "original").read_bytes() if state["existed"] else None
        if original is None:
            target.unlink(missing_ok=True)
        else:
            private_write(target, original)
            if os.name != "nt":
                target.chmod(state["mode"])
        state["restored"] = True
        private_write(directory / "state.json", json.dumps(state).encode())
        return
    raise SetupError("没有可恢复的本命令备份。")


def prompt_mac():
    values = []
    for title, secret in [("请输入 New API HTTPS 地址（保留端口，可带 /v1）", False), ("请输入个人 API 密钥", True)]:
        script = "text returned of (display dialog " + json.dumps(title, ensure_ascii=False) + " default answer \"\" with title \"Codex 连接 New API\"" + (" with hidden answer" if secret else "") + ")"
        result = subprocess.run(["osascript", "-e", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        if result.returncode:
            if "-128" in result.stderr:
                raise Cancelled()
            raise SetupError("无法打开 macOS 输入窗口；请在已登录桌面用户的终端运行，SSH 会话请使用 --terminal。")
        values.append(result.stdout.strip())
    return values


WINDOWS_FORM = r'''
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
$f=New-Object Windows.Forms.Form
$f.Text='Codex - New API';$f.Width=530;$f.Height=235;$f.StartPosition='CenterScreen'
$f.FormBorderStyle='FixedDialog';$f.MaximizeBox=$false;$f.MinimizeBox=$false
$l1=New-Object Windows.Forms.Label;$l1.Text='New API HTTPS URL (keep port, optional /v1)';$l1.SetBounds(15,15,480,22)
$u=New-Object Windows.Forms.TextBox;$u.SetBounds(15,40,480,25)
$l2=New-Object Windows.Forms.Label;$l2.Text='Personal API key';$l2.SetBounds(15,76,480,22)
$k=New-Object Windows.Forms.TextBox;$k.SetBounds(15,100,480,25);$k.UseSystemPasswordChar=$true
$ok=New-Object Windows.Forms.Button;$ok.Text='OK';$ok.SetBounds(310,145,85,30);$ok.DialogResult='OK'
$cancel=New-Object Windows.Forms.Button;$cancel.Text='Cancel';$cancel.SetBounds(410,145,85,30);$cancel.DialogResult='Cancel'
$f.Controls.AddRange(@($l1,$u,$l2,$k,$ok,$cancel));$f.AcceptButton=$ok;$f.CancelButton=$cancel
if($f.ShowDialog() -ne 'OK'){exit 3}
@($u.Text,$k.Text)|ConvertTo-Json -Compress
$f.Dispose()
'''


def prompt_windows():
    result = powershell(WINDOWS_FORM, 300)
    if result.returncode == 3:
        raise Cancelled()
    if result.returncode:
        raise SetupError("Windows 输入窗口被会话或管理策略阻止；可使用 --terminal，勿直接关闭 UAC 或绕过执行策略。")
    return json.loads(result.stdout.decode("utf-8-sig"))


def prompt_linux():
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return prompt_terminal()
    try:
        import tkinter as tk
    except ImportError:
        return prompt_terminal()
    try:
        root = tk.Tk()
    except tk.TclError:
        return prompt_terminal()
    root.title("Codex - New API")
    root.resizable(False, False)
    values = []
    for index, (label, secret) in enumerate([("New API HTTPS URL (keep port, optional /v1)", False), ("Personal API key", True)]):
        tk.Label(root, text=label).grid(row=index * 2, column=0, padx=16, pady=(12, 0), sticky="w")
        entry = tk.Entry(root, width=54, show="*" if secret else "")
        entry.grid(row=index * 2 + 1, column=0, padx=16, pady=4)
        values.append(entry)
    result = []
    def accept():
        result.extend(entry.get() for entry in values)
        root.destroy()
    tk.Button(root, text="OK", command=accept).grid(row=4, column=0, pady=12)
    root.bind("<Return>", lambda event: accept())
    root.mainloop()
    if not result:
        raise Cancelled()
    return result


def prompt_terminal():
    if not sys.stdin.isatty():
        raise SetupError("没有可交互终端；请直接粘贴教程的一行命令，不要把密钥放入命令参数。")
    return input("New API HTTPS 地址： ").strip(), getpass.getpass("个人 API 密钥（不回显）： ").strip()


def main():
    if sys.version_info < (3, 11):
        raise SetupError("需要 Python 3.11 或以上版本。")
    parser = argparse.ArgumentParser(description="直接输入 New API 地址和密钥，自动配置 Codex。")
    parser.add_argument("--terminal", action="store_true", help="使用终端输入，适合 SSH/无桌面 Linux")
    parser.add_argument("--restore", action="store_true", help="恢复本命令最近一次切换前的配置")
    options = parser.parse_args()
    if os.name != "nt" and os.geteuid() == 0:
        raise SetupError("请用日常桌面用户运行，不要 sudo 或 root；否则会给错误的账号配置。")
    home = config_home()
    preflight(home)
    if options.restore:
        restore(home)
        print("已恢复切换前配置；请完全退出并重新打开 Codex。")
        return
    command = discover_codex()
    if options.terminal:
        url, key = prompt_terminal()
    elif sys.platform == "darwin":
        url, key = prompt_mac()
    elif os.name == "nt":
        url, key = prompt_windows()
    else:
        url, key = prompt_linux()
    result = configure(home, command, url.strip(), key.strip())
    print("配置完成，默认模型 " + result["model"] + "；备份编号 " + result["backup_id"])
    print("请完全退出并重新打开桌面 Codex，并新建会话；已有会话可能保留旧连接。")


if __name__ == "__main__":
    try:
        main()
    except (Cancelled, KeyboardInterrupt, EOFError):
        print("已取消，未继续配置。")
    except SetupError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print("操作未完成（" + type(error).__name__ + "）；未输出连接地址、密钥或配置内容。", file=sys.stderr)
        sys.exit(1)
