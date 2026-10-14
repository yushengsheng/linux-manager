from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SERVICES = {
    "exchange": ("小军交易系统", ("xiaojun-exchange-web.service", "xiaojun-exchange-worker.service", "xiaojun-exchange-nginx.service")),
    "hysteria2": ("Hysteria2 代理", ("sing-box.service",)),
    "reality": ("VLESS + REALITY + Vision", ("linux-manager-xray.service",)),
    "xui": ("代理管理面板", ("x-ui.service",)),
    "nginx": ("Nginx 网页入口", ("nginx.service",)),
    "cliproxyapi": ("CLIProxyAPI · AI 接口与管理后台", ("cli-proxy-api.service",)),
}


class ManagerError(Exception):
    """可以直接显示给用户的错误，不包含原始连接参数。"""


def validate_host(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise ManagerError("请输入服务器 IP 或完整域名，不要包含网址、空格或命令。")
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):
        raise ManagerError("服务器域名格式不正确。")
    return value


def validate_user(value: str) -> str:
    if not USERNAME.fullmatch(value):
        raise ManagerError("账号名应以小写字母或下划线开头，最多 32 位，仅使用字母、数字、下划线和连字符。")
    return value


def validate_port(value: str | int) -> int:
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise ManagerError("端口必须是 1 至 65535 的整数。") from None
    if not 1 <= port <= 65535:
        raise ManagerError("端口必须是 1 至 65535 的整数。")
    return port


def validate_password(value: str, minimum: int = 12) -> str:
    if len(value) < minimum or len(value) > 256 or any(c in value for c in "\n\r\x00"):
        raise ManagerError(f"新密码需为 {minimum} 至 256 个字符，且不能包含换行。")
    return value


@dataclass
class Connection:
    label: str = "我的服务器"
    host: str = field(default="", repr=False)
    username: str = field(default="", repr=False)
    port: int = 22
    auth: str = "password"
    key_path: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    key_passphrase: str = field(default="", repr=False)
    sudo_password: str = field(default="", repr=False)
    identifier: str = field(default_factory=lambda: secrets.token_hex(8))
    remember: bool = True

    def validate(self) -> None:
        self.host = validate_host(self.host)
        validate_user(self.username)
        self.port = validate_port(self.port)
        if self.auth not in {"password", "key"}:
            raise ManagerError("请选择密码或密钥登录。")
        if self.auth == "password" and not self.password:
            raise ManagerError("请输入当前服务器登录密码。")
        if self.auth == "key" and not Path(self.key_path).expanduser().is_file():
            raise ManagerError("请选择存在的 SSH 私钥文件。")
        if not re.fullmatch(r"[a-f0-9]{16}", self.identifier):
            raise ManagerError("连接档案损坏，请重新添加服务器。")
        if any(c in self.password + self.sudo_password for c in "\n\r\x00"):
            raise ManagerError("登录密码不能包含换行。")

    def public_record(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k not in {"password", "key_passphrase", "sudo_password"}}

    def changed(self, **values) -> "Connection":
        return Connection(**(asdict(self) | values))


class Redactor:
    def __init__(self, *values: str):
        self.values = set(v for v in values if v)

    def add(self, *values: str) -> None:
        self.values.update(v for v in values if v)

    def text(self, value: object) -> str:
        text = str(value)
        for secret in sorted(self.values, key=len, reverse=True):
            text = text.replace(secret, "[已隐藏]")
        text = re.sub(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", "[服务器地址]", text)
        text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----", "[私钥已隐藏]", text)
        text = re.sub(r"(?i)\bBearer\s+[^\s,;\"'<>]+", "Bearer [已隐藏]", text)
        text = re.sub(r"(?i)([?&](?:code|state|oauth_code|authorization_code)=)[^&\s#]+", r"\1[已隐藏]", text)
        text = re.sub(r"(?i)((?:password|passwd|token|secret|management[_-]?key|api[_-]?keys?|authorization)\s*[=:]\s*)[^\s,;]+", r"\1[已隐藏]", text)
        text = re.sub(r"(?:hysteria2|hy2|ss|vmess|vless|trojan)://\S+", "[连接信息已隐藏]", text)
        return text


def atomic_private(path: Path, text: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(text.encode("utf-8") if isinstance(text, str) else text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, directory: Path, vault=None):
        from .vault import LocalVault
        self.directory = directory
        self.vault = vault if vault is not None else LocalVault()
        self.last_warning = ""
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)

    def profiles(self) -> list[Connection]:
        self.last_warning = ""
        try:
            rows = json.loads((self.directory / "profiles.json").read_text())
            allowed = set(Connection.__dataclass_fields__) - {"password", "key_passphrase", "sudo_password"}
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return []
            profiles = [Connection(**{k: v for k, v in row.items() if k in allowed}) for row in rows]
            for connection in profiles:
                if connection.remember:
                    try:
                        values = self.vault.get(connection.identifier)
                        for key in ["password", "key_passphrase", "sudo_password"]:
                            if isinstance(values.get(key), str):
                                setattr(connection, key, values[key])
                    except (ManagerError, ValueError, TypeError):
                        self.last_warning = "本机登录信息未能读取，请重新填写或允许本程序访问钥匙串。"
            return profiles
        except (OSError, ValueError, TypeError):
            return []

    def save(self, profiles: list[Connection], update_identifiers=None) -> None:
        self.last_warning = ""
        for connection in profiles:
            if update_identifiers is not None and connection.identifier not in update_identifiers:
                continue
            try:
                if connection.remember:
                    self.vault.put(connection.identifier, {key: getattr(connection, key) for key in ["password", "key_passphrase", "sudo_password"]})
                else:
                    self.vault.delete(connection.identifier)
            except ManagerError as error:
                self.last_warning = str(error)
        atomic_private(self.directory / "profiles.json", json.dumps([c.public_record() for c in profiles], ensure_ascii=False, indent=2))

    def remove(self, identifier):
        profiles = self.profiles()
        self.vault.delete(identifier)
        self.save([profile for profile in profiles if profile.identifier != identifier], update_identifiers=set())

    def history(self) -> list[dict]:
        try:
            rows = json.loads((self.directory / "history.json").read_text())
            if not isinstance(rows, list):
                return []
            return [row for row in rows if isinstance(row, dict)
                    and all(isinstance(row.get(field), str) and row[field] for field in ("task_id", "operation", "state"))][-200:]
        except (OSError, ValueError, TypeError):
            return []

    def record(self, item: dict) -> None:
        rows = self.history() + [item]
        atomic_private(self.directory / "history.json", json.dumps(rows[-200:], ensure_ascii=False, indent=2))

