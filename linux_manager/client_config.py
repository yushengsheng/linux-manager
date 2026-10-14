"""Local client setup and recoverable snapshots; never changes server accounts."""
from __future__ import annotations

import datetime
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import threading
import tomllib
import urllib.error
import urllib.parse
import urllib.request

from .models import ManagerError, atomic_private
from .releases import https_context

CLIENTS = {"codex": "GPT / Codex", "claude": "Claude Code", "pi": "Pi", "opencode": "OpenCode"}
PROVIDER = "linux-manager-cliproxyapi"
_LOCK = threading.Lock()
_LIMIT = 4 * 1024 * 1024


def chat_models(models):
    """Image generation, speech, and internal review models aren't chat choices."""
    return list(dict.fromkeys(model for model in models if isinstance(model, str) and model
        and not any(ord(c) < 32 for c in model)
        and not any(name in model.lower() for name in ("image", "tts", "transcribe", "whisper", "auto-review"))))


def _codex_catalog(models, sources):
    metadata = {}
    for source in sources:
        if not source:
            continue
        try:
            rows = json.loads(source)["models"]
            metadata.update({r["slug"]: r for r in rows if isinstance(r, dict) and isinstance(r.get("slug"), str)})
        except (ValueError, KeyError, TypeError, UnicodeError):
            continue
    rows = []
    for index, model in enumerate(models):
        # Unknown aliases get conservative generic metadata, not another model's capabilities.
        row = {"slug": model, "display_name": model, "description": "CLIProxyAPI gateway model",
            "default_reasoning_level": None, "supported_reasoning_levels": [], "shell_type": "unified_exec",
            "visibility": "list", "supported_in_api": True, "priority": index, "upgrade": None,
            "context_window": 32768, "input_modalities": ["text"], "support_verbosity": False,
            "default_verbosity": None, "apply_patch_tool_type": "freeform",
            "truncation_policy": {"mode": "tokens", "limit": 10000}, "experimental_supported_tools": [],
            "base_instructions": "You are a coding assistant. Follow the user and repository instructions. Use the available tools when needed. Verify your work and describe the result accurately."}
        row.update(copy.deepcopy(metadata.get(model, {})))
        row.update(slug=model, visibility="list", supported_in_api=True, priority=index, upgrade=None)
        rows.append(row)
    return _json_bytes({"models": rows})


def gateway_connection(information):
    data = information.get("data", {})
    if information.get("service") != "cliproxyapi" or not data.get("installed"):
        raise ManagerError("请先安装并启动所选服务器的 CLIProxyAPI。")
    base = dict(information.get("rows", [])).get("API 基础地址", "")
    _check_url(base)
    keys = data.get("api_keys", [])
    if not isinstance(keys, list) or not keys or any(not isinstance(k, str) or not k for k in keys):
        raise ManagerError("服务器未返回有效的客户端 API Key；请刷新或在后台检查。")
    return {"base_url": base.rstrip("/"), "api_keys": keys}


def _check_url(base):
    try:
        url = urllib.parse.urlsplit(base)
        valid = url.scheme == "https" and url.hostname and url.port != 0 and url.path.rstrip("/") == "/v1"
        valid = valid and not (url.username or url.password or url.query or url.fragment)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ManagerError("客户端接口地址必须是有效的 HTTPS 地址，并以 /v1 结尾。")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # A gateway key must never follow an HTTP redirect.


def gateway_models(base_url, api_key):
    """Check TLS and client authentication from this Mac without inference."""
    _check_url(base_url)
    if not isinstance(api_key, str) or not api_key.strip() or any(c in api_key for c in "\r\n\x00"):
        raise ManagerError("客户端 API Key 格式不正确。")
    request = urllib.request.Request(base_url.rstrip("/") + "/models", headers={
        "Authorization": "Bearer " + api_key, "Accept": "application/json", "User-Agent": "linux-server-manager"})
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=https_context()))
    try:
        with opener.open(request, timeout=20) as response:
            body = response.read(_LIMIT + 1)
        if len(body) > _LIMIT:
            raise ValueError()
        listing = json.loads(body)
        rows = listing["data"]
        if not isinstance(rows, list):
            raise ValueError()
        models = sorted({row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)
                         and row["id"] and not any(ord(c) < 32 for c in row["id"])})
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            raise ManagerError("客户端 Key 被服务器拒绝；请刷新 Key，勿使用管理 Key。") from None
        raise ManagerError("读取服务器模型列表失败（HTTP " + str(error.code) + "）；未改动本地配置。") from None
    except (OSError, ValueError, KeyError, TypeError):
        raise ManagerError("本机无法读取服务器模型列表；请检查 HTTPS 证书、网络和接口地址。未改动本地配置。") from None
    if not models:
        raise ManagerError("服务器模型列表为空；请先添加有效上游账号。未改动本地配置。")
    return models


def _json_object(content, title):
    try:
        value = json.loads(content or b"{}")
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise ManagerError(title + "不是有效的 JSON 对象；未覆盖原文件。") from None


def _table(data, key):
    value = data.setdefault(key, {})
    if not isinstance(value, dict):
        raise ManagerError("现有配置中的 " + key + " 格式不正确；未覆盖原文件。")
    return value


def _json_bytes(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()


def _toml_structure(text):
    """Find table boundaries outside multiline strings, preserving other text."""
    result = []
    assignments = []
    quote = None
    for index, line in enumerate(text.splitlines(keepends=True)):
        if quote is None and re.match(r'\s*(?:model|model_provider|model_catalog_json|"model"|"model_provider"|"model_catalog_json"|\'model\'|\'model_provider\'|\'model_catalog_json\')\s*=', line):
            assignments.append(index)
        if quote is None and line.lstrip().startswith("["):
            try:
                table = tomllib.loads(line)
            except tomllib.TOMLDecodeError:
                table = None
            if table is not None:
                result.append((index, table))
        pos = 0
        while pos < len(line):
            if quote:
                if quote == '"""' and line[pos] == "\\":
                    pos += 2; continue
                if line.startswith(quote, pos):
                    pos += 3; quote = None
                else:
                    pos += 1
            elif line[pos] == "#":
                break
            elif line.startswith(('"""', "'''"), pos):
                quote = line[pos:pos + 3]; pos += 3
            elif line[pos] in "\"'":
                short = line[pos]; pos += 1
                while pos < len(line) and line[pos] != short:
                    pos += 2 if short == '"' and line[pos] == "\\" else 1
                pos += 1
            else:
                pos += 1
    return result, assignments


def _codex_config(content, base, model, key_path, catalog_path):
    try:
        text = content.decode("utf-8")
        current = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise ManagerError("Codex 配置不是有效的 TOML；未覆盖原文件。") from None
    if current.get("profile"):
        raise ManagerError("Codex 正在使用独立 profile；请先取消默认 profile，再配置客户端。")
    lines = text.splitlines(keepends=True)
    headers, assignments = _toml_structure(text)
    root_end = headers[0][0] if headers else len(lines)
    remove = set()
    for index in assignments:
        if index >= root_end:
            continue
        match = re.match(r'\s*(?:model|model_provider|model_catalog_json|"model"|"model_provider"|"model_catalog_json"|\'model\'|\'model_provider\'|\'model_catalog_json\')\s*=', lines[index])
        if not match:
            continue
        value = lines[index][match.end():]
        end = index
        while True:
            try:
                tomllib.loads("value = " + value)
                break
            except tomllib.TOMLDecodeError:
                end += 1
                if end >= root_end:
                    raise ManagerError("无法安全修改 Codex 模型配置；未覆盖原文件。") from None
                value += lines[end]
        remove.update(range(index, end + 1))
    for n, (index, table) in enumerate(headers):
        providers = table.get("model_providers", {})
        if isinstance(providers, dict) and PROVIDER in providers:
            remove.update(range(index, headers[n + 1][0] if n + 1 < len(headers) else len(lines)))
    prefix = "model = " + json.dumps(model, ensure_ascii=False) + "\nmodel_provider = " + json.dumps(PROVIDER) + "\n"
    prefix += "model_catalog_json = " + json.dumps(str(catalog_path), ensure_ascii=False) + "\n"
    remaining = "".join(line for i, line in enumerate(lines) if i not in remove)
    block = (f'\n[model_providers.{PROVIDER}]\nname = "Linux CLIProxyAPI"\n'
             f'base_url = {json.dumps(base)}\nwire_api = "responses"\n'
             f'\n[model_providers.{PROVIDER}.auth]\ncommand = "/bin/cat"\n'
             f'args = [{json.dumps(str(key_path), ensure_ascii=False)}]\n')
    output = prefix + remaining.rstrip("\n") + "\n" + block
    try:
        checked = tomllib.loads(output)
        if checked["model_provider"] != PROVIDER or checked["model"] != model:
            raise ValueError()
        expected = dict(current)
        expected.update(model=model, model_provider=PROVIDER, model_catalog_json=str(catalog_path))
        expected["model_providers"] = dict(current.get("model_providers", {}))
        expected["model_providers"][PROVIDER] = checked["model_providers"][PROVIDER]
        if checked != expected:
            raise ValueError()
    except (tomllib.TOMLDecodeError, ValueError, KeyError):
        raise ManagerError("生成的 Codex 配置校验失败；未覆盖原文件。") from None
    return output.encode()


class ClientConfigurator:
    def __init__(self, backup_directory, home=None, environment=None):
        self.home = Path(home or Path.home()).absolute()
        self.backups = Path(backup_directory).absolute()
        env = os.environ if environment is None else environment
        self.directory_settings = self.backups.parent / "client-config-directories.json"
        self.directory_overrides = {}
        if self.directory_settings.exists():
            self.directory_overrides = _json_object(self.directory_settings.read_bytes(), "客户端目录设置")
            if any(k not in CLIENTS or not isinstance(v, str) for k, v in self.directory_overrides.items()):
                raise ManagerError("客户端目录设置无效；请检查本机 client-config-directories.json。")
        def directory(value):
            text = str(value)
            if text == "~" or text.startswith("~/"):
                text = str(self.home) + text[1:]
            if isinstance(value, str):
                def expand(match):
                    name = match[1] or match[2]
                    if name == "HOME": return str(self.home)
                    if name not in env:
                        raise ManagerError("客户端配置目录引用了未设置的环境变量 " + name + "；请检查客户端启动环境。")
                    return env[name]
                text = re.sub(r'\$(?:\{([A-Za-z_][A-Za-z_0-9]*)\}|([A-Za-z_][A-Za-z_0-9]*))', expand, text)
            path = Path(text).expanduser()
            if not path.is_absolute() or any(ord(c) < 32 for c in text):
                raise ManagerError("客户端配置目录必须是绝对路径；可使用 ~/ 或 $HOME，请检查客户端启动环境。")
            return path
        self.directories = {
            "codex": directory(env.get("CODEX_HOME") or self.home / ".codex"),
            "claude": directory(env.get("CLAUDE_CONFIG_DIR") or self.home / ".claude"),
            "pi": directory(env.get("PI_CODING_AGENT_DIR") or self.home / ".pi/agent"),
            "opencode": directory(env.get("XDG_CONFIG_HOME") or self.home / ".config") / "opencode",
        }
        self.directories.update({client: directory(Path(path)) for client, path in self.directory_overrides.items()})

    def set_directory(self, client, path):
        if client not in CLIENTS:
            raise ManagerError("未支持这个客户端。")
        target = Path(path).expanduser()
        if not target.is_absolute() or not target.is_dir():
            raise ManagerError("请选择客户端实际使用的配置目录。")
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
            raise ManagerError("配置目录包含符号链接；请选择真实目录。")
        overrides = self.directory_overrides | {client: str(target)}
        atomic_private(self.directory_settings, _json_bytes(overrides))
        self.directory_overrides = overrides
        self.directories[client] = target

    def paths(self, client):
        if client not in CLIENTS:
            raise ManagerError("未支持这个客户端。")
        directory = self.directories[client]
        names = {"codex": ["config.toml", "linux-manager-cliproxyapi.key", "linux-manager-cliproxyapi-models.json"], "claude": ["settings.json"],
                 "pi": ["models.json", "settings.json", "linux-manager-cliproxyapi.key"], "opencode": ["opencode.json"]}
        return [directory / name for name in names[client]]

    def _read(self, path):
        # Refuse indirection instead of unexpectedly overwriting another file.
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ManagerError("配置路径包含符号链接；请先确认真实配置位置。未覆盖文件。")
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_size > _LIMIT:
            raise ManagerError("配置文件类型或大小不符合要求；未覆盖文件。")
        return {"content": path.read_bytes(), "mode": stat.S_IMODE(path.stat().st_mode)}

    def _snapshot(self, client):
        return {path: self._read(path) for path in self.paths(client)}

    def _save(self, client, state, action, model=""):
        identifier = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
        self.backups.mkdir(parents=True, mode=0o700, exist_ok=True)
        (self.backups / client).mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.backups, 0o700)
        os.chmod(self.backups / client, 0o700)
        directory = self.backups / client / identifier
        directory.mkdir(parents=True, mode=0o700)
        rows = []
        for n, (path, original) in enumerate(state.items()):
            row = {"path": str(path), "existed": original is not None}
            if original is not None:
                name = str(n) + ".bin"
                atomic_private(directory / name, original["content"])
                row.update(file=name, mode=original["mode"], sha256=hashlib.sha256(original["content"]).hexdigest())
            rows.append(row)
        manifest = {"id": identifier, "client": client, "action": action, "model": model,
                    "created": datetime.datetime.now().isoformat(timespec="microseconds"), "files": rows}
        atomic_private(directory / "manifest.json", _json_bytes(manifest))
        return manifest

    def backups_for(self, client):
        self.paths(client)
        rows = []
        for path in (self.backups / client).glob("*/manifest.json"):
            try:
                row = _json_object(path.read_bytes(), "备份记录")
                valid = all(isinstance(row.get(k), str) for k in ("id", "created", "action", "model"))
                if valid and row.get("client") == client and row["id"] == path.parent.name and re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{8}", row["id"]) and row["action"] in {"configure", "restore"}:
                    datetime.datetime.fromisoformat(row["created"])
                    rows.append({k: row.get(k, "") for k in ("id", "created", "action", "model")})
            except (OSError, ManagerError, ValueError):
                continue
        return sorted(rows, key=lambda row: row["created"], reverse=True)

    def _write(self, path, state):
        if state is None:
            path.unlink(missing_ok=True)
        else:
            atomic_private(path, state["content"])
            os.chmod(path, state["mode"])

    def _commit(self, client, before, desired, action, model=""):
        manifest = self._save(client, before, action, model)
        if self._snapshot(client) != before:
            raise ManagerError("配置在备份期间被其他程序修改；已停止，请重试。")
        changed = []
        try:
            for path, state in desired.items():
                changed.append(path)
                self._write(path, state)
        except Exception:
            failed = False
            for path in reversed(changed):
                try:
                    self._write(path, before[path])
                except Exception:
                    failed = True
            if failed:
                raise ManagerError("写入失败且自动撤回未完成。原配置备份编号：" + manifest["id"] + "；请使用恢复功能。") from None
            raise ManagerError("写入失败，已自动恢复操作前的配置。备份编号：" + manifest["id"]) from None
        return {"backup_id": manifest["id"], "client": client, "paths": [str(p) for p in desired]}

    def configure(self, client, base_url, api_key, model, available_models):
        _check_url(base_url)
        base_url = base_url.rstrip("/")
        if not isinstance(api_key, str) or not api_key.strip() or any(c in api_key for c in "\r\n\x00"):
            raise ManagerError("客户端 API Key 格式不正确。")
        if not isinstance(model, str) or model not in available_models or any(ord(c) < 32 for c in model):
            raise ManagerError("请选择服务器模型列表中的有效模型。")
        choices = chat_models(available_models)
        if model not in choices:
            raise ManagerError("请选择可用于对话的模型；图像、语音及内部审查模型不加入客户端列表。")
        with _LOCK:
            before = self._snapshot(client)
            paths = self.paths(client)
            def content(index):
                return before[paths[index]]["content"] if before[paths[index]] is not None else b""
            if client == "codex":
                sources = [content(2)]
                cached = self._read(self.directories[client] / "models_cache.json")
                if cached: sources.append(cached["content"])
                try:
                    configured = tomllib.loads(content(0).decode() or "") if content(0) else {}
                except (UnicodeError, tomllib.TOMLDecodeError):
                    raise ManagerError("Codex 配置不是有效的 TOML；未覆盖原文件。") from None
                custom = configured.get("model_catalog_json")
                if isinstance(custom, str):
                    custom_path = Path(custom)
                    if custom_path.is_absolute() and custom_path != paths[2]:
                        original = self._read(custom_path)
                        if original: sources.append(original["content"])
                output = [_codex_config(content(0), base_url, model, paths[1], paths[2]), api_key.encode(), _codex_catalog(choices, sources)]
            elif client == "claude":
                data = _json_object(content(0), "Claude Code 配置")
                env = _table(data, "env")
                env.update(ANTHROPIC_BASE_URL=base_url.removesuffix("/v1"), ANTHROPIC_AUTH_TOKEN=api_key,
                           ANTHROPIC_API_KEY="", CLAUDE_CODE_OAUTH_TOKEN="", ANTHROPIC_MODEL=model)
                for name in ("HAIKU", "SONNET", "OPUS"):
                    env["ANTHROPIC_DEFAULT_" + name + "_MODEL"] = next((m for m in choices if "claude" in m.lower() and name.lower() in m.lower()), model)
                env["CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY"] = "1"
                for name in ("BEDROCK", "VERTEX", "FOUNDRY"):
                    env["CLAUDE_CODE_USE_" + name] = "0"
                data["model"] = model
                data.pop("apiKeyHelper", None)
                output = [_json_bytes(data)]
            elif client == "pi":
                data = _json_object(content(0), "Pi 模型配置")
                auth_path = self.directories[client] / "auth.json"
                auth = self._read(auth_path)
                if auth and PROVIDER in _json_object(auth["content"], "Pi 授权配置"):
                    raise ManagerError("Pi 中已有同名提供商授权，可能覆盖新 Key；请先在 Pi 注销这个提供商。")
                _table(data, "providers")[PROVIDER] = {
                    "baseUrl": base_url, "api": "openai-completions", "authHeader": True,
                    "apiKey": "!/bin/cat " + shlex.quote(str(paths[2])), "models": [{"id": m} for m in choices]}
                settings = _json_object(content(1), "Pi 设置")
                settings.update(defaultProvider=PROVIDER, defaultModel=model)
                # Restricting model cycling to the old provider can hide the new default.
                if "enabledModels" in settings:
                    existing = settings["enabledModels"]
                    if not isinstance(existing, list):
                        raise ManagerError("Pi enabledModels 格式不正确；未覆盖原文件。")
                    for m in choices:
                        selected = PROVIDER + "/" + m
                        if selected not in existing:
                            existing.append(selected)
                output = [_json_bytes(data), _json_bytes(settings), api_key.encode()]
            else:
                if (self.directories[client] / "opencode.jsonc").exists():
                    raise ManagerError("OpenCode 使用 JSONC 配置；请先转为 opencode.json，避免覆盖注释或配置优先级冲突。")
                data = _json_object(content(0), "OpenCode 配置")
                _table(data, "provider")[PROVIDER] = {"npm": "@ai-sdk/openai-compatible", "name": "Linux CLIProxyAPI",
                    "options": {"baseURL": base_url, "apiKey": api_key}, "models": {m: {"name": m} for m in choices}}
                data["model"] = PROVIDER + "/" + model
                for field in ("enabled_providers", "disabled_providers"):
                    if field in data:
                        if not isinstance(data[field], list):
                            raise ManagerError("OpenCode " + field + " 格式不正确；未覆盖原文件。")
                        if field == "disabled_providers":
                            data[field] = [name for name in data[field] if name != PROVIDER]
                        elif PROVIDER not in data[field]:
                            data[field].append(PROVIDER)
                output = [_json_bytes(data)]
            desired = {path: {"content": value, "mode": 0o600} for path, value in zip(paths, output)}
            return self._commit(client, before, desired, "configure", model)

    def restore(self, client, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{8}", identifier):
            raise ManagerError("请选择有效的备份编号。")
        with _LOCK:
            before = self._snapshot(client)
            directory = self.backups / client / identifier
            try:
                manifest = _json_object((directory / "manifest.json").read_bytes(), "备份记录")
                if manifest.get("client") != client or manifest.get("id") != identifier:
                    raise ValueError()
                rows = manifest["files"]
                allowed = {str(p) for p in before}
                actual = {row["path"] for row in rows} if isinstance(rows, list) else set()
                legacy = client == "codex" and actual == allowed - {str(self.paths(client)[2])}
                if not isinstance(rows, list) or len(rows) != len(actual) or (actual != allowed and not legacy):
                    raise ValueError()
                desired = {self.paths(client)[2]: None} if legacy else {}
                for row in rows:
                    path = Path(row["path"])
                    if row["existed"] is False:
                        desired[path] = None
                        continue
                    if row["existed"] is not True or not re.fullmatch(r"\d+\.bin", row["file"]):
                        raise ValueError()
                    content = (directory / row["file"]).read_bytes()
                    mode = row["mode"]
                    if hashlib.sha256(content).hexdigest() != row["sha256"] or type(mode) is not int or not 0 <= mode <= 0o777:
                        raise ValueError()
                    desired[path] = {"content": content, "mode": mode}
            except (OSError, ManagerError, ValueError, KeyError, TypeError):
                raise ManagerError("备份缺失、损坏或路径与当前客户端不一致；未恢复文件。") from None
            result = self._commit(client, before, desired, "restore")
            result["restored_id"] = identifier
            return result
