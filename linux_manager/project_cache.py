"""Private local snapshots of project metadata; credentials stay in Keychain."""
import datetime
import json
from pathlib import Path
from urllib.parse import urlsplit

from .models import ManagerError, SERVICES, atomic_private
from .project_info import server_key


def safe_url(value):
    if not isinstance(value, str) or len(value) > 2000 or any(c.isspace() for c in value): return ""
    try:
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment: return ""
        url.port
    except ValueError: return ""
    return value


TEXT_FIELDS = {"id", "kind", "name", "product", "description", "state", "substate", "startup", "executable",
               "working_directory", "definition", "definition_revision", "unit", "image", "version", "compose_project", "discovery_note",
               "framework", "web_note", "revision"}
BUILTIN_FIELDS = {"service", "installed", "uninstalled", "version", "host", "port", "backend_port", "scheme", "path", "frontend_ports"}
MAX_PROJECTS = 3000
MAX_CACHE_BYTES = 8 * 1024 * 1024


def builtin_metadata(row):
    result = {key: value for key, value in row.items() if key in BUILTIN_FIELDS}
    if "frontend_listeners" in row:
        result["frontend_listeners"] = [
            {"port": item["port"], "protocol": item["protocol"]}
            for item in row["frontend_listeners"]
            if isinstance(item, dict) and type(item.get("port")) is int and 1 <= item["port"] <= 65535
            and item.get("protocol") in {"tcp", "udp"}
        ]
    return result


def project_metadata(project):
    result = {key: value[:2000] for key, value in project.items() if key in TEXT_FIELDS and isinstance(value, str)}
    if not result.get("id", "").startswith("external:"): raise ManagerError("项目缓存标识无效。")
    result.setdefault("kind", result["id"].split(":")[1])
    result.setdefault("name", result["id"].rsplit(":", 1)[-1])
    result.setdefault("state", "unknown")
    for key in ("pid", "owner_uid"):
        if isinstance(project.get(key), int): result[key] = project[key]
    result["capabilities"] = [v for v in project.get("capabilities", []) if v in {"start", "stop", "restart", "enable", "disable"}]
    result["ports"] = []
    for port in project.get("ports", [])[:100]:
        if not isinstance(port, dict) or not isinstance(port.get("port"), int) or not 1 <= port["port"] <= 65535: continue
        result["ports"].append({key: port[key] for key in ("port", "protocol", "local_only", "container_port") if key in port})
    result["web_endpoints"] = []
    for endpoint in project.get("web_endpoints", [])[:30]:
        if isinstance(endpoint, dict) and safe_url(endpoint.get("url")):
            result["web_endpoints"].append({"url": endpoint["url"], "source": str(endpoint.get("source", ""))[:300],
                                            "local_only": bool(endpoint.get("local_only"))})
    if project.get("registered_local"): result["registered_local"] = True
    return result


class ProjectCache:
    def __init__(self, directory): self.directory = Path(directory) / "project-cache"

    def _path(self, connection): return self.directory / (server_key(connection) + ".json")

    def load(self, connection):
        path = self._path(connection)
        if not path.exists(): return {"version": 1, "projects": {}, "builtins": {}}
        try:
            if path.stat().st_size > MAX_CACHE_BYTES: raise ValueError()
            data = json.loads(path.read_text())
            if data.get("version") != 1 or not isinstance(data.get("projects"), dict) or not isinstance(data.get("builtins"), dict): raise ValueError()
            if len(data["projects"]) > MAX_PROJECTS or any(not isinstance(p, dict) or key != p.get("id") for key, p in data["projects"].items()): raise ValueError()
            data["projects"] = {key: project_metadata(p) for key, p in data["projects"].items()}
            data["builtins"] = {key: builtin_metadata(row)
                                for key, row in data["builtins"].items() if key in SERVICES and isinstance(row, dict)}
            return data
        except (OSError, ValueError, TypeError, AttributeError):
            raise ManagerError("本机项目信息缓存无法读取；原文件已保留，未覆盖。") from None

    def update(self, connection, projects=None, builtins=None, replace=False, remove=None):
        data = self.load(connection)
        if projects is not None:
            current = {} if replace else data["projects"]
            for project in projects:
                row = project_metadata(project); current[row["id"]] = row
            data["projects"] = current
        if remove: data["projects"].pop(remove, None)
        if builtins:
            for key, information in builtins.items():
                if key in SERVICES:
                    data["builtins"][key] = builtin_metadata(information.get("data", {}))
        data["saved_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        encoded = json.dumps(data, ensure_ascii=False)
        if len(data["projects"]) > MAX_PROJECTS or len(encoded.encode("utf-8")) > MAX_CACHE_BYTES:
            raise ManagerError("本次项目信息超过本机缓存上限；原缓存已保留，未覆盖。")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        atomic_private(self._path(connection), encoded)
        return data
