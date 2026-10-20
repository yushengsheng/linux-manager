"""Bounded discovery and explicit management of applications installed elsewhere.

No environment variables, complete command lines, application databases or
configuration contents are returned by discovery. This module also runs on
the server, bundled into the existing SSH agent; it has no extra dependency.
"""
from pathlib import Path
import hashlib
import json
import os
import pwd
import re
import shutil
import http.client
import ipaddress
import ssl
import time
from urllib.parse import urlsplit


class ExternalProjectError(Exception):
    pass


_UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\\-]{0,240}\.service")
_SYSTEM = re.compile(
    r"^(?:systemd|dbus|ssh|sshd|apt|dpkg|unattended-upgrades|ufw|fail2ban|"
    r"getty|serial-getty|user|user-runtime-dir|cron|crond|rsyslog|syslog|"
    r"networking|NetworkManager|networkd-dispatcher|polkit|accounts-daemon|"
    r"cloud-init|cloud-config|cloud-final|cloud-init-local|snapd|apparmor|"
    r"auditd|avahi-daemon|bluetooth|console-setup|keyboard-setup|plymouth|"
    r"e2scrub|fstrim|logrotate|lvm2|lvm|multipathd|mdmonitor|ModemManager|"
    r"wpa_supplicant|udisks2|upower|power-profiles-daemon|irqbalance|thermald|"
    r"fwupd|motd-news|man-db|docker|containerd|procps|kmod|rc-local|"
    r"rescue|emergency|initrd|packagekit|pm2|linux-manager)(?:[.@-]|$)"
)
_CUSTOM_ROOTS = ("/opt/", "/srv/", "/usr/local/", "/var/www/", "/home/", "/root/")
_PRODUCTS = {
    "openlist": "OpenList", "alist": "AList", "filebrowser": "File Browser",
    "1panel": "1Panel", "bt-panel": "宝塔面板", "aapanel": "aaPanel",
    "memos": "Memos", "vaultwarden": "Vaultwarden", "portainer": "Portainer",
    "nezha": "哪吒监控", "komari": "Komari", "beszel": "Beszel",
    "sub-store": "Sub-Store", "subconverter": "Subconverter", "s-ui": "S-UI",
    "frpc": "FRP 客户端", "frps": "FRP 服务端", "gost": "GOST",
    "realm": "Realm", "new-api": "New API", "one-api": "One API",
    "open-webui": "Open WebUI", "ollama": "Ollama", "uptime-kuma": "Uptime Kuma",
    "adguard": "AdGuard Home", "headscale": "Headscale", "tailscale": "Tailscale",
    "caddy": "Caddy", "traefik": "Traefik", "dufs": "Dufs", "rustdesk": "RustDesk",
    "hermes": "Hermes Agent",
}
_PROPERTIES = "Id,Description,FragmentPath,ExecStart,WorkingDirectory,MainPID,ActiveState,SubState,UnitFileState"
_DOCKER_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},'
    '"state":{{json .State.Status}},"ports":{{json .NetworkSettings.Ports}},'
    '"restart_policy":{{json .HostConfig.RestartPolicy.Name}},'
    '"compose_project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"working_directory":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},'
    '"version":{{json (index .Config.Labels "org.opencontainers.image.version")}}}'
)


def _product(text):
    text = text.lower()
    return next((name for key, name in _PRODUCTS.items() if key in text), "")


def _public_text(value, maximum=500):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))[:maximum]


class ExternalProjects:
    def __init__(self, command, excluded_units=(), excluded_directories=()):
        self.command = command
        self.excluded_units = set(excluded_units)
        self.excluded_directories = {str(Path(value)).rstrip("/") for value in excluded_directories}
        self._web_probes = {}
        self._proxy_cache = None

    def _run(self, args, timeout=15):
        try:
            result = self.command(args, check=False, timeout=timeout)
        except Exception:
            raise ExternalProjectError("读取项目状态未完成，请检查工具和权限后重试。") from None
        if result.returncode:
            # Command diagnostics may contain addresses, environment values or
            # credentials. Never turn them into GUI messages/task diagnostics.
            raise ExternalProjectError("服务器工具未完成操作；请检查项目状态和管理员权限。")
        return result.stdout

    def _eligible_unit(self, unit):
        return bool(_UNIT.fullmatch(unit) and not unit.endswith("@.service")
                    and unit not in self.excluded_units and not _SYSTEM.match(unit))

    @staticmethod
    def _blocks(output):
        return [dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
                for block in output.split("\n\n") if block.strip()]

    def _unit_project(self, values):
        unit = values.get("Id", "")
        if not self._eligible_unit(unit):
            return None
        executable = re.search(r"(?:^|[ {;])path=([^ ;}]+)", values.get("ExecStart", ""))
        executable = executable.group(1) if executable else ""
        work = values.get("WorkingDirectory", "").lstrip("-")
        fragment = values.get("FragmentPath", "")
        product = _product(" ".join((unit, executable, work)))
        if not (fragment.startswith("/etc/systemd/system/") or
                (fragment.startswith(_CUSTOM_ROOTS) and "/.config/systemd/user/" in fragment) or product
                or any(value.startswith(_CUSTOM_ROOTS) for value in (executable, work))):
            return None
        if fragment == "/dev/null" or values.get("UnitFileState") == "masked":
            return None
        try:
            stat = Path(fragment).stat()
            revision = f"{stat.st_dev}:{stat.st_ino}:{stat.st_mtime_ns}:{stat.st_size}"
        except OSError: revision = ""
        return {
            "id": "external:systemd:" + unit, "kind": "systemd", "name": unit.removesuffix(".service"),
            "product": product, "description": _public_text(values.get("Description")), "unit": unit,
            "state": values.get("ActiveState", "unknown"), "substate": values.get("SubState", ""),
            "startup": values.get("UnitFileState", "unknown"), "executable": executable,
            "working_directory": work, "definition": fragment,
            "definition_revision": revision,
            "pid": int(values.get("MainPID", "0")) if values.get("MainPID", "0").isdigit() else 0,
            "capabilities": ["start", "stop", "restart"] +
                (["enable", "disable"] if values.get("UnitFileState") in
                 {"enabled", "enabled-runtime", "disabled", "linked", "linked-runtime", "indirect"} else []),
            "ports": [],
        }

    def _systemd(self):
        output = self._run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
        units = {line.split()[0] for line in output.splitlines() if line.split()}
        # Also include loaded instances: templates themselves cannot be shown
        # without an instance and abort a multi-unit `systemctl show` request.
        loaded = self._run(["systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"])
        units.update(line.split()[0] for line in loaded.splitlines() if line.split())
        units = sorted(unit for unit in units if self._eligible_unit(unit))
        projects = []
        seen = set()
        for offset in range(0, len(units), 80):
            batch = units[offset:offset + 80]
            output = self._run(["systemctl", "show", *batch, "--property=" + _PROPERTIES])
            for values in self._blocks(output):
                project = self._unit_project(values)
                if project and project["id"] not in seen:
                    projects.append(project); seen.add(project["id"])
        return projects

    @staticmethod
    def _application_homes():
        return [entry for entry in pwd.getpwall()
                if entry.pw_dir == "/root" or entry.pw_dir.startswith("/home/")]

    def _user_systemctl(self, owner, arguments, timeout=15):
        # Reuse an existing user manager. Never start a session or a daemon.
        runtime = Path("/run/user") / str(owner.pw_uid)
        if not (runtime / "bus").is_socket():
            raise ExternalProjectError("用户服务管理器未运行；可查看安装信息，暂不能管理服务。")
        return self._run(["runuser", "-u", owner.pw_name, "--", "env",
                          "XDG_RUNTIME_DIR=" + str(runtime),
                          "DBUS_SESSION_BUS_ADDRESS=unix:path=" + str(runtime / "bus"),
                          "systemctl", "--user", *arguments], timeout=timeout)

    def _user_systemd(self):
        projects = []
        for owner in self._application_homes():
            directory = Path(owner.pw_dir) / ".config/systemd/user"
            if not directory.is_dir(): continue
            units = sorted(path.name for path in directory.glob("*.service") if self._eligible_unit(path.name))[:300]
            if not units: continue
            try:
                for offset in range(0, len(units), 80):
                    output = self._user_systemctl(owner, ["show", *units[offset:offset + 80], "--property=" + _PROPERTIES])
                    for values in self._blocks(output):
                        project = self._unit_project(values)
                        if project:
                            for key in ("working_directory", "executable", "definition"):
                                project[key] = project[key].replace("%h", owner.pw_dir).replace("%u", owner.pw_name).replace("%U", str(owner.pw_uid))
                            project.update(id=f"external:systemd-user:{owner.pw_uid}:" + project["unit"],
                                           kind="systemd-user", owner_uid=owner.pw_uid)
                            projects.append(project)
            except ExternalProjectError:
                for unit in units:
                    project = self._user_unit_file(owner, unit)
                    if project and all(p["id"] != project["id"] for p in projects): projects.append(project)
        return projects

    def _user_unit_file(self, owner, unit):
        path = Path(owner.pw_dir) / ".config/systemd/user" / unit
        try:
            if not path.is_file() or path.stat().st_size > 128 * 1024: return None
            # Select metadata only; do not interpret Environment or execute
            # shell commands from the service file.
            values = {"Id": unit, "FragmentPath": str(path), "ActiveState": "unknown", "UnitFileState": "unknown"}
            for line in path.read_text().splitlines():
                key, separator, value = line.partition("=")
                if separator and key.strip() in {"Description", "WorkingDirectory"}:
                    values[key.strip()] = value.strip().strip('"').replace("%h", owner.pw_dir).replace("%u", owner.pw_name)
            project = self._unit_project(values)
            if project:
                project.update(id=f"external:systemd-user:{owner.pw_uid}:" + unit, kind="systemd-user", owner_uid=owner.pw_uid,
                               capabilities=[], discovery_note="用户服务管理器未连接；显示服务定义中的安装信息，暂不提供启停。")
            return project
        except (OSError, UnicodeError): return None

    @staticmethod
    def _read_public_version(project):
        work = project.get("working_directory", "")
        if not work or not work.startswith(_CUSTOM_ROOTS): return
        directory = Path(work)
        for name in ("package.json", "pyproject.toml"):
            manifest = directory / name
            try:
                if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 128 * 1024: continue
                text = manifest.read_text()
                if name == "package.json":
                    value = json.loads(text).get("version", "")
                else:
                    match = re.search(r'^version\s*=\s*[\"\']([A-Za-z0-9_.+-]{1,100})[\"\']\s*$', text, re.M)
                    value = match[1] if match else ""
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", value):
                    project["version"] = value; return
            except (OSError, ValueError, AttributeError, UnicodeError): continue
        for name in ("VERSION", "version.txt"):
            path = directory / name
            try:
                if not path.is_symlink() and path.is_file() and path.stat().st_size <= 150:
                    value = path.read_text().strip()
                    if re.fullmatch(r"v?\d[\w.+-]{0,99}", value): project["version"] = value; return
            except (OSError, UnicodeError): pass
        git = directory / ".git"
        try:
            if git.is_dir() and not git.is_symlink():
                head = git / "HEAD"
                if head.is_symlink() or head.stat().st_size > 300: return
                value = head.read_text().strip()
                if re.fullmatch(r"ref: refs/heads/[A-Za-z0-9_/-]+", value) and ".." not in value:
                    reference = git / value.removeprefix("ref: ")
                    if reference.resolve().is_relative_to(git.resolve()) and reference.stat().st_size <= 100:
                        value = reference.read_text().strip()
                if re.fullmatch(r"[a-f0-9]{40,64}", value): project["revision"] = value[:12]
        except (OSError, ValueError, UnicodeError): pass

    def _web_protocol(self, port, deadline):
        if port in self._web_probes: return self._web_probes[port]
        for host in ("127.0.0.1", "::1"):
            for scheme in ("http", "https"):
                if time.monotonic() >= deadline: return ""
                connection = None
                try:
                    if scheme == "https":
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                        connection = http.client.HTTPSConnection(host, port, timeout=0.6, context=context)
                    else: connection = http.client.HTTPConnection(host, port, timeout=0.6)
                    # HEAD reads no business data, sends no credentials and
                    # never follows a redirect to an external host.
                    connection.request("HEAD", "/", headers={"Connection": "close", "User-Agent": "LinuxManager-LocalCheck"})
                    response = connection.getresponse()
                    if 100 <= response.status <= 599:
                        self._web_probes[port] = scheme
                        return scheme
                except (OSError, ValueError, http.client.HTTPException): pass
                finally:
                    if connection: connection.close()
        self._web_probes[port] = ""
        return ""

    @staticmethod
    def _nginx_blocks(text):
        # Parse structure only. Never return complete directives/configuration,
        # authorization headers, private keys or arbitrary nginx variables.
        text = re.sub(r"(?m)#.*$", "", text)
        tokens = re.findall(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};]+', text)
        root = {"header": [], "directives": [], "children": []}; stack = [root]; words = []
        for token in tokens:
            if token == "{":
                node = {"header": words, "directives": [], "children": []}
                stack[-1]["children"].append(node); stack.append(node); words = []
            elif token == "}":
                if len(stack) > 1: stack.pop()
                words = []
            elif token == ";":
                if words: stack[-1]["directives"].append(words)
                words = []
            else: words.append(token.strip("\"'"))
        return root

    def _proxy_routes(self):
        if self._proxy_cache is not None: return self._proxy_cache
        self._proxy_cache = []
        if not shutil.which("nginx"): return self._proxy_cache
        try: text = self._run(["nginx", "-T"], timeout=10)
        except ExternalProjectError: return self._proxy_cache
        if len(text) > 4 * 1024 * 1024: return self._proxy_cache
        root = self._nginx_blocks(text)
        def nodes(node):
            yield node
            for child in node["children"]: yield from nodes(child)
        all_nodes = list(nodes(root))
        upstreams = {}
        for node in all_nodes:
            if len(node["header"]) == 2 and node["header"][0] == "upstream":
                upstreams[node["header"][1]] = [line[1] for line in node["directives"] if len(line) > 1 and line[0] == "server"]
        for server in all_nodes:
            if server["header"] != ["server"]: continue
            names = [v for line in server["directives"] if line[0] == "server_name" for v in line[1:]
                     if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", v) and v != "localhost"]
            listens = []
            for line in server["directives"]:
                if line[0] != "listen" or len(line) < 2: continue
                address, _, number = line[1].rpartition(":")
                number = number or line[1]
                if number.isdigit() and 1 <= int(number) <= 65535:
                    listens.append((int(number), "https" if "ssl" in line else "http", address.strip("[]") in {"127.0.0.1", "::1"}))
            if not any(line[0] == "listen" for line in server["directives"]):
                listens.append((80, "http", False))
            for location in server["children"]:
                if not location["header"] or location["header"][0] != "location": continue
                path = location["header"][-1]
                if not re.fullmatch(r"/[A-Za-z0-9_./~-]{0,150}", path): continue
                for line in location["directives"]:
                    if line[0] != "proxy_pass" or len(line) != 2: continue
                    try:
                        target = urlsplit(line[1])
                        if target.scheme not in {"http", "https"} or target.username or target.password or not target.hostname: continue
                        upstream = upstreams.get(target.hostname)
                        targets = upstream or [target.netloc]
                        for address in targets:
                            parsed = urlsplit("http://" + address)
                            if parsed.hostname != "localhost" and not ipaddress.ip_address(parsed.hostname).is_loopback: continue
                            port = parsed.port or (80 if upstream or target.scheme == "http" else 443)
                            for number, scheme, local in listens:
                                self._proxy_cache.append({"backend_port": port, "port": number, "scheme": scheme,
                                                          "host": next(iter(names), ""), "path": path, "local_only": local,
                                                          "source": "Nginx 反向代理配置"})
                    except (ValueError, TypeError): continue
        return self._proxy_cache

    def _enrich_projects(self, projects):
        routes = self._proxy_routes()
        deadline = time.monotonic() + 6
        for project in projects:
            if not project.get("working_directory") and project.get("pid"):
                process = self._process(project["pid"])
                if process and process[1].startswith(_CUSTOM_ROOTS): project["working_directory"] = process[1]
            if not project.get("version"): self._read_public_version(project)
            endpoints = []
            for port in project.get("ports", [])[:16]:
                if port.get("protocol") != "tcp": continue
                number = port["port"]
                matching = [route for route in routes if route["backend_port"] == number]
                for route in matching:
                    endpoint = {key: value for key, value in route.items() if key != "backend_port"}
                    if endpoint not in endpoints: endpoints.append(endpoint)
                scheme = self._web_protocol(number, deadline)
                if scheme:
                    endpoints.append({"port": number, "scheme": scheme, "path": "/", "local_only": bool(port.get("local_only")),
                                      "source": "监听端口的 HTTP 响应"})
            project["web_endpoints"] = endpoints
            if not endpoints:
                project["web_note"] = "未确认网页入口：可能是命令行程序、未启动或使用其他协议。"
            elif all(e["local_only"] for e in endpoints):
                project["web_note"] = "网页仅在服务器本机监听，需通过原反向代理或 SSH 转发访问。"
            else:
                project["web_note"] = "已识别网页协议或代理配置；外部可达性仍取决于防火墙和云安全组。"

    def _hermes(self, projects):
        occupied = {p.get("working_directory", "").rstrip("/") for p in projects}
        found = []
        for owner in self._application_homes():
            home = Path(owner.pw_dir)
            for relative in (".hermes/hermes-agent", "hermes-agent", ".local/share/hermes-agent", ".local/share/hermes"):
                path = home / relative
                try:
                    if not (path / "hermes_cli/main.py").is_file() or not (path / "pyproject.toml").is_file(): continue
                    path = path.resolve(strict=True)
                    # Only known code locations are eligible; never follow an
                    # install symlink into credentials or unrelated directories.
                    if not any(path == home / value for value in (".hermes/hermes-agent", "hermes-agent", ".local/share/hermes-agent", ".local/share/hermes")): continue
                    if str(path) in self.excluded_directories: continue
                    version = ""
                    manifest = path / "pyproject.toml"
                    if not manifest.is_symlink() and manifest.stat().st_size <= 128 * 1024:
                        match = re.search(r'^version\s*=\s*[\"\']([A-Za-z0-9_.+-]{1,100})[\"\']\s*$', manifest.read_text(), re.M)
                        if match: version = match[1]
                    if str(path) in occupied:
                        for project in projects:
                            if project.get("working_directory", "").rstrip("/") == str(path):
                                project["product"] = "Hermes Agent"
                                if version and not project.get("version"): project["version"] = version
                        continue
                    found.append({"id": "external:directory:" + hashlib.sha256(str(path).encode()).hexdigest(),
                                  "kind": "directory", "name": "Hermes Agent", "product": "Hermes Agent", "state": "detected",
                                  "working_directory": str(path), "version": version, "capabilities": [], "ports": [],
                                  "discovery_note": "已识别 Hermes 安装；未读取配置、会话、密钥或执行项目代码。未连接用户服务时仅显示安装信息。"})
                    occupied.add(str(path))
                except (OSError, ValueError): continue
        return found

    def _docker(self, identifiers=None):
        if identifiers is None:
            ids = self._run(["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"])
            ids = [value for value in ids.splitlines() if re.fullmatch(r"[a-f0-9]{64}", value)]
        else: ids = identifiers
        projects = []
        for offset in range(0, len(ids), 40):
            output = self._run(["docker", "inspect", "--type=container", "--format", _DOCKER_FORMAT, *ids[offset:offset + 40]])
            for line in output.splitlines():
                row = json.loads(line)
                ports = []
                for target, bindings in (row.get("ports") or {}).items():
                    number, _, protocol = target.partition("/")
                    for binding in bindings or []:
                        if str(binding.get("HostPort", "")).isdigit():
                            ports.append({"port": int(binding["HostPort"]), "protocol": protocol,
                                          "local_only": binding.get("HostIp", "").strip("[]") in {"127.0.0.1", "::1"},
                                          "container_port": int(number) if number.isdigit() else 0})
                projects.append({
                    "id": "external:docker:" + row["id"], "kind": "docker",
                    "name": _public_text(row.get("name", "").lstrip("/")), "product": _product(row.get("image", "")),
                    "image": _public_text(row.get("image")), "version": _public_text(row.get("version")),
                    "state": row.get("state", "unknown"), "startup": row.get("restart_policy", ""),
                    "compose_project": _public_text(row.get("compose_project")),
                    "working_directory": _public_text(row.get("working_directory")),
                    "capabilities": ["start", "stop", "restart"], "ports": ports,
                })
        return projects

    def _listeners(self):
        rows = []
        for line in self._run(["ss", "-lntupH"]).splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            address, _, number = fields[4].rpartition(":")
            if not number.isdigit():
                continue
            rows.append({"port": int(number), "protocol": fields[0],
                         "local_only": address.strip("[]") in {"127.0.0.1", "::1"} or address.startswith("127."),
                         "pids": [int(pid) for pid in re.findall(r"pid=(\d+)", line)]})
        return rows

    @staticmethod
    def _unit_owns_process(project, process):
        cgroup = process[2]
        if project["kind"] == "systemd-user":
            prefix = "/user.slice/user-" + str(project["owner_uid"]) + ".slice/"
            return prefix in cgroup and bool(re.search(r"/" + re.escape(project["unit"]) + r"(?:/|$)", cgroup, re.M))
        return bool(re.search(r"/system.slice/" + re.escape(project["unit"]) + r"(?:/|$)", cgroup, re.M))

    @staticmethod
    def _pm2_homes():
        return [(entry, Path(entry.pw_dir) / ".pm2") for entry in pwd.getpwall()
                if entry.pw_dir == "/root" or entry.pw_dir.startswith("/home/")]

    def _pm2(self):
        projects = []
        for owner, home in self._pm2_homes():
            dump = home / "dump.pm2"
            if not dump.is_file() or dump.stat().st_size > 4 * 1024 * 1024:
                continue
            try:
                rows = json.loads(dump.read_text())
                daemon_pid = int((home / "pm2.pid").read_text().strip())
                daemon_alive = self._process(daemon_pid) is not None and (home / "rpc.sock").is_socket()
            except (OSError, ValueError, TypeError):
                daemon_alive = False
                try: rows = json.loads(dump.read_text())
                except (OSError, ValueError): continue
            if not isinstance(rows, list):
                continue
            cli_candidates = [Path(value) for value in (shutil.which("pm2"), "/usr/local/bin/pm2", "/usr/bin/pm2") if value]
            nvm = Path(owner.pw_dir) / ".nvm/versions/node"
            if nvm.is_dir(): cli_candidates.extend(sorted(nvm.glob("*/bin/pm2"), reverse=True))
            cli = next((path for path in cli_candidates if path.is_file() and os.access(path, os.X_OK)), None)
            seen = set()
            for row in rows:
                if not isinstance(row, dict): continue
                name = _public_text(row.get("name"), 150)
                if not name or name in seen: continue
                seen.add(name)
                work = _public_text(row.get("pm_cwd"))
                executable = _public_text(row.get("pm_exec_path"))
                active_pids = []
                # Filenames originate from the dump, never use a name as a glob.
                if (home / "pids").is_dir():
                    for path in (home / "pids").iterdir():
                        if not (path.name.startswith(name + "-") and path.suffix == ".pid"): continue
                        try:
                            pid = int(path.read_text().strip())
                            process = self._process(pid)
                            if process and process[1] == work: active_pids.append(pid)
                        except (OSError, ValueError): pass
                identity = hashlib.sha256((str(home) + "\0" + name).encode()).hexdigest()
                manageable = bool(daemon_alive and cli and name != "all" and not name.isdigit()
                                  and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_. -]{0,149}", name))
                projects.append({
                    "id": "external:pm2:" + identity, "kind": "pm2", "name": name,
                    "product": _product(name + " " + executable), "state": "active" if active_pids else "inactive",
                    "working_directory": work, "executable": executable, "pids": active_pids,
                    "version": _public_text(row.get("version")), "startup": "PM2 保存的应用记录",
                    "capabilities": ["start", "stop", "restart"] if manageable else [], "ports": [],
                    "pm2_home": str(home), "pm2_cli": str(cli) if cli else "", "owner_uid": owner.pw_uid,
                    "discovery_note": "基于 PM2 已保存记录和进程核对；未保存的新应用可按独立进程发现或手动登记。",
                })
        return projects

    @staticmethod
    def _process(pid):
        path = Path("/proc") / str(pid)
        try:
            executable = str((path / "exe").resolve(strict=True))
            work = str((path / "cwd").resolve(strict=True))
            cgroup = (path / "cgroup").read_text()[:8192]
            stat = (path / "stat").read_text().rsplit(")", 1)[1].split()
            return executable, work, cgroup, stat[19]
        except (OSError, ValueError, IndexError):
            return None

    def _directories(self, projects):
        roots = [Path(value) for value in ("/opt", "/srv", "/var/www", "/root")]
        roots.extend(Path(entry.pw_dir) for entry in pwd.getpwall() if entry.pw_dir.startswith("/home/"))
        occupied = self.excluded_directories | {p.get("working_directory", "").rstrip("/") for p in projects}
        markers = ("package.json", "pyproject.toml", "go.mod", "Cargo.toml", "requirements.txt",
                   "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")
        found = []
        for root in dict.fromkeys(roots):
            try:
                with os.scandir(root) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 300: break
                        if entry.name.startswith(".") or entry.name.lower() in {"backups", "backup", "logs", "data", "secrets", "credentials", "keys"}:
                            continue
                        if not entry.is_dir(follow_symlinks=False): continue
                        path = Path(entry.path)
                        if any(value and (str(path) == value or value.startswith(str(path) + "/")) for value in occupied): continue
                        if not any((path / marker).is_file() for marker in markers): continue
                        try:
                            project = self.directory(str(path)); project["state"] = "detected"
                            project["discovery_note"] = "常用安装目录的一层只读检查；未执行项目代码或读取配置、数据库。"
                            found.append(project)
                        except ExternalProjectError: continue
            except OSError: continue
        return found

    def discover(self):
        projects, warnings = [], []
        if shutil.which("systemctl"):
            try: projects.extend(self._systemd())
            except ExternalProjectError: warnings.append("自建服务未能完整读取，请检查服务管理器和管理员权限。")
            projects.extend(self._user_systemd())
        if shutil.which("docker"):
            try: projects.extend(self._docker())
            except (ExternalProjectError, ValueError, TypeError): warnings.append("Docker 容器未能完整读取，请检查 Docker 状态和权限。")
        try: projects.extend(self._pm2())
        except (OSError, ValueError, TypeError): warnings.append("部分 PM2 已保存应用未能读取。")
        try:
            listeners = self._listeners()
        except ExternalProjectError:
            listeners = []; warnings.append("监听端口未能读取；未将未知端口猜测为项目地址。")
        unit_projects = [p for p in projects if p["kind"] in {"systemd", "systemd-user"}]
        pm2_projects = {pid: p for p in projects if p["kind"] == "pm2" for pid in p["pids"]}
        orphaned = {}
        process_cache = {}
        for listener in listeners:
            for pid in listener["pids"]:
                if pid not in process_cache: process_cache[pid] = self._process(pid)
                process = process_cache[pid]
                if not process:
                    continue
                executable, work, cgroup, started = process
                units = re.findall(r"/([^/\n]+\.service)(?:/|$)", cgroup, re.M)
                project = pm2_projects.get(pid) or next((p for p in unit_projects if self._unit_owns_process(p, process)), None)
                if project is None:
                    # Managed/system service descendants and container processes
                    # are not a second independent application.
                    if any(not unit.startswith("pm2-") for unit in units) or "docker" in cgroup or "kubepods" in cgroup:
                        continue
                    if not (executable.startswith(_CUSTOM_ROOTS) or
                            (work.startswith(_CUSTOM_ROOTS) and work.count("/") >= 2)):
                        continue
                    identifier = f"external:process:{pid}:{started}"
                    project = orphaned.setdefault(identifier, {
                        "id": identifier, "kind": "process", "name": Path(work).name or Path(executable).name,
                        "product": _product(executable + " " + work), "state": "active", "pid": pid,
                        "executable": executable, "working_directory": work, "capabilities": [], "ports": [],
                    })
                port = {key: value for key, value in listener.items() if key != "pids"}
                if port not in project["ports"]: project["ports"].append(port)
        projects.extend(orphaned.values())
        projects.extend(self._hermes(projects))
        projects.extend(self._directories(projects))
        self._enrich_projects(projects)
        projects.sort(key=lambda row: (row["kind"], row["name"].casefold()))
        return {"projects": projects, "warnings": warnings}

    @staticmethod
    def directory(path):
        if not isinstance(path, str) or len(path) > 1000 or any(c in path for c in "\n\r\0"):
            raise ExternalProjectError("请填写有效的项目安装目录。")
        try: directory = Path(path).resolve(strict=True)
        except (OSError, ValueError): raise ExternalProjectError("项目目录不存在或无法读取。") from None
        if not str(directory).startswith(_CUSTOM_ROOTS) or not directory.is_dir() or any(
                part.startswith(".") or part.lower() in {"secrets", "credentials", "keys"} for part in directory.parts[1:]):
            raise ExternalProjectError("只能登记应用目录；不读取系统目录或凭据目录。")
        version = ""
        manifest = directory / "package.json"
        if manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 128 * 1024:
            try:
                value = json.loads(manifest.read_text()).get("version", "")
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", value): version = value
            except (OSError, ValueError, AttributeError): pass
        return {"id": "external:directory:" + hashlib.sha256(str(directory).encode()).hexdigest(),
                "kind": "directory", "name": directory.name, "product": _product(directory.name),
                "state": "registered", "working_directory": str(directory), "version": version,
                "capabilities": [], "ports": [], "discovery_note": "本机登记的安装目录；启停需使用原有启动方式。"}

    def details(self, identifier, directory=None):
        if not isinstance(identifier, str) or not identifier.startswith("external:") or len(identifier) > 300:
            raise ExternalProjectError("外部项目标识无效。")
        if identifier.startswith("external:directory:"):
            if directory:
                project = self.directory(directory)
                if project["id"] != identifier: project = None
            else:
                project = next((p for p in self._directories([]) + self._hermes([]) if p["id"] == identifier), None)
        elif re.fullmatch(r"external:systemd-user:\d{1,10}:[A-Za-z0-9_.@:\\-]+", identifier):
            _, _, uid, unit = identifier.split(":", 3)
            project = None
            try: owner = pwd.getpwuid(int(uid))
            except KeyError: owner = None
            if owner and owner in self._application_homes() and self._eligible_unit(unit):
                try:
                    values = self._blocks(self._user_systemctl(owner, ["show", unit, "--property=" + _PROPERTIES]))
                    if values: project = self._unit_project(values[0])
                except ExternalProjectError:
                    project = self._user_unit_file(owner, unit)
                if project and project["unit"] == unit:
                    for key in ("working_directory", "executable", "definition"):
                        project[key] = project.get(key, "").replace("%h", owner.pw_dir).replace("%u", owner.pw_name).replace("%U", str(owner.pw_uid))
                    project.update(id=identifier, kind="systemd-user", owner_uid=owner.pw_uid)
                else: project = None
        elif identifier.startswith("external:systemd:"):
            unit = identifier.removeprefix("external:systemd:")
            project = None
            if self._eligible_unit(unit):
                values = self._blocks(self._run(["systemctl", "show", unit, "--property=" + _PROPERTIES]))
                if values: project = self._unit_project(values[0])
                if project and project["id"] != identifier: project = None
        elif re.fullmatch(r"external:docker:[a-f0-9]{64}", identifier):
            rows = self._docker([identifier.removeprefix("external:docker:")])
            project = next((p for p in rows if p["id"] == identifier), None)
        elif re.fullmatch(r"external:pm2:[a-f0-9]{64}", identifier):
            project = next((p for p in self._pm2() if p["id"] == identifier), None)
        elif re.fullmatch(r"external:process:\d{1,20}:\d{1,20}", identifier):
            _, _, pid, started = identifier.split(":")
            process = self._process(int(pid))
            project = None
            if process:
                executable, work, cgroup, current_start = process
                units = re.findall(r"/([^/\n]+\.service)(?:/|$)", cgroup, re.M)
                if current_start == started and not any(not unit.startswith("pm2-") for unit in units) and "docker" not in cgroup and "kubepods" not in cgroup and (
                        executable.startswith(_CUSTOM_ROOTS) or (work.startswith(_CUSTOM_ROOTS) and work.count("/") >= 2)):
                    project = {"id": identifier, "kind": "process", "name": Path(work).name or Path(executable).name,
                               "product": _product(executable + " " + work), "state": "active", "pid": int(pid),
                               "executable": executable, "working_directory": work, "capabilities": [], "ports": []}
        else: project = None
        if not project:
            raise ExternalProjectError("项目已不存在或不属于可管理的外部项目，请重新读取列表。")
        if project["kind"] in {"systemd", "systemd-user", "pm2", "process"}:
            try:
                for listener in self._listeners():
                    belongs = False
                    for pid in listener["pids"]:
                        if project["kind"] == "pm2": belongs = pid in project["pids"]
                        elif project["kind"] == "process": belongs = pid == project["pid"]
                        else:
                            process = self._process(pid)
                            belongs = bool(process and self._unit_owns_process(project, process))
                        if belongs: break
                    port = {key: value for key, value in listener.items() if key != "pids"}
                    if belongs and port not in project["ports"]: project["ports"].append(port)
            except ExternalProjectError:
                project["discovery_note"] = "项目详情已读取；本次监听端口未能读取。"
        project["credential_management"] = "local_record"
        self._enrich_projects([project])
        return project

    def manage(self, identifier, action, expected=None):
        project = self.details(identifier)  # Revalidate immediately, not the GUI cache.
        if action not in project["capabilities"]:
            raise ExternalProjectError("此项目不支持该管理操作；独立进程请使用其原有启动方式。")
        if not expected or expected != self.fingerprint(project):
            raise ExternalProjectError("项目定义已变化，请重新读取信息并确认后再操作。")
        if project["kind"] == "systemd":
            self._run(["systemctl", action, project["unit"]], timeout=90)
        elif project["kind"] == "systemd-user":
            self._user_systemctl(pwd.getpwuid(project["owner_uid"]), [action, project["unit"]], timeout=90)
        elif project["kind"] == "docker":
            container = identifier.removeprefix("external:docker:")
            if not re.fullmatch(r"[a-f0-9]{64}", container):
                raise ExternalProjectError("容器标识无效，请重新读取列表。")
            self._run(["docker", action, container], timeout=90)
        elif project["kind"] == "pm2":
            owner = pwd.getpwuid(project["owner_uid"])
            cli = Path(project["pm2_cli"])
            self._run(["runuser", "-u", owner.pw_name, "--", "env", "PM2_HOME=" + project["pm2_home"],
                       "PATH=" + str(cli.parent) + ":/usr/local/bin:/usr/bin:/bin", str(cli), action, project["name"]], timeout=90)
        updated = self.details(identifier)
        expected_state = {"start": {"active", "running"}, "restart": {"active", "running"},
                          "stop": {"inactive", "failed", "exited", "dead"}}
        if action in expected_state and updated["state"] not in expected_state[action]:
            raise ExternalProjectError("操作已提交，但项目状态尚未达到预期；请查看项目详情，勿连续重复操作。")
        if action == "enable" and updated["startup"] not in {"enabled", "enabled-runtime"}:
            raise ExternalProjectError("自启状态未达到预期，请读取详情核对。")
        if action == "disable" and updated["startup"] in {"enabled", "enabled-runtime"}:
            raise ExternalProjectError("自启状态未达到预期，请读取详情核对。")
        return {"external_project": updated, "action": action}

    @staticmethod
    def fingerprint(project):
        identity = {key: project.get(key, "") for key in
                    ("id", "definition", "definition_revision", "executable", "working_directory", "image")}
        return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    def logs(self, identifier):
        project = self.details(identifier)
        if project["kind"] != "systemd":
            return {"logs": "容器或独立程序的业务日志可能包含凭据；请在项目原有管理界面查看。"}
        # Do not expose application log lines even if they contain words such as
        # 'Started'. Only records emitted by systemd itself are eligible.
        output = self._run(["journalctl", "--no-pager", "-n", "80", "--output=json",
                            "-u", project["unit"], "_COMM=systemd"])
        counts = {"启动": 0, "停止": 0, "失败": 0}
        for line in output.splitlines():
            try: message = str(json.loads(line).get("MESSAGE", ""))
            except (ValueError, TypeError): continue
            for word, pattern in (("启动", r"^Started\b"), ("停止", r"^Stopped\b"), ("失败", r"^Failed\b")):
                if re.search(pattern, message): counts[word] += 1
        return {"logs": "最近服务生命周期记录（不读取业务日志）：\n" +
                "\n".join(f"{label}：{count} 次" for label, count in counts.items())}
