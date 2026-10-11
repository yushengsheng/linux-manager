"""Embedded in the standalone remote agent; uses its allowlisted helpers."""
import importlib.util
import contextlib

_initial_deploy = deploy


def _nginx_package():
    result = command(["dpkg-query", "-W", "-f=${Version}", "nginx"], check=False)
    current = result.stdout.strip() if result.returncode == 0 else ""
    policy = command(["apt-cache", "policy", "nginx"], check=False).stdout
    match = re.search(r"Candidate:\s+(\S+)", policy)
    candidate = match.group(1) if match and match.group(1) != "(none)" else current
    return current, candidate


def _deployment_state(kind, address):
    try:
        data = connection_details({"service": kind, "host": address})
        data.pop("initialization_code", None)
        data.pop("subscription_base", None)
        if kind == "exchange":
            current = Path("/opt/xiaojun-exchange/current")
            if (current / "version.txt").is_file():
                data["version"] = (current / "version.txt").read_text().strip()
            data["_ready"] = current.is_dir() and Path("/etc/xiaojun-exchange/server.env").is_file() and Path("/etc/xiaojun-exchange/nginx.conf").is_file()
            if data["_ready"]:
                try:
                    _exchange_installer(current).verify_payload(current)
                    unit = Path("/etc/systemd/system/xiaojun-exchange-web.service")
                    data["_ready"] = unit.is_file() and bool(re.search(r"--port\s+\d+", unit.read_text()))
                except (OSError, ValueError, ImportError, AttributeError, SyntaxError):
                    data["_ready"] = False
            data["_present"] = any(Path(p).exists() for p in ["/opt/xiaojun-exchange", "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange"])
        elif kind == "hysteria2":
            binary = Path("/usr/local/bin/sing-box")
            executable_ready = False
            if binary.is_file():
                try:
                    output = command([str(binary), "version"], check=False).stdout
                except OSError:
                    output = ""
                match = re.search(r"sing-box version (\d+\.\d+\.\d+)", output)
                if match: data["version"] = "v" + match.group(1); executable_ready = True
            data["_ready"] = executable_ready and Path("/etc/sing-box/config.json").is_file() and "proxy_password" in data
            data["_present"] = binary.exists() or Path("/etc/sing-box/config.json").exists()
        elif kind == "xui":
            binary = Path("/usr/local/x-ui/x-ui")
            executable_ready = False
            if binary.is_file():
                try:
                    result = command([str(binary), "-v"], check=False)
                    output = result.stdout + "\n" + result.stderr
                except OSError:
                    output = ""
                match = re.search(r"(?m)^\s*v?(\d+\.\d+\.\d+)\s*$", output)
                if match: data["version"] = "v" + match.group(1); executable_ready = True
            database = Path("/etc/x-ui/x-ui.db")
            if database.is_file():
                with contextlib.closing(sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True)) as db:
                    row = db.execute("SELECT password FROM users LIMIT 1").fetchone()
                    require(row is not None, "面板账号资料不完整，已保留数据库，不能重置覆盖。")
                    data["_password_hash"] = row[0]
            data["_ready"] = executable_ready and database.is_file() and bool(data.get("_password_hash"))
            data["_present"] = binary.exists() or database.exists()
        else:
            data["version"], data["_candidate"] = _nginx_package()
            managed = Path("/etc/nginx/conf.d/linux-manager-default.conf")
            data["_present"] = bool(data["version"])
            data["_ready"] = managed.is_file()
            data["installed"] = managed.is_file()
            if managed.is_file():
                text = managed.read_text()
                match = re.search(r"listen\s+(\d+)", text)
                require(match is not None, "本程序的 Nginx 配置缺少端口，不能猜测覆盖。")
                data["port"] = int(match.group(1))
                match = re.search(r"server_name\s+([^;]+);", text)
                data["host"] = match.group(1).strip() if match else address
            else:
                data["port"] = 80
                data["host"] = address
        data.setdefault("host", address)
        return data
    except (OSError, ValueError, sqlite3.DatabaseError):
        raise OperationError("已有项目配置无法读取，已保留数据。请先修复配置或从有效备份恢复，不能清空覆盖。") from None


def _bootstrap_reset_allowed():
    root = Path("/opt/xiaojun-exchange")
    marker = root / ".install-incomplete.json"
    if any(Path(p).is_symlink() for p in [root, marker, "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange"]) or not marker.is_file():
        return False
    try:
        saved = json.loads(marker.read_text())
        data = Path("/var/lib/xiaojun-exchange")
        return saved.get("phase") == "bootstrap" and not any(Path("/etc/systemd/system").glob("xiaojun-exchange-*")) and (not data.exists() or all(p.name == "setup-token" for p in data.iterdir()))
    except (OSError, ValueError):
        return False


def _state_fingerprint(data):
    values = {key: data.get(key) for key in ["installed", "version", "host", "port", "backend_port", "proxy_password", "panel_username", "_password_hash", "_ready", "_present", "_certificate_state"]}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def deployment_preflight(params):
    kind = params.get("service")
    require(kind in {"exchange", "hysteria2", "xui", "nginx"}, "部署项目无效。")
    address = host(params.get("host")); number = port(params.get("port", 80 if kind == "nginx" else 0))
    release = platform.freedesktop_os_release()
    require((release.get("ID"), release.get("VERSION_ID")) in {("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")}, "当前系统尚未支持自动部署。")
    architecture = platform.machine()
    require(architecture in {"x86_64", "aarch64"} and (kind != "exchange" or architecture == "x86_64"), "当前服务器架构尚未支持此项目。")
    require(shutil.disk_usage("/").free >= 1024 ** 3, "磁盘可用空间不足 1 GiB。")
    data = _deployment_state(kind, address)
    present = bool(data.get("_present"))
    ready = bool(data.get("_ready"))
    requested = params.get("version", "")
    if params.get("version_policy") == "keep":
        require(present and data.get("version"), "没有可保持的现有版本，请选择最新稳定版或指定版本。")
        requested = data["version"]
    if kind == "nginx":
        requested = requested or data.get("_candidate")
        require(isinstance(requested, str) and re.fullmatch(r"[a-zA-Z0-9.+:~_-]{1,100}", requested), "系统仓库没有可安装的 Nginx 版本，请检查软件源。")
        if requested != data.get("version"):
            require(command(["apt-cache", "show", "nginx=" + requested], check=False).returncode == 0, "系统仓库没有所选 Nginx 版本，现有项目保持不变。")
    else:
        require(isinstance(requested, str) and re.fullmatch(r"v\d+\.\d+\.\d+", requested), "请先确认具体稳定发行版本。")
    changes = []
    def change(field, value, label, concealed=False):
        old = data.get(field)
        if old != value:
            changes.append({"field": field, "name": label, "before": "已隐藏" if concealed else old, "after": "将更新" if concealed else value})
    change("version", requested, "版本")
    change("port", number, "服务端口")
    change("host", address, "访问地址")
    if kind == "nginx" and certificate_renewals():
        files = [file for file, _, _ in certificate_renewals()] + [Path(NGINX_ACME_SITE), Path(NGINX_MANAGED_SITE), Path(CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies"), ROOT / "installed.json"]
        data["_certificate_state"] = {"files": [(str(file), hashlib.sha256(file.read_bytes()).hexdigest() if file.is_file() else None) for file in files], "timer": unit_info("linux-manager-cert-renew.timer")}
    if kind == "nginx" and certificate_webroot_needed():
        changes.append({"field": "certificate_renewal", "name": "证书自动续期兼容", "before": "需要补齐", "after": "通过 Nginx 验证并启用续期"})
    if kind == "exchange":
        backend = port(params.get("backend_port", data.get("backend_port", 18880)))
        require(backend != number, "访问端口和内部端口不能相同。")
        change("backend_port", backend, "内部端口")
        if not present or backend != data.get("backend_port"):
            ensure_port_available(backend)
    if kind == "hysteria2":
        secret = params.get("proxy_password") or data.get("proxy_password")
        password(secret)
        change("proxy_password", secret, "服务密码", True)
    elif kind == "xui":
        account = params.get("panel_username") or data.get("panel_username")
        username(account)
        change("panel_username", account, "面板账号", True)
        value = params.get("panel_password")
        if value:
            password(value)
            import bcrypt
            if not data.get("_password_hash") or not bcrypt.checkpw(value.encode(), data["_password_hash"].encode()):
                changes.append({"field": "panel_password", "name": "面板密码", "before": "已隐藏", "after": "将更新"})
        else:
            require(present and data.get("_password_hash"), "首次安装或缺少原账号时需要填写面板密码。")
    if not present or number != data.get("port"):
        ensure_port_available(number, "udp" if kind == "hysteria2" else "tcp")
    action = "install"
    if present:
        if ready:
            action = "update" if requested != data.get("version") else "reconfigure" if changes else "unchanged"
        elif kind == "exchange" and _bootstrap_reset_allowed():
            action = "retry"
        elif kind == "exchange":
            require(Path("/opt/xiaojun-exchange/current/version.txt").is_file() or data.get("uninstalled") and data.get("uninstall_task") and data.get("version") and Path("/etc/xiaojun-exchange/server.env").is_file() and Path("/var/lib/xiaojun-exchange").is_dir(), "安装布局无法识别，已保留交易数据；请先恢复官方安装布局，不能清空覆盖。")
            action = "repair"
        elif kind in {"hysteria2", "xui"}:
            action = "repair"
        else:
            action = "install"
    return {"service": kind, "architecture": architecture, "preflight": "passed", "action": action,
            "installed": present, "reinstall": bool(data.get("uninstalled")), "version": requested, "port": number, "host": address,
            "changes": changes, "fingerprint": _state_fingerprint(data),
            "requires_archive": kind != "nginx" and action in {"install", "update", "repair", "retry"},
            "backend_port": port(params.get("backend_port", data.get("backend_port", 18880))) if kind == "exchange" else None}


def _deployment_units(kind):
    return list(UNITS[kind]) if kind != "nginx" else ["nginx.service"]


def _deployment_backup_size(paths):
    total = 0
    for name in paths:
        path = Path(name)
        if path.is_symlink():
            continue
        files = path.rglob("*") if path.is_dir() else [path]
        for file in files:
            if file.is_file() and not file.is_symlink():
                total += file.stat().st_size
    return total


def _deployment_backup(kind, action):
    paths = {
        "exchange": ["/etc/xiaojun-exchange", "/opt/xiaojun-exchange/current"],
        "hysteria2": ["/etc/sing-box", "/usr/local/bin/sing-box"],
        "xui": ["/etc/x-ui", "/usr/local/x-ui"],
        "nginx": ["/etc/nginx"],
    }[kind]
    units = _deployment_units(kind)
    if kind == "nginx" and certificate_renewals():
        paths += [CERTIFICATE_CONFIG + "/renewal", CERTIFICATE_CONFIG + "/renewal-hooks"]
        units += ["linux-manager-cert-renew.service", "linux-manager-cert-renew.timer"]
    if kind == "exchange" and action in {"update", "repair", "retry"}:
        paths += ["/var/lib/xiaojun-exchange"]
        units += ["xiaojun-exchange-maintenance.timer", "xiaojun-exchange-logrotate.timer"]
        for name in ["xiaojun-exchange-maintenance.service", "xiaojun-exchange-logrotate.service", "xiaojun-exchange-cert-renew.service", "xiaojun-exchange-cert-renew.timer"]:
            units.append(name)
        units = list(dict.fromkeys(units + [file.name for file in Path("/etc/systemd/system").glob("xiaojun-exchange-*") if file.suffix in {".timer", ".service"}]))
    if action == "retry":
        paths += ["/opt/xiaojun-exchange"]
    state = {unit: unit_info(unit) for unit in units}
    if kind == "nginx":
        require(state.get("linux-manager-cert-renew.service", {}).get("ActiveState") not in {"active", "activating"}, "证书正在续期，请等待完成后再安装 Nginx。")
    paths += ["/etc/systemd/system/" + unit for unit in units] + [str(ROOT / "installed.json"), "/etc/linux-server-manager/tls"]
    require(shutil.disk_usage("/").free >= _deployment_backup_size(paths) + 1024 ** 3,
            "空间不足以备份原项目并保留运行空间，现有服务未停止。请先增加磁盘可用空间。")
    extra = {"deployment": True, "service": kind, "unit_states": state}
    if kind == "nginx":
        extra["nginx_version"] = _nginx_package()[0]
    try:
        if (action in {"update", "repair", "retry"} and kind != "nginx" or kind == "xui") and any(state[unit].get("LoadState") == "loaded" for unit in units):
            command(["systemctl", "stop", *[unit for unit in units if state[unit].get("LoadState") == "loaded"]], timeout=360)
        directory = backup_files(paths, extra)
    except Exception:
        for unit, original in state.items():
            if original.get("ActiveState") == "active": command(["systemctl", "start", unit], timeout=360, check=False)
        raise
    return directory


def restore_deployment(identifier):
    manifest = json.loads((ROOT / "tasks" / identifier / "backup/manifest.json").read_text())
    extra = manifest["extra"]
    units = list(extra["unit_states"])
    for unit in units:
        if extra["service"] == "nginx" and unit == "linux-manager-cert-renew.service":
            continue
        if unit_info(unit).get("LoadState") == "loaded": command(["systemctl", "stop", unit], timeout=360, check=False)
    if extra.get("nginx_version") and _nginx_package()[0] != extra["nginx_version"]:
        folder = ROOT / "tasks" / identifier / "nginx-original-packages"
        packages = sorted(str(file) for file in folder.glob("*.deb"))
        require(packages, "原 Nginx 安装包不可用，不能保证版本恢复。")
        command(["apt-get", "install", "-y", "--allow-downgrades", *packages], timeout=600, env={"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"})
    restore_files(identifier)
    cert_hook()
    for unit, state in extra["unit_states"].items():
        if extra["service"] == "nginx" and unit == "linux-manager-cert-renew.service":
            # An independent oneshot may have started after the backup. Never
            # kill/re-run a live certificate renewal as part of site rollback.
            continue
        if state.get("LoadState") == "masked" or state.get("UnitFileState") == "masked":
            command(["systemctl", "mask", unit])
            require(unit_info(unit).get("LoadState") == "masked", "原服务屏蔽状态恢复未通过，请查看任务记录。")
            continue
        if state.get("LoadState") == "not-found" and unit == "linux-manager-cert-renew.timer":
            command(["systemctl", "disable", unit], check=False)
        if state.get("LoadState") == "loaded":
            startup = state.get("UnitFileState")
            if startup in {"enabled", "disabled"}:
                command(["systemctl", "enable" if startup == "enabled" else "disable", unit])
            command(["systemctl", "restart" if state.get("ActiveState") == "active" else "stop", unit], timeout=360)
            restored = unit_info(unit)
            require(restored.get("LoadState") == "loaded" and (restored.get("ActiveState") == "active" if state.get("ActiveState") == "active" else restored.get("ActiveState") in {"inactive", "failed"}), "原项目服务状态恢复未通过，请查看任务记录。")
            if startup:
                require(restored.get("UnitFileState") == startup, "原项目开机启动状态恢复未通过，请查看任务记录。")


def _exchange_installer(source):
    spec = importlib.util.spec_from_file_location("verified_exchange_installer", source / "linux_exchange/install.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _replace_env(path, changes):
    original = Path(path)
    rows = original.read_text().splitlines() if original.is_file() else []
    seen = set(); result = []
    for row in rows:
        key = row.partition("=")[0]
        if key in changes:
            result.append(key + "=" + changes[key]); seen.add(key)
        else: result.append(row)
    result.extend(key + "=" + value for key, value in changes.items() if key not in seen)
    private_write(path, "\n".join(result) + "\n")


def _change_exchange(params, plan):
    number = plan["port"]; backend = plan["backend_port"]; address = plan["host"]
    source = Path("/opt/xiaojun-exchange/current")
    previous = connection_details({"service":"exchange", "host":address})
    version_change = plan["action"] in {"update", "repair"}
    if version_change:
        unpack(TASK / "release.tar.gz", TASK / "exchange-source")
        source = TASK / "exchange-source"
    installer = _exchange_installer(source)
    version, manifest = installer.verify_payload(source)
    require(version == plan["version"], "交易系统发行包版本与已确认版本不一致。")
    cert, key = certificate(params)
    if version_change:
        target = Path("/opt/xiaojun-exchange/releases") / (version + "-" + TASK.name[:8])
        require(not target.exists(), "版本暂存目录已存在，请检查原任务。")
        target.mkdir(parents=True)
        for name in manifest:
            file = target / name; file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, file); file.chmod(0o755 if name.startswith("bin/") or name.endswith(".sh") else 0o644)
        shutil.copy2(source / "linux-release-manifest.json", target / "linux-release-manifest.json")
        installer.verify_payload(target)
        environment = Path("/opt/xiaojun-exchange/environments") / target.name
        step("准备新版本独立运行环境，保留原版本与业务数据…", 35)
        command(["python3", "-m", "venv", str(environment)], timeout=120)
        command([str(environment / "bin/python"), "-m", "pip", "install", "--no-cache-dir", "--require-hashes", "-r", str(target / "requirements-linux.lock")], timeout=1800)
        command([str(environment / "bin/python"), "-m", "pip", "check"], timeout=90)
        pins = json.loads((target / "linux_exchange/deploy/proxy-runtimes.json").read_text())
        updates = {}
        for name, pin in pins.items():
            binary = target / "bin" / name
            require(hashlib.sha256(binary.read_bytes()).hexdigest() == pin["executable_sha256"], "新版本附带的运行内核校验失败。")
            variable = {"xray": "XRAY", "sing-box": "SING_BOX", "hysteria": "HYSTERIA"}[name]
            updates[variable + "_PATH"] = str(binary); updates[variable + "_EXECUTABLE_SHA256"] = pin["executable_sha256"]
        _replace_env("/etc/xiaojun-exchange/server.env", updates)
        for pattern in ["*.service", "*.timer"]:
            for unit in (target / "linux_exchange/deploy").glob(pattern):
                text = unit.read_text().replace("--port 18880", "--port " + str(backend)).replace("/opt/xiaojun-exchange/venv", str(environment))
                private_write("/etc/systemd/system/" + unit.name, text, 0o644)
        link = Path("/opt/xiaojun-exchange/current.new")
        link.unlink(missing_ok=True); link.symlink_to(target); os.replace(link, Path("/opt/xiaojun-exchange/current"))
    else:
        unit = Path("/etc/systemd/system/xiaojun-exchange-web.service")
        text = unit.read_text()
        require(re.search(r"--port\s+\d+", text), "网页服务端口配置无法识别，需要使用修复安装。")
        private_write(unit, re.sub(r"--port\s+\d+", "--port " + str(backend), text), 0o644)
    _replace_env("/etc/xiaojun-exchange/server.env", {"XIAOJUN_PUBLIC_ORIGIN": "https://" + address + ":" + str(number)})
    tls = Path("/etc/xiaojun-exchange/tls"); tls.mkdir(mode=0o700, exist_ok=True)
    private_write(tls / "fullchain.pem", Path(cert).read_bytes()); private_write(tls / "privkey.pem", Path(key).read_bytes())
    configuration = Path("/etc/xiaojun-exchange/nginx.conf")
    if configuration.is_file() and (plan["action"] != "repair" or plan.get("reinstall")):
        text = configuration.read_text()
        old_port = str(previous.get("port", number))
        old_backend = str(previous.get("backend_port", backend))
        text = re.sub(r"(listen\s+(?:\[::\]:)?)" + re.escape(old_port) + r"(?=[\s;])", lambda match:match.group(1)+str(number), text)
        text = text.replace("127.0.0.1:" + old_backend, "127.0.0.1:" + str(backend))
        text = re.sub(r"(server_name\s+)" + re.escape(previous.get("host", address)) + r"(?=\s*;)", lambda match:match.group(1)+address, text)
        text = re.sub(r"(ssl_certificate\s+)[^;]+;", lambda match:match.group(1)+str(tls / "fullchain.pem")+";", text)
        text = re.sub(r"(ssl_certificate_key\s+)[^;]+;", lambda match:match.group(1)+str(tls / "privkey.pem")+";", text)
    else:
        text = installer.nginx_config(address, number, backend, tls / "fullchain.pem", tls / "privkey.pem", False)
    private_write("/etc/xiaojun-exchange/nginx.conf", text)
    # systemd removes RuntimeDirectory when the old version is stopped.
    # nginx -t needs this directory before the new unit recreates it.
    Path("/run/xiaojun-exchange-nginx").mkdir(mode=0o755, parents=True, exist_ok=True)
    command(["nginx", "-t", "-c", "/etc/xiaojun-exchange/nginx.conf"])
    command(["systemctl", "daemon-reload"])
    if plan.get("reinstall"):
        command(["systemctl", "enable", *UNITS["exchange"], "xiaojun-exchange-maintenance.timer", "xiaojun-exchange-logrotate.timer"])
    if version_change:
        command(["systemctl", "start", *UNITS["exchange"]], timeout=360)
        for timer in ["xiaojun-exchange-maintenance.timer", "xiaojun-exchange-logrotate.timer"]:
            command(["systemctl", "start", timer])
    else:
        command(["systemctl", "restart", "xiaojun-exchange-web.service"], timeout=90)
        command(["systemctl", "reload-or-restart", "xiaojun-exchange-nginx.service"], timeout=90)
    for _ in range(20):
        if all(unit_info(unit).get("ActiveState") == "active" for unit in UNITS["exchange"]):
            try:
                verify_local_https(address, number, certificate_data=params.get("tls_cert")); break
            except OperationError: pass
        time.sleep(1)
    else: raise OperationError("交易系统新配置检查未通过。")
    allow_port(number)
    mark_installed("exchange", {"version": version, "port": number, "host": address, "certificate_source": "manager" if cert.startswith("/etc/linux-server-manager/letsencrypt/") else "custom", "certificate_lineage":str(Path(cert).parent)})


def _change_hysteria(params, plan):
    config_path = Path("/etc/sing-box/config.json")
    config = json.loads(config_path.read_text()) if config_path.is_file() else {"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}
    inbound = next((item for item in config["inbounds"] if item.get("type") == "hysteria2"), None)
    if inbound is None:
        inbound = {"type":"hysteria2","tag":"hy2-in","listen":"::","users":[]}; config["inbounds"].append(inbound)
    cert, key = certificate(params)
    inbound["listen_port"] = plan["port"]
    if params.get("proxy_password"):
        if inbound.get("users"): inbound["users"][0]["password"] = params["proxy_password"]
        else: inbound["users"] = [{"name":"client","password":params["proxy_password"]}]
    inbound.setdefault("tls", {}).update(enabled=True, certificate_path=cert, key_path=key)
    if any(item["field"] == "host" for item in plan["changes"]):
        inbound["tls"]["server_name"] = plan["host"]
    if plan["action"] in {"update", "repair"}:
        unpack(TASK / "release.tar.gz", TASK / "unpacked")
        binaries = list((TASK / "unpacked").rglob("sing-box")); require(len(binaries) == 1, "代理安装包结构不符合预期。")
        shutil.copy2(binaries[0], "/usr/local/bin/sing-box"); Path("/usr/local/bin/sing-box").chmod(0o755)
    private_write(config_path, json.dumps(config, indent=2))
    command(["/usr/local/bin/sing-box", "check", "-c", str(config_path)])
    if not Path("/etc/systemd/system/sing-box.service").is_file():
        private_write("/etc/systemd/system/sing-box.service", "[Unit]\nDescription=sing-box\nAfter=network-online.target\n[Service]\nExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n", 0o644)
    command(["systemctl", "daemon-reload"])
    if plan.get("reinstall"): command(["systemctl", "enable", "sing-box.service"])
    command(["systemctl", "restart", "sing-box.service"])
    time.sleep(2)
    require(unit_info("sing-box.service").get("ActiveState") == "active" and any(item["port"] == plan["port"] and item["protocol"] == "udp" for item in listeners()), "代理新配置未能正常监听。")
    allow_port(plan["port"], "udp")
    mark_installed("hysteria2", {"version": plan["version"], "port": plan["port"], "host": plan["host"]})


def _panel_connection_config(database):
    with contextlib.closing(sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        nodes = list(db.execute("SELECT id,settings,stream_settings FROM inbounds ORDER BY id")) if "inbounds" in tables else []
        settings = {key:value for key,value in db.execute("SELECT key,value FROM settings") if key.startswith(("web", "sub"))} if "settings" in tables else {}
        users = list(db.execute("SELECT username,password FROM users ORDER BY rowid")) if "users" in tables else []
        return {"nodes":nodes, "settings":settings, "users":users}


def _restore_panel_connection_config(db, saved):
    ids = [row[0] for row in db.execute("SELECT id FROM inbounds ORDER BY id")]
    require(ids == [row[0] for row in saved["nodes"]], "目标版本不能保留原节点编号，已停止版本切换。")
    require(list(db.execute("SELECT username,password FROM users ORDER BY rowid")) == saved["users"], "目标版本改变了原登录账号，已停止版本切换。")
    # Some official migrations rewrite client JSON metadata. Restore the
    # original connection definitions, while retaining new schema and migration
    # markers. The explicitly requested deployment fields are applied below.
    for identifier, settings, stream in saved["nodes"]:
        db.execute("UPDATE inbounds SET settings=?,stream_settings=? WHERE id=?", (settings,stream,identifier))
    for key,value in saved["settings"].items():
        db.execute("DELETE FROM settings WHERE key=?", (key,))
        db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (key,value))


def _change_xui(params, plan):
    import bcrypt
    folder = Path("/usr/local/x-ui"); database = Path("/etc/x-ui/x-ui.db")
    before = _deployment_state("xui", plan["host"]).get("inbounds", [])
    preserved = _panel_connection_config(database) if database.is_file() and plan["action"] in {"update", "repair"} else None
    cert, key = certificate(params)
    command(["systemctl", "stop", "x-ui.service"], timeout=90, check=False)
    if plan["action"] in {"update", "repair"}:
        unpack(TASK / "release.tar.gz", TASK / "unpacked")
        binaries = [p for p in (TASK / "unpacked").rglob("x-ui") if p.is_file()]
        require(len(binaries) == 1, "面板安装包结构不符合预期。")
        if folder.exists(): shutil.rmtree(folder)
        shutil.copytree(binaries[0].parent, folder); (folder / "x-ui").chmod(0o755)
        command([str(folder / "x-ui"), "migrate"], timeout=120)
    with contextlib.closing(sqlite3.connect(database)) as db, db:
        if preserved is not None:
            _restore_panel_connection_config(db, preserved)
        fields = {item["field"] for item in plan["changes"]}
        if "panel_username" in fields and params.get("panel_username"):
            db.execute("UPDATE users SET username=? WHERE rowid=(SELECT rowid FROM users ORDER BY rowid LIMIT 1)", (username(params["panel_username"]),))
        if "panel_password" in fields and params.get("panel_password"):
            hashed = bcrypt.hashpw(password(params["panel_password"]).encode(), bcrypt.gensalt()).decode()
            db.execute("UPDATE users SET password=? WHERE rowid=(SELECT rowid FROM users ORDER BY rowid LIMIT 1)", (hashed,))
        for setting, value in {"webPort":str(plan["port"]),"webCertFile":cert,"webKeyFile":key}.items():
            db.execute("DELETE FROM settings WHERE key=?", (setting,)); db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (setting, value))
    after = _deployment_state("xui", plan["host"])
    require(before == after.get("inbounds", []), "目标版本改变了原节点配置，已停止并恢复原项目。")
    if not Path("/etc/systemd/system/x-ui.service").is_file():
        private_write("/etc/systemd/system/x-ui.service", "[Unit]\nDescription=x-ui\nAfter=network-online.target\n[Service]\nWorkingDirectory=/usr/local/x-ui\nExecStart=/usr/local/x-ui/x-ui\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n", 0o644)
    command(["systemctl", "daemon-reload"])
    if plan.get("reinstall"): command(["systemctl", "enable", "x-ui.service"])
    command(["systemctl", "start", "x-ui.service"])
    time.sleep(3)
    require(unit_info("x-ui.service").get("ActiveState") == "active", "管理面板新版本启动失败。")
    verify_local_https(plan["host"], plan["port"], after.get("path", "/"), params.get("tls_cert"))
    allow_port(plan["port"])
    mark_installed("xui", {"version":plan["version"],"port":plan["port"],"host":plan["host"],"path":after.get("path", "/")})


def _default_nginx_site_unchanged():
    source = Path("/etc/nginx/sites-available/default")
    if not source.exists(): return True
    metadata = command(["dpkg-query", "-W", "-f=${Conffiles}", "nginx-common"], check=False).stdout
    match = re.search(r"/etc/nginx/sites-available/default\s+([a-f0-9]{32})", metadata)
    return bool(match and hashlib.md5(source.read_bytes(), usedforsecurity=False).hexdigest() == match.group(1))


def _change_nginx(params, plan):
    renewals = certificate_renewals()
    if renewals:
        pause_certificate_renewal()
    current, _ = _nginx_package()
    if current != plan["version"]:
        if current:
            folder = TASK / "nginx-original-packages"; folder.mkdir()
            command(["apt-get", "-o", "Dir::Cache::Archives=" + str(folder), "--download-only", "--reinstall", "install", "-y", "nginx=" + current, "nginx-common=" + current], timeout=600)
            require(list(folder.glob("*.deb")), "未能备份原 Nginx 软件包，已停止版本切换。")
        absent = unit_info("nginx.service").get("LoadState") == "not-found"
        if absent: command(["systemctl", "mask", "nginx.service"])
        try:
            command(["apt-get", "install", "-y", "--allow-downgrades", "nginx=" + plan["version"], "nginx-common=" + plan["version"]], timeout=600, env={"DEBIAN_FRONTEND":"noninteractive","NEEDRESTART_MODE":"l"})
        finally:
            if absent: command(["systemctl", "unmask", "nginx.service"], check=False)
    default = Path("/etc/nginx/sites-enabled/default")
    if default.exists() or default.is_symlink():
        require(_default_nginx_site_unchanged(), "默认 Nginx 站点已经自定义，不能自动移除；已保留原配置。")
        default.unlink()
    config = Path("/etc/nginx/conf.d/linux-manager-default.conf")
    if config.is_file():
        text = config.read_text()
        text = re.sub(r"(listen\s+(?:\[::\]:)?)(\d+)(?=[\s;])", lambda match:match.group(1)+str(plan["port"]), text)
        text = re.sub(r"(server_name\s+)[^;]+;", lambda match:match.group(1)+plan["host"]+";", text)
    else:
        text = "# Managed by linux-server-manager\nserver {\n listen " + str(plan["port"]) + ";\n listen [::]:" + str(plan["port"]) + ";\n server_name " + plan["host"] + ";\n root /var/www/html;\n index index.html index.htm index.nginx-debian.html;\n location / { try_files $uri $uri/ =404; }\n}\n"
    private_write(config, text, 0o644)
    command(["nginx", "-t"]); command(["systemctl", "daemon-reload"])
    if unit_info("nginx.service").get("LoadState") == "masked" or unit_info("nginx.service").get("UnitFileState") == "masked":
        # The isolated trading installer masks the separate system service.
        # Explicit deployment of a standalone site may enable it, after its
        # original mask has already been captured by the rollback backup.
        command(["systemctl", "unmask", "nginx.service"])
        command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "nginx.service"]); command(["systemctl", "reload-or-restart", "nginx.service"])
    require(unit_info("nginx.service").get("ActiveState") == "active", "Nginx 新配置未正常启动。")
    if renewals:
        prepare_certificate_webroot(certificate_renewal_addresses())
        allow_port(80)
        migrate_certificate_renewals()
        ensure_certificate_renewal()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://127.0.0.1:" + str(plan["port"]) + "/", headers={"Host": plan["host"]})
    for attempt in range(20):
        try:
            with opener.open(request, timeout=5) as response:
                require(response.status == 200, "Nginx 网页检查未通过。")
            break
        except (OSError, urllib.error.URLError):
            if attempt == 19:
                raise OperationError("Nginx 新端口网页检查未通过。") from None
            time.sleep(0.5)
    allow_port(plan["port"])
    mark_installed("nginx", {"version":plan["version"],"port":plan["port"],"host":plan["host"],"scheme":"http","config_file":"/etc/nginx/conf.d/linux-manager-default.conf"})


def deploy(params):
    plan = deployment_preflight(params)
    if params.get("deployment_fingerprint"):
        require(plan["fingerprint"] == params["deployment_fingerprint"], "项目配置在预览后已经变化，未执行改动。请重新预览。")
    kind = plan["service"]; action = plan["action"]
    if action == "unchanged":
        return {"service":kind,"version":plan["version"],"port":plan["port"],"action":"unchanged","verified":"existing-configuration-matches","message":"部署条件相同，无需重复安装。"}
    if kind == "exchange" and plan["installed"] and action != "retry":
        require(params.get("maintenance_confirmed") is True, "请先在交易网页停止交易并确认撤单及清理完成，再调整部署条件。")
    if plan["requires_archive"]:
        archive = TASK / "release.tar.gz"
        require(archive.is_file(), "缺少已校验的目标版本安装包，未执行改动。")
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == params.get("release_sha256"), "目标版本安装包校验失败。")
    if action == "install" and kind != "nginx":
        return _initial_deploy(params)
    step("备份原配置与必要数据，只调整变化的部署条件…", 15)
    _deployment_backup(kind, action)
    if action == "retry":
        require(_bootstrap_reset_allowed(), "未完成安装已有运行数据，已停止重装。")
        certificate(params)
        for path in ["/opt/xiaojun-exchange", "/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange"]:
            if Path(path).exists(): shutil.rmtree(path)
        result = _initial_deploy(params)
    else:
        {"exchange":_change_exchange,"hysteria2":_change_hysteria,"xui":_change_xui,"nginx":_change_nginx}[kind](params, plan)
        result = {"service":kind,"version":plan["version"],"port":plan["port"],"verified":"new-configuration-and-service"}
    return result | {"action":action,"backup_id":TASK.name,"changes":plan["changes"]}
