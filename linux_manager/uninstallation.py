"""Embedded after redeployment.py. Remove only owned files; never purge data."""

UNINSTALL_LAYOUTS = {
    "exchange": {
        "programs": ["/opt/xiaojun-exchange"],
        "units": UNITS["exchange"] + ["xiaojun-exchange-maintenance.service", "xiaojun-exchange-maintenance.timer", "xiaojun-exchange-logrotate.service", "xiaojun-exchange-logrotate.timer", "xiaojun-exchange-cert-renew.service", "xiaojun-exchange-cert-renew.timer"],
        "extras": ["/etc/logrotate.d/xiaojun-exchange", "/etc/needrestart/conf.d/xiaojun-exchange.conf"],
        "retain": ["/etc/xiaojun-exchange", "/var/lib/xiaojun-exchange", "/var/lib/xiaojun-exchange-acme", "/var/log/xiaojun-exchange-nginx", "/var/log/xiaojun-exchange-acme"],
    },
    "hysteria2": {"programs": ["/usr/local/bin/sing-box"], "units": ["sing-box.service"], "extras": [], "retain": ["/etc/sing-box"]},
    "xui": {"programs": ["/usr/local/x-ui"], "units": ["x-ui.service"], "extras": [], "retain": ["/etc/x-ui"]},
    "nginx": {"programs": [], "units": [], "extras": ["/etc/nginx/conf.d/linux-manager-default.conf"], "retain": ["/var/www", "/etc/nginx"]},
}


def _uninstall_records():
    value = json.loads((ROOT / "installed.json").read_text())
    require(isinstance(value, dict), "项目安装记录无法识别，不能自动卸载。")
    return value


def _uninstall_paths(kind):
    layout = UNINSTALL_LAYOUTS[kind]
    return layout["programs"] + ["/etc/systemd/system/" + unit for unit in layout["units"]] + layout["extras"]


def _uninstall_safe_path(name):
    path = Path(name)
    require(path.resolve() == path.absolute() and not path.is_symlink(), "发现自定义链接或挂载布局，未卸载；请先核对项目文件归属。")
    return path


def _exchange_certificate_dependencies():
    values = []
    config = Path("/etc/sing-box/config.json")
    if config.is_file():
        for inbound in json.loads(config.read_text()).get("inbounds", []):
            tls = inbound.get("tls") or {}
            values.extend(tls.get(name) for name in ["certificate_path", "key_path"])
    database = Path("/etc/x-ui/x-ui.db")
    if database.is_file():
        with contextlib.closing(sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True)) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "settings" in tables:
                values.extend(row[0] for row in db.execute("SELECT value FROM settings WHERE key IN ('webCertFile','webKeyFile','subCertFile','subKeyFile')"))
            if "inbounds" in tables:
                for row in db.execute("SELECT stream_settings FROM inbounds"):
                    stream = json.loads(row[0] or "{}")
                    for settings in ["tlsSettings", "xtlsSettings"]:
                        for certificate in (stream.get(settings) or {}).get("certificates", []):
                            values.extend(certificate.get(name) for name in ["certificateFile", "keyFile"])
    base = Path("/etc/xiaojun-exchange").resolve()
    require(not any(isinstance(value, str) and value and Path(value).resolve().is_relative_to(base) for value in values), "其他代理仍使用交易系统的证书文件，请先迁移证书与续期，再卸载交易系统。")
    for file in [Path("/etc/nginx/nginx.conf"), *Path("/etc/nginx/conf.d").glob("*.conf"), *Path("/etc/nginx/sites-enabled").glob("*")]:
        if file.is_file():
            text = "\n".join(line for line in file.read_text().splitlines() if not line.lstrip().startswith("#"))
            require("/etc/xiaojun-exchange/" not in text, "其他 Nginx 网站仍引用交易配置或证书，请先分离依赖，再卸载交易系统。")


def _uninstall_references(kind):
    layout = UNINSTALL_LAYOUTS[kind]
    needles = layout["programs"] + layout["units"]
    if not needles:
        return
    for base in ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system", "/run/systemd/transient"]:
        for suffix in ["service", "timer", "socket", "path", "target"]:
            for file in Path(base).glob("*." + suffix):
                if file.name in layout["units"] or not file.is_file():
                    continue
                text = "\n".join(line for line in file.read_text().splitlines() if not line.lstrip().startswith(("#", ";")))
                require(not any(name in text for name in needles), "其他系统服务引用本项目的程序或服务，请先分离依赖；不会连带卸载。")
    if kind == "exchange":
        for file in Path("/etc/systemd/system").glob("xiaojun-exchange-*"):
            require(file.name in layout["units"], "发现未识别的交易系统服务，已保留现场，不能自动卸载。")
        renewal = unit_info("xiaojun-exchange-cert-renew.timer")
        require(renewal.get("ActiveState") != "active" and renewal.get("UnitFileState") != "enabled", "交易系统自带的证书续期仍已启用，请先迁移续期到独立工具；卸载不会破坏共用证书续期。")
        for service in ["hysteria2", "xui"]:
            lineage = proxy_certificate_lineage(service)
            require(not lineage or not lineage.startswith("/etc/xiaojun-exchange/"), "代理仍使用交易系统自带的证书，请先迁移证书和续期，再卸载交易系统。")
        _exchange_certificate_dependencies()


def uninstall_preflight(params):
    kind = params.get("service")
    require(kind in UNINSTALL_LAYOUTS, "卸载项目无效。")
    require(params.get("keep_data") is True and not params.get("purge"), "仅支持保留数据卸载，不能自动清空账号、配置或业务数据。")
    try:
        _uninstall_safe_path(ROOT / "installed.json")
        records = _uninstall_records()
        record = records.get(kind)
        require(isinstance(record, dict) and bool(record.get("installed") or record.get("uninstalled")), "没有本程序的安装记录，不能自动卸载未知来源的项目。")
        layout = UNINSTALL_LAYOUTS[kind]
        paths = _uninstall_paths(kind)
        stamps = []
        for name in paths + layout["retain"]:
            file = _uninstall_safe_path(name)
            if name not in paths or not file.exists():
                continue
            info = file.stat()
            require(info.st_dev == ROOT.stat().st_dev, "项目文件与恢复目录分属不同磁盘，暂不自动卸载；现有服务未停止。")
            stamp = {"path": name, "inode": info.st_ino, "mtime": info.st_mtime_ns, "size": info.st_size, "mode": info.st_mode}
            if file.is_file() and info.st_size <= 1024 * 1024:
                stamp["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            if file.is_dir():
                stamp["entries"] = sorted(child.name for child in file.iterdir())
            stamps.append(stamp)
        states = {}
        for unit in layout["units"]:
            state = unit_info(unit)
            require(state.get("LoadState") in {"loaded", "not-found"}, "服务状态无法确认，未卸载；请先修复或解除自定义屏蔽。")
            require(state.get("ActiveState") in {"active", "inactive", "failed"}, "服务仍在启动或停止，未卸载；请稍后重新预览。")
            if state.get("LoadState") == "loaded":
                file = Path("/etc/systemd/system/" + unit)
                require(file.is_file() and state.get("FragmentPath") == str(file) and not state.get("DropInPaths"), "项目使用自定义服务来源或附加配置，不能自动卸载。")
                text = file.read_text()
                require(not re.search(r"(?m)^\s*(?:Alias|Also|PropagatesStopTo|OnFailure|OnSuccess)\s*=[^\S\n]*\S", text), "服务关联其他启动项，不能自动卸载。")
                require(not any(Path(base + "/" + unit).exists() for base in ["/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system", "/run/systemd/transient"]), "发现同名的其他服务定义，移除后可能启用未知服务，未卸载。")
                if unit.endswith(".service"):
                    owners = layout["programs"] + layout["extras"] + (["/etc/xiaojun-exchange/nginx.conf"] if kind == "exchange" else [])
                    starts = re.findall(r"(?m)^ExecStart=(.+)$", text)
                    require(len(starts) == 1 and any(name in starts[0] for name in owners) and not re.search(r"(?m)^Exec(?:Stop|StopPost|StartPost)=", text), "服务程序布局无法识别，未卸载。")
                require(state.get("UnitFileState") in {"enabled", "disabled", "static"}, "服务启动配置无法识别，未卸载。")
            states[unit] = {key: state.get(key) for key in ["LoadState", "ActiveState", "UnitFileState"]}
        if kind == "hysteria2" and Path("/etc/sing-box/config.json").exists():
            config = json.loads(Path("/etc/sing-box/config.json").read_text())
            inbounds = config.get("inbounds")
            require(isinstance(inbounds, list) and len(inbounds) == 1 and inbounds[0].get("type") == "hysteria2", "sing-box 还包含其他节点或无法识别的配置，不能作为独立 HY2 卸载。")
        if kind == "nginx" and Path(paths[0]).exists():
            require(Path(paths[0]).read_text().startswith("# Managed by linux-server-manager\n"), "Nginx 站点归属无法确认，不能移除自定义网站。")
        _uninstall_references(kind)
        action = "unchanged" if record.get("uninstalled") and not stamps and all(state["LoadState"] == "not-found" for state in states.values()) else "uninstall"
        fingerprint = hashlib.sha256(json.dumps({"service": kind, "record": record, "files": stamps, "states": states}, sort_keys=True).encode()).hexdigest()
        return {"service": kind, "action": action, "fingerprint": fingerprint, "remove_paths": [row["path"] for row in stamps], "retained_paths": layout["retain"], "units": states,
                "message": "仅移除本程序的独立站点；保留共享 Nginx 核心和其他网站。" if kind == "nginx" else "移除项目程序及专属服务，配置与业务数据留在原位置。"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError):
        raise OperationError("卸载预检查无法完成，未改动服务。请先核对安装记录、配置数据库和文件权限。") from None


def restore_uninstall(identifier):
    folder = ROOT / "tasks" / validate_task_id(identifier) / "uninstall"
    _uninstall_safe_path(folder)
    saved = json.loads((folder / "manifest.json").read_text())
    kind = saved["service"]
    require(kind in UNINSTALL_LAYOUTS, "卸载恢复记录无效。")
    allowed = _uninstall_paths(kind)
    require(set(saved["units"]) == set(UNINSTALL_LAYOUTS[kind]["units"]), "卸载恢复服务范围无效。")
    require(len(saved["paths"]) == len(set(saved["paths"])) and all(name in allowed for name in saved["paths"]), "卸载恢复路径无效，不能覆盖其他文件。")
    records = _uninstall_records()
    current = records.get(kind, {})
    require(current == saved["record"] or current.get("uninstall_task") == identifier, "安装记录已被其他操作改变，不覆盖新项目记录。")
    for index, name in enumerate(saved["paths"]):
        source = _uninstall_safe_path(name); backup = _uninstall_safe_path(folder / "files" / str(index))
        require(source.exists() != backup.exists(), "原位置被占用或恢复备份缺失，不覆盖新安装；请检查卸载恢复记录。")
    for index, name in reversed(list(enumerate(saved["paths"]))):
        source = _uninstall_safe_path(name); backup = _uninstall_safe_path(folder / "files" / str(index))
        require(source.exists() or backup.exists(), "卸载恢复文件缺失，已保留现场。")
        if backup.exists():
            require(not source.exists(), "原程序位置已被占用，不覆盖新的安装；请检查卸载恢复记录。")
            source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.rename(backup, source)
    records[kind] = saved["record"]
    write_json(ROOT / "installed.json", records)
    if kind == "nginx":
        command(["nginx", "-t"])
        if unit_info("nginx.service").get("ActiveState") == "active":
            command(["systemctl", "reload", "nginx.service"])
    else:
        command(["systemctl", "daemon-reload"])
        for unit, state in saved["units"].items():
            if state["LoadState"] == "loaded":
                if state["UnitFileState"] in {"enabled", "disabled"}:
                    command(["systemctl", "enable" if state["UnitFileState"] == "enabled" else "disable", unit])
                command(["systemctl", "start" if state["ActiveState"] == "active" else "stop", unit], timeout=360)
                restored = unit_info(unit)
                require(restored.get("ActiveState") == "active" if state["ActiveState"] == "active" else restored.get("ActiveState") in {"inactive", "failed"}, "卸载恢复后的服务状态验证未通过。")
                if state["UnitFileState"] in {"enabled", "disabled"}:
                    require(restored.get("UnitFileState") == state["UnitFileState"], "卸载恢复后的开机启动验证未通过。")
    cert_hook()


def uninstall_project(params):
    plan = uninstall_preflight(params)
    require(isinstance(params.get("uninstall_fingerprint"), str) and params["uninstall_fingerprint"] == plan["fingerprint"], "卸载范围在预览后变化，未执行改动。请重新预览。")
    kind = plan["service"]
    if plan["action"] == "unchanged":
        return {"service": kind, "action": "unchanged", "data_retained": True, "message": "项目已卸载，未进行额外改动。"}
    if kind == "exchange":
        require(params.get("maintenance_confirmed") is True, "请先在交易网页停止交易并完成撤单、清理，才能卸载交易系统。")
    folder = TASK / "uninstall"
    _uninstall_safe_path(folder)
    folder.mkdir(mode=0o700)
    (folder / "files").mkdir(mode=0o700)
    records = _uninstall_records()
    # Journal the entire fixed scope before stopping or moving anything. Atomic
    # renames preserve ownership and nested links without following their targets.
    write_json(folder / "manifest.json", {"service": kind, "paths": plan["remove_paths"], "units": plan["units"], "record": records[kind]})
    step("停止目标项目并保存移除文件；配置、账号和业务数据保持原位…", 20)
    loaded = [unit for unit, state in plan["units"].items() if state["LoadState"] == "loaded"]
    if loaded:
        command(["systemctl", "stop", *loaded], timeout=360)
        require(all(unit_info(unit).get("ActiveState") in {"inactive", "failed"} for unit in loaded), "目标服务未完全停止，不能移除程序。")
        enabled = [unit for unit in loaded if plan["units"][unit]["UnitFileState"] == "enabled"]
        if enabled:
            command(["systemctl", "disable", *enabled])
    for index, name in enumerate(plan["remove_paths"]):
        source = _uninstall_safe_path(name)
        os.rename(source, folder / "files" / str(index))
    step("验证项目服务已移除，保留共享系统依赖与防火墙规则…", 75)
    if kind == "nginx":
        command(["nginx", "-t"])
        if unit_info("nginx.service").get("ActiveState") == "active":
            command(["systemctl", "reload", "nginx.service"])
    else:
        command(["systemctl", "daemon-reload"])
        require(all(unit_info(unit).get("LoadState") == "not-found" and unit_info(unit).get("ActiveState") != "active" for unit in plan["units"]), "项目服务移除验证未通过。")
    records = _uninstall_records()
    records[kind] = records[kind] | {"installed": False, "uninstalled": now(), "uninstall_task": TASK.name}
    write_json(ROOT / "installed.json", records)
    cert_hook()
    return {"service": kind, "action": "uninstall", "data_retained": True, "uninstall_backup_id": TASK.name, "retained_paths": plan["retained_paths"], "verified": "owned-files-and-units-removed"}


_installed_connection_details = connection_details


def connection_details(params):
    data = _installed_connection_details(params)
    if data.get("uninstalled"):
        present = Path("/etc/nginx/conf.d/linux-manager-default.conf").is_file() if params.get("service") == "nginx" else any(unit.get("LoadState") == "loaded" for unit in data.get("units", []))
        if present:
            data.pop("uninstalled")
            data["installed"] = True
        else:
            data.update(installed=False, data_retained=True)
    return data
