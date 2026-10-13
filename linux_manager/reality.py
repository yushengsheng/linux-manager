"""Standalone Xray node, embedded in the remote agent before redeployment."""
import uuid
import zipfile

REALITY_BINARY = "/usr/local/lib/linux-manager-xray/xray"
REALITY_DIRECTORY = "/etc/linux-manager-xray"
REALITY_CONFIG = REALITY_DIRECTORY + "/config.json"
REALITY_UNIT = "linux-manager-xray.service"
REALITY_DEFAULT_TARGET = "www.microsoft.com"


def _reality_paths_check():
    for name in [str(Path(REALITY_BINARY).parent), REALITY_BINARY, REALITY_DIRECTORY, REALITY_CONFIG, "/etc/systemd/system/" + REALITY_UNIT]:
        file = Path(name)
        require(not file.is_symlink() and file.resolve() == file.absolute(), "REALITY 使用了自定义链接布局，已保留现场，不能自动覆盖。")


def _reality_server_name(value):
    value = host(value)
    require("." in value and not re.fullmatch(r"[0-9.]+", value), "REALITY 目标需为支持 TLS 1.3 和 HTTP/2 的网站域名。")
    return value


def _reality_target_check(name):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((name, 443), timeout=12) as connection:
            with context.wrap_socket(connection, server_hostname=name) as secured:
                require(secured.selected_alpn_protocol() == "h2", "REALITY 目标网站不支持 HTTP/2，请更换目标域名。")
    except (OSError, ssl.SSLError):
        raise OperationError("服务器无法验证 REALITY 目标网站的 TLS 1.3 连接，请在可选设置更换目标域名。") from None


def _reality_public_key(private):
    require(isinstance(private, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", private), "REALITY 私钥格式无法识别，已保留原配置。")
    SECRETS.add(private)
    der = bytes.fromhex("302e020100300506032b656e04220420") + base64.urlsafe_b64decode(private + "=")
    try:
        result = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise OperationError("无法生成 REALITY 连接公钥，请确认服务器已安装 openssl。") from None
    require(result.returncode == 0 and len(result.stdout) == 44 and result.stdout.startswith(bytes.fromhex("302a300506032b656e032100")), "REALITY 公钥检查失败，已保留原配置。")
    return base64.urlsafe_b64encode(result.stdout[-32:]).decode().rstrip("=")


def _reality_configuration():
    _reality_paths_check()
    config = json.loads(Path(REALITY_CONFIG).read_text())
    inbounds = config.get("inbounds")
    require(isinstance(inbounds, list) and len(inbounds) == 1, "独立 REALITY 配置包含其他节点，不能自动覆盖。")
    inbound = inbounds[0]
    stream = inbound.get("streamSettings") or {}
    settings = inbound.get("settings") or {}
    clients = settings.get("clients") or []
    require(inbound.get("tag") == "manager-reality" and inbound.get("protocol") == "vless" and settings.get("decryption") == "none" and stream.get("security") == "reality" and stream.get("network") in {"tcp", "raw"} and len(clients) == 1 and clients[0].get("flow") == "xtls-rprx-vision", "独立 REALITY 配置布局无法识别，已保留原节点。")
    uuid.UUID(clients[0]["id"])
    SECRETS.add(clients[0]["id"])
    reality = stream["realitySettings"]
    names = reality.get("serverNames") or []
    shorts = reality.get("shortIds") or []
    require(len(names) == 1 and len(shorts) == 1 and re.fullmatch(r"[a-fA-F0-9]{16}", shorts[0]), "REALITY 目标或短 ID 无法识别，已保留原配置。")
    _reality_server_name(names[0])
    require(reality.get("target", reality.get("dest")) == names[0] + ":443", "REALITY 目标配置不一致，已保留原节点。")
    port(inbound["port"])
    return config, inbound, clients[0], reality


def reality_details(data):
    if not Path(REALITY_CONFIG).is_file():return data
    _, inbound, client, reality = _reality_configuration()
    data.update(installed=True, port=inbound["port"], uuid=client["id"], public_key=_reality_public_key(reality["privateKey"]), short_id=reality["shortIds"][0], server_name=reality["serverNames"][0])
    return data


def _reality_state(data):
    _reality_paths_check()
    binary = Path(REALITY_BINARY)
    state = unit_info(REALITY_UNIT)
    present = binary.exists() or Path(REALITY_DIRECTORY).exists() or state.get("LoadState") != "not-found"
    if present:
        manifest = ROOT / "installed.json"
        record = json.loads(manifest.read_text()).get("reality", {}) if manifest.is_file() else {}
        require(record.get("installed") or record.get("uninstalled"), "检测到未知来源的独立 Xray 安装，已保留现场，不能覆盖。")
        if state.get("LoadState") == "loaded":
            unit = Path("/etc/systemd/system/" + REALITY_UNIT)
            require(unit.is_file() and state.get("FragmentPath") == str(unit) and not state.get("DropInPaths") and ("ExecStart=" + REALITY_BINARY + " run -config " + REALITY_CONFIG) in unit.read_text(), "REALITY 使用自定义服务或附加配置，不能自动调整。")
    ready = False
    if binary.is_file():
        output = command([str(binary), "version"], check=False).stdout
        match = re.search(r"Xray (\d+\.\d+\.\d+)", output)
        if match:data["version"] = "v" + match.group(1); ready = True
    data.update(_present=present, _ready=ready and bool(data.get("uuid")) and state.get("LoadState") == "loaded")
    if Path(REALITY_CONFIG).is_file():
        data["_config_sha256"] = hashlib.sha256(Path(REALITY_CONFIG).read_bytes()).hexdigest()
    return data


def _reality_install_binary():
    with zipfile.ZipFile(TASK / "release.tar.gz") as package:
        members = package.infolist()
        require(sum(item.file_size for item in members) <= 200 * 1024 * 1024, "Xray 安装包展开后过大。")
        for item in members:
            name = Path(item.filename)
            require(not name.is_absolute() and ".." not in name.parts and "\\" not in item.filename and (item.external_attr >> 16) & 0o170000 != 0o120000, "Xray 安装包包含不安全路径或链接。")
        binaries = [item for item in members if item.filename == "xray" and not item.is_dir()]
        require(len(binaries) == 1 and 0 < binaries[0].file_size <= 100 * 1024 * 1024, "Xray 安装包缺少唯一可用内核。")
        private_write(REALITY_BINARY, package.read(binaries[0]), 0o755)


def _change_reality(params, plan):
    _reality_paths_check()
    name = plan["server_name"]
    if plan["action"] in {"install", "repair"}:
        apt(["openssl", "ca-certificates"])
    if plan["action"] in {"install", "repair"} or any(item["field"] == "server_name" for item in plan["changes"]):
        step("检查 REALITY 目标网站的 TLS 1.3 和 HTTP/2…", 25)
        _reality_target_check(name)
    if plan["action"] in {"install", "update", "repair"}:_reality_install_binary()
    if Path(REALITY_CONFIG).is_file():
        config, inbound, _, reality = _reality_configuration()
    else:
        require(plan["action"] == "install", "原 REALITY 配置缺失，不能在修复时重置连接凭据；请从配置备份恢复。")
        generated = command([REALITY_BINARY, "x25519"]).stdout
        private = re.search(r"(?im)^\s*Private(?:\s*Key)?\s*:\s*([A-Za-z0-9_-]{43})\s*$", generated)
        require(private is not None, "Xray 未生成有效 REALITY 私钥。")
        SECRETS.add(private.group(1))
        identifier = str(uuid.uuid4()); SECRETS.add(identifier)
        reality = {"show":False, "target":name + ":443", "xver":0, "serverNames":[name], "privateKey":private.group(1), "shortIds":[secrets.token_hex(8)]}
        inbound = {"tag":"manager-reality", "listen":"::", "port":plan["port"], "protocol":"vless", "settings":{"clients":[{"id":identifier, "flow":"xtls-rprx-vision"}], "decryption":"none"}, "streamSettings":{"network":"raw", "security":"reality", "realitySettings":reality}}
        config = {"log":{"loglevel":"warning"}, "inbounds":[inbound], "outbounds":[{"protocol":"freedom", "tag":"direct"}]}
    inbound["port"] = plan["port"]
    reality.update(target=name + ":443", serverNames=[name]); reality.pop("dest", None)
    private_write(REALITY_CONFIG, json.dumps(config, indent=2))
    _reality_public_key(reality["privateKey"])
    command([REALITY_BINARY, "run", "-test", "-config", REALITY_CONFIG])
    output = command([REALITY_BINARY, "version"]).stdout
    require(re.search(r"Xray " + re.escape(plan["version"][1:]) + r"(?:\s|$)", output), "Xray 内核版本与已确认发行版不一致。")
    unit = "/etc/systemd/system/" + REALITY_UNIT
    if not Path(unit).is_file():
        private_write(unit, "[Unit]\nDescription=Linux manager VLESS REALITY Vision\nAfter=network-online.target\nWants=network-online.target\n[Service]\nExecStart=" + REALITY_BINARY + " run -config " + REALITY_CONFIG + "\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n", 0o644)
    command(["systemctl", "daemon-reload"])
    if plan["action"] == "install" or plan.get("reinstall"):command(["systemctl", "enable", REALITY_UNIT])
    command(["systemctl", "restart", REALITY_UNIT])
    for _ in range(10):
        if unit_info(REALITY_UNIT).get("ActiveState") == "active" and any(item["port"] == plan["port"] and item["protocol"] == "tcp" and not item["local_only"] and "xray" in item.get("processes", []) for item in listeners()):break
        time.sleep(0.5)
    else:raise OperationError("REALITY 服务或 TCP 节点端口检查未通过。")
    allow_port(plan["port"], "tcp")
    mark_installed("reality", {"version":plan["version"], "port":plan["port"], "host":plan["host"], "server_name":name})
