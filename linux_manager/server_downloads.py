"""Public GitHub downloads for the Linux worker; no local files or login."""
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORIES = {"exchange": "yushengsheng/xiaojun-bn", "hysteria2": "SagerNet/sing-box",
                "reality": "XTLS/Xray-core", "xui": "MHSanaei/3x-ui",
                "cliproxyapi": "router-for-me/CLIProxyAPI",
                "cliproxyapi-panel": "router-for-me/Cli-Proxy-API-Management-Center"}
MAX_SIZE = 100 * 1024 * 1024


class DownloadError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DownloadError(message)


class ReleasePage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.fragments = set()
        self.digests = {}
        self.unstable = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.add(urllib.parse.urljoin("https://github.com", attrs["href"]))
        if tag == "include-fragment" and attrs.get("src"):
            self.fragments.add(urllib.parse.urljoin("https://github.com", attrs["src"]))
        if tag == "clipboard-copy":
            label = attrs.get("aria-label", "")
            value = attrs.get("value", "")
            if label.startswith("Copy to clipboard digest for ") and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", value):
                name = label.removeprefix("Copy to clipboard digest for ")
                require(name not in self.digests, "官方发行页面的校验信息重复，已停止安装。")
                self.digests[name] = value

    def handle_data(self, data):
        if data.strip() in {"Pre-release", "Draft"}:
            self.unstable = True


def read_page(url):
    request = urllib.request.Request(url, headers={"User-Agent": "linux-server-manager", "Accept": "text/html", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=20) as response:
        content = response.read(4 * 1024 * 1024 + 1)
        require(len(content) <= 4 * 1024 * 1024, "官方发行页面超过允许大小。")
        page = ReleasePage()
        page.feed(content.decode("utf-8"))
        return response.geturl(), page


def release_info(service, version=None):
    require(service in REPOSITORIES, "安装来源不在允许列表中。")
    require(version is None or isinstance(version, str) and re.fullmatch(r"v\d+\.\d+\.\d+", version), "请确认完整稳定版本号。")
    repository = REPOSITORIES[service]
    endpoint = "latest" if version is None else "tags/" + version
    request = urllib.request.Request(f"https://api.github.com/repos/{repository}/releases/{endpoint}", headers={"User-Agent": "linux-server-manager", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            content = response.read(4 * 1024 * 1024 + 1)
            require(len(content) <= 4 * 1024 * 1024, "官方发行信息超过允许大小。")
            release = json.loads(content)
    except (OSError, ValueError, http.client.HTTPException):
        # Public pages are independent of the REST API's anonymous rate limit.
        base = f"https://github.com/{repository}/releases/"
        try:
            final, page = read_page(base + ("latest" if version is None else "tag/" + version))
            match = re.fullmatch(re.escape(base) + r"tag/(v\d+\.\d+\.\d+)", final)
            require(match is not None and not page.unstable, "官方公开发行信息无效或属于测试版。")
            selected = match.group(1)
            require(version is None or selected == version, "官方返回的版本与已确认版本不一致。")
            url = base + "expanded_assets/" + selected
            require(url in page.fragments, "官方发行页面缺少可验证的文件列表。")
            final, files = read_page(url)
            require(final == url and not files.unstable, "官方发行文件列表来源不一致。")
            prefix = base + "download/" + selected + "/"
            assets = [{"name": link.removeprefix(prefix), "browser_download_url": link,
                       "size": None, "digest": files.digests.get(link.removeprefix(prefix)), "_public": True}
                      for link in files.links if link.startswith(prefix) and "/" not in link.removeprefix(prefix)]
            release = {"tag_name": selected, "draft": False, "prerelease": False, "assets": assets}
        except (OSError, ValueError, http.client.HTTPException):
            raise DownloadError("Linux 无法读取 GitHub 官方发行信息，请检查服务器网络或版本号；未修改项目。") from None
    require(isinstance(release, dict) and release.get("draft") is False and release.get("prerelease") is False and re.fullmatch(r"v\d+\.\d+\.\d+", str(release.get("tag_name", ""))), "官方发行信息无效或属于测试版。")
    require(version is None or release["tag_name"] == version, "官方返回的版本与已确认版本不一致。")
    require(isinstance(release.get("assets"), list) and all(isinstance(a, dict) for a in release["assets"]), "官方发行文件列表无效。")
    return release


def download_asset(repository, version, asset, destination, progress, maximum=MAX_SIZE):
    name = asset.get("name", "")
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", name), "发行文件名称无效。")
    url = f"https://github.com/{repository}/releases/download/{version}/{name}"
    size = asset.get("size")
    public = asset.get("_public") is True and size is None
    require(asset.get("browser_download_url") == url and (public or type(size) is int and 0 < size <= maximum), "发行文件来源或大小无效。")
    destination = Path(destination)
    partial = destination.with_name(destination.name + ".part")
    deadline = time.monotonic() + 300
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "linux-server-manager"}), timeout=20) as response, partial.open("wb") as output:
            partial.chmod(0o600)
            origin = urllib.parse.urlsplit(response.geturl())
            require(origin.scheme == "https" and origin.hostname in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} and origin.username is None and origin.port in {None, 443}, "发行文件下载地址偏离官方 HTTPS 来源。")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(re.fullmatch(r"[0-9]+", length) and 0 < int(length) <= maximum and (public or int(length) == size), "发行文件大小与官方记录不一致。")
                size = int(length)
            digest = hashlib.sha256()
            count = 0
            reported = 0
            read = getattr(response, "read1", response.read)
            while block := read(256 * 1024):
                require(time.monotonic() <= deadline, "Linux 下载超过 5 分钟，已停止本次安装；未修改项目。")
                count += len(block)
                require(count <= (size if size is not None else maximum), "发行文件超过允许大小。")
                output.write(block)
                digest.update(block)
                if time.monotonic() - reported >= 1:
                    progress(count, size)
                    reported = time.monotonic()
            require(count > 0 and (size is None or count == size), "发行文件下载不完整，未执行安装。")
        partial.replace(destination)
        return digest.hexdigest()
    except (OSError, ValueError, http.client.HTTPException):
        raise DownloadError("Linux 下载官方发行文件失败或超时，请检查服务器访问 GitHub 的网络；未修改项目。") from None
    finally:
        partial.unlink(missing_ok=True)


def download_release(service, version, architecture, destination, progress=lambda count, size: None):
    require(architecture in {"x86_64", "aarch64"} and (service != "exchange" or architecture == "x86_64"), "当前服务器架构不支持此项目。")
    release = release_info(service, version)
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[architecture]
    name = {"exchange": f"xiaojun-bn-{version}-linux-amd64.tar.gz", "hysteria2": f"sing-box-{version[1:]}-linux-{arch}.tar.gz",
            "reality": "Xray-linux-" + {"amd64": "64", "arm64": "arm64-v8a"}[arch] + ".zip", "xui": f"x-ui-linux-{arch}.tar.gz",
            "cliproxyapi": f"CLIProxyAPI_{version[1:]}_linux_{'aarch64' if architecture == 'aarch64' else 'amd64'}.tar.gz"}[service]
    assets = [a for a in release["assets"] if a.get("name") == name]
    require(len(assets) == 1, "官方发行版缺少唯一的当前架构安装包。")
    repository = REPOSITORIES[service]
    if service == "exchange":
        require(any(a.get("name") == "install-linux.sh" and a.get("browser_download_url") == f"https://github.com/{repository}/releases/download/{version}/install-linux.sh" for a in release["assets"]), "官方发行版缺少 Linux 安装器。")
    expected = str(assets[0].get("digest") or "").removeprefix("sha256:")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        checksum_names = {"SHA256SUMS", f"sing-box-{version[1:]}-checksums.txt", "checksums.txt"}
        checksums = [a for a in release["assets"] if a.get("name") in checksum_names]
        require(len(checksums) == 1, "官方发行包缺少可验证的 SHA-256 校验信息。")
        checksum_file = Path(destination).with_suffix(".sha256")
        try:
            download_asset(repository, version, checksums[0], checksum_file, lambda *args: None, maximum=1024 * 1024)
            matches = [row[0] for line in checksum_file.read_text().splitlines() if len(row := line.split()) == 2 and row[1].lstrip("*") == name and re.fullmatch(r"[a-fA-F0-9]{64}", row[0])]
            require(len(matches) == 1, "官方校验清单无效或含有重复条目。")
            expected = matches[0]
        finally:
            checksum_file.unlink(missing_ok=True)
    try:
        actual = download_asset(repository, version, assets[0], destination, progress)
        require(actual == expected.lower(), "官方发行包 SHA-256 校验失败，文件未被执行。")
        return actual
    except Exception:
        Path(destination).unlink(missing_ok=True)
        raise


def download_panel(version, destination):
    release = release_info("cliproxyapi-panel", version)
    assets = [a for a in release["assets"] if a.get("name") == "management.html"]
    require(len(assets) == 1, "官方管理页面发行文件不唯一。")
    expected = str(assets[0].get("digest") or "").removeprefix("sha256:")
    require(re.fullmatch(r"[a-fA-F0-9]{64}", expected), "官方管理页面缺少 SHA-256，未替换。")
    try:
        actual = download_asset(REPOSITORIES["cliproxyapi-panel"], version, assets[0], destination, lambda *args: None, maximum=20 * 1024 * 1024)
        require(actual == expected.lower(), "管理页面 SHA-256 校验失败。")
        return actual
    except Exception:
        Path(destination).unlink(missing_ok=True)
        raise
