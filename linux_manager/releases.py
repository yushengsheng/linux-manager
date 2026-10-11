"""Public release discovery; no connection profile or credentials are sent."""
from __future__ import annotations

import json
import hashlib
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .models import ManagerError

EXCHANGE_REPOSITORY = "yushengsheng/xiaojun-bn"
LATEST_STABLE = "最新稳定版"
SPECIFIC_VERSION = "指定版本"
KEEP_CURRENT = "保持当前版本"
MAX_ASSET_SIZE = 100 * 1024 * 1024


class _ReleasePage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.fragments = set()
        self.unstable = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self.links.add(urllib.parse.urljoin("https://github.com", attributes["href"]))
        if tag == "include-fragment" and attributes.get("src"):
            self.fragments.add(urllib.parse.urljoin("https://github.com", attributes["src"]))

    def handle_data(self, data):
        if data.strip() in {"Pre-release", "Draft"}:
            self.unstable = True


def _public_page(url):
    request = urllib.request.Request(url, headers={"User-Agent": "linux-server-manager", "Accept": "text/html", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=25, context=https_context()) as response:
        content = response.read(4 * 1024 * 1024 + 1)
        if len(content) > 4 * 1024 * 1024:
            raise ManagerError("官方发行页面超过允许大小，已停止部署。")
        page = _ReleasePage()
        page.feed(content.decode("utf-8"))
        return response.geturl(), page


def _public_release(version):
    # Public release pages/assets do not share the REST API's anonymous quota.
    base = f"https://github.com/{EXCHANGE_REPOSITORY}/releases/"
    final_url, page = _public_page(base + ("latest" if version is None else "tag/" + version))
    match = re.fullmatch(re.escape(base) + r"tag/(v\d+\.\d+\.\d+)", final_url)
    if match is None or page.unstable:
        raise ManagerError("官方公开发行信息无效或属于测试版，已停止部署。")
    selected = match.group(1)
    if version is not None and selected != version:
        raise ManagerError("官方返回的版本与指定版本不一致，已停止部署。")
    assets_url = base + "expanded_assets/" + selected
    if assets_url not in page.fragments:
        raise ManagerError("官方发行页面缺少可验证的文件列表，已停止部署。")
    final_url, files = _public_page(assets_url)
    if final_url != assets_url:
        raise ManagerError("官方发行文件列表来源不一致，已停止部署。")
    assets = []
    for name in ["install-linux.sh", "SHA256SUMS", f"xiaojun-bn-{selected}-linux-amd64.tar.gz"]:
        url = base + f"download/{selected}/{name}"
        if url not in files.links:
            raise ManagerError("该官方发行版缺少 Linux 安装器、安装包或 SHA-256 校验清单，已停止部署。")
        assets.append({"name": name, "browser_download_url": url, "size": None, "_public_release": True})
    return {"tag_name": selected, "draft": False, "prerelease": False, "assets": assets}


def github_cli():
    executable = shutil.which("gh")
    if executable:
        return executable
    # Finder launches macOS apps with a smaller PATH than the terminal.
    for candidate in [Path("/opt/homebrew/bin/gh"), Path("/usr/local/bin/gh")]:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def https_context():
    try:
        import truststore
    except ImportError:
        return ssl.create_default_context()
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def release_info(version: str | None = None) -> dict:
    if version is not None and (not isinstance(version, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", version)):
        raise ManagerError("请输入完整发行版本号，例如 v1.1.84。")
    endpoint = "latest" if version is None else "tags/" + version
    url = f"https://api.github.com/repos/{EXCHANGE_REPOSITORY}/releases/{endpoint}"
    request = urllib.request.Request(url, headers={"User-Agent": "linux-server-manager", "Accept": "application/vnd.github+json"})
    release = None
    try:
        with urllib.request.urlopen(request, timeout=25, context=https_context()) as response:
            release = json.loads(response.read(4 * 1024 * 1024))
    except (urllib.error.URLError, OSError, ValueError) as error:
        limited = isinstance(error, urllib.error.HTTPError) and error.code in {403, 429} and (error.code == 429 or (error.headers or {}).get("X-RateLimit-Remaining") == "0")
        reason = "GitHub API 已限流。" if limited else "GitHub API 发行版查询失败。"
        # gh owns its authentication. Tokens never enter our request, logs,
        # connection profiles, or the remote server.
        cli = github_cli()
        if cli:
            try:
                result = subprocess.run([cli, "api", "--hostname", "github.com", f"/repos/{EXCHANGE_REPOSITORY}/releases/{endpoint}"], capture_output=True, timeout=30)
                if not result.returncode:
                    release = json.loads(result.stdout)
                else:
                    reason += "本机 GitHub 登录未取得发行信息。"
            except (OSError, subprocess.TimeoutExpired, ValueError):
                reason += "本机 GitHub 登录未取得有效发行信息。"
        if release is None:
            try:
                release = _public_release(version)
            except (urllib.error.URLError, OSError, ValueError):
                raise ManagerError(reason + "公开发行页面也无法读取，请检查网络、版本号或稍后重试。本次不会提交部署任务。") from None
    if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
        raise ManagerError("官方发行信息无效或属于测试版，已停止部署。")
    selected = release.get("tag_name", "")
    if not isinstance(selected, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", selected):
        raise ManagerError("官方发行版本号格式不受支持，已停止部署。")
    if version is not None and selected != version:
        raise ManagerError("官方返回的版本与指定版本不一致，已停止部署。")
    assets = release.get("assets", [])
    if not isinstance(assets, list) or not any(isinstance(asset, dict) and asset.get("name") == "install-linux.sh" and asset.get("browser_download_url") == f"https://github.com/{EXCHANGE_REPOSITORY}/releases/download/{selected}/install-linux.sh" for asset in assets):
        raise ManagerError("该官方发行版缺少 Linux 安装器，已停止部署。")
    return release


def exchange_version(version: str | None = None) -> str:
    return release_info(version)["tag_name"]


def download_asset(asset: dict, version: str, destination: Path) -> None:
    name = asset.get("name", "")
    expected_url = f"https://github.com/{EXCHANGE_REPOSITORY}/releases/download/{version}/{name}"
    size = asset.get("size", 0)
    public = asset.get("_public_release") is True and size is None and name in {"install-linux.sh", "SHA256SUMS", f"xiaojun-bn-{version}-linux-amd64.tar.gz"}
    if (not public and (type(size) is not int or not 0 < size <= MAX_ASSET_SIZE)) or asset.get("browser_download_url") != expected_url:
        raise ManagerError("发行文件来源或大小无效，已停止安装。")
    # Download private assets through the already-authorized local GitHub CLI.
    identifier = asset.get("id")
    cli = github_cli()
    if cli and isinstance(identifier, int) and identifier > 0:
        try:
            with destination.open("wb") as output:
                destination.chmod(0o600)
                result = subprocess.run([cli, "api", "--hostname", "github.com", f"/repos/{EXCHANGE_REPOSITORY}/releases/assets/{identifier}", "-H", "Accept: application/octet-stream"], stdout=output, stderr=subprocess.PIPE, timeout=180)
            if not result.returncode and destination.stat().st_size == size:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        with urllib.request.urlopen(expected_url, timeout=120, context=https_context()) as response, destination.open("wb") as output:
            destination.chmod(0o600)
            origin = urllib.parse.urlsplit(response.geturl())
            if origin.scheme != "https" or origin.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} or origin.username is not None or origin.port not in {None, 443}:
                raise ManagerError("发行文件下载地址偏离官方 HTTPS 来源，已停止安装。")
            length = response.headers.get("Content-Length")
            if length is not None:
                if not re.fullmatch(r"[0-9]+", length) or not 0 < int(length) <= MAX_ASSET_SIZE or (not public and int(length) != size):
                    raise ManagerError("发行文件大小无效或与官方记录不一致，已停止安装。")
                if public:
                    size = int(length)
            count = 0
            while block := response.read(1024 * 1024):
                count += len(block)
                if count > (MAX_ASSET_SIZE if size is None else size):
                    raise ManagerError("发行文件大小不一致或超过允许大小，已停止安装。")
                output.write(block)
        if not count or (size is not None and count != size):
            raise ManagerError("发行文件下载不完整，已停止安装。")
    except (urllib.error.URLError, OSError, ValueError):
        raise ManagerError("官方发行包下载失败，请检查本机网络；公开发行文件无需 GitHub 登录。") from None


def download_exchange(version: str, destination: Path) -> str:
    release = release_info(version)
    filename = f"xiaojun-bn-{version}-linux-amd64.tar.gz"
    asset = next((a for a in release["assets"] if a.get("name") == filename), None)
    if asset is None:
        raise ManagerError("官方发行版缺少 Linux 安装包，已停止安装。")
    expected = str(asset.get("digest") or "").removeprefix("sha256:")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        checksums = next((a for a in release["assets"] if a.get("name") == "SHA256SUMS"), None)
        if checksums is None:
            raise ManagerError("官方发行包缺少 SHA-256 校验信息，已停止安装。")
        checksum_file = destination.with_suffix(".sha256")
        download_asset(checksums, version, checksum_file)
        try:
            lines = checksum_file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            raise ManagerError("官方发行包校验清单无法读取，已停止安装。") from None
        matches = [row[0] for line in lines if len(row := line.split()) == 2 and row[1].lstrip("*") == filename and re.fullmatch(r"[a-fA-F0-9]{64}", row[0])]
        if len(matches) != 1:
            raise ManagerError("官方发行包校验清单无效，已停止安装。")
        expected = matches[0]
    download_asset(asset, version, destination)
    with destination.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected.lower():
        raise ManagerError("官方发行包 SHA-256 校验失败，文件未被执行。")
    return actual
