"""Pinned public stable releases, locally verified before SSH transfer."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.request

from .models import ManagerError
from .releases import github_cli, https_context

REPOSITORIES = {'hysteria2':'SagerNet/sing-box','reality':'XTLS/Xray-core','xui':'MHSanaei/3x-ui'}


def official_release(service, version=None):
    if service not in REPOSITORIES:
        raise ManagerError('此项目的官方来源未配置。')
    if version is not None and not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ManagerError('请填写完整稳定版本号。')
    endpoint = '/repos/' + REPOSITORIES[service] + '/releases/' + ('latest' if version is None else 'tags/'+version)
    request = urllib.request.Request('https://api.github.com'+endpoint,headers={'User-Agent':'linux-server-manager','Accept':'application/vnd.github+json'})
    result = None
    try:
        with urllib.request.urlopen(request,timeout=25,context=https_context()) as response:
            result=json.loads(response.read(4*1024*1024))
    except (urllib.error.URLError,OSError,ValueError):
        cli=github_cli()
        if cli:
            try:
                response=subprocess.run([cli,'api','--hostname','github.com',endpoint],capture_output=True,timeout=30)
                if response.returncode==0:result=json.loads(response.stdout)
            except (OSError,ValueError,subprocess.TimeoutExpired):pass
    if not isinstance(result,dict) or result.get('draft') is not False or result.get('prerelease') is not False or not re.fullmatch(r'v\d+\.\d+\.\d+',str(result.get('tag_name',''))):
        raise ManagerError('无法获取官方稳定发行版，已停止部署；请检查本机网络。')
    if version is not None and result['tag_name']!=version:
        raise ManagerError('官方返回的版本与预览不一致，已停止部署。')
    return result


def official_version(service, version=None):
    return official_release(service,version)['tag_name']


def download_project(service, version, architecture, destination):
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(architecture)
    if not arch:raise ManagerError('当前服务器架构尚未支持此项目。')
    release=official_release(service,version)
    if service == 'reality':
        name = 'Xray-linux-' + {'amd64':'64', 'arm64':'arm64-v8a'}[arch] + '.zip'
    else:
        name=f'sing-box-{version[1:]}-linux-{arch}.tar.gz' if service=='hysteria2' else f'x-ui-linux-{arch}.tar.gz'
    asset=next((item for item in release.get('assets',[]) if item.get('name')==name),None)
    if not asset:raise ManagerError('官方发行版缺少匹配服务器架构的安装包。')
    expected=str(asset.get('digest') or '').removeprefix('sha256:')
    if not re.fullmatch(r'[a-fA-F0-9]{64}',expected):raise ManagerError('官方安装包没有 SHA-256 校验信息，已停止部署。')
    url=f'https://github.com/{REPOSITORIES[service]}/releases/download/{version}/{name}'
    size=asset.get('size',0)
    if asset.get('browser_download_url')!=url or not isinstance(size,int) or not 0<size<=100*1024*1024:
        raise ManagerError('官方安装包来源或大小不正确。')
    destination=Path(destination)
    try:
        with urllib.request.urlopen(url,timeout=180,context=https_context()) as response,destination.open('wb') as output:
            destination.chmod(0o600);count=0
            while block:=response.read(1024*1024):
                count+=len(block)
                if count>size:raise ManagerError('安装包大小异常，已停止部署。')
                output.write(block)
    except (urllib.error.URLError,OSError):
        cli=github_cli()
        if not cli:raise ManagerError('官方安装包下载失败，请检查本机网络。') from None
        try:
            with destination.open('wb') as output:
                destination.chmod(0o600)
                response=subprocess.run([cli,'api','--hostname','github.com',f'/repos/{REPOSITORIES[service]}/releases/assets/{asset["id"]}','-H','Accept: application/octet-stream'],stdout=output,stderr=subprocess.PIPE,timeout=180)
            if response.returncode:raise ManagerError('官方安装包下载失败，请检查本机网络。')
        except (OSError,subprocess.TimeoutExpired):raise ManagerError('官方安装包下载失败，请检查本机网络。') from None
    with destination.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if destination.stat().st_size!=size or actual.lower()!=expected.lower():raise ManagerError('官方安装包校验失败，文件未被执行。')
    return actual
