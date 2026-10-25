# New API 配置教程

复制自己系统的一行命令，先输入 New API 的 HTTPS 地址，再输入个人 API 密钥；显示“配置完成”后退出并重新打开 Codex，新建会话。

## macOS / Linux

使用日常普通用户，在本机终端复制整行，不要 sudo：

```sh
printf 'New API HTTPS 地址： '; IFS= read -r NEWAPI_SETUP_ORIGIN; export NEWAPI_SETUP_ORIGIN; sh -c 'set -eu; origin=${NEWAPI_SETUP_ORIGIN%/}; origin=${origin%/v1}; case "$origin" in https://*) ;; *) exit 1 ;; esac; authority=${origin#https://}; case "$authority" in *'"'"'@'"'"'*|*'"'"'?'"'"'*|*'"'"'#'"'"'*|*'"'"' '"'"'*|*/*) printf '"'"'%s\n'"'"' '"'"'请使用 HTTPS 根地址，勿带账号或后台路径。'"'"' >&2; exit 1 ;; esac; export NEWAPI_SETUP_ORIGIN="$origin"; file=$(mktemp); trap '"'"'rm -f "$file"'"'"' EXIT HUP INT TERM; curl --proto '"'"'=https'"'"' --tlsv1.2 -fsS "$origin/client-setup/install.sh" -o "$file"; sh "$file" "$@" ' newapi
```

地址只输入一次，保留真实 HTTPS 端口，可填根地址或 `/v1`；不要带后台页面路径、账号密码或查询参数。macOS 使用密钥弹窗；Linux 有图形组件时弹窗，无桌面时使用终端隐藏输入。

## Windows

在普通 PowerShell / Windows Terminal 的 PowerShell 标签页复制整行，不要放到 cmd.exe 或 WSL：

```powershell
& { $env:NEWAPI_SETUP_ORIGIN=(Read-Host 'New API HTTPS 地址').TrimEnd('/') -replace '/v1$',''; try { $u=[Uri]$env:NEWAPI_SETUP_ORIGIN; if($u.Scheme -ne 'https' -or !$u.Host -or $u.UserInfo -or $u.Query -or $u.Fragment -or $u.AbsolutePath -ne '/'){throw 'invalid_address'}; & ([scriptblock]::Create((Invoke-RestMethod -MaximumRedirection 0 -Uri ($env:NEWAPI_SETUP_ORIGIN+'/client-setup/install.ps1')))); if($LASTEXITCODE -ne 0){throw 'setup_failed'} } catch { Write-Error '服务器配置命令未完成，请检查地址、网络或上方提示。' } }
```

密钥输入框隐藏内容。不需要预装 Python、Node、npm，不需要管理员窗口、关闭 UAC 或绕过执行策略。Windows 7、32 位系统和禁止用户应用的企业策略不在支持范围。

## 下载与隐私

- 安装入口、配置源码、uv 0.13.5、Python 3.13.17 和必要时的 Codex CLI 0.164.0 全部从输入的 Linux 服务器下载。客户端安装过程不访问 GitHub、PyPI 或其他运行时下载站；服务器管理员准备镜像时才需要访问官方源。
- 支持 macOS / Windows / Linux 的 x86_64 与 ARM64；Linux 同时准备 glibc 与 musl Python。官方组件保持原始文件和摘要，下载后核验 SHA-256。配置源码以摘要固定版本，缺失或校验失败即停止，不回退到 GitHub。
- 密钥在本机隐藏输入，经 HTTPS 验证；保存在本机受限配置中，macOS/Linux 权限 600，Windows 为当前用户专用 ACL。不把密钥写入命令参数、不读取钥匙串、不上传本机配置。
- 保留原登录记录、其他服务商、插件和思考强度。默认模型仍为 `gpt-6.1-sol`；已安装的桌面程序不会被覆盖或重启。
- 组件存放在当前用户 Codex 目录的 `newapi-runtime` 中；使用现有 CLI 或准备私有副本。首次需要下载，之后复用缓存。
- 新旧配置 × 无登录、ChatGPT 登录、API 登录均使用合成记录测试。写入响应丢失时先停止写入进程，再确认本次内容并撤回；撤回失败保留可恢复备份，其他程序的配置变化不被覆盖。连续备份按创建时间恢复，兼容旧备份。

证书无效、网络不通、密钥无效、模型无权限或目录不可写时会明确失败。只有这台服务器可达仍不等于上游推理永远可用；配置完成后可用一句简单问题，并在 New API 使用日志确认模型、Token 和费用。

请在使用 Codex 的同一台电脑、同一用户下配置。Windows 与 WSL、远程 SSH 与本机桌面相互独立。设置过 `CODEX_HOME` 时，终端和桌面必须使用同一目录。

## 恢复原配置

macOS / Linux：

```sh
printf 'New API HTTPS 地址： '; IFS= read -r NEWAPI_SETUP_ORIGIN; export NEWAPI_SETUP_ORIGIN; sh -c 'set -eu; origin=${NEWAPI_SETUP_ORIGIN%/}; origin=${origin%/v1}; case "$origin" in https://*) ;; *) exit 1 ;; esac; authority=${origin#https://}; case "$authority" in *'"'"'@'"'"'*|*'"'"'?'"'"'*|*'"'"'#'"'"'*|*'"'"' '"'"'*|*/*) printf '"'"'%s\n'"'"' '"'"'请使用 HTTPS 根地址，勿带账号或后台路径。'"'"' >&2; exit 1 ;; esac; export NEWAPI_SETUP_ORIGIN="$origin"; file=$(mktemp); trap '"'"'rm -f "$file"'"'"' EXIT HUP INT TERM; curl --proto '"'"'=https'"'"' --tlsv1.2 -fsS "$origin/client-setup/install.sh" -o "$file"; sh "$file" "$@" ' newapi --restore
```

Windows PowerShell：

```powershell
& { $env:NEWAPI_SETUP_ORIGIN=(Read-Host 'New API HTTPS 地址').TrimEnd('/') -replace '/v1$',''; try { $u=[Uri]$env:NEWAPI_SETUP_ORIGIN; if($u.Scheme -ne 'https' -or !$u.Host -or $u.UserInfo -or $u.Query -or $u.Fragment -or $u.AbsolutePath -ne '/'){throw 'invalid_address'}; & ([scriptblock]::Create((Invoke-RestMethod -MaximumRedirection 0 -Uri ($env:NEWAPI_SETUP_ORIGIN+'/client-setup/install.ps1')))) -Restore; if($LASTEXITCODE -ne 0){throw 'setup_failed'} } catch { Write-Error '服务器配置命令未完成，请检查地址、网络或上方提示。' } }
```

恢复只需输入服务器地址，不用再次输入密钥。后续配置被修改时会停止恢复，避免覆盖其他设置。

## 验证记录

2026-10-25 完整验收通过：[GitHub Actions 三系统记录](https://github.com/yushengsheng/linux-manager/actions/runs/40199574995)。macOS 14、Ubuntu 24.04、Windows Server 2022 均从一次性 HTTPS 镜像完成运行环境准备；客户端外部下载站被阻断，未预装 Python/Codex 时仍通过。Windows 使用禁用管理员组和权限的受限令牌运行客户端，未跳过 HTTPS 证书校验。

本地 46 项定向检查通过，1 项 Windows 专属检查跳过；服务器 Linux 的 20 项更新恢复检查、真实 systemd/Nginx 隔离成功更新和失败数据库回滚均通过。真实服务器 20 个公开组件入口、源码摘要、macOS 安装准备及 Linux 普通用户全量准备已验证；生产服务健康、更新只读检查通过。测试配置使用虚拟密钥和合成登录记录，没有改动日常 Codex 连接。

## 服务器镜像维护

源码和公开组件清单位于 `tools/new_api_setup.py` 与 `tools/new_api_mirror_assets.json`。服务器静态目录提供 `/client-setup/install.sh`、`install.ps1` 和按版本保存的组件。管理员用 `tools/build_new_api_mirror.py` 校验并准备镜像，再用 `scripts/install_new_api_client_mirror.py` 发布到现有 Nginx HTTPS 入口；无需增加对外端口。发布前复核所有摘要，Nginx 检查失败会还原原配置。组件包和真实连接资料不进入 Git 仓库。

开源依据：[uv](https://github.com/astral-sh/uv)（MIT/Apache-2.0）、[Python 构建](https://github.com/astral-sh/python-build-standalone)、[Codex CLI](https://github.com/openai/codex)（Apache-2.0）。
