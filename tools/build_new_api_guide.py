"""Render self-contained one-line commands from the exact tested setup source."""
import base64
import hashlib
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).parents[1]
SHORT_REF = "06c5bb493606a70bfe5b9baca8c693d910319a03"


def commands(check_only=False):
    source = (ROOT / "tools/new_api_setup.py").read_text(encoding="utf-8").encode("utf-8")
    payload = base64.b64encode(zlib.compress(source, 9)).decode("ascii")
    body = "zlib.decompress(base64.b64decode('" + payload + "'))"
    action = "print(__import__('hashlib').sha256(" + body + ").hexdigest())" if check_only else "exec(compile(" + body + ",'<newapi-setup>','exec'))"
    loader = "import sys,base64,zlib;assert sys.version_info>=(3,11),'Python 3.11+ required';" + action
    unix = "python3 -c " + "'" + loader.replace("'", '"') + "'"
    windows = '& { $c="' + loader + '"; $p=Get-Command py.exe -ErrorAction SilentlyContinue; if($p){ & $p.Source -3 -c $c }else{ $p=Get-Command python.exe -ErrorAction SilentlyContinue; if(!$p -or $p.Source -like "*WindowsApps*"){throw "Please install Python 3.11+ from python.org with the Python launcher, then retry."}; & $p.Source -c $c } }'
    assert all("\n" not in command for command in [unix, windows])
    return source, {"macOS": unix, "Linux": unix, "Windows": windows}


def build(report=None):
    source, entries = commands()
    checksum = hashlib.sha256(source).hexdigest()
    text = '''# new api 配置教程

本教程将当前用户的本地 Codex 改为通过 New API 调用，默认模型为 `gpt-6.1-sol`，接口协议为 Responses。每个人只需复制自己系统的一行命令，再输入自己的 New API 地址和个人 API 密钥。无需手工下载或保存配置脚本，不读取系统钥匙串，也不把密钥写入终端命令历史。

## 先看权限与适用条件

- 用平时打开 Codex 的同一个普通用户运行。macOS/Linux **不要加 sudo、不要用 root**；Windows **不要预先“以管理员身份运行”**。否则容易写到另一个账号的配置目录。
- 需要 Python 3.11+，以及可用的 Codex CLI 0.164.0 或以上。已有桌面版会优先尝试使用 PATH 中的 CLI，并查找已知的桌面安装位置；不是所有旧版、商店版或非官方安装布局都带可直接调用的 CLI。
- 安装/更新 Python、Codex 属于运行环境准备，与本配置命令不同。单位管理的电脑可能需要管理员安装；**配置步骤本身不要求先提权**，不会自动升级软件、关闭 UAC 或绕过 PowerShell 执行策略。
- New API 必须可通过有效 HTTPS 证书访问，渠道已启用、`gpt-6.1-sol` 已配置价格且对该密钥开放。自定义端口（例如 2026）会原样保留。
- 必须在运行桌面 Codex 的那台电脑上配置。不要把本机配置命令运行在已 SSH 登录的 Linux 服务器里，再以为修改了本机桌面版。
- 原生 Windows 与 WSL 是两个环境。Windows 桌面版请用原生 PowerShell 命令；在 WSL 使用 Linux 命令只会配置 WSL 内的 Codex。
- 如果设置了 `CODEX_HOME`，本命令使用该目录。桌面版进程与终端必须使用同一个配置目录；终端临时设置的变量不会自动传给已运行的桌面程序。

## 使用前检查

macOS/Linux 在终端执行：

```sh
python3 --version
codex --version
```

Windows 打开普通 PowerShell 执行：

```powershell
py -3 --version
codex --version
```

如果 `codex` 命令不存在，但已安装桌面版，先直接尝试下文的一行配置命令：它也会查找已知的桌面内置 CLI。仍提示找不到 CLI 时，使用官方用户安装方式：

```sh
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Windows 官方安装方式：

```powershell
irm https://chatgpt.com/codex/install.ps1 | iex
```

安装完成后重新打开终端再配置。Python 缺失时从 [python.org](https://www.python.org/downloads/) 安装；Windows 建议保留 Python Launcher。以上是必要依赖准备，不是要求下载本教程的配置脚本。

## 地址和密钥怎么填

1. 地址填 New API 的 **HTTPS 根地址**或以 `/v1` 结尾的 API 地址；端口保留 2026 等实际端口。不要带 `/keys`、`/usage-logs/common`、查询参数或管理员用户名密码。
2. 密钥填个人后台“API 密钥”页面创建的那把 API Key，不是管理员登录密码或 CLIProxyAPI 管理密钥。
3. 密钥输入框不回显。配置先校验 `/v1/models`，没有权限、证书不可信或模型不可用时不切换服务商。
4. 配置成功后**完全退出并重新打开桌面 Codex，再新建会话**。终端版重新启动 `codex`。旧线程、远程任务或已运行进程可能继续保留原连接。

## macOS：复制一整行

在已登录桌面的终端使用。依次弹出地址和密钥输入框；SSH/没有 GUI 的会话可在命令末尾追加 ` --terminal`，改为终端输入。

```sh
MAC_COMMAND
```

## Linux：复制一整行

桌面环境且 Python Tk 可用时弹出输入窗口；没有桌面或 Tk 时自动回退到终端输入，密钥不回显。这是可运行的无头模式，不承诺无桌面的服务器能弹出图形窗口。无需为配置过程专门 sudo 安装 GUI。

```sh
LINUX_COMMAND
```

## Windows：复制一整行

使用原生 Windows PowerShell/Windows Terminal 的 PowerShell 标签页，**不要放到 cmd.exe 或 WSL**。命令支持 Python Launcher，也支持非商店占位符的 `python.exe`；会弹出同时填写地址和密钥的窗口。不使用 `ExecutionPolicy Bypass`、管理员窗口或保存 `.ps1` 文件。

```powershell
WINDOWS_COMMAND
```

如果 Windows 没有交互式桌面，或企业策略阻止 WinForms，请在 Python 调用中追加 `--terminal` 使用终端模式；不应通过关闭安全策略强行弹窗。

## 会改什么、会保留什么

- 在当前用户的 Codex 配置中增加/更新 `newapi_gateway` 服务商，将默认模型切为 `gpt-6.1-sol`，配置 HTTPS Responses 与 HTTP 流式传输。
- 保留已有其他服务商、插件、思考强度等设置；不执行 `codex login/logout`，不修改 `auth.json`，不删除原来的 GPT 账号登录信息。
- 原配置先保存在本机私有备份目录。密钥按用户要求保存在本机 Codex 配置中；POSIX 权限为 600，Windows 设置为当前用户专用 ACL，不依赖临时终端环境变量或系统钥匙串。
- 密钥只发往所填写的 HTTPS 接口，拒绝携带密钥跟随 HTTP 重定向；不把完整地址、密钥和配置内容输出到日志。
- 压缩编码只用于把完整源码放在同一行中，不是远程下载器；执行的是本教程附带的固定代码。配置过程中会使用 Codex 自带的原子配置接口，不拼接/覆盖整份 TOML。

## 怎么确认确实生效

1. 看命令是否明确显示“配置完成”；错误或取消不等于成功。
2. 重开 Codex 并新建会话，选择 `gpt-6.1-sol`，发送一句简短问题。
3. 打开自己的 New API 后台“使用日志”，确认出现该模型的请求、Token 和费用。仅看到本地配置成功不能证明上游模型永远正常。
4. 原有 ChatGPT 登录信息可能仍显示在账号界面，这是保留登录状态的结果；是否走 New API 以当前服务商及 New API 使用日志为准。

## 恢复原配置

使用对应系统同一条配置命令，给 Python 调用追加 `--restore`。macOS/Linux 可直接在整行末尾加 ` --restore`；Windows 将两处 `-c $c` 改为 `-c $c --restore` 后执行。恢复不要求再输入地址和密钥。

恢复后同样重启 Codex并新建会话。如果配置后来又被其他程序或用户修改，自动恢复会停止，避免覆盖新设置；原备份仍保留。不要把含旧密钥的备份上传或发到聊天中。

## 权限与失败处理

| 提示/现象 | 原因和处理 |
|---|---|
| 不能修改配置/Permission denied/Access denied | 常见于此前用 root/管理员账号创建了文件，或目录被锁定。请管理员只修复当前用户 Codex 目录的所有权/ACL；不要用 sudo 重跑，也不要 chmod 777。 |
| Python 或 CLI 不存在/版本过旧 | 先按官方方式安装/更新运行环境，重新打开终端，再重试。命令不会自动改动系统软件。 |
| 密钥被拒绝 | 检查是否填了个人 API Key、是否已启用/过期及额度是否足够。 |
| 没有 gpt-6.1-sol | 检查渠道、定价、分组、密钥模型白名单；此命令不会自动启用服务端渠道或改价。 |
| HTTPS/证书错误 | 检查证书有效期、主机名、系统时间、代理和证书链。不能用“不验证证书”解决。企业私有 CA 由管理员按官方文档安装/设置。 |
| 企业策略覆盖配置 | MDM、requirements 或组织允许的服务商列表优先级更高；需要管理员批准，不是给命令提权就能解决。 |
| 配完仍走旧接口 | 完全退出全部 Codex 进程后重开，确认新建的是本机新会话，且桌面与终端使用同一 CODEX_HOME；不要结束仍在工作的任务来强行刷新。 |
| Windows PowerShell 被约束/禁止 .NET/应用控制拦截 | 联系设备管理员；不提供绕过执行策略、AppLocker 或企业安全限制的方法。 |
| Windows 沙箱首次初始化要求额外权限 | 这是 Codex 执行工具的系统要求，与写入 New API 连接配置不同；按官方沙箱说明处理，不为配置接口关闭沙箱。 |

## 测试结果与适用边界

TEST_REPORT

测试只使用临时配置目录、一次性 HTTPS 测试 CA/服务器、虚拟 API Key 和合成 ChatGPT/API 登录记录；不会把真人账号、服务器连接资料或生产密钥上传 GitHub。真实 CLI 发送 Responses 请求并验证使用了新网关密钥，而不是旧账号凭据。

“合成登录状态验证”不等于真正登录了某个人的 GPT 账号；“桌面安装目录布局模拟”不等于完整安装并操作了所有桌面版本的首次登录界面。企业设备、旧版客户端、非标准打包、WSL/远程任务和故障网络不可能无条件保证成功。只有表中实际执行且通过的项目才算已验证，不能声称任何环境都“完美运行”。

本次源代码 SHA-256：`SOURCE_SHA`。可审阅源码：`tools/new_api_setup.py`；教程由 `tools/build_new_api_guide.py` 生成，保证三系统命令内置同一份已测试代码。

## 官方依据

- [Codex 网关接入与自定义服务商](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)
- [Codex 原子配置接口](https://learn.chatgpt.com/docs/app-server)
- [环境变量及原生 Windows/WSL 配置目录](https://learn.chatgpt.com/docs/config-file/environment-variables)
- [认证、登录缓存与自定义 CA](https://learn.chatgpt.com/docs/auth)
- [Windows 部署与沙箱要求](https://learn.chatgpt.com/docs/enterprise/windows-deployment)
'''
    report_text = "GitHub 三系统测试正在准备，尚不标记为通过。"
    if report:
        report_text = report
    text = text.replace("MAC_COMMAND", entries["macOS"]).replace("LINUX_COMMAND", entries["Linux"]).replace("WINDOWS_COMMAND", entries["Windows"]).replace("SOURCE_SHA", checksum).replace("TEST_REPORT", report_text)
    (ROOT / "new api 配置教程.md").write_text(text)
    return len(source), {k: len(v) for k, v in entries.items()}


def server_commands(restore=False):
    import shlex
    loader = """set -eu; origin=${NEWAPI_SETUP_ORIGIN%/}; origin=${origin%/v1}; case "$origin" in https://*) ;; *) exit 1 ;; esac; authority=${origin#https://}; case "$authority" in *'@'*|*'?'*|*'#'*|*' '*|*/*) printf '%s\\n' '请使用 HTTPS 根地址，勿带账号或后台路径。' >&2; exit 1 ;; esac; export NEWAPI_SETUP_ORIGIN="$origin"; file=$(mktemp); trap 'rm -f "$file"' EXIT HUP INT TERM; curl --proto '=https' --tlsv1.2 -fsS "$origin/client-setup/install.sh" -o "$file"; sh "$file" "$@" """
    unix = "printf 'New API HTTPS 地址： '; IFS= read -r NEWAPI_SETUP_ORIGIN; export NEWAPI_SETUP_ORIGIN; sh -c " + shlex.quote(loader) + ' newapi' + (' --restore' if restore else '')
    windows = "& { $env:NEWAPI_SETUP_ORIGIN=(Read-Host 'New API HTTPS 地址').TrimEnd('/') -replace '/v1$',''; try { $u=[Uri]$env:NEWAPI_SETUP_ORIGIN; if($u.Scheme -ne 'https' -or !$u.Host -or $u.UserInfo -or $u.Query -or $u.Fragment -or $u.AbsolutePath -ne '/'){throw 'invalid_address'}; & ([scriptblock]::Create((Invoke-RestMethod -MaximumRedirection 0 -Uri ($env:NEWAPI_SETUP_ORIGIN+'/client-setup/install.ps1'))))" + (' -Restore' if restore else '') + "; if($LASTEXITCODE -ne 0){throw 'setup_failed'} } catch { Write-Error '服务器配置命令未完成，请检查地址、网络或上方提示。' } }"
    return {"macOS": unix, "Linux": unix, "Windows": windows}


def build_short(report=None):
    entries, restores = server_commands(), server_commands(restore=True)
    text = f'''# New API 配置教程

复制自己系统的一行命令，先输入 New API 的 HTTPS 地址，再输入个人 API 密钥；显示“配置完成”后退出并重新打开 Codex，新建会话。

## macOS / Linux

使用日常普通用户，在本机终端复制整行，不要 sudo：

```sh
{entries["macOS"]}
```

地址只输入一次，保留真实 HTTPS 端口，可填根地址或 `/v1`；不要带后台页面路径、账号密码或查询参数。macOS 使用密钥弹窗；Linux 有图形组件时弹窗，无桌面时使用终端隐藏输入。

## Windows

在普通 PowerShell / Windows Terminal 的 PowerShell 标签页复制整行，不要放到 cmd.exe 或 WSL：

```powershell
{entries["Windows"]}
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
{restores["macOS"]}
```

Windows PowerShell：

```powershell
{restores["Windows"]}
```

恢复只需输入服务器地址，不用再次输入密钥。后续配置被修改时会停止恢复，避免覆盖其他设置。

## 验证记录

{report or '当前修改正在进行完整验收；以最终交付记录为准。'}

## 服务器镜像维护

源码和公开组件清单位于 `tools/new_api_setup.py` 与 `tools/new_api_mirror_assets.json`。服务器静态目录提供 `/client-setup/install.sh`、`install.ps1` 和按版本保存的组件。管理员用 `tools/build_new_api_mirror.py` 校验并准备镜像，通过 Nginx 提供 HTTPS，无需增加对外端口。组件包和真实连接资料不进入 Git 仓库。

开源依据：[uv](https://github.com/astral-sh/uv)（MIT/Apache-2.0）、[Python 构建](https://github.com/astral-sh/python-build-standalone)、[Codex CLI](https://github.com/openai/codex)（Apache-2.0）。
'''
    (ROOT / "new api 配置教程.md").write_text(text, encoding="utf-8")
    return entries


if __name__ == "__main__":
    build_short()
    print(json.dumps({"guide_written": True, "download_source": "configured_linux_server"}))
