# new api 配置教程

**只做三步：复制自己系统的一行命令 → 输入 New API 地址和个人 API 密钥 → 退出并重新打开 Codex。**

无需先检查 Python/CLI 版本，无需手工安装配置脚本，也无需把密钥写在命令里。命令自动检查运行环境；缺失时下载带校验的用户级运行组件，然后弹出输入窗口。默认模型是 `gpt-6.1-sol`。

## macOS：直接复制这一整行

在本机“终端”中执行，不要加 sudo：

```
curl -fsSL https://raw.githubusercontent.com/yushengsheng/linux-manager/06c5bb493606a70bfe5b9baca8c693d910319a03/tools/new_api_bootstrap.sh | sh
```

先显示“正在自动检查并准备运行环境”，首次下载可能需要等一会儿；之后依次出现地址和密钥输入窗口。密钥不回显。输入后明确显示“配置完成”才算成功。

## Linux：直接复制这一整行

在要使用 Codex 的那台 Linux 电脑，以日常普通用户执行，不要 sudo/root：

```
curl -fsSL https://raw.githubusercontent.com/yushengsheng/linux-manager/06c5bb493606a70bfe5b9baca8c693d910319a03/tools/new_api_bootstrap.sh | sh
```

有桌面和可用图形组件时弹出窗口；SSH/无桌面时自动使用终端输入，密钥不回显。不要求为了配置专门安装桌面或给整个命令提权。

## Windows：直接复制这一整行

打开普通 **PowerShell** 或 Windows Terminal 的 PowerShell 标签页，复制执行；不用管理员窗口，不要放到 cmd.exe 或 WSL：

```
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/yushengsheng/linux-manager/06c5bb493606a70bfe5b9baca8c693d910319a03/tools/new_api_bootstrap.ps1)))
```

随后在弹出的窗口填写地址和密钥。无需提前安装 Python/Node/npm，也不需要保存 `.ps1`、修改执行策略或关闭 UAC。Windows 7、32 位系统及禁止用户应用的企业终端不在支持范围内。

## 地址和密钥填写方法

1. 地址填 New API 的 HTTPS 网站根地址或以 `/v1` 结尾的 API 地址，保留真实端口，例如 2026。不要带 `/keys` 等后台页面路径，不填用户名密码。
2. 密钥填个人后台“API 密钥”页面创建的 API Key，不是管理员登录密码，也不是 CLIProxyAPI 管理密钥。
3. 命令自动验证 HTTPS、密钥权限和模型可用性。错误时停止，不能把错误提示当成成功。
4. 完成后正常退出桌面 Codex 并重新打开，**新建会话**。旧会话、远程任务可能继续保留原接口。不要强制结束仍在工作的任务。

如果看到 `sh-3.2$`，只是进入了另一个 shell，不代表配置成功。可输入 `exit` 回到原终端，再粘贴上面的整条 `curl ... | sh` 命令。**不要单独输入 `sh`，也不要只复制说明文字。**

## 一键命令自动完成的事项

- 下载固定版本的配置源码并核对 SHA-256；准备 uv 0.13.5 的官方运行组件及独立 Python 3.13，不依赖用户事先安装 Python。
- 自动寻找已有可用 Codex CLI（含已知桌面内置布局）；缺少或过旧时，自动下载校验官方 Codex CLI 0.164.0 的私有副本。不会覆盖/升级已有桌面 App，也不把系统 Python 或旧 CLI 卸载。
- 运行组件位于当前用户的 Codex 数据目录下，不需要系统管理员权限，不要求用户配置 PATH 或环境变量。首次需要联网下载；以后可复用 Python/CLI 缓存。
- 先校验 HTTPS、密钥和 `gpt-6.1-sol` 权限，再备份和修改服务商。保留原插件、其他服务商和思考强度，不执行 ChatGPT 登录/退出，不删旧 `auth.json`。
- 密钥按本任务要求保存在本机权限受限的 Codex 配置中，不读系统钥匙串；macOS/Linux 文件权限为 600，Windows 为当前用户专用 ACL。不要上传配置或备份。
- 下载的临时引导文件用后自动清理。短命令会联网读取固定 GitHub 提交中的源码，不是要求用户事先下载保存脚本；可以在 GitHub 上审阅该提交。

## 权限与必要边界

**普通个人电脑无需先提权。** 请使用平时启动桌面 Codex 的同一个用户运行；macOS/Linux 加 sudo 会给错误的账号配置，因此命令主动拒绝 root。Windows 无需先选“以管理员身份运行”。

下面情况不能靠“一键脚本”无条件解决，但也不会让用户先逐项排查：命令会检测、停止并给出原因。

| 遇到的问题 | 处理方式 |
|---|---|
| 当前账号不能写入配置目录 | 常见于以前用 sudo/管理员账号创建的文件。让管理员修复当前账号目录所有权/ACL，不要 chmod 777 或改用 root 配置。 |
| 单位 MDM/应用控制禁止用户安装或自定义网关 | 需要单位管理员允许。命令不会绕过企业策略、UAC、AppLocker 或关闭执行策略。 |
| 网络不能访问 GitHub/官方运行时下载站 | 自动准备会失败并提示，先恢复正常网络；不会关闭 HTTPS 验证。 |
| New API 证书无效、密钥无效、渠道停用或模型未定价 | 后台修正后重新运行。命令不会擅自启用渠道、加额度或改价。 |
| 非标准处理器/过旧系统 | 支持 64 位 Intel/AMD 和 ARM 的常见 macOS/Linux/Windows 平台；不承诺所有旧系统和第三方打包。 |

原生 Windows 与 WSL 配置独立。Windows 桌面版用 Windows 命令；在 WSL 运行 Linux 命令只配置 WSL 内的 Codex。远程 SSH 命令只改远程主机，不会替本机桌面 App 改配置。

如自行设置过 `CODEX_HOME`，终端和桌面版必须使用同一目录。脚本不会重新安装桌面 App，不会跳过桌面程序自身的首次引导；准备私有 CLI 是为了可靠写入配置和提供终端运行能力。

## 如何确认真正走了 New API

看到“配置完成”后，重开 Codex并新建会话，发一句简单问题。进入 New API 后台“使用日志”，确认出现该模型的 Token 和费用。仅有本地写入成功，不等于上游模型永远不会故障。GPT 原登录信息可能仍保留，这是正常的；是否经 New API 以当前服务商和使用日志为准。

## 恢复原连接

macOS/Linux 运行：

```
curl -fsSL https://raw.githubusercontent.com/yushengsheng/linux-manager/06c5bb493606a70bfe5b9baca8c693d910319a03/tools/new_api_bootstrap.sh | sh -s -- --restore
```

Windows PowerShell 运行：

```
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/yushengsheng/linux-manager/06c5bb493606a70bfe5b9baca8c693d910319a03/tools/new_api_bootstrap.ps1))) -Restore
```

恢复不要求再次输入密钥。配置后来如果被其他程序修改，会停止自动恢复以避免覆盖新设置；原备份保留。恢复后同样重开 Codex并新建会话。

## 实际测试结果

2026-10-25 已完成新版完整验收：[GitHub Actions 三系统全部通过](https://github.com/yushengsheng/linux-manager/actions/runs/40182307903)。验收提交 `3cede4c2cac657e2818b42fd752461144717d049`；短命令固定读取其中完全相同的入口文件，入口再校验固定配置源码及官方组件。

| 环境 | 无预装依赖的自动准备 | 新旧配置 × 3 类登录记录 | 模拟 HTTPS Responses 请求 | 权限 |
|---|---|---|---|---|
| macOS 14 | 通过，使用独立 Python，官方 CLI 下载校验通过 | 6 种组合通过 | 6 次成功，新密钥正确 | 普通用户 |
| Ubuntu 24.04 | 通过，使用独立 Python，官方 CLI 下载校验通过 | 6 种组合通过 | 6 次成功，新密钥正确 | 非 root |
| Windows Server 2022 | 通过，PATH 无 Python/Codex 时仍可自动准备 | 6 种组合通过 | 6 次成功，新密钥正确 | 禁用管理员组和高权限的受限令牌 |

另外验证了：临时文件清理、不提前修改连接、正确密钥选择、保留旧登录记录与其他设置、私有文件权限、只读目录/文件停止、错误密钥和证书拒绝、备份恢复、企业策略覆盖时回滚。macOS 原生弹窗已显示并自动关闭；Linux 虚拟桌面中实际填写图形窗口及测试无桌面回退；Windows 实际创建并验证了隐藏密钥控件。没有人工操作所有桌面版本的首次登录流程。

本机也实际跑通自动准备流程，未改当前日常 Codex 连接。以上使用虚拟密钥与测试网关；不以此承诺上游模型永远可用。

测试用的是一次性 HTTPS 模拟网关、虚拟 API Key 和合成登录记录，不会上传真人 GPT 账号或生产服务器密钥。桌面内置安装路径为代表性布局模拟；没有人工完整安装并操作所有桌面版本的首次登录界面。不能承诺任何系统策略、任何网络、任何旧版本都“完美兼容”。

## 官方与开源依据

- [Codex 官方 CLI 安装与使用](https://learn.chatgpt.com/docs/cli)
- [Codex 网关配置](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)
- [Codex 原子配置接口](https://learn.chatgpt.com/docs/app-server)
- [uv 官方开源仓库](https://github.com/astral-sh/uv)，采用 MIT/Apache-2.0 许可证；用于准备独立 Python，避免要求用户手工安装依赖。
