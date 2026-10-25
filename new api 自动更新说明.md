# New API 自动更新说明

服务器已配置自动更新。本次已从 `v1.0.0-rc.46` 实际升级到 `v1.0.0-rc.47`。

## 运行方式

- 按北京时间每天凌晨 **04:30** 检查，附加最多 10 分钟的随机延迟；服务器启动后也会补查。
- 跟随 [New API 官方发布](https://github.com/QuantumNous/new-api/releases/latest)，跳过 GitHub 标记为草稿或预发布的版本。官方目前把 RC 版本作为正式发布提供，因此会跟随该发布渠道。
- 没有新版就结束，不重复安装、不重启现有 New API。
- 使用 Linux 自带的 systemd 定时任务，不需要额外服务器端口或另装 Docker。

## 更新保护

1. 先下载官方程序，核对官方 SHA256、CPU 架构和磁盘余量。下载阶段网站照常使用。
2. 更新开始时，网站暂时返回维护状态（HTTP 503），等待正在进行的调用结束。最多等待 5 分钟，仍有调用则暂缓本次更新。
3. 停止 New API 后，备份旧程序和完整数据目录。保留最近 7 份完整备份，仅服务器 root 可访问。
4. 安装新版并检查启动状态，核对原有持久数据、权限规则及实际生效的模型价格。内部实例心跳和重新生成的权限记录编号不作为业务变化。
5. 校验通过才恢复网站访问；失败则恢复旧程序和备份数据。恢复访问后，不会再自动回退数据库，避免抹掉用户后来产生的充值、用量和扣费记录。

如果某个新版本确实无法通过校验，会保留旧版并记录失败；相同下载内容不反复安装，后续新发布仍会自动检查。网络故障、磁盘不足和正在进行的调用不会被强行绕过。

2026-10-25 已部署异常恢复修复：恢复前重新验证维护入口并等待请求结束；维护标记丢失或入口保护失效时，保留当前数据和备份，停止自动回滚并报告 `rollback_requires_manual_review`，避免覆盖可能已产生的新用量。重复执行恢复命令不会绕过该保护。安装过程中被强制终止的版本也会持久记录失败，仍可用 `--retry-failed` 明确重试。

客户端配置所需的安装脚本、uv、Python 和 Codex CLI 已托管到服务器 HTTPS 静态目录，客户端安装不再依赖 GitHub。服务器端 New API 自动更新仍需访问官方 GitHub 发布源；客户端无需承担这项网络依赖。

## 本次验证

- 更新恢复的 20 项针对性检查已在本地及服务器 Linux 通过，涵盖维护保护缺失、用量保留、进程中断、失败版本跳过及明确重试。
- 在隔离的真实 systemd 服务与 Nginx 中，验证了维护保护、成功更新，以及新版修改测试余额后启动失败时，旧程序和原余额恢复。
- 生产服务已实际升级至 `v1.0.0-rc.47`，原有业务数据、权限规则和生效的模型价格校验一致。
- 本次重新验证了生产 HTTPS 健康状态、定时任务和只读版本检查，当前版本仍为 `v1.0.0-rc.47`；生产 New API 未因脚本更新而重启。
- 客户端服务器镜像的三系统完整安装、配置及恢复验收已通过，记录见[三系统检查](https://github.com/yushengsheng/linux-manager/actions/runs/40199134678)。

自动更新需要短暂维护窗口。未来版本若改变原有业务数据或生效价格，会触发保护；不能保证所有未来版本都无需人工处理。

## 服务器管理命令

查看定时任务：

```sh
sudo systemctl status new-api-auto-update.timer --no-pager
```

立即检查并在有新版时更新：

```sh
sudo systemctl start new-api-auto-update.service
```

查看更新记录：

```sh
sudo journalctl -u new-api-auto-update.service -n 30 --no-pager
```

停止后续自动检查（已进行的更新会继续完成）：

```sh
sudo systemctl disable --now new-api-auto-update.timer
```

恢复自动检查：

```sh
sudo systemctl enable --now new-api-auto-update.timer
```

确认已解决失败原因后，手动重试相同版本：

```sh
sudo /usr/local/sbin/new-api-auto-update --retry-failed
```

恢复尚未完成的更新事务：

```sh
sudo /usr/local/sbin/new-api-auto-update --recover
```

更新任务结束时会自动检查未完成事务；维护标记保存在服务器持久目录中，断电重启后仍可继续恢复。
