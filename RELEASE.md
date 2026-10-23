# 本地运行与正式发版

## 日常运行

双击根目录 `启动本地最新版.app`。这是固定的源码入口，直接运行同目录的 `linux服务器管理.py`，使用本机现有 Python / Tk 和依赖；不会复制源码、打包或生成版本目录。源码更新后正常退出旧窗口，再打开同一个入口即可。

保留 `--desktop-data`，继续使用原桌面版的本机档案、项目缓存和钥匙串。运行中的进程不会自动加载已修改的源码。不要为更新源码替换入口、迁移数据目录或重新安装正式包。

新克隆的源码没有本机启动器时，可在 macOS 上一次性恢复这个轻量入口：

```sh
osacompile -o 启动本地最新版.app scripts/启动本地最新版.applescript
```

它仅生成启动入口，不包含 Python、主程序副本或本机数据；之后修改程序源码无需重复生成。已有入口时保留原文件。

## 正式发版

只有用户明确要求发版时才执行以下流程。普通开发、检查或测试通过都不触发打包、推送或发布；本地入口不会调用发版工具。

单独要求更新 GitHub 时，仅同步检查通过的源码、测试和说明，不构建安装包、不创建标签或 Release。提交使用明确的文件清单，保留无关本机文件。

1. 检查当前差异、版本号及发布说明；保留无关未跟踪文件。使用 `python3 tools/run_tests.py` 完成回归，确认对外源码及文档已在本机检查和脱敏。本机连接资料、钥匙串、私钥、缓存和运行日志不得提交或进入安装包。
2. 使用包含 arm64 / x86_64 的 Python 与 Tk，执行 `python3 tools/build_desktop.py --target-arch universal2`。构建工作区仍在 `/private/tmp/linux-manager-build-universal2/`；构建不会替换本机源码入口或关闭任何现有窗口。
3. 将构建完成的 `linux服务器管理.app` 和交付说明整理到 `dist/release/新版v<版本>-Mac通用/`。将 `scripts/启动linux服务器管理.applescript` 编译为该目录中的 `启动linux服务器管理.app`；两个分发应用的版本号必须与源码一致，最低 macOS 版本为 11.0，修改元数据后重新签名并核验。不要把本地源码入口放入独立安装包。
4. 执行 `python3 tools/package_desktop.py`，在 `dist/release/` 生成该版本的 ZIP 与同名 `.sha256`；执行 `python3 tools/final_release_audit.py` 验收。完整通过后才上传；工具会核对源码摘要、签名、双架构自检、文件内容、权限、链接和 SHA-256。
5. 按已授权范围提交源码、推送同一版本标签并创建 GitHub Release，上传已验收的 ZIP 与校验文件，核对线上附件和发布状态。发版请求包含打包和更新 GitHub；仅要求上传源码时不创建 Release。

`dist/` 已被 Git 忽略，不提交发布产物。项目根目录只保留固定本地入口；版本历史通过 Git 和 GitHub Releases 获取，不为日常测试生成带版本号的程序。现有正式产物可以保留在 `dist/release/`，不自动删除或覆盖旧版。

`tools/package_desktop.py` 和 `tools/final_release_audit.py` 默认使用上述固定发布目录，均支持 `--release-dir`、`--archive`。归档工具只打包明确指定的交付目录，目录缺失时直接停止，不打包项目根目录。

完整回归使用合成数据、假凭据及隔离目录，不预读历史连接档案。`tools/live_*` 等手动服务器测试工具不属于本地回归入口，运行前须有对具体测试服务器及操作范围的明确授权。

手工运行 `tools/live_direct_download_regression.py` 时，须由操作者在本机设置 `LM_AUTHORIZED_TEST_PROFILE` 为已授权测试档案的备注；未设置时在读取档案前停止。源码不保存真实测试档案别名，环境变量本身不代表服务器操作已获授权。
