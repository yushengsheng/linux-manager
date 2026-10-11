-- 只链接本地源码，不携带主程序、Python、档案或密钥；改代码后重新启动即可。
on run
    set launchStep to "定位本地源码"
    try
        set launcherPath to POSIX path of (path to me)
        set folderPath to do shell script "/usr/bin/dirname " & quoted form of launcherPath
        set sourcePath to folderPath & "/linux服务器管理.py"
        set pythonPath to (POSIX path of (path to home folder)) & ".local/share/uv/python/cpython-3.11-macos-aarch64-none/bin/python3.11"
        do shell script "/bin/test -f " & quoted form of sourcePath
        set launchStep to "检查本机 Python"
        do shell script "/bin/test -x " & quoted form of pythonPath
        set launchStep to "检查源码运行环境"
        do shell script quoted form of pythonPath & " " & quoted form of sourcePath & " --self-check"
        set launchStep to "启动本地最新版"
        do shell script "/usr/bin/screen -dmS linux-manager-local " & quoted form of pythonPath & " " & quoted form of sourcePath & " --desktop-data"
    on error problem number code
        if launchStep is "定位本地源码" and code is 1 then
            set detail to "请将此启动器放在 linux服务器管理.py 与 linux_manager 源码目录旁边，不能单独移动启动器。"
        else if launchStep is "检查本机 Python" and code is 1 then
            set detail to "未找到本机已配置的 Python 3.11 / Tk 运行环境。源码和登录资料未改动，请先修复运行环境。"
        else
            set detail to launchStep & "失败（错误 " & code & "）。请检查本地源码与运行环境；服务器未因此执行操作。"
        end if
        display alert "本地最新版未能启动" message detail as critical
    end try
end run
