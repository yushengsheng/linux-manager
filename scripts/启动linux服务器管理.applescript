-- 无终端窗口的启动器，打开同一文件夹里的主程序。
on run
    set launchStep to "定位启动器"
    try
        set launcherPath to POSIX path of (path to me)
        set folderPath to do shell script "/usr/bin/dirname " & quoted form of launcherPath
        set appPath to folderPath & "/linux服务器管理.app"
        set launchStep to "检查主程序位置"
        do shell script "/bin/test -d " & quoted form of appPath
        set launchStep to "检查主程序完整性"
        do shell script "/bin/test -x " & quoted form of (appPath & "/Contents/MacOS/linux服务器管理")
        set launchStep to "打开主程序"
        do shell script "/usr/bin/open " & quoted form of appPath
    on error problem number code
        if launchStep is "检查主程序位置" and code is 1 then
            set detail to "未找到同一文件夹内的 linux服务器管理.app，请将主程序与启动器放在一起。"
        else if launchStep is "检查主程序完整性" and code is 1 then
            set detail to "主程序文件不完整或没有执行权限，请重新解压完整安装包。"
        else
            set detail to launchStep & "失败（错误 " & code & "）：" & return & problem
        end if
        display alert "程序未能启动" message detail as critical
    end try
end run
