-- 无终端窗口的启动器，打开同一文件夹里的主程序。
on run
    set launcherPath to POSIX path of (path to me)
    set folderPath to do shell script "/usr/bin/dirname " & quoted form of launcherPath
    set appPath to folderPath & "/linux服务器管理.app"
    try
        do shell script "/usr/bin/test -x " & quoted form of (appPath & "/Contents/MacOS/linux服务器管理")
        do shell script "/usr/bin/open " & quoted form of appPath
    on error
        display alert "程序未能启动" message "请将启动linux服务器管理.app 与 linux服务器管理.app 放在同一个文件夹，确认程序文件完整后重新打开。" as critical
    end try
end run
