"""Open a native interactive terminal through the program's existing SSH master."""
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from .models import ManagerError, atomic_private


def _applescript_string(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def open_terminal(ssh):
    if sys.platform != "darwin":
        raise ManagerError("此命令行入口使用 macOS 系统终端。")
    ssh.connection.validate()
    if not ssh.trusted():
        raise ManagerError("请先确认服务器身份指纹，再打开命令行。")
    if not ssh.control_path or not Path(ssh.control_path).exists():
        raise ManagerError("当前服务器连接尚未就绪，请连接成功后再打开命令行。")

    folder = Path(tempfile.mkdtemp(prefix="terminal-", dir=ssh.directory))
    folder.chmod(0o700)
    try:
        config = ssh._config(folder)
        launcher = folder / "terminal.command"
        cleanup = shlex.join(["/bin/rm", "-f", "--", str(config), str(launcher)])
        cleanup += "; " + shlex.join(["/bin/rmdir", "--", str(folder)])
        # If the managed connection has gone away, fail instead of opening a
        # fresh connection. No saved password or passphrase enters this script.
        command = shlex.join([
            "/usr/bin/ssh", "-F", str(config), "-tt",
            "-o", "BatchMode=yes", "-o", "ProxyCommand=/usr/bin/false",
            "linux-manager-server",
        ])
        atomic_private(launcher, "#!/bin/sh\ntrap " + shlex.quote(cleanup) + " EXIT\n" + command + "\n")
        launcher.chmod(0o700)
        # Replace Terminal's local shell: after SSH exits, pasted commands
        # cannot accidentally run on the user's Mac.
        launch = "exec " + shlex.join(["/bin/sh", str(launcher)])
        label = "服务器命令行 · " + ssh.connection.label.replace("\n", " ").replace("\r", " ")
        source = (
            'tell application "Terminal"\n'
            "    set serverTab to do script " + _applescript_string(launch) + "\n"
            "    try\n"
            "        set custom title of serverTab to " + _applescript_string(label) + "\n"
            "    end try\n"
            "    activate\n"
            "end tell\n"
        )
        result = subprocess.run(["/usr/bin/osascript", "-"], input=source,
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ManagerError("未能打开系统终端，请检查 macOS 是否允许本程序控制“终端”。")
    except (OSError, subprocess.TimeoutExpired):
        shutil.rmtree(folder, ignore_errors=True)
        raise ManagerError("打开系统终端未完成，请检查是否已有终端窗口，再重新操作。") from None
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
