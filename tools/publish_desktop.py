"""Publish only after verifying and stopping this task's tracked GUI instance."""
from pathlib import Path
import json
import os
import shutil
import signal
import re
import subprocess
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    from linux_manager.models import atomic_private
    from linux_manager import VERSION
    private = Path("/private/tmp/linux-manager-development")
    tracking = private / "bundle-process.json"
    state = json.loads(tracking.read_text())
    binary = Path(state["executable"])
    target = binary.parents[2]
    pid = state["pid"]
    process = subprocess.run(["ps", "-ww", "-p", str(pid), "-o", "pid=,ppid=,command="], capture_output=True, text=True)
    data = Path(state["data"])
    window_file = data / "window-state.json"
    window = json.loads(window_file.read_text()) if window_file.exists() else {}
    owned = process.returncode == 0 and str(binary) in process.stdout and window.get("pid") == pid and window.get("title") == "linux服务器管理"
    if not owned and "--finish-authorized-update" in sys.argv:
        proof = json.loads((private / "window-owner-check.json").read_text())
        candidate = window.get("pid")
        remaining = subprocess.run(["ps", "-ww", "-p", str(candidate), "-o", "pid=,ppid=,command="],capture_output=True,text=True)
        if proof.get("pid") == candidate and proof.get("executable_matches") and proof.get("onscreen_window_count") == 0 and remaining.returncode == 0 and str(binary) in remaining.stdout:
            pid = candidate
            owned = True
    all_commands = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True, text=True).stdout.splitlines()
    matching = {int(command.split(None, 1)[0]) for command in all_commands if str(binary) in command}
    if matching - ({pid} if owned else set()):
        raise RuntimeError("another application instance remains running")
    if not owned and any(str(binary) in command for command in all_commands):
        raise RuntimeError("user application instance remains running")
    processes = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True)
    family = {pid}
    pairs = [tuple(map(int, line.split())) for line in processes.stdout.splitlines() if len(line.split()) == 2]
    for _ in range(len(pairs)):
        children = {child for child, parent in pairs if parent in family}
        if children <= family: break
        family.update(children)
    if family - {pid}:
        raise RuntimeError("tracked instance has active child commands")
    history = json.loads((data / "history.json").read_text()) if (data / "history.json").exists() else []
    latest = {row.get("task_id"): row for row in history}
    if any(r.get("state") in {"submitted", "queued", "running", "awaiting_verification", "recovery_failed"} for r in latest.values()):
        raise RuntimeError("local application has unfinished tasks")
    source = Path("/private/tmp/linux-manager-build/dist/linux服务器管理.app")
    if not (source / "Contents/MacOS/linux服务器管理").is_file(): raise RuntimeError("build unavailable")
    check = json.loads((data / "ui-check.json").read_text()) if (data / "ui-check.json").exists() else {}
    old_version = check.get("version", "")
    replacement = "--replace-owned-validation-build" in sys.argv and owned
    if not re.fullmatch(r"\d+\.\d+\.\d+", old_version) or old_version == VERSION and not replacement:
        raise RuntimeError("previous version unavailable or update already installed")
    previous = target.parent / (".linux服务器管理-v" + old_version + ".app")
    if previous.exists():
        raise RuntimeError("previous upgrade backup already exists")
    print("已核对本项目原窗口和进程，无未完成的本机任务。", flush=True)
    if owned:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            if subprocess.run(["ps", "-p", str(pid)], capture_output=True).returncode:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("old instance remains running")
    # A UI upgrade must preserve the user's current accounts, keys and profiles.
    protected = {str(file.relative_to(data)): file.read_bytes() for file in data.rglob("*") if file.is_file() and file.name not in {"application.lock", "window-state.json", "ui-check.json"}}
    target.rename(previous)
    shutil.copytree(source, target, symlinks=True)
    document = target.parent / "linux服务器管理使用说明.md"
    if Path("linux服务器管理使用说明.md").resolve() != document.resolve():
        shutil.copy2(Path("linux服务器管理使用说明.md"), document)
    archive = target.parent / ("linux服务器管理-macOS-v" + VERSION + ".zip")
    archive.unlink(missing_ok=True)
    result = subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(target), str(archive)], capture_output=True)
    if result.returncode: raise RuntimeError("zip build failed")
    with zipfile.ZipFile(archive) as package:
        if package.testzip(): raise RuntimeError("zip verification failed")
    if any(not (data / name).is_file() or (data / name).read_bytes() != content for name, content in protected.items()):
        raise RuntimeError("local account data changed during UI update")
    (data / "ui-check.json").unlink(missing_ok=True)
    (data / "window-state.json").unlink(missing_ok=True)
    output = (private / "bundle-output.log").open("wb")
    child = subprocess.Popen([str(binary), "--ui-check"], stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    output.close()
    atomic_private(tracking, json.dumps(state | {"pid": child.pid, "previous_pid": pid}))
    print(json.dumps({"version": VERSION, "created_pid": child.pid, "zip_checked": True, "original_instance_stopped": True, "saved_account_files_preserved": True}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("交付或启动尚未完成；已停止重复启动，原始参数不向外输出。", flush=True)
        raise SystemExit(1)
