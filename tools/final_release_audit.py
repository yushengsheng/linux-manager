"""Check the delivered local release without exposing account metadata."""
from pathlib import Path
import json
import plistlib
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from linux_manager import VERSION
from linux_manager.models import atomic_private


def main():
    private = Path("/private/tmp/linux-manager-development")
    state = json.loads((private / "bundle-process.json").read_text())
    data = Path(state["data"])
    target = BASE / "linux服务器管理.app"
    archive = BASE / ("linux服务器管理-macOS-v" + VERSION + ".zip")
    forbidden = {"profiles.json", "history.json", "current.json", "test-connection.json", "known_hosts", "askpass.sock", "session.sock", ".git"}
    metadata = []
    for file in [data / "profiles.json", BASE / "scripts/.rename_account_gui_state.json"]:
        if file.is_file():
            value = json.loads(file.read_text())
            rows = value if isinstance(value, list) else [value]
            for row in rows:
                for field in ["host", "key_path", "private_key", "password", "key_passphrase", "sudo_password"]:
                    value = row.get(field)
                    if isinstance(value, str) and len(value) >= 10:
                        metadata.append(value.encode())
    source = Path("/private/tmp/linux-manager-build/source/linux_manager")
    originals = list((BASE / "linux_manager").rglob("*.py"))
    source_matches = all((source / file.relative_to(BASE / "linux_manager")).read_bytes() == file.read_bytes() for file in originals)
    source_private_values_absent = all(not any(value in file.read_bytes() for value in metadata) for file in originals)
    with zipfile.ZipFile(archive) as package:
        zip_valid = package.testzip() is None
        names = package.namelist()
        private_files_absent = not any(set(Path(name).parts) & forbidden for name in names)
    values_absent = True
    for file in target.rglob("*"):
        if file.is_file() and not file.is_symlink():
            content = file.read_bytes()
            if any(value in content for value in metadata) or b"-----BEGIN OPENSSH PRIVATE KEY-----" in content:
                values_absent = False
    process = subprocess.run(["ps", "-ww", "-p", str(state["pid"]), "-o", "command="], capture_output=True, text=True)
    window = json.loads((data / "window-state.json").read_text())
    ui = json.loads((data / "ui-check.json").read_text())
    launcher = BASE / "启动linux服务器管理.app"
    launcher_info = plistlib.loads((launcher / "Contents/Info.plist").read_bytes())
    results = {
        "version": VERSION,
        "package_crc_passed": zip_valid,
        "package_local_data_absent": private_files_absent,
        "package_private_values_absent": values_absent,
        "built_source_matches_current": source_matches,
        "source_private_values_absent": source_private_values_absent,
        "native_launcher_present": (launcher / "Contents/MacOS" / launcher_info["CFBundleExecutable"]).is_file(),
        "tracked_process_running": process.returncode == 0 and state["executable"] in process.stdout,
        "tracked_window_displayed": window.get("pid") == state["pid"] and window.get("mapped") is True,
        "ui_version_matches": ui.get("version") == VERSION,
        "local_profiles_loaded": ui.get("profiles_ready") is True,
        "saved_login_information_loaded": ui.get("saved_login_information_ready") is True,
        "ui_pages_checked": ui.get("pages"),
        "ui_layout_passed": ui.get("horizontal_overflow") == [],
        "ui_help_passed": ui.get("help_dialog") is True,
        "ui_max_tab_switch_ms": max(ui.get("tab_switch_ms", {}).values(), default=0),
    }
    atomic_private(private / "final-release-result.json", json.dumps(results))
    assert all(value is True for key, value in results.items() if key not in {"version", "ui_pages_checked", "ui_max_tab_switch_ms"})
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"release_audit_passed": False, "failure_type": type(error).__name__}))
        raise SystemExit(1)
