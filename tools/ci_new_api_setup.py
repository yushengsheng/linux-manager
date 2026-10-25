"""Disposable hosted-runner tests. Never reads production credentials."""
import argparse
import base64
import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
VERSION = "0.164.0"


def install():
    prefix = Path(os.environ["RUNNER_TEMP"]) / "newapi-codex-runtime"
    command = ["npm", "install", "--prefix", str(prefix), "@openai/codex@" + VERSION, "--no-audit", "--no-fund"]
    if os.name == "nt":
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", *command]
    subprocess.run(command, check=True)
    found = []
    for path in (prefix / "node_modules" / "@openai").rglob("codex.exe" if os.name == "nt" else "codex"):
        if path.is_file():
            header = path.read_bytes()[:4]
            if header.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
                found.append(path)
    if not found:
        raise RuntimeError("official_native_cli_not_found")
    executable = found[0].resolve()
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
        stream.write("NEWAPI_CODEX_BINARY=" + str(executable) + "\n")
    print("Installed official Codex CLI " + VERSION + " into a job-owned directory.")


def restricted_windows_child():
    """Use the same user SID but a token with admin group disabled and no privileges."""
    import msvcrt
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    class SIDATTR(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]
    class STARTUP(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]
    class PROCESS(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.CreateRestrictedToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SIDATTR), wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(wintypes.HANDLE)]
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR, ctypes.POINTER(STARTUP), ctypes.POINTER(PROCESS)]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token, limited, sid = wintypes.HANDLE(), wintypes.HANDLE(), wintypes.LPVOID()
    def check(ok):
        if not ok:raise RuntimeError("restricted_token_error_" + str(ctypes.get_last_error()))
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0001 | 0x0002 | 0x0008, ctypes.byref(token)))
    check(advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)))
    group = SIDATTR(sid, 0)
    check(advapi.CreateRestrictedToken(token, 0x1, 1, ctypes.byref(group), 0, None, 0, None, ctypes.byref(limited)))
    log = Path(os.environ["RUNNER_TEMP"]) / "newapi-restricted-test.log"
    with log.open("wb") as output, open(os.devnull, "rb") as input_file:
        handles = [msvcrt.get_osfhandle(output.fileno()), msvcrt.get_osfhandle(input_file.fileno())]
        for handle in handles:os.set_handle_inheritable(handle, True)
        startup = STARTUP()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = 0x100
        startup.hStdInput, startup.hStdOutput, startup.hStdError = handles[1], handles[0], handles[0]
        process = PROCESS()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([sys.executable, str(Path(__file__).resolve()), "--restricted-child"]))
        check(advapi.CreateProcessAsUserW(limited, None, command, None, None, True, 0, None, str(ROOT), ctypes.byref(startup), ctypes.byref(process)))
        try:
            waited = kernel.WaitForSingleObject(process.hProcess, 15 * 60 * 1000)
            if waited != 0:
                kernel.TerminateProcess(process.hProcess, 1)
                raise RuntimeError("restricted_test_timeout")
            code = wintypes.DWORD()
            check(kernel.GetExitCodeProcess(process.hProcess, ctypes.byref(code)))
        finally:
            kernel.CloseHandle(process.hThread)
            kernel.CloseHandle(process.hProcess)
    kernel.CloseHandle(token)
    kernel.CloseHandle(limited)
    # Log contains only test fixtures; do not print config snapshots or certificate material.
    print(log.read_text(encoding="utf-8", errors="replace"))
    return code.value


def supplemental(setup):
    checks = {}
    from tools.build_new_api_guide import commands
    source, entries = commands(check_only=True)
    if os.name == "nt":
        shell = shutil.which("powershell.exe")
        checked = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", "-"], input=entries["Windows"].encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    else:
        checked = subprocess.run(["/bin/sh", "-c", entries["macOS" if sys.platform == "darwin" else "Linux"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    checks["literal_one_line_shell_and_payload_verified"] = checked.returncode == 0 and hashlib.sha256(source).hexdigest().encode() in checked.stdout
    if not checks["literal_one_line_shell_and_payload_verified"]:
        raise RuntimeError("literal_command_or_payload_failed")
    with tempfile.TemporaryDirectory(prefix="newapi-discovery-") as tmp:
        home = Path(tmp).resolve()
        real = Path(os.environ["NEWAPI_CODEX_BINARY"])
        if sys.platform == "darwin":
            target = home / "Applications/Codex.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
        elif os.name == "nt":
            target = home / "local/Programs/OpenAI/Codex/bin/codex.exe"
        else:
            target = home / ".local/bin/codex"
        target.parent.mkdir(parents=True)
        shutil.copy2(real, target)
        original_which = shutil.which
        def which(name):
            return None if name.startswith("codex") else original_which(name)
        with mock.patch.dict(os.environ, {"NEWAPI_CODEX_BINARY": "", "LOCALAPPDATA": str(home / "local")}), mock.patch.object(Path, "home", return_value=home), mock.patch.object(shutil, "which", side_effect=which):
            selected = setup.discover_codex()
        checks["desktop_layout_or_user_install_without_cli_on_path"] = str(target) in selected
        if not checks["desktop_layout_or_user_install_without_cli_on_path"]:
            raise RuntimeError("bundled_cli_discovery_failed")
    if sys.platform == "darwin":
        original_run = subprocess.run
        compiled = []
        def native_dialog(args, **kwargs):
            script = args[-1].replace('default answer ""', 'default answer "fixture"')
            script = script[:-1] + " giving up after 1)"
            result = original_run(["osascript", "-e", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            compiled.append(result.returncode == 0)
            return result
        try:
            with mock.patch.object(subprocess, "run", side_effect=native_dialog):setup.prompt_mac()
            checks["native_dialog_automatic_close"] = all(compiled)
        except setup.SetupError:
            checks["native_dialog_automatic_close"] = "runner_without_interactive_desktop"
    elif os.name == "nt":
        # Native controls are constructed on the hosted runner; no human dialog action is claimed.
        script = setup.WINDOWS_FORM[:setup.WINDOWS_FORM.index("if($f.ShowDialog()")]
        script += "\n@{masked=$k.UseSystemPasswordChar;entries=(@($u,$k).Count);form_created=$null -ne $f}|ConvertTo-Json -Compress;$f.Dispose()"
        result = setup.powershell(script)
        if result.returncode:
            raise RuntimeError("windows_native_controls_failed")
        values = json.loads(result.stdout.decode("utf-8-sig"))
        checks["native_masked_controls_created"] = values["masked"] and values["entries"] == 2 and values["form_created"]
        checks["non_admin_process"] = not bool(ctypes.windll.shell32.IsUserAnAdmin())
        if not checks["non_admin_process"]:
            raise RuntimeError("windows_tests_must_run_without_admin_token")
    else:
        checks["non_root_process"] = os.geteuid() != 0
        if os.environ.get("DISPLAY"):
            import tkinter as tk
            constructor = tk.Tk
            def make():
                root = constructor()
                def fill():
                    entries = [w for w in root.winfo_children() if isinstance(w, tk.Entry)]
                    entries[0].insert(0, "https://gateway.example.invalid")
                    entries[1].insert(0, "fixture-key")
                    if entries[1].cget("show") != "*":raise RuntimeError("password_not_masked")
                    next(w for w in root.winfo_children() if isinstance(w, tk.Button)).invoke()
                root.after(100, fill)
                return root
            with mock.patch.object(tk, "Tk", side_effect=make):
                checks["linux_gui_automatic_entry"] = setup.prompt_linux() == ["https://gateway.example.invalid", "fixture-key"]
        else:
            checks["linux_gui_automatic_entry"] = "no_display"
        with mock.patch.dict(os.environ, {"DISPLAY": "", "WAYLAND_DISPLAY": ""}), mock.patch.object(setup, "prompt_terminal", return_value=("fixture-url", "fixture-key")):
            checks["headless_terminal_fallback"] = setup.prompt_linux() == ("fixture-url", "fixture-key")
    return checks


def run():
    from tests.test_new_api_setup import NewApiSetupTests, setup
    source = (ROOT / "tools/new_api_setup.py").read_text(encoding="utf-8").encode("utf-8")
    report = {"platform": sys.platform, "python": sys.version.split()[0], "codex": VERSION,
        "source_sha256": hashlib.sha256(source).hexdigest(), "auth_state_method": "synthetic records, no real user login",
        "desktop_method": "real CLI copied into representative desktop/user install layout, not full app UI"}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NewApiSetupTests))
    report.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        auth_matrix_cases=6, successful_gateway_requests=len(NewApiSetupTests.gateway.requests),
        all_observed_gateway_auth_correct=all(r["correct_auth"] for r in NewApiSetupTests.gateway.requests))
    try:
        report["supplemental"] = supplemental(setup)
    except Exception as error:
        report["supplemental_error"] = type(error).__name__ + ": " + str(error)
        result.errors.append(("supplemental", "failed"))
    report["passed"] = result.wasSuccessful()
    destination = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "newapi-test-result.json"
    destination.write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--restricted-child", action="store_true")
    options = parser.parse_args()
    if options.install:
        install()
    elif os.name == "nt" and not options.restricted_child and ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit(restricted_windows_child())
    else:
        sys.exit(run())
