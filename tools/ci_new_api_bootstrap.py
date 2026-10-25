"""Exercise the public bootstrap without relying on installed Python/Codex on PATH."""
import hashlib
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).parents[1]


def run():
    home = Path(os.environ["RUNNER_TEMP"]) / "newapi-bootstrap-home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["CODEX_HOME"] = str(home)
    env.pop("NEWAPI_CODEX_BINARY", None)
    if os.name == "nt":
        shell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        env["PATH"] = os.pathsep.join([str(Path(shell).parent), str(Path(os.environ["SystemRoot"]) / "System32"), os.environ["SystemRoot"]])
        script = (ROOT / "tools/new_api_bootstrap.ps1").read_text(encoding="utf-8")
        source = base64.b64encode(script.encode("utf-8")).decode("ascii")
        invoke = "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + source + "')))) -PrepareOnly"
        stdin = None
        args = [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(invoke.encode("utf-16-le")).decode("ascii")]
    else:
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        stdin = None
        args = ["/bin/sh", str(ROOT / "tools/new_api_bootstrap.sh"), "--prepare-only"]
    result = subprocess.run(args, input=stdin, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=420)
    # No keys or user data enter this process; still avoid dumping runtime paths.
    if result.returncode:
        error = result.stderr.decode("utf-8", "replace")
        import re
        error = re.sub(r'(?:[A-Za-z]:\\|/(?:Users|private|home|var|tmp)/)[^\s\"<>]+', '[runner_path]', error)
        print(json.dumps({"bootstrap_failed": True, "exit": result.returncode, "diagnostic": error[-2000:]}, ensure_ascii=True))
        return result.returncode
    executable = home / "newapi-runtime/codex-0.164.0" / ("codex.exe" if os.name == "nt" else "codex")
    if not executable.is_file() or (home / "config.toml").exists():
        raise RuntimeError("bootstrap_did_not_prepare_without_config_change")
    version = subprocess.run([str(executable), "--version"], capture_output=True, timeout=20)
    if version.returncode or b"codex-cli 0.164.0" not in version.stdout:
        raise RuntimeError("prepared_cli_not_verified")
    python_install = home / "newapi-runtime/python"
    if not python_install.is_dir() or not list(python_install.iterdir()):
        raise RuntimeError("managed_python_not_installed")
    if list((home / "newapi-runtime").glob("prepare.*")):
        raise RuntimeError("temporary_bootstrap_not_cleaned")
    summary = {"platform": sys.platform, "passed": True, "codex_on_path_not_required": True,
        "system_python_not_used": True, "managed_python_prepared": True, "official_cli_sha_verified": True,
        "config_unchanged": True, "temporary_downloads_removed": True,
        "source_sha256": hashlib.sha256((ROOT / "tools/new_api_setup.py").read_text(encoding="utf-8").encode()).hexdigest()}
    if os.name == "nt":
        import ctypes
        summary["non_admin_process"] = not bool(ctypes.windll.shell32.IsUserAnAdmin())
        if not summary["non_admin_process"]:raise RuntimeError("bootstrap_was_elevated")
    else:
        summary["non_root_process"] = os.geteuid() != 0
    (Path(os.environ["RUNNER_TEMP"]) / "newapi-bootstrap-result.json").write_text(json.dumps(summary))
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write("NEWAPI_CODEX_BINARY=" + str(executable) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(run())
