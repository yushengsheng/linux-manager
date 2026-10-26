"""Exercise the public bootstrap without relying on installed Python/Codex on PATH."""
import hashlib
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import ssl
import urllib.request

ROOT = Path(__file__).parents[1]


def run():
    from tests.test_new_api_setup import Gateway
    from tools.build_new_api_mirror import build
    mirror = Path(os.environ['RUNNER_TEMP']) / 'newapi-fixture-mirror'
    build(mirror, current_platform=True)
    print(json.dumps({'bootstrap_stage': 'mirror_verified'}), flush=True)
    gateway = Gateway(Path(tempfile.mkdtemp(prefix='mirror-tls-', dir=os.environ['RUNNER_TEMP'])), mirror=mirror)
    try:
        return run_client(mirror, gateway)
    finally:
        gateway.close()


def run_client(mirror, gateway):
    from tools.build_new_api_guide import server_commands
    home = Path(os.environ["RUNNER_TEMP"]) / "newapi-bootstrap-home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["CODEX_HOME"] = str(home)
    env.pop("NEWAPI_CODEX_BINARY", None)
    env['NEWAPI_CI_DIAGNOSTICS'] = '1'
    env.update(NEWAPI_SETUP_ORIGIN=gateway.base.removesuffix('/v1'),
               SSL_CERT_FILE=str(gateway.cert), CURL_CA_BUNDLE=str(gateway.cert),
               UV_SYSTEM_CERTS='true', NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1')
    # Any accidental external download must fail, even on a GitHub-connected runner.
    env.update(HTTPS_PROXY='http://localhost:9', HTTP_PROXY='http://localhost:9', ALL_PROXY='http://localhost:9',
               https_proxy='http://localhost:9', http_proxy='http://localhost:9', all_proxy='http://localhost:9')
    context = ssl.create_default_context(cafile=str(gateway.cert))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(env['NEWAPI_SETUP_ORIGIN'] + '/client-setup/install.' + ('ps1' if os.name == 'nt' else 'sh')) as response:
        downloaded = response.read(128 * 1024)
    if downloaded != (mirror / ('install.ps1' if os.name == 'nt' else 'install.sh')).read_bytes():
        raise RuntimeError('bootstrap_download_mismatch')
    if os.name == "nt":
        # Provision the test author's official CLI before running the client.
        # Native Windows clients now reuse an installation and download no runtime.
        executable = mirror / 'codex/0.164.0/codex-x86_64-pc-windows-msvc.exe'
        env['NEWAPI_CODEX_BINARY'] = str(executable)
        for key in list(env):
            if key.upper() == 'PSMODULEPATH':env.pop(key)
        shell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        env["PATH"] = os.pathsep.join([str(Path(shell).parent), str(Path(os.environ["SystemRoot"]) / "System32"), os.environ["SystemRoot"]])
        print(json.dumps({'bootstrap_stage': 'trust_fixture_certificate'}), flush=True)
        if os.environ.get('NEWAPI_CI_PARENT_TRUST') != '1':
            raise RuntimeError('fixture_requires_admin_test_parent')
        request = Path(os.environ['RUNNER_TEMP']) / 'newapi-fixture-trust-request.json'
        ready = request.with_suffix('.ready')
        fingerprint = hashlib.sha1(ssl.PEM_cert_to_DER_cert(gateway.cert.read_text())).hexdigest()
        temporary = request.with_suffix('.tmp')
        temporary.write_text(json.dumps({'certificate': str(gateway.cert)}))
        temporary.replace(request)
        deadline = time.monotonic() + 60
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.2)
        if not ready.exists() or ready.read_text().strip() != fingerprint:
            raise RuntimeError('fixture_certificate_trust_failed')
        print(json.dumps({'bootstrap_stage': 'fixture_certificate_trusted'}), flush=True)
        invoke = ("$blockedProxy=[Net.WebProxy]::new('http://localhost:9'); "
                  "$blockedProxy.BypassProxyOnLocal=$true; [Net.WebRequest]::DefaultWebProxy=$blockedProxy; "
                  'function Read-Host { $env:NEWAPI_SETUP_ORIGIN }; ' + server_commands(prepare_only=True)['Windows'])
        stdin = None
        args = [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(invoke.encode("utf-16-le")).decode("ascii")]
    else:
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        stdin = (env['NEWAPI_SETUP_ORIGIN'] + '\n').encode('utf-8')
        args = ["/bin/sh", '-c', server_commands(prepare_only=True)['Linux']]
    print(json.dumps({'bootstrap_stage': 'run_server_only_client'}), flush=True)
    result = subprocess.run(args, input=stdin, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=420)
    # No keys or user data enter this process; still avoid dumping runtime paths.
    if result.returncode:
        error = result.stderr.decode("utf-8", "replace")
        import re
        error = re.sub(r'(?:[A-Za-z]:\\|/(?:Users|private|home|var|tmp)/)[^\s\"<>]+', '[runner_path]', error)
        print(json.dumps({"bootstrap_failed": True, "exit": result.returncode, "diagnostic_head": error[:2500], "diagnostic_tail": error[-1200:]}, ensure_ascii=True))
        return result.returncode
    executable = Path(env['NEWAPI_CODEX_BINARY']) if os.name == 'nt' else home / 'newapi-runtime/codex-0.164.0/codex'
    if not executable.is_file() or (home / "config.toml").exists():
        raise RuntimeError("bootstrap_did_not_prepare_without_config_change")
    version = subprocess.run([str(executable), "--version"], capture_output=True, timeout=20)
    if version.returncode or b"codex-cli 0.164.0" not in version.stdout:
        raise RuntimeError("prepared_cli_not_verified")
    python_install = home / "newapi-runtime/python"
    if os.name == 'nt':
        if (home / 'newapi-runtime').exists() or (home / 'auth.json').exists():
            raise RuntimeError('native_setup_created_runtime_or_login')
        if any(path.startswith(('uv/', 'python/', 'codex/')) for path in gateway.downloads):
            raise RuntimeError('native_setup_downloaded_runtime')
    elif not python_install.is_dir() or not list(python_install.iterdir()):
        raise RuntimeError("managed_python_not_installed")
    if list((home / "newapi-runtime").glob("prepare.*")):
        raise RuntimeError("temporary_bootstrap_not_cleaned")
    summary = {"platform": sys.platform, "passed": True, "codex_on_path_not_required": True,
        "system_python_not_used": True, "managed_python_prepared": os.name != 'nt', "official_cli_sha_verified": True,
        "uses_installed_codex": os.name == 'nt', "runtime_downloads_required": os.name != 'nt',
        "config_unchanged": True, "temporary_downloads_removed": True,
         "github_access_blocked_for_client": True, "server_only_downloads": True,
         "downloaded_components": gateway.downloads,
        "source_sha256": hashlib.sha256((ROOT / "tools/new_api_setup.py").read_text(encoding="utf-8").encode()).hexdigest()}
    if os.name == "nt":
        import ctypes
        summary["non_admin_process"] = not bool(ctypes.windll.shell32.IsUserAnAdmin())
        if not summary["non_admin_process"]:raise RuntimeError("bootstrap_was_elevated")
    else:
        summary["non_root_process"] = os.geteuid() != 0
    (Path(os.environ["RUNNER_TEMP"]) / "newapi-bootstrap-result.json").write_text(json.dumps(summary))
    if os.environ.get("GITHUB_ENV") and os.name != "nt":
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write("NEWAPI_CODEX_BINARY=" + str(executable) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(run())
