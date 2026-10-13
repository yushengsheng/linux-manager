"""Real installation/renewal acceptance on disposable GitHub Ubuntu runners.

Uses the unmodified remote agent and official exchange release. Only the ACME
endpoint/trust store and a forced-renewal systemd override are test fixtures.
Never run this against an existing installation or a user's server.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=90, **kwargs)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)
    print("PASS: " + message, flush=True)


def task(remote):
    remote.TASK = remote.ROOT / "tasks" / secrets.token_hex(12)
    remote.TASK.mkdir(parents=True, mode=0o700)
    remote.write_json(remote.TASK / "status.json", {"state": "running", "events": []})


def service_identity(unit):
    return run(["systemctl", "show", unit, "--property=MainPID,InvocationID"]).stdout


def tls_certificate(address):
    with socket.create_connection(("127.0.0.1", 26483), timeout=10) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=address) as secured:
            return secured.getpeercert(binary_form=True)


def certificate_der(path):
    return ssl.PEM_cert_to_DER_cert(Path(path).read_text().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--order", choices=["nginx-first", "exchange-first"], required=True)
    parser.add_argument("--address", choices=["exchange.test", "127.0.0.1"], required=True)
    parser.add_argument("--web-port", type=int, choices=[80, 8080], required=True)
    parser.add_argument("--pebble-source", type=Path, required=True)
    parser.add_argument("--pebble-binary", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise SystemExit("Requires a disposable GitHub Actions runner with root and systemd")
    paths = ["/etc/linux-server-manager", "/opt/linux-server-manager", "/var/lib/linux-server-manager",
             "/etc/xiaojun-exchange", "/opt/xiaojun-exchange", "/var/lib/xiaojun-exchange"]
    if any(Path(path).exists() for path in paths):
        raise SystemExit("Existing installation detected; refusing to modify it")

    spec = importlib.util.spec_from_file_location("ci_remote", BASE / "linux_manager/remote_agent.py")
    remote = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(remote)
    remote.CERTBOT_LOCK = (BASE / "linux_manager/resources/requirements-certbot.lock").read_text()
    artifacts = Path(os.environ["RUNNER_TEMP"]) / "certificate-acceptance"
    artifacts.mkdir()
    source = args.pebble_source.resolve()
    config = json.loads((source / "test/config/pebble-config.json").read_text())
    config["pebble"].update(listenAddress="127.0.0.1:14000", managementListenAddress="127.0.0.1:15000", httpPort=80, tlsPort=443)
    configuration = artifacts / "pebble-config.json"
    configuration.write_text(json.dumps(config))
    with Path("/etc/hosts").open("a") as stream:
        stream.write("\n127.0.0.1 exchange.test\n")
    shutil.copyfile(source / "test/certs/pebble.minica.pem", "/usr/local/share/ca-certificates/linux-manager-ci-acme.crt")
    run(["update-ca-certificates"])
    os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
    # The same local CA handles both issuance and Certbot's reconfigure dry run.
    Path("/etc/letsencrypt").mkdir(exist_ok=True)
    Path("/etc/letsencrypt/cli.ini").write_text("server = https://localhost:14000/dir\n")
    log = (artifacts / "pebble.log").open("w")
    pebble = subprocess.Popen([str(args.pebble_binary.resolve()), "-config", str(configuration)], cwd=source,
                              stdout=log, stderr=log, env=os.environ | {"PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_AUTHZREUSE": "0"})
    try:
        for _ in range(60):
            try:
                with urllib.request.urlopen("https://localhost:15000/roots/0", timeout=2) as response:
                    root = response.read()
                break
            except OSError:
                if pebble.poll() is not None:
                    raise RuntimeError("Local ACME test CA exited")
                time.sleep(0.5)
        else:
            raise RuntimeError("Local ACME test CA did not start")
        Path("/usr/local/share/ca-certificates/linux-manager-ci-issued.crt").write_bytes(root)
        run(["update-ca-certificates"])
        nginx_params = {"service": "nginx", "host": args.address, "port": args.web_port}
        exchange_digest = None
        def deploy_nginx():
            task(remote)
            plan = remote.deployment_preflight(nginx_params)
            remote.deploy(nginx_params | {"deployment_fingerprint": plan["fingerprint"]})
            return plan

        def deploy_exchange():
            nonlocal exchange_digest
            task(remote)
            params = {"service": "exchange", "version": "v1.1.88", "host": args.address,
                      "port": 26483, "backend_port": 18880}
            plan = remote.deployment_preflight(params)
            wire = params | {"deployment_fingerprint": plan["fingerprint"]}
            remote.deploy(wire)
            exchange_digest = wire["release_sha256"]
            check(exchange_digest == "5507422fe74144b7c179db3d408dfe660726776927acd36ea6ab0a55d1826370", "Linux downloaded and verified the official exchange release")

        if args.order == "nginx-first":
            deploy_nginx()
            shared_identity = service_identity("nginx.service")
            deploy_exchange()
            check(service_identity("nginx.service") == shared_identity, "exchange installation preserves running shared Nginx")
        else:
            deploy_exchange()
            check(remote.certificate_renewals()[0][1] == "standalone", "exchange first obtains a standalone certificate")
            original = Path(remote.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes()
            workers = {unit: service_identity(unit) for unit in remote.UNITS["exchange"]}
            deploy_nginx()
            check(original == Path(remote.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes(), "webroot migration preserves the existing certificate")
            check(all(service_identity(unit) == identity for unit, identity in workers.items()), "webroot migration preserves all exchange service processes")

        check(all(auth == "webroot" and root == remote.CERTIFICATE_WEBROOT for _, auth, root in remote.certificate_renewals()), "real Certbot renewal configuration uses the shared webroot")
        remote.verify_certificate_webroot({args.address})
        check(not list(Path(remote.CERTIFICATE_WEBROOT + "/.well-known/acme-challenge").iterdir()), "real HTTP challenge probe is cleaned up")
        remote.verify_local_https(args.address, 26483)
        timer = remote.unit_info("linux-manager-cert-renew.timer")
        check(timer["ActiveState"] == "active" and timer["UnitFileState"] == "enabled", "real renewal timer is active and enabled")
        check(run(["systemctl", "show", "linux-manager-cert-renew.timer", "--property=NextElapseUSecMonotonic", "--value"]).stdout.strip() not in {"", "0", "infinity"}, "renewal timer has a next scheduled run")

        # Delete only the test installation's hook; repeat deployment must repair
        # it through the same preview/fingerprint/deployment path as the GUI.
        Path(remote.CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies").unlink()
        plan = deploy_nginx()
        check(any(item["field"] == "certificate_renewal" for item in plan["changes"]) and not remote.certificate_webroot_needed(), "existing coexistence installation repairs a missing renewal hook")
        check(remote.deployment_preflight(nginx_params)["action"] == "unchanged", "repeating a repaired deployment is idempotent")

        # Exercise the actual installed systemd service immediately, with its
        # normal deploy hook, rather than wait for natural certificate expiry.
        override = Path("/etc/systemd/system/linux-manager-cert-renew.service.d/ci.conf")
        override.parent.mkdir()
        forced = remote.certbot_arguments("renew") + ["--quiet", "--force-renewal", "--no-random-sleep-on-renew"]
        override.write_text("[Service]\nEnvironment=REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nExecStart=\nExecStart=" + " ".join(forced) + "\n")
        run(["systemctl", "daemon-reload"])
        identities = {unit: service_identity(unit) for unit in ["nginx.service", *remote.UNITS["exchange"]]}
        before = tls_certificate(args.address)
        remote.command(["systemctl", "start", "linux-manager-cert-renew.service"], timeout=300)
        check(run(["systemctl", "show", "linux-manager-cert-renew.service", "--property=Result", "--value"]).stdout.strip() == "success", "real systemd renewal service completes successfully")
        expected = certificate_der(remote.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem")
        for _ in range(50):
            after = tls_certificate(args.address)
            if after == expected and after != before:
                break
            time.sleep(0.1)
        check(after == expected and after != before, "renewal changes the certificate actually served over HTTPS")
        check(Path("/etc/xiaojun-exchange/tls/fullchain.pem").read_bytes() == Path(remote.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes(), "deploy hook synchronizes the renewed exchange certificate")
        check(all(service_identity(unit) == identity for unit, identity in identities.items()), "renewal reloads the entry without restarting any exchange or shared Nginx process")
        remote.verify_local_https(args.address, 26483)
        request = urllib.request.Request("http://127.0.0.1:" + str(args.web_port) + "/", headers={"Host": args.address})
        with urllib.request.urlopen(request, timeout=5) as response:
            check(response.status == 200, "original webpage remains accessible after renewal")

        task(remote)
        params = {"service": "nginx", "keep_data": True}
        plan = remote.uninstall_preflight(params)
        remote.uninstall_project(params | {"uninstall_fingerprint": plan["fingerprint"]})
        remote.verify_certificate_webroot({args.address})
        check(not Path(remote.NGINX_MANAGED_SITE).exists(), "webpage removal preserves the real named ACME route")
        remote.restore_uninstall(remote.TASK.name)
        remote.verify_certificate_webroot({args.address})
        remote.verify_local_https(args.address, 26483)
        check(Path(remote.NGINX_MANAGED_SITE).is_file(), "webpage uninstall recovery restores its original route")

        summary = {"order": args.order, "address_type": "ip" if args.address == "127.0.0.1" else "domain",
                   "web_port": args.web_port, "exchange": "v1.1.88", "exchange_sha256": exchange_digest,
                   "certbot": run([remote.ensure_certbot(), "--version"]).stdout.strip(),
                   "nginx": run(["nginx", "-v"]).stderr.strip(), "result": "passed",
                   "scope": "Real official installation, systemd, HTTP-01 and HTTPS renewal against local Pebble CA; no public production CA or trading accounts"}
        (artifacts / "result.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary), flush=True)
    finally:
        pebble.terminate()
        pebble.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
