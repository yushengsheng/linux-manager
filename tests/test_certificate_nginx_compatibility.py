"""Isolated installation order, ACME routing, renewal and rollback regressions."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import types
import unittest
import urllib.request
from unittest import mock

spec = importlib.util.spec_from_file_location("certificate_remote_test", Path(__file__).resolve().parents[1] / "linux_manager/remote_agent.py")
REMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REMOTE)


class CertificateCompatibilityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-certificate-test-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.fs = self.base / "fs"
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(REMOTE, "Path", side_effect=self.path))
        self.root = self.path("/var/lib/linux-server-manager")
        self.root.mkdir(parents=True)
        self.task = self.root / "tasks" / ("a" * 24)
        self.task.mkdir(parents=True)
        self.stack.enter_context(mock.patch.object(REMOTE, "ROOT", self.root))
        self.stack.enter_context(mock.patch.object(REMOTE, "TASK", self.task))
        self.stack.enter_context(mock.patch.object(REMOTE, "SECRETS", set()))
        self.stack.enter_context(mock.patch.object(REMOTE, "step"))
        self.stack.enter_context(mock.patch.object(REMOTE, "allow_port"))
        self.stack.enter_context(mock.patch.object(REMOTE, "verify_local_https"))
        self.stack.enter_context(mock.patch.object(REMOTE, "listeners", return_value=[]))
        self.stack.enter_context(mock.patch.object(REMOTE, "unit_info", side_effect=self.unit_info))
        self.stack.enter_context(mock.patch.object(REMOTE.platform, "machine", return_value="x86_64"))
        self.stack.enter_context(mock.patch.object(REMOTE.shutil, "disk_usage", return_value=types.SimpleNamespace(free=10 * 1024**3)))
        self.stack.enter_context(mock.patch.object(REMOTE.time, "sleep"))
        self.stack.enter_context(mock.patch.object(REMOTE, "command", side_effect=self.command))
        self.stack.enter_context(mock.patch.object(REMOTE.urllib.request, "build_opener", return_value=types.SimpleNamespace(open=self.open)))
        self.states = {"nginx.service": {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}}
        self.calls = []
        self.failure = None
        self.probe_failure = False
        self.write("/opt/linux-server-manager/certbot/bin/certbot", "fixture executable", 0o755)
        self.write(self.root / "installed.json", "{}")

    def path(self, value):
        path = Path(value)
        return self.fs / str(path).lstrip("/") if path.is_absolute() and not path.is_relative_to(self.base) else path

    def write(self, name, content, mode=0o600):
        file = self.path(name)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        file.chmod(mode)
        return file

    def unit_info(self, unit):
        return dict(self.states.get(unit, {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": "disabled"}))

    def renewal(self, name, address="fixture.invalid", authenticator="standalone"):
        base = REMOTE.CERTIFICATE_CONFIG + "/live/" + name
        self.write(base + "/fullchain.pem", "valid:" + address)
        self.write(base + "/privkey.pem", "fixture-key")
        extra = "webroot_path = " + REMOTE.CERTIFICATE_WEBROOT + ",\n[[webroot_map]]\n" + address + " = " + REMOTE.CERTIFICATE_WEBROOT + "\n" if authenticator == "webroot" else ""
        return self.write(REMOTE.CERTIFICATE_CONFIG + "/renewal/" + name + ".conf", "version = 5.8.0\n[renewalparams]\nauthenticator = " + authenticator + "\n" + extra)

    def command(self, args, **kwargs):
        self.calls.append(list(args))
        if self.failure and self.failure(args):
            raise REMOTE.OperationError("fixture command failed")
        output = ""
        if args[0] == "openssl":
            certificate = self.path(args[args.index("-in") + 1])
            data = certificate.read_text() if certificate.exists() else ""
            if "-ext" in args:
                output = "X509v3 Subject Alternative Name:\n" + ", ".join(("IP Address:" if name[0].isdigit() else "DNS:") + name for name in data.removeprefix("valid:").split())
            elif "-checkhost" in args or "-checkip" in args:
                return types.SimpleNamespace(returncode=0 if args[-1] in data.removeprefix("valid:").split() else 1, stdout="", stderr="")
        elif args[0] == "systemctl":
            action = args[1]
            for unit in [item for item in args[2:] if item.endswith((".timer", ".service"))]:
                state = self.states.setdefault(unit, {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"})
                if action in {"start", "restart", "reload-or-restart"} or action == "enable" and "--now" in args:
                    state["ActiveState"] = "active"
                elif action == "stop": state["ActiveState"] = "inactive"
                if action in {"enable", "disable"}: state["UnitFileState"] = "enabled" if action == "enable" else "disabled"
                elif action == "mask": state.update(LoadState="masked", UnitFileState="masked")
                elif action == "unmask": state.update(LoadState="loaded", UnitFileState="disabled")
        elif args[0].endswith("/bin/certbot"):
            name = args[args.index("--cert-name") + 1]
            if args[1] == "certonly":
                address = args[args.index("--ip-address" if "--ip-address" in args else "-d") + 1]
                self.renewal(name, address, "webroot" if "--webroot" in args else "standalone")
            elif args[1] == "reconfigure":
                file = self.path(REMOTE.CERTIFICATE_CONFIG + "/renewal/" + name + ".conf")
                file.write_text("version = 5.8.0\n[renewalparams]\nauthenticator = webroot\nwebroot_path = " + REMOTE.CERTIFICATE_WEBROOT + ",\n")
        elif args[:2] == ["dpkg-query", "-W"]: output = "1.24.0"
        elif args[:2] == ["apt-cache", "policy"]: output = "Candidate: 1.24.0"
        elif args[0] == "python3" and "install.py" in args[1] and "--check" not in args:
            cert = self.path(args[args.index("--tls-cert") + 1])
            key = self.path(args[args.index("--tls-key") + 1])
            self.write("/etc/xiaojun-exchange/tls/fullchain.pem", cert.read_text())
            self.write("/etc/xiaojun-exchange/tls/privkey.pem", key.read_text())
            for unit in REMOTE.UNITS["exchange"]:
                self.states[unit] = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}
        return types.SimpleNamespace(returncode=0, stdout=output, stderr="")

    def open(self, request, **kwargs):
        url = request.full_url if hasattr(request, "full_url") else request
        if "/.well-known/acme-challenge/" in url:
            token = url.rsplit("/", 1)[1]
            content = b"wrong route" if self.probe_failure else self.path(REMOTE.CERTIFICATE_WEBROOT + "/.well-known/acme-challenge/" + token).read_bytes()
        else:
            content = b"fixture home page"
        response = mock.MagicMock(status=200)
        response.read.side_effect = lambda size=-1: content[:size] if size >= 0 else content
        response.__enter__.return_value = response
        return response

    def deploy_nginx(self, port=80, address="fixture.invalid"):
        REMOTE._change_nginx({}, {"version": "1.24.0", "port": port, "host": address})

    def deploy_exchange(self, address="fixture.invalid"):
        archive = self.task / "release.tar.gz"
        archive.write_bytes(b"fixture verified release")
        def unpack(archive, folder): self.write(folder / "linux_exchange/install.py", "fixture installer")
        certificate = REMOTE.certificate
        def public_paths(params):
            return tuple("/" + str(Path(name).relative_to(self.fs)) for name in certificate(params))
        with mock.patch.object(REMOTE, "unpack", side_effect=unpack), mock.patch.object(REMOTE, "certificate", side_effect=public_paths):
            return REMOTE.deploy_exchange({"version": "v1.1.88", "host": address, "port": 26483, "backend_port": 18880, "release_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()})

    def certificate_commands(self, verb):
        return [args for args in self.calls if args[0].endswith("/bin/certbot") and args[1] == verb]

    def test_nginx_first_exchange_uses_webroot_and_registers_sync_hook(self):
        self.deploy_nginx()
        self.deploy_exchange()
        args = self.certificate_commands("certonly")[0]
        self.assertIn("--webroot", args)
        self.assertNotIn("--standalone", args)
        self.assertEqual(REMOTE.certificate_renewals()[0][1:], ("webroot", REMOTE.CERTIFICATE_WEBROOT))
        record = json.loads((self.root / "installed.json").read_text())["exchange"]
        self.assertEqual(record["certificate_source"], "manager")
        hook = self.path(REMOTE.CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies").read_text()
        self.assertIn("nginx -t -c /etc/xiaojun-exchange/nginx.conf", hook)
        self.assertIn("reload xiaojun-exchange-nginx.service", hook)
        self.assertFalse(any(args[:2] == ["systemctl", "stop"] and "nginx.service" in args for args in self.calls))

    def test_exchange_first_later_nginx_migrates_without_reissuing_or_restarting_trading(self):
        self.deploy_exchange()
        self.assertIn("--standalone", self.certificate_commands("certonly")[0])
        certificate = self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes()
        self.calls.clear()
        self.deploy_nginx()
        self.assertEqual(len(self.certificate_commands("reconfigure")), 1)
        self.assertFalse(self.certificate_commands("certonly"))
        self.assertEqual(certificate, self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes())
        self.assertEqual(self.unit_info("linux-manager-cert-renew.timer")["ActiveState"], "active")
        self.assertFalse(any(any(unit in args for unit in REMOTE.UNITS["exchange"]) for args in self.calls))

    def test_ip_certificate_keeps_shortlived_profile_with_webroot(self):
        self.deploy_nginx()
        REMOTE.ensure_certificate("192.0.2.10")
        args = self.certificate_commands("certonly")[0]
        self.assertIn("--ip-address", args)
        self.assertIn("shortlived", args)
        self.assertIn("192.0.2.10", self.path(REMOTE.NGINX_ACME_SITE).read_text())

    def test_custom_nginx_port_still_serves_acme_on_80_and_is_idempotent(self):
        self.renewal("manager")
        self.deploy_nginx(port=8080)
        self.assertIn("listen 8080;", self.path(REMOTE.NGINX_MANAGED_SITE).read_text())
        self.assertIn("listen 80;", self.path(REMOTE.NGINX_ACME_SITE).read_text())
        self.assertFalse(REMOTE.certificate_webroot_needed())
        self.calls.clear()
        self.deploy_nginx(port=8080)
        self.assertFalse(self.certificate_commands("reconfigure"))

    def test_nginx_homepage_probe_uses_site_host_with_shared_acme_default(self):
        self.renewal("manager")
        requests = []
        def open_request(request, **kwargs):
            requests.append(request)
            return self.open(request, **kwargs)
        with mock.patch.object(REMOTE.urllib.request, "build_opener", return_value=types.SimpleNamespace(open=open_request)):
            self.deploy_nginx()
        home = [request for request in requests if request.full_url == "http://127.0.0.1:80/"]
        self.assertEqual(len(home), 1)
        self.assertEqual(home[0].get_header("Host"), "fixture.invalid")

    def test_all_managed_certificates_migrate_and_keep_host_routing(self):
        self.renewal("manager")
        self.renewal("manager-123456789abc", "other.invalid 192.0.2.20")
        self.deploy_nginx()
        self.assertEqual(len(self.certificate_commands("reconfigure")), 2)
        text = self.path(REMOTE.NGINX_ACME_SITE).read_text()
        self.assertIn("other.invalid", text)
        self.assertIn("192.0.2.20", text)
        self.assertNotIn("fixture.invalid", text)

    def test_reusing_valid_certificate_repairs_missing_renewal_timer_without_issuance(self):
        self.renewal("manager")
        before = self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes()
        REMOTE.ensure_certificate("fixture.invalid")
        self.assertFalse(self.certificate_commands("certonly"))
        self.assertTrue(self.path("/etc/systemd/system/linux-manager-cert-renew.timer").is_file())
        self.assertEqual(self.unit_info("linux-manager-cert-renew.timer")["UnitFileState"], "enabled")
        self.assertEqual(before, self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes())

    def test_missing_renewal_metadata_is_reported_without_replacing_certificate(self):
        file = self.renewal("manager")
        file.unlink()
        with self.assertRaisesRegex(REMOTE.OperationError, "续期资料缺失"):
            REMOTE.ensure_certificate("fixture.invalid")
        self.assertFalse(self.certificate_commands("certonly"))
        self.assertFalse(self.path("/etc/systemd/system/linux-manager-cert-renew.timer").exists())

    def test_restrictive_umask_does_not_hide_challenge_files_from_nginx_workers(self):
        self.deploy_nginx()
        previous = os.umask(0o077)
        try:
            REMOTE.prepare_certificate_webroot({"fixture.invalid"})
        finally:
            os.umask(previous)
        for suffix in ["", "/.well-known", "/.well-known/acme-challenge"]:
            self.assertEqual(self.path(REMOTE.CERTIFICATE_WEBROOT + suffix).stat().st_mode & 0o777, 0o755)

    def test_wrong_address_gets_independent_certificate_and_preserves_old_certificate(self):
        self.renewal("manager", "old.invalid")
        self.deploy_nginx()
        old = self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes()
        cert, _ = REMOTE.ensure_certificate("new.invalid")
        self.assertNotEqual(Path(cert).parent.name, "manager")
        self.assertEqual(old, self.path(REMOTE.CERTIFICATE_CONFIG + "/live/manager/fullchain.pem").read_bytes())

    def test_unmanaged_80_is_rejected_before_issuing_or_stopping_services(self):
        with mock.patch.object(REMOTE, "listeners", return_value=[{"port": 80, "protocol": "tcp", "processes": ["unknown"]}]):
            with self.assertRaisesRegex(REMOTE.OperationError, "TCP 80"):
                REMOTE.ensure_certificate("fixture.invalid")
        self.assertFalse(self.calls)

    def test_custom_acme_configuration_is_preserved(self):
        self.deploy_nginx()
        custom = self.write(REMOTE.NGINX_ACME_SITE, "# custom site\n")
        before = self.path(REMOTE.NGINX_MANAGED_SITE).read_bytes()
        with self.assertRaisesRegex(REMOTE.OperationError, "自定义"):
            REMOTE.prepare_certificate_webroot({"fixture.invalid"})
        self.assertEqual(custom.read_text(), "# custom site\n")
        self.assertEqual(before, self.path(REMOTE.NGINX_MANAGED_SITE).read_bytes())

    def test_routing_failure_restores_nginx_files_and_cleans_probe(self):
        self.deploy_nginx()
        before = self.path(REMOTE.NGINX_MANAGED_SITE).read_bytes()
        self.probe_failure = True
        with self.assertRaisesRegex(REMOTE.OperationError, "验证路径"):
            REMOTE.prepare_certificate_webroot({"fixture.invalid"})
        self.assertEqual(before, self.path(REMOTE.NGINX_MANAGED_SITE).read_bytes())
        self.assertFalse(self.path(REMOTE.NGINX_ACME_SITE).exists())
        self.assertFalse(list(self.path(REMOTE.CERTIFICATE_WEBROOT + "/.well-known/acme-challenge").iterdir()))

    def test_partial_migration_failure_restores_every_renewal_config_and_timer(self):
        first = self.renewal("manager")
        second = self.renewal("manager-123456789abc", "other.invalid")
        before = [file.read_bytes() for file in [first, second]]
        self.states["linux-manager-cert-renew.timer"] = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}
        self.failure = lambda args: "reconfigure" in args and "manager-123456789abc" in args
        with self.assertRaises(REMOTE.OperationError): REMOTE.migrate_certificate_renewals()
        self.assertEqual(before, [file.read_bytes() for file in [first, second]])
        self.assertEqual(self.unit_info("linux-manager-cert-renew.timer")["ActiveState"], "active")

    def test_active_renewal_stops_migration_without_killing_certificate_service(self):
        file = self.renewal("manager")
        before = file.read_bytes()
        self.states["linux-manager-cert-renew.service"] = {"LoadState": "loaded", "ActiveState": "activating", "UnitFileState": "static"}
        with self.assertRaisesRegex(REMOTE.OperationError, "正在续期"):
            REMOTE.migrate_certificate_renewals()
        self.assertEqual(before, file.read_bytes())
        self.assertFalse(any(args[:2] == ["systemctl", "stop"] and "linux-manager-cert-renew.service" in args for args in self.calls))

    def test_active_renewal_blocks_backup_before_site_or_timer_mutation(self):
        self.renewal("manager")
        self.states["linux-manager-cert-renew.service"] = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "static"}
        with self.assertRaisesRegex(REMOTE.OperationError, "正在续期"):
            REMOTE._deployment_backup("nginx", "reconfigure")
        self.assertFalse((self.task / "backup/manifest.json").exists())
        self.assertFalse(self.calls)

    def test_rollback_does_not_interrupt_renewal_started_after_backup(self):
        self.renewal("manager")
        self.write("/etc/systemd/system/linux-manager-cert-renew.service", "original renew service")
        self.states["linux-manager-cert-renew.service"] = {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "static"}
        REMOTE._deployment_backup("nginx", "reconfigure")
        self.states["linux-manager-cert-renew.service"]["ActiveState"] = "activating"
        with mock.patch.object(REMOTE.os, "chown"):
            REMOTE.restore_deployment(self.task.name)
        self.assertEqual(self.unit_info("linux-manager-cert-renew.service")["ActiveState"], "activating")
        self.assertFalse(any("linux-manager-cert-renew.service" in args for args in self.calls))

    def test_rollback_restores_previously_masked_shared_nginx(self):
        self.renewal("manager")
        self.states["nginx.service"].update(LoadState="masked", UnitFileState="masked")
        REMOTE._deployment_backup("nginx", "reconfigure")
        self.deploy_nginx()
        with mock.patch.object(REMOTE.os, "chown"):
            REMOTE.restore_deployment(self.task.name)
        self.assertEqual(self.unit_info("nginx.service")["LoadState"], "masked")

    def test_matching_nginx_deployment_previews_renewal_repair(self):
        self.renewal("manager")
        self.deploy_nginx()
        self.renewal("manager")
        state = {"installed": True, "_present": True, "_ready": True, "version": "1.24.0", "port": 80, "host": "fixture.invalid"}
        with mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "debian", "VERSION_ID": "12"}), mock.patch.object(REMOTE, "_deployment_state", return_value=state):
            plan = REMOTE.deployment_preflight({"service": "nginx", "version_policy": "keep", "host": "fixture.invalid", "port": 80})
        self.assertEqual(plan["action"], "reconfigure")
        self.assertEqual([item["field"] for item in plan["changes"]], ["certificate_renewal"])

    def test_missing_exchange_sync_is_detected_even_with_webroot_and_enabled_timer(self):
        self.deploy_exchange()
        self.deploy_nginx()
        self.assertFalse(REMOTE.certificate_webroot_needed())
        self.write(REMOTE.CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies", "#!/bin/sh\n")
        self.assertTrue(REMOTE.certificate_webroot_needed())
        self.deploy_nginx()
        self.assertFalse(REMOTE.certificate_webroot_needed())

    def test_preview_detects_renewal_configuration_race(self):
        file = self.renewal("manager")
        self.deploy_nginx()
        state = {"installed": True, "_present": True, "_ready": True, "version": "1.24.0", "port": 80, "host": "fixture.invalid"}
        params = {"service": "nginx", "version_policy": "keep", "host": "fixture.invalid", "port": 80}
        with mock.patch.object(REMOTE.platform, "freedesktop_os_release", return_value={"ID": "debian", "VERSION_ID": "12"}), mock.patch.object(REMOTE, "_deployment_state", side_effect=lambda *args: dict(state)):
            plan = REMOTE.deployment_preflight(params)
            file.write_text(file.read_text() + "# externally changed\n")
            with mock.patch.object(REMOTE, "_deployment_backup") as backup:
                with self.assertRaisesRegex(REMOTE.OperationError, "预览后已经变化"):
                    REMOTE.deploy(params | {"deployment_fingerprint": plan["fingerprint"]})
            backup.assert_not_called()

    def test_deployment_rollback_restores_renewals_site_and_timer(self):
        file = self.renewal("manager")
        self.write("/etc/systemd/system/linux-manager-cert-renew.service", "original renew service")
        timer = self.write("/etc/systemd/system/linux-manager-cert-renew.timer", "original renew timer")
        self.states["linux-manager-cert-renew.timer"] = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}
        self.states["linux-manager-cert-renew.service"] = {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "static"}
        before = file.read_bytes(), timer.read_bytes()
        REMOTE._deployment_backup("nginx", "reconfigure")
        self.failure = lambda args: "reconfigure" in args
        with self.assertRaises(REMOTE.OperationError): self.deploy_nginx()
        self.failure = None
        with mock.patch.object(REMOTE.os, "chown"):
            REMOTE.restore_deployment(self.task.name)
        self.assertEqual(before, (file.read_bytes(), timer.read_bytes()))
        self.assertFalse(self.path(REMOTE.NGINX_ACME_SITE).exists())
        self.assertFalse(self.path(REMOTE.NGINX_MANAGED_SITE).exists())
        self.assertEqual(self.unit_info("nginx.service")["ActiveState"], "inactive")
        self.assertEqual(self.unit_info("linux-manager-cert-renew.timer")["ActiveState"], "active")

    def test_sync_hook_checks_configuration_and_reloads_only_exchange_entry(self):
        self.renewal("manager")
        REMOTE.mark_installed("exchange", {"certificate_source": "manager", "certificate_lineage": "/etc/linux-server-manager/letsencrypt/live/manager"})
        hook = self.path(REMOTE.CERTIFICATE_CONFIG + "/renewal-hooks/deploy/linux-manager-proxies")
        script = hook.read_text()
        checks = []
        def fake(name, body):
            file = self.write(self.base / "bin" / name, "#!/bin/sh\n" + body + "\n", 0o755)
            return str(file)
        log = self.base / "hook.log"
        fake("install", 'printf "copy\\n" >> "$HOOK_LOG"')
        fake("nginx", 'printf "check\\n" >> "$HOOK_LOG"; exit "${CHECK_STATUS:-0}"')
        fake("systemctl", 'printf "%s\\n" "$*" >> "$HOOK_LOG"')
        for status in ["0", "1"]:
            if log.exists(): log.unlink()
            result = subprocess.run(["/bin/sh", str(hook)], env={"PATH": str(self.base / "bin"), "RENEWED_LINEAGE": "/etc/linux-server-manager/letsencrypt/live/manager", "HOOK_LOG": str(log), "CHECK_STATUS": status}, capture_output=True)
            checks.append((result.returncode, log.read_text().splitlines()))
        self.assertEqual(checks[0], (0, ["copy", "copy", "check", "reload xiaojun-exchange-nginx.service"]))
        self.assertEqual(checks[1], (1, ["copy", "copy", "check"]))
        self.assertNotIn("worker", script)

    def test_uninstalling_webpage_keeps_named_certificate_validation_and_can_restore(self):
        self.deploy_exchange()
        self.deploy_nginx()
        original = self.path(REMOTE.NGINX_ACME_SITE).read_bytes()
        self.assertNotIn("fixture.invalid", original.decode())
        params = {"service": "nginx", "keep_data": True}
        plan = REMOTE.uninstall_preflight(params)
        REMOTE.uninstall_project(params | {"uninstall_fingerprint": plan["fingerprint"]})
        self.assertFalse(self.path(REMOTE.NGINX_MANAGED_SITE).exists())
        self.assertIn("fixture.invalid", self.path(REMOTE.NGINX_ACME_SITE).read_text())
        self.assertEqual(self.unit_info("linux-manager-cert-renew.timer")["ActiveState"], "active")
        REMOTE.restore_uninstall(self.task.name)
        self.assertTrue(self.path(REMOTE.NGINX_MANAGED_SITE).is_file())
        self.assertEqual(original, self.path(REMOTE.NGINX_ACME_SITE).read_bytes())


@unittest.skipUnless(os.environ.get("LINUX_MANAGER_TEST_NGINX"), "optional local nginx executable")
class NativeNginxRoutingTests(unittest.TestCase):
    def test_real_nginx_serves_challenge_and_preserves_webpage_for_both_site_ports(self):
        binary = os.environ["LINUX_MANAGER_TEST_NGINX"]
        for site_port in [80, 8080]:
            with self.subTest(site_port=site_port), tempfile.TemporaryDirectory(prefix="lm-native-acme-") as directory, contextlib.ExitStack() as stack:
                base = Path(directory).resolve()
                public = base / "public"
                webroot = base / "acme"
                public.mkdir(); (public / "index.html").write_text("original webpage")
                (base / "logs").mkdir()
                site = base / "site.conf"
                acme = base / "acme.conf"
                site.write_text("# Managed by linux-server-manager\nserver {\n listen " + str(site_port) + ";\n server_name fixture.invalid;\n root " + str(public) + ";\n}\n")
                stack.enter_context(mock.patch.object(REMOTE, "NGINX_MANAGED_SITE", str(site)))
                stack.enter_context(mock.patch.object(REMOTE, "NGINX_ACME_SITE", str(acme)))
                stack.enter_context(mock.patch.object(REMOTE, "CERTIFICATE_WEBROOT", str(webroot)))
                with mock.patch.object(REMOTE, "command"), mock.patch.object(REMOTE, "verify_certificate_webroot"):
                    REMOTE.prepare_certificate_webroot({"fixture.invalid", "other.invalid", "192.0.2.10"})
                def free_port():
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", 0))
                        return listener.getsockname()[1]
                acme_port, home_port = free_port(), free_port()
                conf = base / "runtime"
                conf.mkdir()
                for file in [site, acme]:
                    text = file.read_text().replace("listen 80;", "listen " + str(acme_port) + ";").replace("listen [::]:80;", "listen [::]:" + str(acme_port) + ";").replace("listen 8080;", "listen " + str(home_port) + ";")
                    (conf / file.name).write_text(text)
                main = base / "nginx.conf"
                main.write_text("pid " + str(base / "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp { access_log off; include " + str(conf) + "/*.conf; }\n")
                args = [binary, "-p", str(base), "-c", str(main)]
                checked = subprocess.run(args + ["-t"], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                log = stack.enter_context((base / "process.log").open("w"))
                process = subprocess.Popen(args + ["-g", "daemon off;"], stdout=log, stderr=log)
                def stop():
                    process.terminate()
                    process.wait(timeout=5)
                stack.callback(stop)
                for _ in range(100):
                    try:
                        with socket.create_connection(("127.0.0.1", acme_port), timeout=0.1): break
                    except OSError: time.sleep(0.02)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                def open_challenge(request, **kwargs):
                    request = urllib.request.Request(request.full_url.replace("http://127.0.0.1/", "http://127.0.0.1:" + str(acme_port) + "/"), headers=dict(request.header_items()))
                    return opener.open(request, **kwargs)
                with mock.patch.object(REMOTE.urllib.request, "build_opener", return_value=types.SimpleNamespace(open=open_challenge)):
                    REMOTE.verify_certificate_webroot({"fixture.invalid", "other.invalid", "192.0.2.10"})
                request = urllib.request.Request("http://127.0.0.1:" + str(acme_port if site_port == 80 else home_port) + "/", headers={"Host": "fixture.invalid"})
                with opener.open(request, timeout=5) as response:
                    self.assertEqual(response.read(), b"original webpage")
                self.assertEqual(list((webroot / ".well-known/acme-challenge").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
