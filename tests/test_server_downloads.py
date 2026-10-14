import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest import mock

from test_linux_manager import REMOTE, MemoryVault
from linux_manager import server_downloads as downloads
from linux_manager.controller import Controller
from linux_manager.models import Connection, Store, Redactor
from linux_manager.transport import WaitingStopped, ConnectionInterrupted, interruptible_ssh

PAYLOAD = b"official fixture payload"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Response(io.BytesIO):
    def __init__(self, body=PAYLOAD, url="https://release-assets.githubusercontent.com/fixture", length=None):
        super().__init__(body)
        self.url = url
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def geturl(self):
        return self.url


class ServerDownloadTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.destination = Path(folder.name) / "release.tar.gz"

    def asset(self, service, name, size=len(PAYLOAD), digest=DIGEST):
        return {"name": name, "size": size, "digest": "sha256:" + digest,
                "browser_download_url": f"https://github.com/{downloads.REPOSITORIES[service]}/releases/download/v1.2.3/{name}"}

    def release(self, assets):
        return {"tag_name": "v1.2.3", "draft": False, "prerelease": False, "assets": assets}

    def test_all_projects_download_matching_architecture_directly(self):
        cases = [("hysteria2", "x86_64", "sing-box-1.2.3-linux-amd64.tar.gz"),
                 ("hysteria2", "aarch64", "sing-box-1.2.3-linux-arm64.tar.gz"),
                 ("reality", "x86_64", "Xray-linux-64.zip"), ("reality", "aarch64", "Xray-linux-arm64-v8a.zip"),
                 ("xui", "x86_64", "x-ui-linux-amd64.tar.gz"), ("xui", "aarch64", "x-ui-linux-arm64.tar.gz"),
                 ("exchange", "x86_64", "xiaojun-bn-v1.2.3-linux-amd64.tar.gz")]
        for service, arch, name in cases:
            assets = [self.asset(service, name)]
            if service == "exchange": assets.append(self.asset(service, "install-linux.sh"))
            with self.subTest(service=service, arch=arch), mock.patch.object(downloads, "release_info", return_value=self.release(assets)), mock.patch.object(downloads.urllib.request, "urlopen", return_value=Response(length=len(PAYLOAD))) as request:
                progress = mock.Mock()
                self.assertEqual(downloads.download_release(service, "v1.2.3", arch, self.destination, progress), DIGEST)
                self.assertEqual(self.destination.read_bytes(), PAYLOAD)
                self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
                self.assertEqual(request.call_args.args[0].full_url, assets[0]["browser_download_url"])
                progress.assert_called_once_with(len(PAYLOAD), len(PAYLOAD))

    def test_anonymous_api_limit_uses_public_page_digest(self):
        base = "https://github.com/XTLS/Xray-core/releases/"
        name = "Xray-linux-64.zip"
        page = f'<include-fragment src="{base}expanded_assets/v1.2.3"></include-fragment>'
        assets = f'<a href="{base}download/v1.2.3/{name}">file</a><clipboard-copy aria-label="Copy to clipboard digest for {name}" value="sha256:{DIGEST}"></clipboard-copy>'
        limited = urllib.error.HTTPError("https://api.github.com", 403, "limited", {}, None)
        responses = [limited, Response(page.encode(), base + "tag/v1.2.3"), Response(assets.encode(), base + "expanded_assets/v1.2.3"), Response()]
        with mock.patch.object(downloads.urllib.request, "urlopen", side_effect=responses):
            self.assertEqual(downloads.download_release("reality", "v1.2.3", "x86_64", self.destination), DIGEST)

    def test_public_exchange_checksums_work_without_api_digest(self):
        name = "xiaojun-bn-v1.2.3-linux-amd64.tar.gz"
        assets = [self.asset("exchange", n) | {"size": None, "digest": None, "_public": True} for n in [name, "SHA256SUMS", "install-linux.sh"]]
        sums = f"{DIGEST}  {name}\n".encode()
        with mock.patch.object(downloads, "release_info", return_value=self.release(assets)), mock.patch.object(downloads.urllib.request, "urlopen", side_effect=[Response(sums), Response()]):
            self.assertEqual(downloads.download_release("exchange", "v1.2.3", "x86_64", self.destination), DIGEST)
        self.assertFalse(self.destination.with_suffix(".sha256").exists())

    def test_mismatch_truncation_oversize_and_redirect_remove_partial_files(self):
        asset = self.asset("hysteria2", "sing-box-1.2.3-linux-amd64.tar.gz")
        for response in [Response(b"corrupt"), Response(PAYLOAD[:-1]), Response(PAYLOAD + b"x"), Response(url="https://untrusted.invalid/payload")]:
            with self.subTest(response=response), mock.patch.object(downloads, "release_info", return_value=self.release([asset])), mock.patch.object(downloads.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(downloads.DownloadError): downloads.download_release("hysteria2", "v1.2.3", "x86_64", self.destination)
                self.assertFalse(self.destination.exists())
                self.assertFalse(self.destination.with_name("release.tar.gz.part").exists())

    def test_missing_digest_never_downloads_executable(self):
        asset = self.asset("xui", "x-ui-linux-amd64.tar.gz") | {"digest": None}
        with mock.patch.object(downloads, "release_info", return_value=self.release([asset])), mock.patch.object(downloads.urllib.request, "urlopen") as request:
            with self.assertRaises(downloads.DownloadError): downloads.download_release("xui", "v1.2.3", "x86_64", self.destination)
            request.assert_not_called()

    def test_duplicate_checksum_is_rejected(self):
        name = "xiaojun-bn-v1.2.3-linux-amd64.tar.gz"
        sums = (f"{DIGEST}  {name}\n" * 2).encode()
        assets = [self.asset("exchange", name) | {"digest": None}, self.asset("exchange", "SHA256SUMS", len(sums)), self.asset("exchange", "install-linux.sh")]
        with mock.patch.object(downloads, "release_info", return_value=self.release(assets)), mock.patch.object(downloads.urllib.request, "urlopen", return_value=Response(sums)) as request:
            with self.assertRaises(downloads.DownloadError): downloads.download_release("exchange", "v1.2.3", "x86_64", self.destination)
            self.assertEqual(request.call_count, 1)

    def test_download_timeout_has_actionable_error_and_cleans_file(self):
        asset = self.asset("xui", "x-ui-linux-amd64.tar.gz")
        with mock.patch.object(downloads, "release_info", return_value=self.release([asset])), mock.patch.object(downloads.urllib.request, "urlopen", side_effect=TimeoutError()):
            with self.assertRaisesRegex(downloads.DownloadError, "Linux.*失败或超时"):
                downloads.download_release("xui", "v1.2.3", "x86_64", self.destination)
        self.assertFalse(self.destination.exists())

    def test_slow_download_has_total_deadline(self):
        asset = self.asset("xui", "x-ui-linux-amd64.tar.gz")
        with mock.patch.object(downloads, "release_info", return_value=self.release([asset])), mock.patch.object(downloads.urllib.request, "urlopen", return_value=Response()), mock.patch.object(downloads.time, "monotonic", side_effect=[0, 301]):
            with self.assertRaisesRegex(downloads.DownloadError, "5 分钟"):
                downloads.download_release("xui", "v1.2.3", "x86_64", self.destination)
        self.assertFalse(self.destination.exists())

    def test_invalid_release_cannot_fall_back_to_a_different_version(self):
        for changes in [{"tag_name": "v1.2.4"}, {"draft": True}, {"prerelease": True}]:
            with self.subTest(changes=changes), mock.patch.object(downloads.urllib.request, "urlopen", return_value=Response(json.dumps(self.release([]) | changes).encode())):
                with self.assertRaises(downloads.DownloadError): downloads.release_info("reality", "v1.2.3")

    def test_remote_download_failure_stops_before_backup_or_install(self):
        plan = {"service": "hysteria2", "action": "update", "requires_archive": True, "version": "v1.2.3", "architecture": "x86_64"}
        with mock.patch.object(REMOTE, "deployment_preflight", return_value=plan), mock.patch.object(REMOTE, "prepare_deployment_archive", side_effect=REMOTE.OperationError("Linux 下载失败")), mock.patch.object(REMOTE, "_deployment_backup") as backup, mock.patch.object(REMOTE, "_change_hysteria") as install:
            with self.assertRaises(REMOTE.OperationError): REMOTE.deploy({})
            backup.assert_not_called(); install.assert_not_called()

    def test_configuration_change_during_download_stops_before_mutation(self):
        plan = {"service": "hysteria2", "action": "update", "requires_archive": True, "version": "v1.2.3", "architecture": "x86_64", "fingerprint": "before"}
        with mock.patch.object(REMOTE, "deployment_preflight", side_effect=[plan, plan | {"fingerprint": "after"}]), mock.patch.object(REMOTE, "prepare_deployment_archive"), mock.patch.object(REMOTE, "_deployment_backup") as backup:
            with self.assertRaisesRegex(REMOTE.OperationError, "下载期间项目配置发生变化"):
                REMOTE.deploy({})
            backup.assert_not_called()

    def test_worker_records_download_failure_and_finishes_task(self):
        root = self.destination.parent
        identifier = "a" * 24
        with mock.patch.object(REMOTE, "ROOT", root), mock.patch.object(REMOTE, "TASK", None), mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 0, "", "")):
            REMOTE.start_task({"operation": "deploy", "service": "hysteria2"}, identifier)
            with mock.patch.object(REMOTE, "deploy", side_effect=REMOTE.OperationError("Linux 下载官方发行文件失败或超时")):
                REMOTE.run_task(identifier)
            self.assertEqual(REMOTE.status_task(identifier)["state"], "failed")
            self.assertIn("Linux 下载", REMOTE.status_task(identifier)["message"])
            self.assertFalse((root / "tasks" / identifier / "request.json").exists())


class StopWaitingTests(unittest.TestCase):
    def test_slow_reader_receives_whole_large_request_after_wait_intervals(self):
        payload = "large request " * 100000
        result = interruptible_ssh([sys.executable, "-c", "import sys,time; time.sleep(.4); s=sys.stdin.read(); print(len(s))"], cancel_event=threading.Event(), timeout=5, input=payload, text=True, start_new_session=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(int(result.stdout), len(payload))

    def test_stalled_local_ssh_can_be_interrupted_and_reaped(self):
        cancel = threading.Event()
        timer = threading.Timer(0.15, cancel.set); timer.start()
        self.addCleanup(timer.join)
        started = time.monotonic()
        with self.assertRaises(WaitingStopped):
            interruptible_ssh([sys.executable, "-c", "import sys,time; sys.stdin.read(); time.sleep(30)"], cancel_event=cancel, timeout=20, input="small request", text=True, start_new_session=True)
        self.assertLess(time.monotonic() - started, 2)

    def test_submission_deadline_prevents_repeated_long_waits(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller(Store(Path(folder), MemoryVault()))
            ssh = mock.Mock(redactor=Redactor())
            controller.transport = mock.Mock(return_value=ssh)
            ticks = [0]
            def clock(): return ticks[0]
            def call(request, **kwargs):
                ticks[0] += kwargs["timeout"]
                raise ConnectionInterrupted("fixture timeout")
            ssh.call.side_effect = call
            with mock.patch("linux_manager.controller.time.monotonic", side_effect=clock), mock.patch("linux_manager.controller.time.sleep", side_effect=lambda n: ticks.__setitem__(0, ticks[0] + n)):
                with self.assertRaises(ConnectionInterrupted):
                    controller.execute(Connection(host="fixture.invalid", username="fixture"), {"operation": "updates"})
            self.assertLessEqual(ticks[0], 90)
            self.assertEqual(sum(c.args[0]["action"] == "start" for c in ssh.call.call_args_list), 1)

    def test_cancel_during_poll_does_not_resubmit_or_cancel_server_job(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller(Store(Path(folder), MemoryVault()))
            ssh = mock.Mock(redactor=Redactor()); controller.transport = mock.Mock(return_value=ssh)
            identifier = "a" * 24
            ssh.call.side_effect = [{"version": "v1.2.3", "fingerprint": "fixture", "requires_archive": True, "installed": False}, {"task_id": identifier}, WaitingStopped("stopped")]
            with mock.patch("linux_manager.controller.secrets.token_hex", return_value=identifier):
                with self.assertRaises(WaitingStopped):
                    controller.execute(Connection(host="fixture.invalid", username="fixture"), {"operation": "deploy", "service": "hysteria2"}, cancel_event=threading.Event())
            self.assertEqual([c.args[0]["action"] for c in ssh.call.call_args_list], ["deployment_preflight", "start", "task"])
            self.assertEqual(controller.store.history()[-1]["state"], "submitted")
            self.assertTrue(all(c.kwargs.get("cancel_event") is not None for c in ssh.call.call_args_list))

    def test_busy_submission_lock_returns_error_instead_of_waiting_forever(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(REMOTE.fcntl, "flock", side_effect=BlockingIOError()), mock.patch.object(REMOTE.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(REMOTE.OperationError, "任务提交仍在处理"):
                with REMOTE.state_lock(Path(folder), timeout=5): pass
