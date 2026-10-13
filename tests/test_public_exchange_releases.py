import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager import releases
from linux_manager.controller import Controller
from linux_manager.models import Connection, ManagerError

VERSION = "v1.1.99"
BASE = f"https://github.com/{releases.EXCHANGE_REPOSITORY}/releases/"
PACKAGE = f"xiaojun-bn-{VERSION}-linux-amd64.tar.gz"
CONTENT = b"isolated official release payload"
DIGEST = hashlib.sha256(CONTENT).hexdigest()


class Response(io.BytesIO):
    def __init__(self, body, url, length=None):
        super().__init__(body)
        self.url = url
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def geturl(self):
        return self.url


def limited(code=403):
    return urllib.error.HTTPError("https://api.github.com/", code, "limited", {"X-RateLimit-Remaining": "0"}, None)


def release_page(version=VERSION, badge="Latest", final_url=None, fragment=None):
    fragment = fragment or BASE + "expanded_assets/" + version
    return Response(f'<span>{badge}</span><include-fragment src="{fragment}"></include-fragment>'.encode(), final_url or BASE + "tag/" + version)


def asset_page(names=None, final_url=None):
    if names is None:
        names = ["install-linux.sh", "SHA256SUMS", PACKAGE]
    body = "".join(f'<a href="/{releases.EXCHANGE_REPOSITORY}/releases/download/{VERSION}/{name}">{name}</a>' for name in names)
    return Response(body.encode(), final_url or BASE + "expanded_assets/" + VERSION)


def public_asset(name=PACKAGE):
    return {"name": name, "size": None, "_public_release": True, "browser_download_url": BASE + f"download/{VERSION}/{name}"}


def payload_responses(content=CONTENT, checksums=None, length=False):
    sums = checksums if checksums is not None else f"{DIGEST}  {PACKAGE}\n".encode()
    return [limited(), release_page(), asset_page(), Response(sums, BASE + f"download/{VERSION}/SHA256SUMS", len(sums) if length else None), Response(content, "https://release-assets.githubusercontent.com/payload", len(content) if length else None)]


class PublicExchangeReleaseTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(releases, "github_cli", return_value=None)
        patch.start()
        self.addCleanup(patch.stop)

    def test_limited_api_uses_latest_public_release_without_login(self):
        for code in [403, 429]:
            with self.subTest(code=code), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(code), release_page(), asset_page()]) as request, mock.patch.object(releases.subprocess, "run") as run:
                release = releases.release_info()
                self.assertEqual(release["tag_name"], VERSION)
                self.assertEqual({a["name"] for a in release["assets"]}, {"install-linux.sh", "SHA256SUMS", PACKAGE})
                self.assertEqual(request.call_args_list[1].args[0].full_url, BASE + "latest")
                for call in request.call_args_list:
                    self.assertNotIn("Authorization", dict(call.args[0].header_items()))
                    self.assertIsNotNone(call.kwargs["context"])
                run.assert_not_called()

    def test_specific_version_uses_only_that_public_tag(self):
        with mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(), asset_page()]) as request:
            self.assertEqual(releases.exchange_version(VERSION), VERSION)
            self.assertEqual(request.call_args_list[1].args[0].full_url, BASE + "tag/" + VERSION)
            self.assertTrue(all("latest" not in call.args[0].full_url for call in request.call_args_list))
        with mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page("v1.1.98")]):
            with self.assertRaisesRegex(ManagerError, "指定版本不一致"):
                releases.exchange_version(VERSION)

    def test_failed_local_login_does_not_block_public_release(self):
        with mock.patch.object(releases, "github_cli", return_value="gh"), mock.patch.object(releases.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"unavailable")), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(), asset_page()]):
            self.assertEqual(releases.exchange_version(), VERSION)

    def test_malformed_api_metadata_is_not_overridden_by_public_page(self):
        for value in [{"draft": True}, {"draft": False, "prerelease": True}, {"tag_name": "v1.1.99-rc1", "draft": False, "prerelease": False}]:
            with self.subTest(value=value), mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(json.dumps(value).encode(), "https://api.github.com/")) as request:
                with self.assertRaises(ManagerError):
                    releases.exchange_version()
                self.assertEqual(request.call_count, 1)

    def test_public_release_redirect_must_stay_on_official_stable_tag(self):
        for url in ["http://github.com/" + releases.EXCHANGE_REPOSITORY + "/releases/tag/" + VERSION, BASE + "tag/v1.1.99-rc1", "https://untrusted.invalid/releases/tag/" + VERSION, "https://github.com/other/repo/releases/tag/" + VERSION, BASE + "tag/" + VERSION + "?redirect=other"]:
            with self.subTest(url=url), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(final_url=url)]):
                with self.assertRaisesRegex(ManagerError, "无效或属于测试版"):
                    releases.exchange_version()

    def test_public_prerelease_draft_and_unbound_asset_list_are_rejected(self):
        pages = [release_page(badge="Pre-release"), release_page(badge="Draft"), release_page(fragment=BASE + "expanded_assets/v1.1.98")]
        for page in pages:
            with self.subTest(page=page.url), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), page]) as request:
                with self.assertRaises(ManagerError):
                    releases.exchange_version()
                self.assertEqual(request.call_count, 2)

    def test_asset_list_cannot_redirect_to_another_source(self):
        with mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(), asset_page(final_url="https://untrusted.invalid/files")]):
            with self.assertRaisesRegex(ManagerError, "列表来源不一致"):
                releases.exchange_version()

    def test_missing_installer_package_or_checksum_list_blocks_deployment(self):
        for missing in ["install-linux.sh", "SHA256SUMS", PACKAGE]:
            names = [name for name in ["install-linux.sh", "SHA256SUMS", PACKAGE] if name != missing]
            with self.subTest(missing=missing), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(), asset_page(names)]):
                with self.assertRaisesRegex(ManagerError, "缺少"):
                    releases.exchange_version()

    def test_external_or_other_version_asset_link_is_not_accepted(self):
        for prefix in ["https://untrusted.invalid/", BASE + "download/v1.1.98/"]:
            page = asset_page(["install-linux.sh", "SHA256SUMS"])
            page = Response(page.getvalue() + f'<a href="{prefix}{PACKAGE}">package</a>'.encode(), page.url)
            with self.subTest(prefix=prefix), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), release_page(), page]):
                with self.assertRaisesRegex(ManagerError, "缺少"):
                    releases.exchange_version()

    def test_public_html_is_bounded(self):
        page = Response(b"x" * (4 * 1024 * 1024 + 1), BASE + "tag/" + VERSION)
        with mock.patch.object(releases.urllib.request, "urlopen", side_effect=[limited(), page]):
            with self.assertRaisesRegex(ManagerError, "超过允许大小"):
                releases.exchange_version()

    def test_limit_and_network_errors_do_not_claim_repository_is_private(self):
        for error, text in [(limited(), "API 已限流"), (limited(429), "API 已限流"), (urllib.error.URLError("unavailable"), "API 发行版查询失败")]:
            with self.subTest(text=text), mock.patch.object(releases.urllib.request, "urlopen", side_effect=[error, urllib.error.URLError("unavailable")]):
                with self.assertRaisesRegex(ManagerError, text) as caught:
                    releases.exchange_version()
                self.assertNotIn("私有仓库", str(caught.exception))
                self.assertNotIn("需要", str(caught.exception))

    def test_public_archive_download_checks_exact_official_sha_and_permissions(self):
        for length in [False, True]:
            with self.subTest(content_length=length), tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", side_effect=payload_responses(length=length)) as request:
                target = Path(folder) / "release.tar.gz"
                self.assertEqual(releases.download_exchange(VERSION, target), DIGEST)
                self.assertEqual(target.read_bytes(), CONTENT)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(request.call_args_list[-2].args[0], BASE + f"download/{VERSION}/SHA256SUMS")
                self.assertEqual(request.call_args_list[-1].args[0], BASE + f"download/{VERSION}/{PACKAGE}")

    def test_corrupt_package_and_duplicate_or_unreadable_checksums_are_rejected(self):
        cases = [(b"changed package", None, "SHA-256 校验失败"), (CONTENT, (f"{DIGEST} {PACKAGE}\n" * 2).encode(), "清单无效"), (CONTENT, b"\xff\xfe", "清单无法读取"), (CONTENT, b"0 invalid-name\n", "清单无效")]
        for content, sums, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", side_effect=payload_responses(content, sums)):
                with self.assertRaisesRegex(ManagerError, error):
                    releases.download_exchange(VERSION, Path(folder) / "release.tar.gz")

    def test_public_stream_is_bounded_even_without_content_length(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(releases, "MAX_ASSET_SIZE", 32), mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(b"x" * 33, BASE + f"download/{VERSION}/{PACKAGE}")):
            with self.assertRaisesRegex(ManagerError, "超过允许大小"):
                releases.download_asset(public_asset(), VERSION, Path(folder) / "release.tar.gz")

    def test_public_content_length_must_be_valid_and_complete(self):
        for length in ["not-a-number", 0, releases.MAX_ASSET_SIZE + 1, len(CONTENT) - 1, len(CONTENT) + 1]:
            with self.subTest(length=length), tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(CONTENT, BASE + f"download/{VERSION}/{PACKAGE}", length)):
                with self.assertRaises(ManagerError):
                    releases.download_asset(public_asset(), VERSION, Path(folder) / "release.tar.gz")
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(b"", BASE + f"download/{VERSION}/{PACKAGE}")):
            with self.assertRaisesRegex(ManagerError, "下载不完整"):
                releases.download_asset(public_asset(), VERSION, Path(folder) / "release.tar.gz")

    def test_download_redirect_cannot_leave_official_https_hosts(self):
        for url in ["http://release-assets.githubusercontent.com/payload", "https://untrusted.invalid/payload", "https://github.com.untrusted.invalid/payload", "https://user@github.com/payload", "https://github.com:444/payload"]:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(CONTENT, url)):
                with self.assertRaisesRegex(ManagerError, "偏离官方 HTTPS"):
                    releases.download_asset(public_asset(), VERSION, Path(folder) / "release.tar.gz")

    def test_api_size_validation_is_not_weakened_by_public_fallback(self):
        for size in [None, True, 0, -1, releases.MAX_ASSET_SIZE + 1]:
            asset = public_asset() | {"size": size, "_public_release": False}
            with self.subTest(size=size), tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen") as request:
                with self.assertRaisesRegex(ManagerError, "来源或大小无效"):
                    releases.download_asset(asset, VERSION, Path(folder) / "release.tar.gz")
                request.assert_not_called()
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", return_value=Response(CONTENT[:-1], BASE + f"download/{VERSION}/{PACKAGE}")):
            with self.assertRaisesRegex(ManagerError, "下载不完整"):
                releases.download_asset(public_asset() | {"size": len(CONTENT), "_public_release": False}, VERSION, Path(folder) / "release.tar.gz")

    def test_deployment_submits_small_parameters_without_local_download(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(releases.urllib.request, "urlopen", side_effect=AssertionError("Mac must not download")):
            connection = Connection(host="host.invalid", username="tester")
            store = mock.Mock(directory=Path(folder))
            store.profiles.return_value = [connection]
            controller = Controller(store)
            controller.transport = mock.Mock()
            controller.transport.return_value.redactor.text.side_effect = lambda text: text
            controller.retry_call = mock.Mock(side_effect=[{"version": VERSION, "fingerprint": "preview", "requires_archive": True, "installed": False, "architecture": "x86_64"}, {"id": "9" * 24, "state": "succeeded", "message": "verified"}])
            sent = []
            controller._submit_task = mock.Mock(side_effect=lambda c, wire, *args: sent.append(wire.copy()) or c)
            status, result = controller.execute(connection, {"operation": "deploy", "service": "exchange", "version": VERSION, "deployment_fingerprint": "preview"})
            self.assertEqual(status["state"], "succeeded")
            self.assertEqual(result, connection)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]["version"], VERSION)
            self.assertNotIn("release_sha256", sent[0])
            self.assertNotIn("release_archive", sent[0])
            self.assertLess(len(json.dumps(sent[0])), 1024)


if __name__ == "__main__":
    unittest.main()
