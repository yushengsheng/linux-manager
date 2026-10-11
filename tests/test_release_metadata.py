import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from linux_manager import VERSION
from tools import build_desktop


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lm-release-metadata-")
        self.addCleanup(directory.cleanup)
        self.bundle = Path(directory.name) / "fixture.app"
        self.info = self.bundle / "Contents/Info.plist"
        self.info.parent.mkdir(parents=True)
        self.info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "local.fixture.desktop", "CFBundleExecutable": "fixture", "CFBundleShortVersionString": "0.0.0"}))

    def test_native_version_matches_source_and_signature_is_verified(self):
        with mock.patch.object(build_desktop, "run") as run:
            build_desktop.configure_bundle(self.bundle)
        metadata = plistlib.loads(self.info.read_bytes())
        self.assertEqual(metadata["CFBundleShortVersionString"], VERSION)
        self.assertEqual(metadata["CFBundleVersion"], VERSION)
        self.assertEqual(metadata["LSMinimumSystemVersion"], "11.0")
        self.assertEqual(metadata["CFBundleIdentifier"], "local.fixture.desktop")
        self.assertEqual(metadata["CFBundleExecutable"], "fixture")
        self.assertEqual(run.call_args_list, [
            mock.call(["codesign", "--force", "--sign", "-", str(self.bundle)], timeout=60),
            mock.call(["codesign", "--verify", "--deep", "--strict", str(self.bundle)], timeout=60),
        ])

    def test_signing_failure_stops_build_without_claiming_valid_signature(self):
        with mock.patch.object(build_desktop, "run", side_effect=SystemExit("fixture-sign-failure")) as run:
            with self.assertRaises(SystemExit):
                build_desktop.configure_bundle(self.bundle)
        run.assert_called_once()

    def test_missing_metadata_is_a_failure_not_a_guess(self):
        self.info.unlink()
        with mock.patch.object(build_desktop, "run") as run:
            with self.assertRaises(FileNotFoundError):
                build_desktop.configure_bundle(self.bundle)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
