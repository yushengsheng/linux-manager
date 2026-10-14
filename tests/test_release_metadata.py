import json
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
        manifest = json.loads((self.bundle / 'Contents/Resources/build-manifest.json').read_text())
        self.assertEqual(manifest['version'], VERSION)
        self.assertEqual(manifest['sources'], build_desktop.source_hashes(build_desktop.BASE))
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

    def test_universal_build_rejects_a_single_architecture_python_before_writing(self):
        import types
        work = self.bundle.parent / 'not-created'
        with mock.patch.object(build_desktop.sys, 'argv', ['build_desktop.py', '--target-arch', 'universal2']), mock.patch.object(build_desktop.platform, 'system', return_value='Darwin'), mock.patch.object(build_desktop, 'WORK', work), mock.patch.object(build_desktop.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='arm64')):
            with self.assertRaisesRegex(SystemExit, 'universal2 Python'):
                build_desktop.main()
        self.assertFalse(work.exists())

    def test_rebuild_removes_stale_modules_and_excludes_cache_files(self):
        project = self.bundle.parent / 'project'; module = project / 'linux_manager'
        module.mkdir(parents=True); (module / 'current.py').write_text('current')
        (project / 'linux服务器管理.py').write_text('entry')
        cache = module / '__pycache__'; cache.mkdir(); (cache / 'current.pyc').write_bytes(b'cache')
        source = self.bundle.parent / 'source'; (source / 'linux_manager').mkdir(parents=True)
        (source / 'linux_manager/deleted.py').write_text('obsolete')
        with mock.patch.object(build_desktop, 'BASE', project):
            build_desktop.prepare_source(source)
        self.assertEqual(build_desktop.source_hashes(source), build_desktop.source_hashes(project))
        self.assertFalse((source / 'linux_manager/deleted.py').exists())
        self.assertFalse((source / 'linux_manager/__pycache__').exists())


if __name__ == "__main__":
    unittest.main()
