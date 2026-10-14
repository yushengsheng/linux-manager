import fcntl
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from linux_manager import gui

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / "scripts/启动本地最新版.applescript"


class LocalDataTests(unittest.TestCase):
    def test_desktop_data_flag_reuses_packaged_profile_directory(self):
        with mock.patch.object(sys, "argv", ["source", "--desktop-data"]), mock.patch.object(sys, "frozen", False, create=True):
            source_data = gui.data_directory()
        with mock.patch.object(sys, "argv", ["bundle"]), mock.patch.object(sys, "frozen", True, create=True):
            self.assertEqual(gui.data_directory(), source_data)
        self.assertEqual(source_data, Path.home() / "Library/Application Support/linux服务器管理")

    def test_unflagged_source_keeps_existing_separate_development_directory(self):
        with mock.patch.object(sys, "argv", ["source"]), mock.patch.object(sys, "frozen", False, create=True):
            self.assertEqual(gui.data_directory(), BASE / "data/linux-manager")

    def test_self_check_accepts_desktop_data_without_loading_profiles(self):
        with mock.patch.object(sys, "argv", ["source", "--desktop-data", "--self-check"]), mock.patch.object(gui, "Store") as store, mock.patch("builtins.print"):
            gui.main()
        store.assert_not_called()

    def test_self_check_reports_broken_tk_without_reading_credentials(self):
        with mock.patch.object(sys, 'argv', ['source', '--self-check']), mock.patch.object(gui.tk, 'Tk', side_effect=gui.tk.TclError('fixture broken Tk')), mock.patch.object(gui, 'Store') as store:
            with self.assertRaisesRegex(SystemExit, '图形界面'):
                gui.main()
        store.assert_not_called()

    def test_old_application_lock_prevents_another_source_window(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            with (directory / "application.lock").open("a") as existing:
                fcntl.flock(existing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with mock.patch.object(sys, "argv", ["source", "--desktop-data"]), mock.patch.object(gui, "data_directory", return_value=directory), mock.patch.object(gui, "App") as app, mock.patch.object(gui.messagebox, "showinfo") as show:
                    gui.main()
                app.assert_not_called()
                self.assertIn("已在运行", show.call_args.args[1])


@unittest.skipUnless(sys.platform == "darwin", "macOS 原生本地启动器")
class LocalLauncherTests(unittest.TestCase):
    def test_python_discovery_accepts_an_installed_runtime_without_an_architecture_specific_path(self):
        import os
        result = subprocess.run(['/bin/sh', str(BASE / 'scripts/find-python.sh'), str(BASE)],
                                env=os.environ | {'LINUX_MANAGER_PYTHON': sys.executable},
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), sys.executable)

    def test_native_entry_runs_current_source_without_a_packaged_main_app(self):
        with tempfile.TemporaryDirectory(prefix="lm-local- 中文'空格-", dir="/private/tmp") as folder:
            root = Path(folder)
            marker = root / "started"
            source = root / "linux服务器管理.py"
            source.write_text("from pathlib import Path\nimport sys\nPath(" + repr(str(marker)) + ").write_text(' '.join(sys.argv[1:])) if '--self-check' not in sys.argv else None\n")
            launcher = root / "启动本地最新版.app"
            script = root / "fixture.applescript"
            text = SOURCE.read_text()
            original = '        set pythonPath to do shell script "/bin/sh " & quoted form of (folderPath & "/scripts/find-python.sh") & " " & quoted form of folderPath'
            quoted = '"' + sys.executable.replace('\\', '\\\\').replace('"', '\\"') + '"'
            self.assertIn(original, text)
            script.write_text(text.replace(original, "        set pythonPath to " + quoted))
            subprocess.run(["/usr/bin/osacompile", "-o", str(launcher), str(script)], check=True, capture_output=True, timeout=15)
            subprocess.run(["/usr/bin/open", "-n", str(launcher)], check=True, capture_output=True, timeout=10)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and (not marker.is_file() or not marker.read_text()):
                time.sleep(0.1)
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.read_text(), "--desktop-data")
            self.assertFalse((root / "linux服务器管理.app").exists())
            self.assertNotIn("Terminal", text)
            self.assertIn("/usr/bin/screen -dmS", text)

    def test_missing_source_has_explicit_native_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="lm-local-missing-", dir="/private/tmp") as folder:
            root = Path(folder); marker = root / "error"
            text = SOURCE.read_text()
            original = '        display alert "本地最新版未能启动" message detail as critical'
            replacement = '        do shell script "/usr/bin/printf \'%s\\n\' " & quoted form of detail & " > " & quoted form of "' + str(marker) + '"'
            script = root / "fixture.applescript"
            script.write_text(text.replace(original, replacement))
            launcher = root / "启动本地最新版.app"
            subprocess.run(["/usr/bin/osacompile", "-o", str(launcher), str(script)], check=True, capture_output=True, timeout=15)
            subprocess.run(["/usr/bin/open", "-n", str(launcher)], check=True, capture_output=True, timeout=10)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and (not marker.is_file() or not marker.read_text()):
                time.sleep(0.1)
            self.assertIn("源码目录旁边", marker.read_text())


if __name__ == "__main__":
    unittest.main()
