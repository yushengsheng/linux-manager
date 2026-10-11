import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "scripts/启动linux服务器管理.applescript"


@unittest.skipUnless(sys.platform == "darwin", "macOS 原生启动器")
class DesktopLauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="linux-launcher-test- 空格'中文-", dir="/private/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.marker = self.root / "started"
        self.script = SOURCE.read_text()

    @staticmethod
    def quote(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def compile(self, text, target, name):
        source = self.root / (name + ".applescript")
        source.write_text(text)
        subprocess.run(["/usr/bin/osacompile", "-o", str(target), str(source)], check=True, capture_output=True, text=True, timeout=15)

    def launch_and_wait(self, launcher, marker, expect_content=False):
        subprocess.run(["/usr/bin/open", "-n", str(launcher)], check=True, capture_output=True, text=True, timeout=10)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if marker.exists() and (not expect_content or marker.stat().st_size > 0):
                return
            time.sleep(0.1)
        self.fail("原生启动器未在时限内产生预期结果")

    def test_all_absolute_system_tools_exist_and_are_executable(self):
        tools = re.findall(r'"(/(?:usr/)?bin/[^\s"]+)', self.script)
        self.assertTrue(tools)
        for tool in tools:
            self.assertTrue(Path(tool).is_file() and os.access(tool, os.X_OK), tool)
        self.assertIn("/bin/test", tools)

    def test_compiled_launcher_opens_sibling_app_with_unicode_spaces_and_quote(self):
        folder = self.root / "原位置"
        folder.mkdir()
        app = folder / "linux服务器管理.app"
        fixture = "on run\n    do shell script \"/usr/bin/touch \" & quoted form of " + self.quote(self.marker) + "\nend run\n"
        self.compile(fixture, app, "fixture")
        (app / "Contents/MacOS/linux服务器管理").symlink_to("applet")
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(app)], check=True, capture_output=True, text=True, timeout=10)
        launcher = folder / "启动linux服务器管理.app"
        self.compile(self.script, launcher, "launcher")
        moved = self.root / "移动后 空格与中文"
        folder.rename(moved)
        self.launch_and_wait(moved / launcher.name, self.marker)

    def diagnostic_launcher(self):
        # Replace only the alert in the fixture, avoiding unattended modal dialogs.
        marker = self.root / "failure"
        original = '        display alert "程序未能启动" message detail as critical'
        self.assertEqual(self.script.count(original), 1)
        replacement = '        do shell script "/usr/bin/printf \'%s\\n\' " & quoted form of detail & " > " & quoted form of ' + self.quote(marker)
        launcher = self.root / "启动linux服务器管理.app"
        self.compile(self.script.replace(original, replacement), launcher, "diagnostic")
        return launcher, marker

    def test_missing_app_reports_location_instead_of_generic_failure(self):
        launcher, marker = self.diagnostic_launcher()
        self.launch_and_wait(launcher, marker, expect_content=True)
        self.assertIn("未找到同一文件夹", marker.read_text())

    def test_open_failure_retains_stage_and_system_error(self):
        binary = self.root / "linux服务器管理.app/Contents/MacOS/linux服务器管理"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o700)
        self.script = self.script.replace(
            '        do shell script "/usr/bin/open " & quoted form of appPath',
            '        do shell script "/bin/sh -c \'exit 42\'"',
        )
        launcher, marker = self.diagnostic_launcher()
        self.launch_and_wait(launcher, marker, expect_content=True)
        detail = marker.read_text()
        self.assertIn("打开主程序失败", detail)
        self.assertIn("42", detail)

    def test_incomplete_app_reports_integrity_instead_of_location(self):
        (self.root / "linux服务器管理.app").mkdir()
        launcher, marker = self.diagnostic_launcher()
        self.launch_and_wait(launcher, marker, expect_content=True)
        self.assertIn("文件不完整或没有执行权限", marker.read_text())


if __name__ == "__main__":
    unittest.main()
