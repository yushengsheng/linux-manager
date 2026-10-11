from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.models import Connection, ManagerError
from linux_manager.terminal import open_terminal
from linux_manager.transport import SSH


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="lm-terminal- 中文'空格-", dir="/private/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.control = self.root / "control"
        self.control.touch()
        self.connection = Connection(label='测试服务器 "一"', host="terminal.invalid", username="fixture",
                                     password="fictional-login-password", sudo_password="fictional-sudo-password")
        self.ssh = SSH(self.connection, self.root, self.control)
        self.ssh.trusted = mock.Mock(return_value=True)
        patch = mock.patch("linux_manager.terminal.sys.platform", "darwin")
        patch.start(); self.addCleanup(patch.stop)

    def launch(self, returncode=0):
        with mock.patch("linux_manager.terminal.subprocess.run", return_value=mock.Mock(returncode=returncode)) as run:
            open_terminal(self.ssh)
        return run

    def test_interactive_shell_reuses_only_the_trusted_current_connection_without_exposing_credentials(self):
        run = self.launch()
        folder = next(self.root.glob("terminal-*"))
        config = folder / "connection.conf"
        launcher = folder / "terminal.command"
        command = shlex.split(launcher.read_text().splitlines()[-1])
        self.assertEqual(command[:3], ["/usr/bin/ssh", "-F", str(config)])
        self.assertIn("-tt", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("ProxyCommand=/usr/bin/false", command)
        self.assertEqual(command[-1], "linux-manager-server")
        self.assertIn(str(self.control), config.read_text())
        self.assertIn("StrictHostKeyChecking yes", config.read_text())
        source = run.call_args.kwargs["input"]
        self.assertEqual(run.call_args.args[0], ["/usr/bin/osascript", "-"])
        self.assertIn("do script \"exec /bin/sh ", source)
        for value in [self.connection.host, self.connection.username, self.connection.password, self.connection.sudo_password]:
            self.assertNotIn(value, source)
            self.assertNotIn(value, launcher.read_text())
        for path, mode in [(folder, 0o700), (config, 0o600), (launcher, 0o700)]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

    def test_disconnected_or_untrusted_server_cannot_open_a_terminal(self):
        for control, trusted in [(None, True), (self.root / "missing-control", True), (self.control, False)]:
            self.ssh.control_path = control
            self.ssh.trusted.return_value = trusted
            with mock.patch("linux_manager.terminal.subprocess.run") as run, self.assertRaises(ManagerError):
                open_terminal(self.ssh)
            run.assert_not_called()
        self.assertEqual(list(self.root.glob("terminal-*")), [])

    def test_native_launch_failure_cleans_only_its_own_helper_files(self):
        with self.assertRaises(ManagerError):
            self.launch(returncode=1)
        self.assertEqual(list(self.root.glob("terminal-*")), [])
        self.assertTrue(self.control.exists())

    def test_shell_exit_preserves_status_and_removes_only_temporary_terminal_config(self):
        self.launch()
        folder = next(self.root.glob("terminal-*"))
        launcher = folder / "terminal.command"
        source = launcher.read_text().splitlines()
        # Exercise the generated wrapper without opening a real SSH connection.
        source[-1] = "/bin/sh -c 'exit 37'"
        launcher.write_text("\n".join(source) + "\n")
        result = subprocess.run(["/bin/sh", str(launcher)], capture_output=True)
        self.assertEqual(result.returncode, 37)
        self.assertFalse(folder.exists())
        self.assertTrue(self.control.exists())

    def test_controller_uses_the_existing_transport_and_does_not_run_management_tasks(self):
        store = mock.Mock(directory=self.root)
        controller = Controller(store)
        controller.connections = mock.Mock()
        controller.connections.control_path.return_value = self.control
        with mock.patch("linux_manager.terminal.open_terminal") as launch:
            controller.open_terminal(self.connection)
        ssh = launch.call_args.args[0]
        self.assertIs(ssh.connection, self.connection)
        self.assertEqual(ssh.control_path, self.control)
        controller.connections.connect.assert_not_called()
        store.record.assert_not_called()


class TerminalActionTests(unittest.TestCase):
    def test_launch_uses_the_existing_worker_and_pins_the_selected_server(self):
        app = object.__new__(App)
        connection = Connection(host="one.invalid", username="fixture")
        app.current = connection; app.busy = False
        app._ready = mock.Mock(return_value=True)
        app._run = mock.Mock(); app.controller = mock.Mock(); app.status = mock.Mock()
        app._open_terminal()
        app.current = Connection(host="two.invalid", username="fixture")
        worker, callback = app._run.call_args.args[:2]
        worker(); callback(None)
        app.controller.open_terminal.assert_called_once_with(connection)

    def test_busy_or_disconnected_application_cannot_launch(self):
        app = object.__new__(App)
        app._run = mock.Mock(); app._ready = mock.Mock(return_value=False)
        app.busy = True; app._open_terminal(); app._ready.assert_not_called()
        app.busy = False; app._open_terminal(); app._run.assert_not_called()
