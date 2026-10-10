import importlib.util
from pathlib import Path
import queue
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "rename_account_gui.py"
SPEC = importlib.util.spec_from_file_location("rename_account_gui", MODULE_PATH)
GUI = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GUI)


class RenameAccountGuiTests(unittest.TestCase):
    def test_connection_state_persists_without_passwords(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "state.json"
            with mock.patch.object(GUI, "STATE_FILE", state_path):
                GUI.RenameAccountApp._save_connection_state(
                    "192.0.2.10", Path("/tmp/test-key"), "myadmin"
                )
                self.assertEqual(
                    GUI.RenameAccountApp._load_connection_state(),
                    {
                        "host": "192.0.2.10",
                        "key_path": "/tmp/test-key",
                        "ssh_user": "myadmin",
                    },
                )
                self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn("password", state_path.read_text(encoding="utf-8").lower())

    def test_terminal_command_quotes_key_path_and_uses_key_only_auth(self):
        command = GUI.RenameAccountApp._terminal_ssh_command(
            Path("/tmp/a key"), "myadmin", "192.0.2.10"
        )
        self.assertIn("-i '/tmp/a key'", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertTrue(command.endswith("myadmin@192.0.2.10"))

    def test_terminal_applescript_escapes_quotes_and_backslashes(self):
        applescript = GUI.RenameAccountApp._terminal_applescript('ssh -i "/tmp/key" host')
        self.assertIn('tell application "Terminal"', applescript)
        self.assertIn('\\"/tmp/key\\"', applescript)

    @mock.patch.object(GUI.time, "sleep")
    @mock.patch.object(GUI.subprocess, "run")
    def test_rename_worker_sends_secrets_only_over_stdin_and_verifies_new_login(self, run, sleep):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "Rename scheduled: account-rename-test\n", ""),
            subprocess.CompletedProcess([], 0, "uid=1001\nNEW_LOGIN_VERIFIED\n", ""),
        ]
        app = object.__new__(GUI.RenameAccountApp)
        app.status_queue = queue.Queue()

        app._rename_worker(
            "192.0.2.10",
            Path("/tmp/test-key"),
            "ubuntu",
            "old-secret",
            "myadmin",
            "new-secret-123456",
        )

        first_call = run.call_args_list[0]
        first_command = first_call.args[0]
        self.assertNotIn("old-secret", " ".join(first_command))
        self.assertNotIn("new-secret-123456", " ".join(first_command))
        self.assertEqual(
            first_call.kwargs["input"],
            "old-secret\nnew-secret-123456\nnew-secret-123456\nRENAME\n",
        )
        self.assertIn("--stdin-secrets", first_command)
        sleep.assert_called_once_with(GUI.SCHEDULE_GRACE_SECONDS)
        verification_command = run.call_args_list[1].args[0]
        self.assertIn("myadmin@192.0.2.10", verification_command)
        messages = []
        while not app.status_queue.empty():
            messages.append(app.status_queue.get_nowait())
        self.assertEqual(messages[-1][0], "success")


if __name__ == "__main__":
    unittest.main()
