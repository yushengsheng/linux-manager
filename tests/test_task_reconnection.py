import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_linux_manager import REMOTE, MemoryVault
from linux_manager.controller import Controller
from linux_manager.models import Connection, ManagerError, Redactor, Store, atomic_private
from linux_manager.transport import AuthenticationFailed, ConnectionInterrupted, SSH


class SubmissionReceiptTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        patch = mock.patch.object(REMOTE, "ROOT", self.root)
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(REMOTE, "command", return_value=subprocess.CompletedProcess([], 0, "", ""))
        self.command = patch.start(); self.addCleanup(patch.stop)
        self.identifier = "a" * 24

    def test_same_request_is_started_once_even_when_queued(self):
        params = {"operation": "updates", "enabled": True}
        for _ in range(2):
            self.assertEqual(REMOTE.start_task(params, self.identifier)["task_id"], self.identifier)
        self.command.assert_called_once()

    def test_duplicate_terminal_task_does_not_depend_on_deleted_secret_request(self):
        params = {"operation": "password", "username": "fixture", "new_password": "fictional-password"}
        REMOTE.start_task(params, self.identifier)
        task = self.root / "tasks" / self.identifier
        (task / "request.json").unlink()
        status = REMOTE.status_task(self.identifier)
        status["state"] = "succeeded"
        REMOTE.write_json(task / "status.json", status)
        REMOTE.start_task(params, self.identifier)
        self.command.assert_called_once()
        self.assertNotIn(params["new_password"], (task / "submission.json").read_text())
        self.assertNotIn("digest", (task / "status.json").read_text())
        self.assertEqual((task / "submission.json").stat().st_mode & 0o777, 0o600)

    def test_same_id_cannot_accept_a_different_operation_or_secret(self):
        params = {"operation": "password", "username": "fixture", "new_password": "fictional-password"}
        REMOTE.start_task(params, self.identifier)
        for changes in [{"operation": "updates"}, {"new_password": "fictional-other-password"}]:
            with self.assertRaises(REMOTE.OperationError):
                REMOTE.start_task(params | changes, self.identifier)
        self.command.assert_called_once()

    def test_duplicate_failed_launch_does_not_launch_again(self):
        self.command.side_effect = REMOTE.OperationError("fixture-launch-error")
        params = {"operation": "updates"}
        with self.assertRaises(REMOTE.OperationError): REMOTE.start_task(params, self.identifier)
        self.assertEqual(REMOTE.start_task(params, self.identifier)["task_id"], self.identifier)
        self.assertEqual(REMOTE.status_task(self.identifier)["state"], "failed")
        self.command.assert_called_once()

    def test_parallel_repeats_return_the_same_task_and_one_launch(self):
        with ThreadPoolExecutor(max_workers=3) as pool:
            ids = list(pool.map(lambda _: REMOTE.start_task({"operation": "updates"}, self.identifier)["task_id"], range(3)))
        self.assertEqual(ids, [self.identifier] * 3)
        self.command.assert_called_once()

    def test_archive_replay_is_verified_without_creating_another_job(self):
        content = b"fixture-release"
        params = {"operation": "deploy", "version": "v1.1.99", "release_archive": base64.b64encode(content).decode(), "release_sha256": REMOTE.hashlib.sha256(content).hexdigest()}
        REMOTE.start_task(params, self.identifier)
        REMOTE.start_task(params, self.identifier)
        self.command.assert_called_once()

    def test_invalid_client_id_and_incomplete_receipt_do_not_launch(self):
        with self.assertRaises(REMOTE.OperationError): REMOTE.start_task({"operation": "updates"}, "../escape")
        (self.root / "tasks" / self.identifier).mkdir(parents=True)
        with self.assertRaises(REMOTE.OperationError): REMOTE.start_task({"operation": "updates"}, self.identifier)
        self.command.assert_not_called()

    def test_receipt_lookup_does_not_depend_on_the_latest_fifty_task_list(self):
        params = {"operation": "updates"}
        REMOTE.start_task(params, self.identifier)
        with mock.patch.object(REMOTE, "task_list", return_value=[{"state": "running"}]):
            REMOTE.start_task(params, self.identifier)
        self.command.assert_called_once()

    def test_lookup_distinguishes_absent_from_a_real_task(self):
        with mock.patch.object(REMOTE.os, "geteuid", return_value=0):
            self.assertEqual(REMOTE.dispatch({"action": "task_lookup", "task_id": self.identifier}), {"task": None})
            REMOTE.start_task({"operation": "updates"}, self.identifier)
            task = REMOTE.dispatch({"action": "task_lookup", "task_id": self.identifier})["task"]
            self.assertEqual(task["state"], "queued")

    def test_confirmation_replay_keeps_original_timestamp_and_never_recovers(self):
        REMOTE.start_task({"operation": "prepare_key"}, self.identifier)
        task = self.root / "tasks" / self.identifier
        status = REMOTE.status_task(self.identifier) | {"state": "awaiting_verification"}
        REMOTE.write_json(task / "status.json", status)
        with mock.patch.object(REMOTE, "restore_files") as restore:
            first = REMOTE.confirm_task(self.identifier)
            second = REMOTE.confirm_task(self.identifier)
            REMOTE.recover(self.identifier)
        self.assertEqual(first, second)
        self.assertEqual(second["state"], "succeeded")
        restore.assert_not_called()

    def test_recovery_winning_race_cannot_be_confirmed_or_resubmitted(self):
        params = {"operation": "prepare_key"}
        REMOTE.start_task(params, self.identifier)
        status = REMOTE.status_task(self.identifier) | {"state": "rolled_back"}
        REMOTE.write_json(self.root / "tasks" / self.identifier / "status.json", status)
        with self.assertRaises(REMOTE.OperationError): REMOTE.confirm_task(self.identifier)
        REMOTE.start_task(params, self.identifier)
        self.command.assert_called_once()


class ControllerReconnectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.store = Store(self.root, MemoryVault())
        self.connection = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        self.store.save([self.connection])
        self.controller = Controller(self.store)
        self.ssh = mock.Mock(); self.ssh.redactor = Redactor()
        self.controller.transport = mock.Mock(return_value=self.ssh)
        self.controller.trust_same_server = mock.Mock()
        self.identifier = "a" * 24
        patch = mock.patch("linux_manager.controller.secrets.token_hex", return_value=self.identifier)
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch("linux_manager.controller.time.sleep")
        patch.start(); self.addCleanup(patch.stop)
        self.success = {"id": self.identifier, "state": "succeeded", "message": "fixture-success", "operation": "updates"}
        self.progress = []

    def execute(self, params=None):
        return self.controller.execute(self.connection, params or {"operation": "updates", "enabled": True}, self.progress.append)

    def actions(self):
        return [call.args[0]["action"] for call in self.ssh.call.call_args_list]

    def test_lost_submission_response_reads_receipt_without_resubmitting(self):
        self.ssh.call.side_effect = [ConnectionInterrupted("fixture-loss"), {"task": self.success}, self.success]
        status, _ = self.execute()
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(self.actions(), ["start", "task_lookup", "task"])
        self.assertEqual(self.store.history()[0]["state"], "submission_unknown")
        self.assertTrue(all(call.args[0].get("task_id") == self.identifier for call in self.ssh.call.call_args_list))

    def test_failure_before_submission_reuses_exact_id_and_payload(self):
        self.ssh.call.side_effect = [ConnectionInterrupted("fixture-loss"), {"task": None}, {"task_id": self.identifier}, self.success]
        self.execute()
        self.assertEqual(self.actions(), ["start", "task_lookup", "start", "task"])
        self.assertEqual(self.ssh.call.call_args_list[0], self.ssh.call.call_args_list[2])

    def test_unreachable_receipt_is_bounded_and_never_resends_unknown_mutation(self):
        self.ssh.call.side_effect = ConnectionInterrupted("fixture-loss")
        with self.assertRaises(ConnectionInterrupted): self.execute()
        self.assertEqual(self.actions().count("start"), 1)
        self.assertEqual(self.actions().count("task_lookup"), self.controller.CONNECTION_ATTEMPTS)
        self.assertEqual(self.store.history()[-1]["task_id"], self.identifier)

    def test_poll_retry_does_not_need_a_persistent_connection(self):
        self.ssh.call.side_effect = [{"task_id": self.identifier}, ConnectionInterrupted("fixture-loss"), self.success]
        self.execute()
        self.assertIsNone(self.controller.connections)
        self.assertEqual(self.actions().count("start"), 1)
        self.assertTrue(all(call.kwargs.get("fresh") for call in self.controller.transport.call_args_list))

    def test_unknown_submission_is_visible_only_in_its_own_server_records(self):
        self.store.record({"task_id": self.identifier, "server_id": self.connection.identifier, "operation": "updates", "state": "submission_unknown"})
        self.store.record({"task_id": "b" * 24, "server_id": "c" * 16, "operation": "updates", "state": "submission_unknown"})
        self.ssh.call.return_value = {"tasks": []}
        self.ssh.call.side_effect = None
        tasks = self.controller.tasks(self.connection)["tasks"]
        self.assertEqual([task["id"] for task in tasks], [self.identifier])
        self.assertEqual(tasks[0]["state"], "submission_unknown")

    def test_unknown_submission_is_replaced_by_received_server_result(self):
        self.store.record({"task_id": self.identifier, "server_id": self.connection.identifier, "operation": "updates", "state": "submission_unknown"})
        self.ssh.call.return_value = {"tasks": [self.success]}
        self.ssh.call.side_effect = None
        self.assertEqual(self.controller.tasks(self.connection)["tasks"], [self.success])
        self.assertEqual(self.store.history()[-1]["state"], "succeeded")

    def test_authentication_failure_and_identity_error_stop_without_retries(self):
        for error in [AuthenticationFailed("fixture-auth"), ManagerError("fixture-identity")]:
            self.ssh.call.reset_mock(); self.ssh.call.side_effect = error
            with self.assertRaises(ManagerError): self.execute()
            self.assertEqual(self.actions(), ["start"])

    def test_confirmation_response_loss_retries_confirm_not_account_mutation(self):
        pending = self.success | {"state": "awaiting_verification", "operation": "prepare_key", "result": {}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, pending, {"root_access": True}, ConnectionInterrupted("fixture-confirm-loss"), self.success]
        self.execute({"operation": "prepare_key", "username": "fixture", "public_key": "ssh-ed25519 AAAA"})
        self.assertEqual(self.actions(), ["start", "task", "ping", "confirm", "confirm"])
        self.assertEqual(self.store.history()[-1]["state"], "succeeded")

    def test_all_confirmation_replies_lost_can_be_reconciled_by_reading_committed_state(self):
        pending = self.success | {"state": "awaiting_verification", "result": {}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, pending, {}] + [ConnectionInterrupted("fixture-confirm-loss")] * self.controller.CONNECTION_ATTEMPTS + [self.success]
        status, _ = self.execute()
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(self.actions().count("start"), 1)
        self.assertEqual(self.actions().count("confirm"), self.controller.CONNECTION_ATTEMPTS)
        self.assertEqual(self.actions()[-1], "task")

    def test_wrong_submission_receipt_stops_without_a_second_start(self):
        self.ssh.call.side_effect = [ConnectionInterrupted("fixture-loss"), {"task": self.success | {"id": "b" * 24}}]
        with self.assertRaises(ManagerError): self.execute()
        self.assertEqual(self.actions(), ["start", "task_lookup"])

    def test_terminal_result_read_loss_is_retried_without_an_extra_confirmation_read(self):
        pending = self.success | {"state": "awaiting_verification", "result": {}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, ConnectionInterrupted("fixture-read-loss"), pending, {}, self.success]
        self.execute()
        self.assertEqual(self.actions(), ["start", "task", "task", "ping", "confirm"])

    def test_rename_uses_new_login_after_old_authentication_fails_only_once(self):
        requests = []
        old = self.connection
        new = old.changed(username="changed")
        def transport(connection, fresh=False):
            ssh = mock.Mock(); ssh.redactor = Redactor()
            def call(request, **kwargs):
                action = request["action"]; requests.append((connection.username, action))
                if action == "start": return {"task_id": self.identifier}
                if action == "task" and connection.username == old.username: raise AuthenticationFailed("fixture-retired-login")
                if action == "task":
                    count = sum(pair == ("changed", "task") for pair in requests)
                    return self.success | {"state": "running" if count == 1 else "awaiting_verification", "result": {"verification": {"username": "changed"}}}
                if action == "ping": return {}
                return self.success
            ssh.call.side_effect = call
            return ssh
        self.controller.transport.side_effect = transport
        self.controller.connections = mock.Mock()
        status, updated = self.execute({"operation": "rename_user", "old_username": "fixture", "new_username": "changed"})
        self.assertEqual(updated.username, new.username)
        self.assertEqual(requests.count((old.username, "task")), 1)
        self.assertEqual(requests.count((new.username, "task")), 2)
        self.assertEqual(self.store.profiles()[0].username, new.username)
        self.controller.connections.disconnect.assert_called_with(old.identifier)

    def test_credential_migration_disconnects_only_owned_master_before_submission(self):
        sequence = []
        self.controller.disconnect_connection = mock.Mock(side_effect=lambda identifier: sequence.append("disconnect"))
        def call(request, **kwargs):
            sequence.append(request["action"])
            return {"task_id": self.identifier} if request["action"] == "start" else self.success
        self.ssh.call.side_effect = call
        self.execute({"operation": "retire_key", "username": "fixture", "public_key": "ssh-ed25519 AAAA", "old_public_key": "ssh-ed25519 BBBB"})
        self.assertEqual(sequence[:2], ["disconnect", "start"])
        self.controller.disconnect_connection.assert_called_once_with(self.connection.identifier)

    def test_verified_new_login_is_saved_even_if_final_history_write_fails(self):
        pending = self.success | {"state": "awaiting_verification", "result": {"verification": {"username": "changed"}}}
        self.ssh.call.side_effect = [{"task_id": self.identifier}, pending, {}, self.success]
        record = self.store.record
        def fail(item):
            if item["state"] == "succeeded": raise OSError("fixture-disk-error")
            record(item)
        self.store.record = fail
        with self.assertRaises(OSError):
            self.execute({"operation": "rename_user", "old_username": "fixture", "new_username": "changed"})
        self.assertEqual(self.store.profiles()[0].username, "changed")

    def test_verification_rejects_wrong_confirmation_or_rolled_back_task(self):
        for answer in [self.success | {"id": "b" * 24}, self.success | {"state": "rolled_back"}]:
            self.ssh.call.reset_mock()
            self.ssh.call.side_effect = [{}, answer]
            with self.assertRaises(ManagerError):
                self.controller.verify_task(self.connection, self.identifier, {"operation": "updates"}, {"result": {}})
            self.assertEqual(self.actions(), ["ping", "confirm"])

    def test_verification_authentication_failure_stops_immediately(self):
        self.ssh.call.side_effect = AuthenticationFailed("fixture-auth")
        with self.assertRaises(ManagerError):
            self.controller.verify_task(self.connection, self.identifier, {"operation": "updates"}, {})
        self.assertEqual(self.actions(), ["ping"])

    def test_security_plan_continues_after_submission_and_confirmation_loss(self):
        jobs = {}; mutations = []; lost_start = False; lost_confirm = False
        def call(request, **kwargs):
            nonlocal lost_start, lost_confirm
            action = request["action"]
            if action == "security_preflight": return {"compatible": True}
            if action == "start":
                identifier = request["task_id"]
                operation = request["params"]["operation"]
                if identifier not in jobs:
                    mutations.append(operation)
                    jobs[identifier] = {"id": identifier, "operation": operation, "state": "awaiting_verification" if operation != "updates" else "succeeded", "message": "fixture-result", "result": {}}
                if operation == "fail2ban" and not lost_start:
                    lost_start = True; raise ConnectionInterrupted("fixture-submit-loss")
                return {"task_id": identifier}
            if action == "task_lookup": return {"task": jobs.get(request["task_id"])}
            if action == "task": return dict(jobs[request["task_id"]])
            if action == "ping": return {}
            if action == "confirm":
                task = jobs[request["task_id"]]; task["state"] = "succeeded"
                if task["operation"] == "retire_key" and not lost_confirm:
                    lost_confirm = True; raise ConnectionInterrupted("fixture-confirm-loss")
                return dict(task)
            self.fail("unexpected action")
        self.ssh.call.side_effect = call
        self.controller.generate_key = mock.Mock(return_value=("fixture-new-key", "ssh-ed25519 AAAA"))
        self.controller.public_key = mock.Mock(return_value="ssh-ed25519 BBBB")
        original = self.connection.changed(auth="key", key_path="fixture-old-key", key_passphrase="fictional-original-phrase")
        identifiers = [format(i, "024x") for i in range(1, 20)]
        with mock.patch("linux_manager.controller.secrets.token_hex", side_effect=identifiers):
            result = self.controller.security_plan(original, {"mode": "rename", "username": "changed", "retire_old_key": True}, self.progress.append)
        self.assertTrue(result["complete"])
        self.assertEqual(mutations, ["prepare_key", "rename_user", "login_policy", "retire_key", "fail2ban", "updates"])
        self.assertEqual(len(result["stages"]), 6)
        self.assertTrue(lost_start and lost_confirm)


class TransportDiagnosticTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.connection = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        self.ssh = SSH(self.connection, self.root)
        self.ssh.trusted = mock.Mock(return_value=True)
        self.identifier = "a" * 24

    def test_no_result_records_only_fixed_private_metadata(self):
        response = subprocess.CompletedProcess([], 255, "", "Connection reset fixture@fixture.invalid fictional-password token=fictional-token")
        with mock.patch("linux_manager.transport.subprocess.run", return_value=response):
            with self.assertRaises(ConnectionInterrupted): self.ssh.call({"action": "start", "task_id": self.identifier, "params": {"password": "fictional-other-secret"}})
        path = self.root / "transport-error.json"
        data = json.loads(path.read_text())
        self.assertEqual(data["reason"], "connection_reset")
        self.assertEqual(data["task_id"], self.identifier)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for value in ["fixture", "fictional-password", "fictional-token", "fictional-other-secret"]:
            self.assertNotIn(value, path.read_text())

    def test_timeout_has_a_private_diagnostic(self):
        with mock.patch("linux_manager.transport.subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 1)):
            with self.assertRaises(ConnectionInterrupted): self.ssh.call({"action": "task", "task_id": self.identifier})
        self.assertEqual(json.loads((self.root / "transport-error.json").read_text())["reason"], "timeout")

    def test_malformed_response_is_bounded_instead_of_crashing_parser(self):
        for raw in ['[]', 'null', '{"ok":true,"data":[]}', '{"ok":"true"}']:
            response = subprocess.CompletedProcess([], 0, "LM_RESULT:" + raw, "")
            with mock.patch("linux_manager.transport.subprocess.run", return_value=response):
                with self.assertRaises(ConnectionInterrupted): self.ssh.call({"action": "ping"})

    def test_identity_authentication_and_bootstrap_failures_are_not_retryable(self):
        for diagnostic in ["Host key verification failed.", "Permission denied (publickey).", "Traceback (most recent call last): fixture-private-detail"]:
            with mock.patch("linux_manager.transport.subprocess.run", return_value=subprocess.CompletedProcess([], 255, "", diagnostic)):
                with self.assertRaises(ManagerError) as caught: self.ssh.call({"action": "ping"})
            self.assertNotIsInstance(caught.exception, ConnectionInterrupted)
            self.assertNotIn("fixture-private-detail", str(caught.exception))

    def test_diagnostic_write_failure_is_visible_without_masking_transport_failure(self):
        def write(path, text):
            if path.name == "transport-error.json": raise OSError("fixture-write")
            atomic_private(path, text)
        with mock.patch("linux_manager.transport.subprocess.run", return_value=subprocess.CompletedProcess([], 255, "", "Connection reset")), mock.patch("linux_manager.transport.atomic_private", side_effect=write):
            with self.assertRaisesRegex(ConnectionInterrupted, "诊断未能保存"): self.ssh.call({"action": "ping"})


if __name__ == "__main__":
    unittest.main()
