import queue
import tempfile
import threading
import time
from pathlib import Path
from unittest import TestCase, mock

from linux_manager.connections import ManagedConnection, PersistentConnections
from linux_manager.controller import Controller
from linux_manager.gui import App
from linux_manager.models import Connection, ManagerError, Store
from linux_manager.transport import SSH


class PersistentConnectionTests(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.connection = Connection(host="fixture.invalid", username="fixture", password="fictional-password")
        self.states = []
        self.manager = PersistentConnections(self.states.append)
        self.addCleanup(self.manager.close)
        self.attempts = []
        self.drop = threading.Event()
        self.reconnected = threading.Event()

    def ssh(self, connection=None):
        value = SSH(connection or self.connection, Path(self.directory.name))
        value.trusted = mock.Mock(return_value=True)
        return value

    def live_attempt(self, session, config):
        self.attempts.append(session.token)
        session._state("connected")
        if len(self.attempts) == 1:
            while not session.stop_event.wait(0.01):
                if self.drop.is_set():
                    return "failed"
        else:
            self.reconnected.set()
            session.stop_event.wait()
        return "disconnected"

    def start(self):
        patch = mock.patch.object(ManagedConnection, "_attempt", lambda session, config: self.live_attempt(session, config))
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(ManagedConnection, "RETRY_DELAY", 0.01)
        patch.start(); self.addCleanup(patch.stop)
        return self.manager.connect(self.ssh())

    def test_repeated_connect_reuses_master_without_new_login(self):
        first = self.start()
        second = self.manager.connect(self.ssh())
        self.assertIs(first, second)
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(self.manager.control_path(self.connection), first.control_path)

    def test_temporary_drop_reconnects_without_submitting_any_remote_task(self):
        session = self.start(); self.drop.set()
        self.assertTrue(self.reconnected.wait(1))
        self.assertEqual(self.manager.status(self.connection)["state"], "connected")
        self.assertIn("reconnecting", [value["state"] for value in self.states])
        self.assertEqual(session.token, self.attempts[1])

    def test_manual_disconnect_stops_retries_and_cleans_socket_directory(self):
        session = self.start(); folder = Path(session.folder.name)
        self.manager.disconnect(self.connection.identifier); session.thread.join(1)
        self.assertTrue(session.stop_event.is_set())
        self.assertFalse(session.thread.is_alive()); self.assertFalse(folder.exists())
        self.assertEqual(len(self.attempts), 1)
        self.assertIsNone(self.manager.control_path(self.connection))

    def test_other_server_is_kept_when_one_is_disconnected(self):
        first = self.start()
        other = self.connection.changed(host="other.invalid", identifier=Connection().identifier)
        second = self.manager.connect(self.ssh(other))
        self.manager.disconnect(self.connection.identifier)
        self.assertTrue(first.stop_event.is_set()); self.assertFalse(second.stop_event.is_set())
        self.assertEqual(self.manager.status(other)["state"], "connected")

    def test_edited_credentials_cannot_borrow_old_authenticated_socket(self):
        old = self.start()
        changed = self.connection.changed(password="different-fictional-password")
        self.assertIsNone(self.manager.control_path(changed))
        new = self.manager.connect(self.ssh(changed))
        self.assertTrue(old.stop_event.is_set()); self.assertNotEqual(old.token, new.token)

    def test_authentication_or_identity_failure_stops_automatic_retries(self):
        for state in ["authentication_failed", "identity_changed"]:
            manager = PersistentConnections(); attempts = []
            def fail(session, config):
                attempts.append(True); return state
            with mock.patch.object(ManagedConnection, "_attempt", fail):
                with self.assertRaises(ManagerError): manager.connect(self.ssh())
            manager.close(); self.assertEqual(attempts, [True])
        self.assertEqual(ManagedConnection.failure_state("Permission denied (publickey)."), "authentication_failed")
        self.assertEqual(ManagedConnection.failure_state("Host key verification failed."), "identity_changed")

    def test_close_prevents_background_connect_from_resurrecting_connection(self):
        self.manager.close()
        with self.assertRaises(ManagerError): self.manager.connect(self.ssh())
        controller = Controller(Store(Path(self.directory.name)))
        controller.close_connections()
        with self.assertRaises(ManagerError): controller.keep_connection(self.connection)

    def test_fresh_security_verification_disables_all_connection_reuse(self):
        controller = Controller(Store(Path(self.directory.name)))
        controller.connections = mock.Mock()
        controller.connections.control_path.return_value = Path(self.directory.name) / "control.sock"
        reused = controller.transport(self.connection)
        fresh = controller.transport(self.connection, fresh=True)
        self.assertIsNotNone(reused.control_path); self.assertIsNone(fresh.control_path)
        text = fresh._config(Path(self.directory.name)).read_text()
        self.assertIn("ControlMaster no", text); self.assertIn("ControlPath none", text)
        self.assertIn("ServerAliveInterval 15", text); self.assertIn("StrictHostKeyChecking yes", text)


class ConnectionUiTests(TestCase):
    def test_connection_event_does_not_finish_or_unfreeze_current_task(self):
        app = object.__new__(App); app.events = queue.Queue(); app.busy = True
        app.buttons = [mock.Mock()]; app.input_states = []
        app._connection_changed = mock.Mock(); app.after = mock.Mock()
        app.events.put(("connection", {"state": "reconnecting"}, None))
        app._drain()
        self.assertTrue(app.busy); app.buttons[0].configure.assert_not_called()
        app._connection_changed.assert_called_once()

    def test_manual_disconnect_clears_readiness_but_keeps_saved_credentials(self):
        app = object.__new__(App); app.current = Connection(host="fixture.invalid")
        app.controller = mock.Mock(); app.store = mock.Mock(); app.report = {"fixture": True}
        app.fleet_states = {}; app._clear_account_view = mock.Mock(); app._render_fleet = mock.Mock()
        app._show_connection_state = mock.Mock(); app.status = mock.Mock()
        app._disconnect()
        app.controller.disconnect_connection.assert_called_once_with(app.current.identifier)
        app.store.save.assert_not_called(); app.store.remove.assert_not_called()
        self.assertIsNone(app.report)

    def test_late_event_from_replaced_session_does_not_change_current_badge(self):
        app = object.__new__(App); app.current = Connection(host="fixture.invalid"); app.profiles = [app.current]
        app.controller = mock.Mock(); app.controller.connection_status.return_value = {"token": "new-session"}
        app._show_connection_state = mock.Mock()
        app._connection_changed({"identifier": app.current.identifier, "token": "old-session", "state": "connected"})
        app._show_connection_state.assert_not_called()
