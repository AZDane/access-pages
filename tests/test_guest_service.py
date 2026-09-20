import http.client
import importlib.util
import json
import os
import socket
import socketserver
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "guest_service.py"
SPEC = importlib.util.spec_from_file_location("guest_service", MODULE_PATH)
guest_service = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest_service)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


class GuestServiceTests(unittest.TestCase):
    def test_action_client_sends_only_access_pages_identifiers(self):
        payload = {
            "capability": "synthetic-page-capability-123456",
            "page_id": "guest", "grant_id": "grant_" + "g" * 16,
            "session": "synthetic-session-token-123456",
            "resource_id": "garden", "action_id": "turn_on",
            "parameters": {}, "proximity": None,
        }
        with (
            patch.object(guest_service, "_connect_broker") as connect,
            patch.object(guest_service.http.client, "HTTPResponse") as response_type,
        ):
            response = response_type.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "success": True, "page": "guest", "resource": "garden",
                "action": "turn_on",
            }).encode()
            status, result = guest_service._broker_guest_auth(
                "/broker-action", payload,
            )
            self.assertEqual((status, result["success"]), (200, True))
            sent = connect.return_value.__enter__.return_value.sendall.call_args.args[0]
            self.assertIn(b"POST /guest/v1/action", sent)
            for forbidden in (b"entity_id", b"service_data", b"grant_deadline"):
                self.assertNotIn(forbidden, sent)
            response.read.return_value = json.dumps({
                "success": True, "entity_id": "switch.garden",
            }).encode()
            with self.assertRaises(RuntimeError):
                guest_service._broker_guest_auth("/broker-action", payload)
        with self.assertRaises(ValueError):
            guest_service._broker_guest_auth("/broker-action", {
                **payload, "proximity": {"within_range": True},
            })

    def test_resource_state_client_sends_only_resource_id_and_rejects_raw_state(self):
        payload = {
            "capability": "synthetic-page-capability-123456",
            "page_id": "guest", "grant_id": "grant_" + "g" * 16,
            "session": "synthetic-session-token-123456",
            "resource_id": "temperature",
        }
        with (
            patch.object(guest_service, "_connect_broker") as connect,
            patch.object(guest_service.http.client, "HTTPResponse") as response_type,
        ):
            response = response_type.return_value
            response.status = 200
            response.read.return_value = json.dumps({
                "entity_id": "sensor.temperature",
                "state": "72", "attributes": {"private": "secret"},
            }).encode()
            with self.assertRaises(RuntimeError):
                guest_service._broker_guest_auth("/broker-resource-state", payload)
            sent = connect.return_value.__enter__.return_value.sendall.call_args.args[0]
            self.assertIn(b"POST /guest/v1/resource-state", sent)
            self.assertIn(b'"resource_id": "temperature"', sent)
            self.assertNotIn(b"entity_id", sent)
            response.read.return_value = json.dumps({
                "resource_id": "temperature", "state": "72",
                "state_attributes": {"unit_of_measurement": "F"},
            }).encode()
            status, result = guest_service._broker_guest_auth(
                "/broker-resource-state", payload,
            )
            self.assertEqual(status, 200)
            self.assertEqual(result["state"], "72")

    def test_health_only_and_headers_cannot_grant_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "http.sock")
            with socketserver.UnixStreamServer(
                path, guest_service.HealthHandler
            ) as server:
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    connection = UnixHTTPConnection(path)
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {
                        "status": "ready", "uid": os.getuid(),
                        "gid": os.getgid(),
                    })
                    connection.close()
                    with patch.object(guest_service, "_broker_health"):
                        connection = UnixHTTPConnection(path)
                        connection.request("GET", "/broker-health")
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.loads(response.read()), {
                            "status": "ready", "broker": "guest",
                        })
                        connection.close()
                    with patch.object(
                        guest_service, "_broker_health",
                        side_effect=RuntimeError("wrong broker"),
                    ):
                        connection = UnixHTTPConnection(path)
                        connection.request("GET", "/broker-health")
                        response = connection.getresponse()
                        self.assertEqual(response.status, 503)
                        response.read()
                        connection.close()
                    with patch.object(
                        guest_service, "_broker_page_identity",
                        return_value=(200, "guest"),
                    ) as identify:
                        connection = UnixHTTPConnection(path)
                        connection.request(
                            "POST", "/broker-page",
                            body=json.dumps({
                                "capability": "synthetic-page-capability-123456",
                                "page_id": "guest",
                            }),
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.loads(response.read()), {
                            "page_id": "guest",
                        })
                        connection.close()
                        identify.assert_called_once_with(
                            "synthetic-page-capability-123456", "guest"
                        )
                    with patch.object(guest_service, "_broker_page_identity") as identify:
                        connection = UnixHTTPConnection(path)
                        connection.request(
                            "POST", "/broker-page",
                            body='{"capability":"wrong","capability":"synthetic-page-capability-123456","page_id":"guest"}',
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, 400)
                        response.read()
                        connection.close()
                        identify.assert_not_called()
                    scoped = {
                        "page_id": "guest",
                        "grant_id": "grant_" + "g" * 16,
                        "expires_at": 2_000_000_000,
                        "status": "verification_required",
                        "session": "synthetic-session-token-123456",
                    }
                    with patch.object(
                        guest_service, "_broker_guest_auth",
                        return_value=(200, scoped),
                    ) as authorize:
                        connection = UnixHTTPConnection(path)
                        request = {
                            "capability": "synthetic-page-capability-123456",
                            "page_id": "guest",
                            "grant_id": "grant_" + "g" * 16,
                            "bootstrap": "synthetic-bootstrap-123456",
                        }
                        connection.request(
                            "POST", "/broker-bootstrap", body=json.dumps(request)
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(json.loads(response.read()), scoped)
                        connection.close()
                        authorize.assert_called_once_with(
                            "/broker-bootstrap", request
                        )
                    for method, route in (
                        ("GET", "/admin"),
                        ("GET", "/discovery"),
                        ("POST", "/policy/publish"),
                        ("GET", "/health?admin=1"),
                    ):
                        connection = UnixHTTPConnection(path)
                        connection.request(method, route, headers={
                            "Authorization": "Bearer forged-admin",
                            "X-Forwarded-User": "admin",
                            "X-Access-Pages-Role": "admin",
                        })
                        response = connection.getresponse()
                        self.assertEqual(response.status, 404)
                        response.read()
                        connection.close()
                finally:
                    server.shutdown()
                    thread.join()

    def test_directory_check_rejects_wrong_owner_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "guest"
            directory.mkdir(mode=0o700)
            guest_service._check_directory(
                directory, os.getuid(), os.getgid(), 0o700
            )
            with self.assertRaises(RuntimeError):
                guest_service._check_directory(directory, 2101, 2101, 0o700)
            directory.chmod(0o777)
            with self.assertRaises(RuntimeError):
                guest_service._check_directory(
                    directory, os.getuid(), os.getgid(), 0o700
                )
            link = Path(temporary) / "link"
            link.symlink_to(directory)
            with self.assertRaises(RuntimeError):
                guest_service._check_directory(
                    link, os.getuid(), os.getgid(), 0o777
                )

    def test_service_refuses_wrong_identity_before_binding(self):
        with patch.object(guest_service.os, "getuid", return_value=2100):
            with self.assertRaisesRegex(RuntimeError, "dedicated identity"):
                guest_service.main()

    def test_existing_socket_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            directory = parent / "guest"
            directory.mkdir(mode=0o700)
            socket_path = directory / "http.sock"
            socket_path.write_text("do not replace")
            with (
                patch.object(guest_service, "SOCKET_PATH", socket_path),
                patch.object(guest_service, "GUEST_UID", os.getuid()),
                patch.object(guest_service, "GUEST_GID", os.getgid()),
                patch.object(guest_service.os, "getgroups", return_value=[]),
                patch.object(guest_service, "_check_directory"),
            ):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    guest_service.main()
            self.assertEqual(socket_path.read_text(), "do not replace")
            self.assertTrue(stat.S_ISREG(socket_path.lstat().st_mode))
