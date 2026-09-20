import os
import http.client
import json
import sqlite3
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from unittest.mock import Mock, patch
from contextlib import ExitStack

os.environ.setdefault("HA_BROKER_TOKEN", "synthetic-broker-token")
os.environ.setdefault("HA_BROKER_ADMIN_TOKEN", "synthetic-admin-broker-token")
os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-owner-token")

import ha_broker
import server as gateway_server
from ha import BrokerHomeAssistantClient, HomeAssistantError
from layerv import LayerVError
from pages import PageStore
from verification import VerificationStore


class HomeAssistantBrokerPolicyTests(unittest.TestCase):
    def test_guest_page_capability_resolves_only_one_current_page(self):
        token = "synthetic-page-capability-123456"
        registry = Path(self.temporary.name) / "guest-registry.json"
        registry.write_text(json.dumps({
            "guest": sha256(token.encode()).hexdigest(),
        }))
        with (
            patch("ha_broker.GUEST_CAPABILITY_REGISTRY", registry),
            patch("ha_broker.PAGE_STORE", self.store),
        ):
            self.assertEqual(ha_broker._guest_page_identity(token), "guest")
            for supplied in ("", "bad", "unknown-capability-123456", "bad\nheader"):
                self.assertEqual(ha_broker._guest_page_identity(supplied), "")
            registry.write_text(json.dumps({
                "guest": sha256(token.encode()).hexdigest(),
                "other": sha256(token.encode()).hexdigest(),
            }))
            self.assertEqual(ha_broker._guest_page_identity(token), "")
            registry.write_text(
                '{"guest":"' + sha256(b"other-capability-123456").hexdigest()
                + '","guest":"' + sha256(token.encode()).hexdigest() + '"}'
            )
            self.assertEqual(ha_broker._guest_page_identity(token), "")
            registry.write_text(json.dumps({
                "guest": sha256(token.encode()).hexdigest(),
            }))
            self.store.delete("guest")
            self.assertEqual(ha_broker._guest_page_identity(token), "")
            registry.write_text("{}")
            self.assertEqual(ha_broker._guest_page_identity(token), "")
            registry.write_text("not json")
            self.assertEqual(ha_broker._guest_page_identity(token), "")

    def test_guest_socket_page_identity_has_no_ha_authority(self):
        token = "synthetic-page-capability-123456"
        registry = Path(self.temporary.name) / "guest-registry.json"
        registry.write_text(json.dumps({
            "guest": sha256(token.encode()).hexdigest(),
        }))
        path = str(Path(self.temporary.name) / "broker.sock")
        with (
            patch("ha_broker.GUEST_PEER_UID", os.getuid()),
            patch("ha_broker.GUEST_CAPABILITY_REGISTRY", registry),
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT") as client,
            ha_broker.GuestSocketServer(path, ha_broker.GuestHandler) as server,
        ):
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                for supplied, claim, route, expected in (
                    (token, "guest", "/guest/v1/page-identity", 200),
                    (token, "other", "/guest/v1/page-identity", 403),
                    ("unknown-capability-123456", "guest", "/guest/v1/page-identity", 401),
                    ("", "guest", "/guest/v1/page-identity", 401),
                    (token, "guest", "/v1/states", 404),
                    (token, "guest", "/v1/page-action", 404),
                    (token, "guest", "/v1/discovery", 404),
                    (token, "guest", "/v1/send-notification", 404),
                ):
                    with self.subTest(supplied=supplied, claim=claim, route=route):
                        connection = socket.socket(socket.AF_UNIX)
                        connection.connect(path)
                        request = (
                            f"POST {route} HTTP/1.1\r\n"
                            "Host: broker\r\n"
                            "X-Broker-Role: admin\r\n"
                            "X-Broker-Token: synthetic-admin-broker-token\r\n"
                            f"X-Page-Capability: {supplied}\r\n"
                            f"X-Access-Pages-Page-ID: {claim}\r\n"
                            "Content-Length: 0\r\n\r\n"
                        ).encode()
                        connection.sendall(request)
                        response = http.client.HTTPResponse(connection)
                        response.begin()
                        self.assertEqual(response.status, expected)
                        body = response.read()
                        if expected == 200:
                            self.assertEqual(json.loads(body), {"page_id": "guest"})
                        connection.close()
                client.assert_not_called()
            finally:
                server.shutdown()
                thread.join()

    def test_guest_socket_rejects_admin_routes_and_forged_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "broker.sock")
            with patch("ha_broker.GUEST_PEER_UID", os.getuid()):
                with ha_broker.GuestSocketServer(
                    path, ha_broker.GuestHandler
                ) as server:
                    thread = threading.Thread(target=server.serve_forever)
                    thread.start()
                    try:
                        for method, route in (
                            ("GET", "/guest/v1/health"),
                            ("POST", "/v1/discovery"),
                            ("POST", "/v1/notification-targets"),
                            ("POST", "/v1/send-notification"),
                            ("POST", "/v1/page-action"),
                            ("POST", "/v1/states"),
                            ("POST", "/v1/policy/publish"),
                            ("GET", "/v1/discovery"),
                            ("GET", "/guest/v1/health?role=admin"),
                        ):
                            with self.subTest(method=method, route=route):
                                connection = socket.socket(socket.AF_UNIX)
                                connection.connect(path)
                                request = (
                                    f"{method} {route} HTTP/1.1\r\n"
                                    "Host: broker\r\n"
                                    "X-Broker-Role: admin\r\n"
                                    "X-Broker-Token: synthetic-admin-broker-token\r\n"
                                    "Content-Length: 18\r\n\r\n"
                                    '{"page_id":"all"}'
                                ).encode()
                                connection.sendall(request)
                                response = http.client.HTTPResponse(connection)
                                response.begin()
                                self.assertEqual(
                                    response.status,
                                    200 if route == "/guest/v1/health" else 404,
                                )
                                response.read()
                                connection.close()
                    finally:
                        server.shutdown()
                        thread.join()

    def test_guest_socket_rejects_wrong_peer_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "broker.sock")
            with patch("ha_broker.GUEST_PEER_UID", os.getuid() + 1):
                with ha_broker.GuestSocketServer(
                    path, ha_broker.GuestHandler
                ) as server:
                    thread = threading.Thread(target=server.serve_forever)
                    thread.start()
                    try:
                        connection = socket.socket(socket.AF_UNIX)
                        connection.connect(path)
                        connection.sendall(
                            b"POST /guest/v1/page-identity HTTP/1.1\r\n"
                            b"Host: broker\r\n"
                            b"X-Page-Capability: synthetic-page-capability-123456\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        try:
                            self.assertEqual(connection.recv(1024), b"")
                        except ConnectionResetError:
                            pass
                        connection.close()
                    finally:
                        server.shutdown()
                        thread.join()

    def test_admin_tcp_discovery_still_uses_admin_token(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), ha_broker.Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with patch("ha_broker.HA_CLIENT") as client:
                    client.discover_entities.return_value = [{"entity_id": "light.one"}]
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", server.server_port
                    )
                    connection.request(
                        "POST", "/v1/discovery", body="{}", headers={
                            "X-Broker-Role": "admin",
                            "X-Broker-Token": "synthetic-admin-broker-token",
                        },
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"light.one", response.read())
                    connection.close()
                    client.discover_entities.assert_called_once_with(force=False)
            finally:
                server.shutdown()
                thread.join()

    def test_admin_cleanup_deletes_sessions_only_after_local_grant_removal(self):
        grant_id = "grant_" + "a" * 16
        secret = "bootstrap-secret-1234567890"
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        page = self.store.load("guest")
        page["access_grants"] = [{
            "id": grant_id, "label": "Guest", "token_hash": sha256(secret.encode()).hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires.isoformat(), "credential_flow": "bootstrap-v1",
            "verification_required": True,
        }]
        self.store.replace("guest", page)
        sessions = VerificationStore(Path(self.temporary.name) / "sessions.sqlite3")
        session, _ = sessions.consume_bootstrap(
            "guest", grant_id, secret, sha256(secret.encode()).hexdigest(), expires,
        )
        self.assertIsNotNone(sessions.guest_session_info(session, "guest"))
        with (
            patch("ha_broker.GUEST_GRANT_STORE", self.store),
            patch("ha_broker.GUEST_SESSION_STORE", sessions),
            ThreadingHTTPServer(("127.0.0.1", 0), ha_broker.Handler) as listener,
        ):
            thread = threading.Thread(target=listener.serve_forever)
            thread.start()
            client = BrokerHomeAssistantClient(
                f"http://127.0.0.1:{listener.server_port}",
                "synthetic-admin-broker-token", broker_role="admin",
            )
            try:
                with self.assertRaises(HomeAssistantError):
                    client.revoke_guest_sessions("guest", grant_id)
                self.assertIsNotNone(sessions.guest_session_info(session, "guest"))
                self.store.remove_access_grant("guest", grant_id)
                self.assertEqual(client.revoke_guest_sessions("guest", grant_id),
                                 {"success": True})
                self.assertIsNone(sessions.guest_session_info(session, "guest"))
            finally:
                listener.shutdown()
                thread.join()

    def test_connection_reset_cleans_broker_sessions_after_local_revocation(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pages = PageStore(root / "pages")
                sessions = VerificationStore(root / "sessions.sqlite3")
                expires = datetime.now(timezone.utc) + timedelta(hours=1)
                grants = []
                tokens = []
                for letter in ("a", "b"):
                    grant_id = "grant_" + letter * 16
                    secret = letter * 43
                    grants.append({
                        "id": grant_id, "label": letter,
                        "token_hash": sha256(secret.encode()).hexdigest(),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "expires_at": expires.isoformat(),
                        "credential_flow": "bootstrap-v1",
                        "verification_required": True,
                        "qurl_id": "q_" + letter,
                        "resource_id": "r_" + letter,
                    })
                    token, _ = sessions.consume_bootstrap(
                        "guest", grant_id, secret,
                        sha256(secret.encode()).hexdigest(), expires,
                    )
                    tokens.append(token)
                page = self.store.load("guest")
                page["access_grants"] = grants
                pages.create(page)
                code, _ = sessions.issue_guest_challenge(tokens[0], "guest", grants[0]["id"])
                sessions.verify_guest_challenge(
                    tokens[0], "guest", grants[0]["id"], code, int(expires.timestamp()),
                )
                sessions.issue_guest_challenge(tokens[1], "guest", grants[1]["id"])

                with (
                    patch("ha_broker.GUEST_GRANT_STORE", pages),
                    patch("ha_broker.GUEST_SESSION_STORE", sessions),
                    ThreadingHTTPServer(("127.0.0.1", 0), ha_broker.Handler) as listener,
                ):
                    thread = threading.Thread(target=listener.serve_forever)
                    thread.start()
                    client = BrokerHomeAssistantClient(
                        f"http://127.0.0.1:{listener.server_port}",
                        "synthetic-admin-broker-token", broker_role="admin",
                    )
                    remote = Mock()
                    if cleanup_fails:
                        remote.delete_qurl.side_effect = LayerVError("offline", status=503)
                    responses = []
                    handler = object.__new__(gateway_server.Handler)
                    handler._send_json = lambda status, payload: responses.append((status, payload))
                    try:
                        with ExitStack() as stack:
                            stack.enter_context(patch("server.PAGE_STORE", pages))
                            stack.enter_context(patch("server.HA_CLIENT", client))
                            stack.enter_context(patch("server.LAYERV_CLIENT", remote))
                            stack.enter_context(patch("server.ACTIVITY_STORE", Mock()))
                            stack.enter_context(patch("server.VERIFICATION_RECIPIENTS", Mock()))
                            stack.enter_context(patch("server.RESET_REQUEST_FILE", root / "reset.request"))
                            stack.enter_context(patch("server.audit"))
                            if cleanup_fails:
                                stack.enter_context(patch.object(
                                    client, "revoke_guest_sessions",
                                    side_effect=HomeAssistantError("offline"),
                                ))
                            handler._reset_layer_v_connection({"confirmation": "RESET"})
                            self.assertEqual(pages.load("guest")["access_grants"], [])
                            for grant, token in zip(grants, tokens):
                                self.assertIsNone(ha_broker._guest_session_status(
                                    "guest", grant["id"], token,
                                ))
                                self.assertEqual(
                                    sessions.guest_session_info(token, "guest") is None,
                                    not cleanup_fails,
                                )
                            if not cleanup_fails:
                                with sqlite3.connect(sessions.path) as db:
                                    for table in ("guest_sessions", "guest_challenges", "guest_verifications"):
                                        self.assertEqual(db.execute(
                                            f"SELECT COUNT(*) FROM {table}"
                                        ).fetchone()[0], 0)
                            self.assertEqual(responses[0][0], 202)
                            self.assertEqual(len(responses[0][1]["remote_failures"]),
                                             2 if cleanup_fails else 0)
                    finally:
                        listener.shutdown()
                        thread.join()
    def test_deadline_is_checked_after_delayed_policy_validation(self):
        deadline = datetime.now(timezone.utc) + timedelta(seconds=1)
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
            patch("ha.datetime", wraps=datetime) as clock,
        ):
            clock.now.return_value = deadline - timedelta(seconds=1)
            def delayed_parameters(*_args):
                clock.now.return_value = deadline + timedelta(seconds=1)
                return {}
            with (
                patch("ha_broker._service_data", side_effect=delayed_parameters),
                self.assertRaises(ha_broker.HomeAssistantError),
            ):
                ha_broker.execute_page_action("guest", "light", "turn_on", {}, deadline.isoformat())
        self.client.call_service.assert_not_called()

    def test_infinite_integer_parameters_fail_without_ha_mutation(self):
        for domain, service, parameter in (
            ("light", "turn_on", "brightness_pct"),
            ("fan", "set_percentage", "percentage"),
        ):
            for value in (float("inf"), float("-inf")):
                resource = {"entity_id": f"{domain}.allowed", "domain": domain, "actions": [{"service": service}]}
                with (
                    self.subTest(domain=domain, value=value),
                    patch("ha_broker.HA_CLIENT", self.client),
                    self.assertRaises(ha_broker.BrokerPolicyError),
                ):
                    self.client.get_states.return_value = [{"entity_id": resource["entity_id"], "attributes": {}}]
                    ha_broker._service_data(resource, {"service": service}, {parameter: value})
        self.client.call_service.assert_not_called()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = PageStore(Path(self.temporary.name))
        self.store.create({
            "id": "guest",
            "title": "Guest",
            "description": "",
            "resources": [{
                "id": "light",
                "name": "Light",
                "entity_id": "light.allowed",
                "domain": "light",
                "widget": "auto",
                "actions": [{
                    "id": "turn_on",
                    "name": "Turn on",
                    "service": "turn_on",
                }],
            }],
            "access_grants": [],
        })
        self.client = Mock()
        self.client.get_states.return_value = [{
            "entity_id": "light.allowed",
            "state": "off",
            "attributes": {},
        }]

    def add_camera(self):
        page = self.store.load("guest")
        page["resources"].append({
            "id": "driveway",
            "name": "Driveway",
            "entity_id": "camera.allowed",
            "domain": "camera",
            "widget": "auto",
            "actions": [{
                "id": "view",
                "name": "Display",
                "service": "view",
            }],
        })
        self.store.replace("guest", page)

    def tearDown(self):
        self.temporary.cleanup()

    def test_broker_derives_upstream_target_from_saved_policy(self):
        """Keep native HA authority out of the caller-controlled protocol."""
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
        ):
            result = ha_broker.execute_page_action(
                "guest",
                "light",
                "turn_on",
                {"brightness_pct": 50},
            )

        self.assertEqual(result, {"success": True})
        self.client.call_service.assert_called_once_with(
            "light",
            "turn_on",
            "light.allowed",
            {"brightness_pct": 50},
        )

    def test_mobile_notification_targets_are_discovered_and_enforced(self):
        self.client._request.side_effect = [
            [{"domain": "notify", "services": {
                "mobile_app_johns_phone": {}, "send_message": {},
            }}],
            [],
            [{"domain": "notify", "services": {
                "mobile_app_johns_phone": {},
            }}],
            [],
            [],
            {},
        ]
        with patch("ha_broker.HA_CLIENT", self.client):
            self.assertEqual(
                ha_broker.notification_targets(),
                ["notify.mobile_app_johns_phone"],
            )
            ha_broker.send_notification(
                "notify.mobile_app_johns_phone", "Guest", "Opened page",
            )
        self.assertEqual(
            self.client._request.call_args_list[-1].args[1],
            "/api/services/notify/mobile_app_johns_phone",
        )

    def test_mobile_notify_entities_are_discovered_and_sent_generically(self):
        services = [{"domain": "notify", "services": {"send_message": {}}}]
        states = [{"entity_id": "notify.mobile_app_johnr_iphone"}]
        self.client._request.side_effect = [
            services, states, services, states, states, {},
        ]
        with patch("ha_broker.HA_CLIENT", self.client):
            self.assertEqual(
                ha_broker.notification_targets(),
                ["notify.mobile_app_johnr_iphone"],
            )
            ha_broker.send_notification(
                "notify.mobile_app_johnr_iphone", "Guest", "Opened page",
            )
        request = self.client._request.call_args_list[-1]
        self.assertEqual(request.args[1], "/api/services/notify/send_message")
        self.assertEqual(
            request.args[2]["target"],
            {"entity_id": "notify.mobile_app_johnr_iphone"},
        )

    def test_camera_image_target_is_derived_from_saved_policy(self):
        """Resolve camera targets from authoritative policy, not input."""
        self.add_camera()
        self.client.get_camera_image.return_value = (b"jpeg", "image/jpeg")
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
        ):
            result = ha_broker.camera_image("guest", "driveway")

        self.assertEqual(result, (b"jpeg", "image/jpeg"))
        self.client.get_camera_image.assert_called_once_with("camera.allowed")

    def test_camera_image_rejects_non_camera_and_unknown_resources(self):
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
        ):
            for resource_id in ("light", "missing"):
                with self.subTest(resource_id=resource_id):
                    with self.assertRaisesRegex(
                        ha_broker.BrokerPolicyError,
                        "Camera not found",
                    ):
                        ha_broker.camera_image("guest", resource_id)
        self.client.get_camera_image.assert_not_called()

    def test_broker_rejects_forged_or_unknown_parameters(self):
        """Fail closed when a caller tries to widen the saved action."""
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
        ):
            with self.assertRaisesRegex(
                ha_broker.BrokerPolicyError,
                "Unknown action parameters",
            ):
                ha_broker.execute_page_action(
                    "guest",
                    "light",
                    "turn_on",
                    {"entity_id": "lock.front_door"},
                )
            with self.assertRaisesRegex(
                ha_broker.BrokerPolicyError,
                "Resource not found",
            ):
                ha_broker.execute_page_action(
                    "guest",
                    "front-door",
                    "unlock",
                    {},
                )

        self.client.call_service.assert_not_called()

    def test_broker_uses_authoritative_page_radius_for_proximity(self):
        page = self.store.load("guest")
        page["proximity"] = {"enabled": True, "radius_meters": 750}
        self.store.replace("guest", page)
        self.client.verify_proximity.return_value = True
        reading = {
            "latitude": 40.0,
            "longitude": -74.0,
            "accuracy_meters": 20,
            "measured_at": 1,
        }
        with (
            patch("ha_broker.PAGE_STORE", self.store),
            patch("ha_broker.HA_CLIENT", self.client),
        ):
            self.assertEqual(
                ha_broker.verify_page_proximity("guest", reading),
                {"within_range": True},
            )
        self.client.verify_proximity.assert_called_once_with(
            "guest", reading, 750
        )

    def test_admin_discovery_uses_separate_credential(self):
        handler = object.__new__(ha_broker.Handler)
        handler.headers = {"X-Broker-Token": "guest-token"}
        with (
            patch("ha_broker.TOKEN", "guest-token"),
            patch("ha_broker.ADMIN_TOKEN", "admin-token"),
        ):
            self.assertTrue(handler._authorized())
            self.assertFalse(handler._authorized(admin=True))
            handler.headers = {"X-Broker-Token": "admin-token"}
            self.assertTrue(handler._authorized(admin=True))
            self.assertFalse(handler._authorized())

    def test_request_role_selects_non_interchangeable_credential(self):
        handler = object.__new__(ha_broker.Handler)
        handler.path = "/v1/states"
        handler.headers = {
            "X-Broker-Token": "admin-token",
            "X-Broker-Role": "admin",
        }
        with (
            patch("ha_broker.TOKEN", "guest-token"),
            patch("ha_broker.ADMIN_TOKEN", "admin-token"),
        ):
            self.assertTrue(handler._admin_request())
            self.assertTrue(handler._authorized(admin=handler._admin_request()))
            handler.headers = {"X-Broker-Token": "admin-token"}
            self.assertFalse(handler._admin_request())
            self.assertFalse(handler._authorized(admin=handler._admin_request()))


if __name__ == "__main__":
    unittest.main()
