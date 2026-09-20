"""Scoped browser routes on the isolated Guest Service."""

import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import guest_service


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("guest-service")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)


class GuestCutoverTests(unittest.TestCase):
    def test_damaged_agent_health_denies_guest_before_broker_auth(self):
        with (
            patch.object(guest_service, "_connector_healthy", return_value=False),
            patch.object(guest_service, "_broker_guest_auth") as broker,
        ):
            status, _headers, _body = self.request("GET", self.prefix + "?bootstrap=secret")
        self.assertEqual(status, 503)
        broker.assert_not_called()

    def setUp(self):
        self.connector_patch = patch.object(guest_service, "_connector_healthy", return_value=True)
        self.connector_patch.start()
        self.static_patch = patch.object(
            guest_service, "STATIC_DIR", Path(__file__).resolve().parents[1] / "static",
        )
        self.static_patch.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.socket_path = str(Path(self.temporary.name) / "guest.sock")
        self.server = guest_service.GuestSocketServer(
            self.socket_path, guest_service.GuestHandler,
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.prefix = "/g/page-a/grant_aaaaaaaaaaaaaaaa/"
        self.calls = []

    def tearDown(self):
        self.connector_patch.stop()
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temporary.cleanup()
        self.static_patch.stop()

    def request(self, method, path, body=None, *, cookie="", capability="page-capability-123456", page_id="page-a"):
        connection = UnixHTTPConnection(self.socket_path)
        headers = {
            "X-Access-Pages-Page-ID": page_id,
            "X-Page-Capability": capability,
        }
        if cookie:
            headers["Cookie"] = "access_pages_guest=" + cookie
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["X-Guest-Request"] = "1"
            body = json.dumps(body)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_active_guest_ceiling_is_shared_across_pages_and_recovers(self):
        entered = threading.Semaphore(0)
        release = threading.Event()
        results = []
        second_page = "/g/page-b/grant_bbbbbbbbbbbbbbbb/"

        def authorize(_route, _payload):
            entered.release()
            if not release.wait(10):
                raise RuntimeError("timed out waiting for blocked guest requests")
            return 200, {"status": "session_ready"}

        def first_page_request():
            results.append(self.request(
                "GET", self.prefix, cookie="session-token-1234567890",
            )[0])

        workers = [threading.Thread(target=first_page_request) for _ in range(64)]
        with patch.object(guest_service, "_broker_guest_auth", side_effect=authorize) as broker:
            try:
                for worker in workers:
                    worker.start()
                for _ in workers:
                    self.assertTrue(entered.acquire(timeout=5))
                self.assertEqual(self.request(
                    "GET", second_page, cookie="session-token-1234567890",
                    page_id="page-b",
                )[0], 503)
                self.assertEqual(broker.call_count, 64)
            finally:
                release.set()
                for worker in workers:
                    if worker.ident is not None:
                        worker.join(timeout=5)
            self.assertEqual(results, [200] * 64)
            self.assertEqual(self.request(
                "GET", second_page, cookie="session-token-1234567890",
                page_id="page-b",
            )[0], 200)

    def test_duplicate_browser_verification_fields_are_rejected(self):
        connection = UnixHTTPConnection(self.socket_path)
        body = b'{"replace":false,"replace":true}'
        route = self.prefix + "api/access/page-a/verification/send"
        with patch.object(guest_service, "_broker_guest_auth", return_value=(200, {"sent": True, "pending": True})) as broker:
            connection.request("POST", route, body=body, headers={
                "X-Access-Pages-Page-ID": "page-a",
                "X-Page-Capability": "page-capability-123456",
                "X-Guest-Request": "1",
                "Cookie": "access_pages_guest=session-token-1234567890",
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            broker.assert_not_called()
        connection.close()

    def broker(self, route, payload):
        self.calls.append((route, payload.copy()))
        if payload["capability"] != "page-capability-123456" or payload["page_id"] != "page-a":
            return 403, {}
        if route == "/broker-bootstrap":
            return (200, {"session": "session-token-1234567890", "expires_at": 2_000_000_000})
        if payload.get("session") != "session-token-1234567890":
            return 401, {}
        if route == "/broker-session-status":
            return 200, {"status": "session_ready"}
        if route == "/broker-page-view":
            return 200, {"id": "page-a", "resources": []}
        if route == "/broker-camera":
            return 200, {"body": b"camera", "content_type": "image/jpeg"}
        if route == "/broker-action":
            return 200, {"success": True, "page": "page-a"}
        if route == "/broker-verification-challenge":
            return 200, {"sent": True, "pending": True}
        if route == "/broker-verification-verify":
            return 200, {"status": "session_ready"}
        raise AssertionError(route)

    def test_browser_flow_uses_broker_and_preserves_shell_assets_and_cookie(self):
        with patch.object(guest_service, "_broker_guest_auth", side_effect=self.broker):
            status, headers, _ = self.request("GET", self.prefix + "?bootstrap=bootstrap-secret-123456")
            self.assertEqual(status, 303)
            self.assertEqual(headers["Location"], self.prefix)
            self.assertIn("Secure; HttpOnly; SameSite=Lax", headers["Set-Cookie"])
            self.assertNotIn("Server", headers)
            self.assertNotIn("Cache-Control", headers)
            self.assertNotIn("Content-Security-Policy", headers)
            session = "session-token-1234567890"
            status, _, body = self.request("GET", self.prefix, cookie=session)
            self.assertEqual(status, 200)
            self.assertIn(b"Powered by", body)
            self.assertIn((self.prefix + "static/access.js").encode(), body)
            status, _, body = self.request("GET", self.prefix + "static/access.js", cookie=session)
            self.assertEqual(status, 200)
            self.assertIn(b"createAccessApi", body)
            status, _, body = self.request("GET", self.prefix + "api/access/page-a", cookie=session)
            self.assertEqual((status, json.loads(body)["id"]), (200, "page-a"))
            status, _, body = self.request("POST", self.prefix + "api/access/page-a/verification/send", {"replace": False}, cookie=session)
            self.assertEqual((status, json.loads(body)["sent"]), (200, True))
            status, _, body = self.request("POST", self.prefix + "api/access/page-a/verification/verify", {"code": "123456"}, cookie=session)
            self.assertEqual((status, json.loads(body)["status"]), (200, "session_ready"))
            status, _, body = self.request("POST", self.prefix + "api/access/page-a/garden/turn_on", {"proximity": None}, cookie=session)
            self.assertEqual((status, json.loads(body)["success"]), (200, True))
            status, _, body = self.request("GET", self.prefix + "api/access/page-a/camera/front?frame=1", cookie=session)
            self.assertEqual((status, body), (200, b"camera"))
            self.assertTrue(all(call[1]["page_id"] == "page-a" for call in self.calls))

    def test_bound_browser_checks_bootstrap_at_broker_before_redirect(self):
        secret = "a" * 43
        cookie = "session-token-1234567890"

        def authorize(route, payload):
            if route == "/broker-bootstrap-resume":
                if payload["bootstrap"] == "bad!":
                    raise ValueError("Invalid bootstrap request")
                return (200, {"status": "session_ready"}) if payload["bootstrap"] == secret else (401, {})
            if route == "/broker-bootstrap":
                return (200, {"session": cookie, "expires_at": 2_000_000_000}) if payload["bootstrap"] == secret else (401, {})
            raise AssertionError(route)

        with patch.object(guest_service, "_broker_guest_auth", side_effect=authorize) as broker:
            self.assertEqual(self.request("GET", self.prefix + "?bootstrap=" + secret, cookie=cookie)[0], 303)
            self.assertEqual(self.request("GET", self.prefix + "?bootstrap=" + "b" * 43, cookie=cookie)[0], 401)
            self.assertEqual(self.request("GET", self.prefix + "?bootstrap=bad!", cookie=cookie)[0], 400)
            self.assertEqual(self.request("GET", self.prefix + "?bootstrap=" + secret)[0], 303)
            self.assertEqual(self.request("GET", self.prefix + "?bootstrap=" + "b" * 43)[0], 401)
        self.assertEqual([call.args[0] for call in broker.call_args_list], [
            "/broker-bootstrap-resume", "/broker-bootstrap-resume", "/broker-bootstrap-resume",
            "/broker-bootstrap", "/broker-bootstrap",
        ])

    def test_verification_pending_revocation_and_cross_page_fail_closed(self):
        def pending(route, payload):
            if route == "/broker-page-view":
                return 403, {}
            return self.broker(route, payload)
        with patch.object(guest_service, "_broker_guest_auth", side_effect=pending):
            status, _, body = self.request("GET", self.prefix + "api/access/page-a", cookie="session-token-1234567890")
            self.assertEqual(status, 403)
            self.assertTrue(json.loads(body)["verification_required"])
            self.assertEqual(self.request("GET", self.prefix, cookie="wrong-session-1234567890")[0], 401)
            self.assertEqual(self.request("GET", self.prefix + "api/access/page-b", cookie="session-token-1234567890")[0], 404)
            self.assertEqual(self.request("GET", "/admin", cookie="session-token-1234567890")[0], 404)
            self.assertEqual(self.request("GET", self.prefix + "api/access/page-a", cookie="session-token-1234567890", capability="wrong-capability-123456")[0], 403)
        with patch.object(guest_service, "_broker_guest_auth", side_effect=OSError("broker down")):
            self.assertEqual(self.request("GET", self.prefix, cookie="session-token-1234567890")[0], 503)

    def test_guest_denials_use_only_fixed_public_messages(self):
        path = self.prefix + "api/access/page-a/garden/turn_on"
        cookie = "session-token-1234567890"
        for code, expected in (
            ("action_rate_limit", "Too many action requests; try again shortly"),
            ("proximity_out_of_range", "Location is outside the allowed area"),
            ("internal secret path /data/secrets", "Guest request denied"),
        ):
            with self.subTest(code=code), patch.object(
                guest_service, "_broker_guest_auth",
                return_value=(403, {"code": code}),
            ):
                status, _, body = self.request(
                    "POST", path, {"proximity": None}, cookie=cookie,
                )
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body)["error"], expected)
