"""Inactive broker-owned scoped guest sessions; no HA execution routes."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import http.client
from http.client import HTTPConnection as RealHTTPConnection
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

os.environ.setdefault("HA_BROKER_TOKEN", "synthetic-broker-token")
os.environ.setdefault("HA_BROKER_ADMIN_TOKEN", "synthetic-admin-broker-token")
os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-owner-token")

import guest_request as diagnostics
import ha_broker
import server
from activity import GuestActivityStore
from ha import HomeAssistantError
from pages import PageStore
from rate_limit import MinimumIntervalRateLimiter, SlidingWindowRateLimiter
from verification import VerificationStore

SEND_GUEST_EMAIL = ha_broker._send_guest_verification_email
EMIT_GUEST_EVENT = ha_broker._emit_guest_event


class BrokerGuestSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.pages = PageStore(root / "current-pages")
        self.policy = PageStore(root / "policy-pages")
        self.sessions = VerificationStore(root / "broker-sessions.sqlite3")
        self.registry = root / "guest-capabilities.json"
        self.socket_path = root / "broker.sock"
        self.cap_a = "page-capability-a-1234567890"
        self.cap_b = "page-capability-b-1234567890"
        self.secret_a = "bootstrap-secret-a-1234567890"
        self.secret_b = "bootstrap-secret-b-1234567890"
        self.secret_v = "bootstrap-secret-v-1234567890"
        self.secret_c = "bootstrap-secret-c-1234567890"
        self.grant_a = "grant_" + "a" * 16
        self.grant_b = "grant_" + "b" * 16
        self.grant_v = "grant_" + "v" * 16
        self.grant_c = "grant_" + "c" * 16
        now = datetime.now(timezone.utc)
        self.expiry = now + timedelta(hours=1)

        def grant(grant_id, secret, verification=False):
            return {
                "id": grant_id,
                "token_hash": sha256(secret.encode()).hexdigest(),
                "created_at": now.isoformat(),
                "expires_at": self.expiry.isoformat(),
                "credential_flow": "bootstrap-v1",
                "verification_required": verification,
            }

        self.pages.create({
            "id": "page-a", "title": "Page A", "resources": [
                {"id": "temperature", "name": "Temperature",
                 "entity_id": "sensor.temperature", "domain": "sensor",
                 "widget": "read_only", "actions": []},
                {"id": "draft", "name": "Draft",
                 "entity_id": "sensor.draft", "domain": "sensor",
                 "widget": "read_only", "actions": []},
                {"id": "front_camera", "name": "Front camera",
                 "entity_id": "camera.front", "domain": "camera",
                 "widget": "read_only", "actions": []},
                {"id": "garden", "name": "Garden light",
                 "entity_id": "switch.garden", "domain": "switch",
                 "actions": [
                     {"id": "turn_on", "name": "On", "service": "turn_on"},
                     {"id": "turn_off", "name": "Off", "service": "turn_off"},
                 ]},
                {"id": "level", "name": "Level",
                 "entity_id": "number.level", "domain": "number",
                 "actions": [{"id": "set_value", "name": "Set",
                              "service": "set_value"}]},
            ],
            "access_grants": [
                grant(self.grant_a, self.secret_a),
                grant(self.grant_b, self.secret_b),
                grant(self.grant_v, self.secret_v, True),
            ],
        })
        self.pages.create({
            "id": "page-b", "title": "Page B", "resources": [
                {"id": "other", "name": "Other",
                 "entity_id": "switch.other", "domain": "switch",
                 "actions": [{"id": "turn_on", "name": "On",
                              "service": "turn_on"}]},
            ],
            "access_grants": [grant(self.grant_c, self.secret_c)],
        })
        for page_id in ("page-a", "page-b"):
            published = self.pages.load(page_id)
            published["access_grants"] = []
            if page_id == "page-a":
                published["resources"] = [item for item in published["resources"]
                                          if item["id"] != "draft"]
            self.policy.create(published)
        self.registry.write_text(json.dumps({
            "page-a": sha256(self.cap_a.encode()).hexdigest(),
            "page-b": sha256(self.cap_b.encode()).hexdigest(),
        }))
        self.patchers = [
            patch("ha_broker.PAGE_STORE", self.policy),
            patch("ha_broker.GUEST_GRANT_STORE", self.pages),
            patch("ha_broker.GUEST_SESSION_STORE", self.sessions),
            patch("ha_broker.GUEST_CAPABILITY_REGISTRY", self.registry),
            patch("ha_broker.GUEST_PEER_UID", os.getuid()),
            patch("ha_broker.GUEST_ACTION_RATE_LIMITER",
                  SlidingWindowRateLimiter(12, 60)),
            patch("ha_broker.GUEST_CAMERA_RATE_LIMITER",
                  SlidingWindowRateLimiter(10, 60)),
            patch("ha_broker.GUEST_CAMERA_REFRESH_LIMITER",
                  MinimumIntervalRateLimiter()),
            patch("ha_broker._emit_guest_event"),
            patch("ha_broker.HA_CLIENT"),
        ]
        self.sent_codes = []
        self.patchers.append(patch(
            "ha_broker._send_guest_verification_email",
            side_effect=lambda *args: self.sent_codes.append(args),
        ))
        for patcher in self.patchers:
            patcher.start()
        self.server = ha_broker.GuestSocketServer(
            str(self.socket_path), ha_broker.GuestHandler
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def request(self, route, capability, page_id, body, *, started_ns=None):
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.connect(str(self.socket_path))
            payload = json.dumps(body).encode()
            timing = diagnostics.RequestTiming("a" * 32, started_ns or diagnostics.clock_ns(),
                                               "action" if route.endswith("/action") else "other")
            request = (
                f"POST {route} HTTP/1.1\r\n"
                "Host: broker\r\n"
                "X-Broker-Role: admin\r\n"
                "X-Broker-Token: synthetic-admin-broker-token\r\n"
                f"X-Page-Capability: {capability}\r\n"
                f"X-Access-Pages-Page-ID: {page_id}\r\n"
                f"{timing.headers()}"
                f"Content-Length: {len(payload)}\r\n\r\n"
            ).encode() + payload
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            status = response.status
            data = response.read()
            return status, json.loads(data) if data and response.getheader("Content-Type", "").startswith("application/json") else None
        finally:
            connection.close()

    def assert_wrong_peer_uid_rejected(self, request):
        """Prove the peer check closed the socket before HTTP dispatch."""
        peer_rejected = threading.Event()
        peer_errors = []
        original_get_request = self.server.get_request
        ha_calls_before = list(ha_broker.HA_CLIENT.mock_calls)

        def observe_peer_check():
            try:
                return original_get_request()
            except PermissionError as error:
                peer_errors.append(error)
                peer_rejected.set()
                raise

        with patch("ha_broker.GUEST_PEER_UID", os.getuid() + 1), \
             patch.object(self.server, "get_request", wraps=observe_peer_check) as peer_check, \
             patch.object(self.server, "finish_request", wraps=self.server.finish_request) as dispatch:
            with self.assertRaises((BrokenPipeError, ConnectionResetError,
                                    http.client.RemoteDisconnected)):
                request()
            self.assertTrue(peer_rejected.wait(2))
            peer_check.assert_called_once_with()
            self.assertEqual(len(peer_errors), 1)
            self.assertEqual(str(peer_errors[0].__cause__),
                             "Guest broker peer is not Guest Service")
            dispatch.assert_not_called()
            self.assertEqual(ha_broker.HA_CLIENT.mock_calls, ha_calls_before)

    def raw_request(self, route, headers, body):
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall((
                f"POST {route} HTTP/1.1\r\nHost: broker\r\n"
                + headers + f"Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body)
            response = http.client.HTTPResponse(connection)
            response.begin()
            status = response.status
            response.read()
            return status
        finally:
            connection.close()

    def test_duplicate_scoped_authority_cannot_select_last_json_value(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_b, self.secret_b,
        )[1]["session"]
        headers = (f"X-Page-Capability: {self.cap_a}\r\n"
                   "X-Access-Pages-Page-ID: page-a\r\n")
        body = (
            '{"grant_id":"' + self.grant_a + '","grant_id":"'
            + self.grant_b + '","session":"' + session + '"}'
        ).encode()
        self.assertEqual(self.raw_request(
            "/guest/v1/session-status", headers, body,
        ), 400)

    def test_duplicate_security_headers_and_forged_admin_role_fail_closed(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        body = json.dumps({"grant_id": self.grant_a, "session": session}).encode()
        base = (f"X-Page-Capability: {self.cap_a}\r\n"
                "X-Access-Pages-Page-ID: page-a\r\n")
        for headers in (
            base + f"X-Page-Capability: {self.cap_b}\r\n",
            base + "X-Access-Pages-Page-ID: page-b\r\n",
        ):
            self.assertIn(self.raw_request(
                "/guest/v1/session-status", headers, body,
            ), {400, 401, 403})
        self.assertEqual(self.raw_request(
            "/guest/v1/session-status",
            base + "X-Broker-Role: admin\r\n"
                   "X-Broker-Token: synthetic-admin-broker-token\r\n"
                   "X-Forwarded-For: 127.0.0.1\r\n",
            body,
        ), 200)
        self.assertEqual(self.raw_request(
            "/v1/discovery",
            base + "X-Broker-Role: admin\r\n"
                   "X-Broker-Token: synthetic-admin-broker-token\r\n",
            body,
        ), 404)

    def test_same_grant_rate_limit_survives_session_and_ip_rotation(self):
        first = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        second = "same-nat-rotated-session-1234567890"
        with self.sessions._connect() as db:
            key = sha256(second.encode()).hexdigest()
            db.execute("INSERT INTO guest_sessions VALUES(?,?,?,?)",
                       (key, "page-a", self.grant_a, int(self.expiry.timestamp())))
            db.execute("INSERT INTO guest_session_grants VALUES(?,?)",
                       (key, sha256(self.secret_a.encode()).hexdigest()))
        for index in range(13):
            body = json.dumps({
                "grant_id": self.grant_a,
                "session": first if index % 2 else second,
                "resource_id": "garden", "action_id": "turn_on",
                "parameters": {}, "proximity": None,
            }).encode()
            headers = (f"X-Page-Capability: {self.cap_a}\r\n"
                       "X-Access-Pages-Page-ID: page-a\r\n"
                       f"X-Forwarded-For: 203.0.113.{index + 1}\r\n"
                       + diagnostics.RequestTiming("a" * 32, diagnostics.clock_ns(),
                                                   "action").headers())
            self.assertEqual(self.raw_request("/guest/v1/action", headers, body),
                             200 if index < 12 else 429)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 12)

    def test_parallel_action_burst_cannot_exceed_grant_limit(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(pool.map(lambda _index: self.action(session)[0], range(20)))
        self.assertEqual(statuses.count(200), 12)
        self.assertEqual(statuses.count(429), 8)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 12)

    def test_broker_restart_resets_only_its_in_memory_rate_window(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        for _ in range(12):
            self.assertEqual(self.action(session)[0], 200)
        self.assertEqual(self.action(session)[0], 429)
        with patch("ha_broker.GUEST_ACTION_RATE_LIMITER", SlidingWindowRateLimiter(12, 60)):
            self.assertEqual(self.action(session)[0], 200)
            self.pages.remove_access_grant("page-a", self.grant_a)
            self.assertEqual(self.action(session)[0], 401)

    def test_verified_state_persists_when_broker_store_is_reopened(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        self.assertEqual(self.challenge(session)[0], 200)
        self.assertEqual(self.verify(session, self.sent_codes[-1][2])[0], 200)
        with patch("ha_broker.GUEST_SESSION_STORE", VerificationStore(self.sessions.path)):
            self.assertEqual(self.status(
                self.cap_a, "page-a", self.grant_v, session,
            )[1]["status"], "session_ready")
            self.assertEqual(self.read(session, grant_id=self.grant_v)[0], 200)

    def test_policy_replacement_during_state_and_camera_fetch_fails_closed(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]

        def replace_state(_entities):
            page = self.policy.load("page-a")
            for resource in page["resources"]:
                if resource["id"] == "temperature":
                    resource["entity_id"] = "sensor.changed"
            self.policy.replace("page-a", page)
            return [{"entity_id": "sensor.temperature", "state": "private"}]

        ha_broker.HA_CLIENT.get_states.side_effect = replace_state
        self.assertEqual(self.read(session)[0], 401)
        ha_broker.HA_CLIENT.get_states.side_effect = None

        def remove_camera(_entity):
            page = self.policy.load("page-a")
            page["resources"] = [resource for resource in page["resources"]
                                 if resource["id"] != "front_camera"]
            self.policy.replace("page-a", page)
            return b"private-image", "image/jpeg"

        ha_broker.HA_CLIENT.get_camera_image.side_effect = remove_camera
        self.assertEqual(self.image(session)[0], 401)

    def test_policy_action_changes_during_preparation_cannot_dispatch(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        original = ha_broker._service_data

        def change_action(resource, action, parameters):
            result = original(resource, action, parameters)
            page = self.policy.load("page-a")
            for item in page["resources"]:
                if item["id"] == "garden":
                    item["actions"] = [item["actions"][1]]
            self.policy.replace("page-a", page)
            return result

        with patch("ha_broker._service_data", side_effect=change_action):
            self.assertIn(self.action(session)[0], {401, 404})
        ha_broker.HA_CLIENT.call_service.assert_not_called()

    def test_revocation_at_initial_and_final_grant_checks_blocks_dispatch(self):
        original = ha_broker._guest_session_status
        for target, grant_id, bootstrap in (
            (1, self.grant_a, self.secret_a),
            (2, self.grant_b, self.secret_b),
        ):
            with self.subTest(check=target):
                session = self.exchange(
                    self.cap_a, "page-a", grant_id, bootstrap,
                )[1]["session"]
                entered = threading.Event()
                resume = threading.Event()
                calls = 0

                def paused_status(page_id, current_grant, current_session):
                    nonlocal calls
                    calls += 1
                    if calls == target:
                        entered.set()
                        if not resume.wait(5):
                            raise RuntimeError("Timed out waiting for revocation")
                    return original(page_id, current_grant, current_session)

                with patch("ha_broker._guest_session_status", side_effect=paused_status):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(self.action, session, grant_id=grant_id)
                        try:
                            self.assertTrue(entered.wait(5))
                            self.pages.remove_access_grant("page-a", grant_id)
                        finally:
                            resume.set()
                        self.assertEqual(future.result(timeout=5)[0], 401)
        ha_broker.HA_CLIENT.call_service.assert_not_called()
        self.assertFalse(any(call.args[2] == "action_success"
                             for call in ha_broker._emit_guest_event.call_args_list))

    def test_revocation_after_ha_dispatch_is_not_reported_as_cancellation(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        dispatched = threading.Event()
        resume = threading.Event()

        def blocked_dispatch(*_args, **_kwargs):
            dispatched.set()
            if not resume.wait(5):
                raise RuntimeError("Timed out waiting for revocation")

        ha_broker.HA_CLIENT.call_service.side_effect = blocked_dispatch
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.action, session)
            try:
                self.assertTrue(dispatched.wait(5))
                self.pages.remove_access_grant("page-a", self.grant_a)
            finally:
                resume.set()
            self.assertEqual(future.result(timeout=5)[0], 200)
        self.assertIn("action_success", [call.args[2]
                      for call in ha_broker._emit_guest_event.call_args_list])
        self.assertEqual(self.action(session)[0], 401)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 1)

    def test_authenticated_guest_flow_records_admin_activity_and_notifications(self):
        """Exercise broker socket -> Admin HTTP -> real activity database."""
        page = self.pages.load("page-a")
        for grant in page["access_grants"]:
            grant["label"] = "Guest A" if grant["id"] == self.grant_a else "Guest"
            if grant["id"] == self.grant_a:
                grant["notifications"] = {
                    "targets": ["email", "notify.mobile_app_phone"],
                    "events": ["initial_login", "successful_action", "failed_action"],
                }
        self.pages.replace("page-a", page)
        activity = GuestActivityStore(Path(self.temporary.name) / "activity.sqlite3")
        for page_id in ("page-a", "page-b"):
            for grant in self.pages.load(page_id)["access_grants"]:
                activity.register_guest(page_id, grant)
        emails = []
        with ExitStack() as stack:
            stack.enter_context(patch("server.PAGE_STORE", self.pages))
            stack.enter_context(patch("server.ACTIVITY_STORE", activity))
            stack.enter_context(patch("server.HA_BROKER_TOKEN", ha_broker.ADMIN_TOKEN))
            audit_events = stack.enter_context(patch("server.audit"))
            targets = stack.enter_context(patch("server.NOTIFICATION_TARGET_STORE"))
            targets.load.return_value = ["notify.mobile_app_phone"]
            smtp = stack.enter_context(patch("server.SMTP_CONFIG_STORE"))
            smtp.load.return_value = SimpleNamespace(administrator_email="owner@example.test")
            admin_ha = stack.enter_context(patch("server.HA_CLIENT"))
            stack.enter_context(patch("server.send_email", side_effect=lambda *args, **kwargs: emails.append(args)))
            admin = server.GatewayHTTPServer(("127.0.0.1", 0), server.Handler)
            admin_thread = threading.Thread(target=admin.serve_forever)
            admin_thread.start()
            try:
                stack.enter_context(patch(
                    "ha_broker.HTTPConnection",
                    side_effect=lambda host, _port, timeout: RealHTTPConnection(
                        host, admin.server_port, timeout=timeout,
                    ),
                ))
                ha_broker._emit_guest_event.side_effect = EMIT_GUEST_EVENT
                ha_broker.HA_CLIENT.get_states.return_value = []
                session = self.exchange(
                    self.cap_a, "page-a", self.grant_a, self.secret_a,
                )[1]["session"]
                view = {"grant_id": self.grant_a, "session": session}
                self.assertEqual(self.request(
                    "/guest/v1/page-view", self.cap_a, "page-a", view,
                )[0], 200)
                self.assertEqual(self.request(
                    "/guest/v1/page-view", self.cap_a, "page-a", view,
                )[0], 200)
                self.assertEqual(self.action(session)[0], 200)
                ha_broker.HA_CLIENT.call_service.side_effect = HomeAssistantError("rejected")
                self.assertEqual(self.action(session)[0], 502)
                self.assertEqual(self.action(session, action_id="unapproved")[0], 404)
                guest = activity.guest_activity("page-a", self.grant_a)
                self.assertIsNotNone(guest["guest"]["first_access_at"])
                self.assertEqual([row["outcome"] for row in guest["actions"]],
                                 ["failed", "success"])
                self.assertEqual(activity.page_guests("page-a")[0]["action_count"], 2)
                self.assertIsNotNone(activity.page_guests("page-a")[0]["last_activity"])
                security = {row["event_type"] for row in guest["security_events"]}
                self.assertIn("home_assistant_action_rejected", security)
                self.assertIn("unapproved_action_attempt", security)
                self.assertEqual(len(emails), 4)
                self.assertTrue(all(args[1] == "owner@example.test" for args in emails))
                self.assertEqual(admin_ha.send_notification.call_count, 4)

                verified_session = self.exchange(
                    self.cap_a, "page-a", self.grant_v, self.secret_v,
                )[1]["session"]
                pending = {"grant_id": self.grant_v, "session": verified_session}
                self.assertEqual(self.request(
                    "/guest/v1/page-view", self.cap_a, "page-a", pending,
                )[0], 403)
                self.assertIsNone(activity.guest_activity(
                    "page-a", self.grant_v,
                )["guest"]["first_access_at"])
                self.assertEqual(self.challenge(verified_session)[0], 200)
                self.assertEqual(self.verify(verified_session, "bad")[0], 401)
                self.assertEqual(self.verify(
                    verified_session, self.sent_codes[-1][2],
                )[0], 200)
                self.assertEqual(self.request(
                    "/guest/v1/page-view", self.cap_a, "page-a", pending,
                )[0], 200)
                verified = activity.guest_activity("page-a", self.grant_v)
                self.assertIsNotNone(verified["guest"]["first_access_at"])
                self.assertIn("guest_email_verified", {
                    row["event_type"] for row in verified["security_events"]
                })
                self.assertIn("verification_failed", {
                    row["event_type"] for row in verified["security_events"]
                })

                camera_session = self.exchange(
                    self.cap_a, "page-a", self.grant_b, self.secret_b,
                )[1]["session"]
                ha_broker.HA_CLIENT.get_camera_image.return_value = (b"image", "image/jpeg")
                self.assertEqual(self.image(
                    camera_session, grant_id=self.grant_b,
                )[0], 200)
                self.assertIsNotNone(activity.guest_activity(
                    "page-a", self.grant_b,
                )["guest"]["first_access_at"])

                ha_broker.HA_CLIENT.call_service.side_effect = None
                direct_action_session = self.exchange(
                    self.cap_b, "page-b", self.grant_c, self.secret_c,
                )[1]["session"]
                self.assertEqual(self.action(
                    direct_action_session, capability=self.cap_b,
                    page_id="page-b", grant_id=self.grant_c,
                    resource_id="other",
                )[0], 200)
                direct = activity.guest_activity("page-b", self.grant_c)
                self.assertIsNotNone(direct["guest"]["first_access_at"])
                self.assertEqual(direct["actions"][0]["outcome"], "success")

                wrong = RealHTTPConnection("127.0.0.1", admin.server_port)
                wrong.request("POST", "/api/internal/guest-event",
                              headers={"X-HA-Broker-Token": "wrong"})
                self.assertEqual(wrong.getresponse().status, 401)
                wrong.close()
                self.assertEqual(activity.page_guests("page-b")[0]["action_count"], 1)
                forged = RealHTTPConnection("127.0.0.1", admin.server_port)
                forged.request("POST", "/api/internal/guest-event", body=json.dumps({
                    "page_id": "page-a", "grant_id": self.grant_b,
                    "event": "initial_access", "target": "attacker@example.test",
                }), headers={"X-HA-Broker-Token": ha_broker.ADMIN_TOKEN})
                self.assertEqual(forged.getresponse().status, 400)
                forged.close()
                self.assertTrue(any(
                    call.args == ("action_executed",)
                    and call.kwargs.get("page_id") == "page-a"
                    and call.kwargs.get("grant_id") == self.grant_a
                    and "client_ip" not in call.kwargs
                    for call in audit_events.call_args_list
                ))
                # Use the real grant limiter and broker route for the old
                # operational rate-limit event, not a helper-only invocation.
                statuses = [self.action(session)[0] for _ in range(15)]
                self.assertIn(429, statuses)
                self.assertTrue(any(
                    call.args == ("action_rate_limited",)
                    and call.kwargs == {"page_id": "page-a", "grant_id": self.grant_a}
                    for call in audit_events.call_args_list
                ))
            finally:
                admin.shutdown()
                admin_thread.join()
                admin.server_close()

    def image(self, session, resource_id="front_camera", grant_id=None):
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.connect(str(self.socket_path))
            payload = json.dumps({
                "grant_id": grant_id or self.grant_a, "session": session,
                "resource_id": resource_id,
            }).encode()
            connection.sendall((
                "POST /guest/v1/camera HTTP/1.1\r\nHost: broker\r\n"
                f"X-Page-Capability: {self.cap_a}\r\n"
                "X-Access-Pages-Page-ID: page-a\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
            ).encode() + payload)
            response = http.client.HTTPResponse(connection)
            response.begin()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def test_camera_refresh_policy_is_enforced_per_grant_and_camera(self):
        page = self.policy.load("page-a")
        for resource in page["resources"]:
            if resource["id"] == "front_camera":
                resource["camera_refresh_interval"] = 15
        self.policy.replace("page-a", page)
        now = [100.0]
        ha_broker.HA_CLIENT.get_camera_image.return_value = (b"image", "image/jpeg")
        with patch("ha_broker.GUEST_CAMERA_REFRESH_LIMITER",
                   MinimumIntervalRateLimiter(clock=lambda: now[0])):
            first = self.exchange(
                self.cap_a, "page-a", self.grant_a, self.secret_a,
            )[1]["session"]
            second = self.exchange(
                self.cap_a, "page-a", self.grant_b, self.secret_b,
            )[1]["session"]
            self.assertEqual(self.image(first)[0], 200)
            self.assertEqual(self.image(first)[0], 429)
            self.assertEqual(self.image(second, grant_id=self.grant_b)[0], 200)
            now[0] += 15
            self.assertEqual(self.image(first)[0], 200)
            page = self.policy.load("page-a")
            for resource in page["resources"]:
                if resource["id"] == "front_camera":
                    resource["camera_refresh_interval"] = 0
            self.policy.replace("page-a", page)
            now[0] += 2
            self.assertEqual(self.image(first)[0], 200)
            now[0] += 1
            self.assertEqual(self.image(first)[0], 429)
            now[0] += 1
            self.assertEqual(self.image(first)[0], 200)
            with patch("ha_broker.GUEST_CAMERA_RATE_LIMITER") as burst:
                burst.allow.return_value = False
                now[0] += 2
                self.assertEqual(self.image(first)[0], 429)

    def exchange(self, capability, page_id, grant_id, bootstrap):
        return self.request(
            "/guest/v1/bootstrap", capability, page_id,
            {"grant_id": grant_id, "bootstrap": bootstrap},
        )

    def test_bound_session_renewal_requires_current_bootstrap_secret(self):
        secret = "a" * 43
        page = self.pages.load("page-a")
        page["access_grants"][0]["token_hash"] = sha256(secret.encode()).hexdigest()
        self.pages.replace("page-a", page)
        session = self.exchange(self.cap_a, "page-a", self.grant_a, secret)[1]["session"]

        def resume(candidate, token=session, grant_id=self.grant_a):
            return self.request(
                "/guest/v1/bootstrap-resume", self.cap_a, "page-a",
                {"grant_id": grant_id, "session": token, "bootstrap": candidate},
            )[0]

        self.assertEqual(resume(secret), 200)
        self.assertEqual(resume("b" * 43), 401)
        self.assertEqual(resume("wrong!"), 401)
        self.assertEqual(resume(secret, token="unknown-session-123456"), 401)
        self.assertEqual(resume(secret, grant_id=self.grant_b), 401)
        self.assertEqual(self.status(self.cap_a, "page-a", self.grant_a, session)[0], 200)

    def status(self, capability, page_id, grant_id, session):
        return self.request(
            "/guest/v1/session-status", capability, page_id,
            {"grant_id": grant_id, "session": session},
        )

    def challenge(self, session, *, capability=None, page_id="page-a", grant_id=None,
                  replace=False):
        return self.request(
            "/guest/v1/verification-challenge", capability or self.cap_a,
            page_id, {"grant_id": grant_id or self.grant_v,
                      "session": session, "replace": replace},
        )

    def verify(self, session, code, *, capability=None, page_id="page-a",
               grant_id=None):
        return self.request(
            "/guest/v1/verification-verify", capability or self.cap_a,
            page_id, {"grant_id": grant_id or self.grant_v,
                      "session": session, "code": code},
        )

    def read(self, session, *, capability=None, page_id="page-a", grant_id=None,
             resource_id="temperature", **extra):
        return self.request(
            "/guest/v1/resource-state", capability or self.cap_a, page_id,
            {"grant_id": grant_id or self.grant_a, "session": session,
             "resource_id": resource_id, **extra},
        )

    def action(self, session, *, capability=None, page_id="page-a", grant_id=None,
               resource_id="garden", action_id="turn_on", parameters=None,
               proximity=None, **extra):
        return self.request(
            "/guest/v1/action", capability or self.cap_a, page_id,
            {"grant_id": grant_id or self.grant_a, "session": session,
             "resource_id": resource_id, "action_id": action_id,
             "parameters": parameters if parameters is not None else {},
             "proximity": proximity, **extra},
        )

    def test_page_view_and_camera_are_session_and_policy_bound(self):
        session = self.exchange(self.cap_a, "page-a", self.grant_a, self.secret_a)[1]["session"]
        ha_broker.HA_CLIENT.get_states.return_value = [
            {"entity_id": "sensor.temperature", "state": "72",
             "attributes": {"unit_of_measurement": "F", "private": "secret"}},
            {"entity_id": "sensor.draft", "state": "private", "attributes": {}},
        ]
        status, view = self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })
        self.assertEqual(status, 200)
        self.assertEqual(view["id"], "page-a")
        self.assertEqual({item["id"] for item in view["resources"]},
                         {"temperature", "front_camera", "garden", "level"})
        self.assertEqual(view["resources"][0]["state_attributes"]["unit_of_measurement"], "F")
        self.assertNotIn("private", json.dumps(view))
        ha_broker.HA_CLIENT.get_camera_image.return_value = (b"image", "image/jpeg")
        self.assertEqual(self.image(session), (200, "image/jpeg", b"image"))
        ha_broker.HA_CLIENT.get_camera_image.assert_called_once_with("camera.front")
        self.assertEqual(self.image(session, "draft")[0], 404)
        pending = self.exchange(self.cap_a, "page-a", self.grant_v, self.secret_v)[1]["session"]
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_v, "session": pending,
        })[0], 403)
        self.assertEqual(self.image("wrong-session-1234567890")[0], 401)
        self.sessions.revoke("page-a", self.grant_a)
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })[0], 401)

    def test_missing_registry_and_unavailable_session_db_fail_closed(self):
        session = self.exchange(self.cap_a, "page-a", self.grant_a, self.secret_a)[1]["session"]
        self.registry.unlink()
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })[0], 401)
        self.registry.write_text(json.dumps({"page-a": "invalid"}))
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })[0], 401)
        self.registry.write_text(json.dumps({
            "page-a": sha256(self.cap_a.encode()).hexdigest(),
            "page-b": sha256(self.cap_b.encode()).hexdigest(),
        }))
        self.sessions.path.unlink()
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })[0], 503)
        self.sessions.path.write_bytes(b"invalid sqlite database")
        self.assertEqual(self.request("/guest/v1/page-view", self.cap_a, "page-a", {
            "grant_id": self.grant_a, "session": session,
        })[0], 503)

    def test_interrupted_ha_dispatch_is_uncertain_and_not_replayed(self):
        from ha import HomeAssistantClient
        session = self.exchange(self.cap_a, "page-a", self.grant_a, self.secret_a)[1]["session"]
        client = HomeAssistantClient("http://ha.invalid", "synthetic")
        for error in (TimeoutError(), ConnectionResetError()):
            with self.subTest(error=type(error)), \
                    patch.object(ha_broker.HA_CLIENT, "call_service", side_effect=client.call_service), \
                    patch("ha.urlopen", side_effect=error) as dispatch:
                status, body = self.action(session)
                self.assertEqual(status, 502)
                self.assertEqual(body["code"], "action_uncertain")
                self.assertEqual(dispatch.call_count, 1)

    def test_action_lifetime_checked_at_dequeue_and_after_preparation(self):
        session = self.exchange(self.cap_a, "page-a", self.grant_a, self.secret_a)[1]["session"]
        body = {"grant_id": self.grant_a, "session": session, "resource_id": "garden",
                "action_id": "turn_on", "parameters": {}, "proximity": None}
        now = diagnostics.clock_ns()
        with patch("ha_broker._guest_action", wraps=ha_broker._guest_action) as dispatch:
            status, _ = self.request("/guest/v1/action", self.cap_a, "page-a", body,
                                     started_ns=now - 8_100_000_000)
            self.assertEqual(status, 503)
            dispatch.assert_not_called()
        ha_broker.HA_CLIENT.call_service.assert_not_called()

        original = ha_broker._service_data
        current = [now]
        def delayed_preparation(*args):
            result = original(*args)
            current[0] += 8_000_000_000
            return result
        with (patch("guest_request.clock_ns", side_effect=lambda: current[0]),
              patch("ha_broker._service_data", side_effect=delayed_preparation)):
            self.assertEqual(self.request("/guest/v1/action", self.cap_a, "page-a", body,
                                          started_ns=now)[0], 503)
        ha_broker.HA_CLIENT.call_service.assert_not_called()
        # A new, explicit command has its own lifetime and can still succeed.
        self.assertEqual(self.action(session)[0], 200)
        ha_broker.HA_CLIENT.call_service.assert_called_once()

    def test_action_requires_trusted_lifetime_and_cannot_downgrade_operation(self):
        session = self.exchange(self.cap_a, "page-a", self.grant_a, self.secret_a)[1]["session"]
        body = json.dumps({"grant_id": self.grant_a, "session": session,
                           "resource_id": "garden", "action_id": "turn_on",
                           "parameters": {}, "proximity": None}).encode()
        headers = f"X-Page-Capability: {self.cap_a}\r\nX-Access-Pages-Page-ID: page-a\r\n"
        self.assertEqual(self.raw_request("/guest/v1/action", headers, body), 400)
        downgraded = diagnostics.RequestTiming("a" * 32, diagnostics.clock_ns() - 9_000_000_000, "state")
        self.assertEqual(self.raw_request("/guest/v1/action", headers +
                                         downgraded.headers(), body), 503)
        ha_broker.HA_CLIENT.call_service.assert_not_called()
        # A diagnostic label cannot reject a valid authorized action either.
        unknown = diagnostics.RequestTiming("b" * 32, diagnostics.clock_ns(), "other")
        self.assertEqual(self.raw_request("/guest/v1/action", headers +
                                         unknown.headers(), body), 200)
        ha_broker.HA_CLIENT.call_service.assert_called_once()

    def test_allowed_action_dispatches_only_policy_service_without_proximity(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        status, result = self.action(session)
        self.assertEqual((status, result), (200, {
            "success": True, "page": "page-a", "resource": "garden",
            "action": "turn_on",
        }))
        args, kwargs = ha_broker.HA_CLIENT.call_service.call_args
        self.assertEqual(args, ("switch", "turn_on", "switch.garden", {}))
        self.assertIn("grant_deadline", kwargs)
        ha_broker.HA_CLIENT.verify_proximity.assert_not_called()

    def test_action_cannot_substitute_ha_authority_or_cross_page(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        other = self.exchange(
            self.cap_b, "page-b", self.grant_c, self.secret_c,
        )[1]["session"]
        for extra in ({"entity_id": "switch.private"}, {"domain": "lock"},
                      {"service": "unlock"}, {"service_data": {}},
                      {"verified": True}, {"within_range": True},
                      {"grant_deadline": "2099-01-01T00:00:00Z"},
                      {"ha_url": "http://ha.invalid"}):
            self.assertEqual(self.action(session, **extra)[0], 400)
        for resource_id, action_id, expected in (
            ("missing", "turn_on", 404),
            ("garden", "missing", 404),
            ("temperature", "view", 404),
            ("other", "turn_on", 404),
        ):
            self.assertEqual(self.action(
                session, resource_id=resource_id, action_id=action_id,
            )[0], expected)
        self.assertEqual(self.action(
            other, grant_id=self.grant_c,
        )[0], 401)
        self.assertEqual(self.action(
            session, capability=self.cap_b, page_id="page-b",
            grant_id=self.grant_a, resource_id="other",
        )[0], 401)
        self.assertEqual(self.action(
            "missing-session-1234567890",
        )[0], 401)
        self.assertEqual(self.action(
            session, capability="missing-capability-123456",
        )[0], 401)
        self.assert_wrong_peer_uid_rejected(lambda: self.action(session))
        ha_broker.HA_CLIENT.call_service.assert_not_called()

    def test_action_parameters_follow_live_capability_and_allowlist(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        ha_broker.HA_CLIENT.get_states.return_value = [{
            "entity_id": "number.level", "state": "4",
            "attributes": {"min": 0, "max": 10, "step": 2},
        }]
        self.assertEqual(self.action(
            session, resource_id="level", action_id="set_value",
            parameters={"value": 5},
        )[0], 400)
        self.assertEqual(self.action(
            session, resource_id="level", action_id="set_value",
            parameters={"value": 6, "service_data": {"entity_id": "number.private"}},
        )[0], 400)
        self.assertEqual(self.action(
            session, parameters={"value": 5},
        )[0], 400)
        self.assertEqual(self.action(
            session, resource_id="level", action_id="set_value",
            parameters={"value": 6},
        )[0], 200)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_args.args,
                         ("number", "set_value", "number.level", {"value": 6.0}))

    def test_verification_required_action_is_individual(self):
        first = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        second = "same-nat-action-session-1234567890"
        with self.sessions._connect() as db:
            key = sha256(second.encode()).hexdigest()
            db.execute("INSERT INTO guest_sessions VALUES(?,?,?,?)",
                       (key, "page-a", self.grant_v, int(self.expiry.timestamp())))
            db.execute("INSERT INTO guest_session_grants VALUES(?,?)",
                       (key, sha256(self.secret_v.encode()).hexdigest()))
        self.assertEqual(self.action(first, grant_id=self.grant_v)[0], 403)
        self.assertEqual(self.challenge(first)[0], 200)
        self.assertEqual(self.verify(first, self.sent_codes[-1][2])[0], 200)
        self.assertEqual(self.action(first, grant_id=self.grant_v)[0], 200)
        self.assertEqual(self.action(second, grant_id=self.grant_v)[0], 403)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 1)

    def test_proximity_reading_is_checked_by_broker_for_actions_only(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        page = self.policy.load("page-a")
        page["proximity"] = {"enabled": True, "radius_meters": 500}
        self.policy.replace("page-a", page)
        ha_broker.HA_CLIENT.get_states.return_value = []
        self.assertEqual(self.read(session)[0], 200)
        self.assertEqual(self.action(session)[0], 403)
        now = datetime.now(timezone.utc).timestamp()
        valid = {"latitude": 33.5, "longitude": -112.1,
                 "accuracy_meters": 10, "measured_at": now}
        for reading, expected in (
            ({**valid, "latitude": float("nan")}, 400),
            ({**valid, "latitude": float("inf")}, 400),
            ({**valid, "latitude": -91}, 400),
            ({**valid, "longitude": 181}, 400),
            ({**valid, "accuracy_meters": -1}, 403),
            ({**valid, "accuracy_meters": 501}, 403),
            ({**valid, "measured_at": now - 301}, 403),
            ({**valid, "measured_at": now + 31}, 403),
            ({"latitude": 33.5}, 400),
            ({**valid, "within_range": True}, 400),
        ):
            self.assertEqual(self.action(session, proximity=reading)[0], expected)
        ha_broker.HA_CLIENT.verify_proximity.return_value = False
        self.assertEqual(self.action(session, proximity=valid)[0], 403)
        ha_broker.HA_CLIENT.verify_proximity.return_value = True
        self.assertEqual(self.action(session, proximity=valid)[0], 200)
        self.assertEqual(ha_broker.HA_CLIENT.verify_proximity.call_args.args,
                         ("page-a", valid, 500))
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 1)

    def test_action_rate_limit_matches_live_twelve_per_minute(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        for _ in range(12):
            self.assertEqual(self.action(session)[0], 200)
        self.assertEqual(self.action(session)[0], 429)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 12)

    def test_revocation_or_policy_change_before_final_recheck_blocks_dispatch(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        original = ha_broker._service_data

        def revoke_during_preparation(resource, action, parameters):
            result = original(resource, action, parameters)
            self.pages.remove_access_grant("page-a", self.grant_a)
            return result

        with patch("ha_broker._service_data", side_effect=revoke_during_preparation):
            self.assertEqual(self.action(session)[0], 401)
        ha_broker.HA_CLIENT.call_service.assert_not_called()

        # A different grant can still exist, but a removed published action
        # cannot dispatch after the broker's final policy reload.
        other = self.exchange(
            self.cap_a, "page-a", self.grant_b, self.secret_b,
        )[1]["session"]

        def remove_policy_during_preparation(resource, action, parameters):
            result = original(resource, action, parameters)
            page = self.policy.load("page-a")
            page["resources"] = [item for item in page["resources"]
                                 if item["id"] != "garden"]
            self.policy.replace("page-a", page)
            return result

        with patch("ha_broker._service_data",
                   side_effect=remove_policy_during_preparation):
            self.assertEqual(self.action(other, grant_id=self.grant_b)[0], 404)
        ha_broker.HA_CLIENT.call_service.assert_not_called()

    def test_dispatched_action_is_not_claimed_revocable(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]

        def dispatched(*_args, **_kwargs):
            self.pages.remove_access_grant("page-a", self.grant_a)

        ha_broker.HA_CLIENT.call_service.side_effect = dispatched
        self.assertEqual(self.action(session)[0], 200)
        self.assertEqual(self.action(session)[0], 401)
        self.assertEqual(ha_broker.HA_CLIENT.call_service.call_count, 1)

    def test_expired_grant_and_uncurated_published_service_cannot_dispatch(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        page = self.policy.load("page-a")
        next(item for item in page["resources"] if item["id"] == "garden")[
            "actions"
        ][0]["service"] = "arbitrary_service"
        self.policy.replace("page-a", page)
        self.assertEqual(self.action(session)[0], 403)
        current = self.pages.load("page-a")
        for grant in current["access_grants"]:
            if grant["id"] == self.grant_a:
                grant["expires_at"] = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                ).isoformat()
        self.pages.replace("page-a", current)
        self.assertEqual(self.action(session)[0], 401)
        ha_broker.HA_CLIENT.call_service.assert_not_called()

    def test_read_is_broker_authorized_and_guest_filtered(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        ha_broker.HA_CLIENT.get_states.return_value = [{
            "entity_id": "sensor.temperature", "state": "72",
            "attributes": {
                "friendly_name": "Thermostat sensor", "unit_of_measurement": "°F",
                "private_token": "do-not-disclose",
            },
            "context": {"user_id": "private-user"},
            "last_changed": "private-timestamp",
        }]
        status, body = self.read(session)
        self.assertEqual(status, 200)
        ha_broker.HA_CLIENT.get_states.assert_called_once_with(
            {"sensor.temperature"},
        )
        self.assertEqual(set(body), {
            "resource_id", "state", "state_attributes",
        })
        self.assertEqual((body["resource_id"], body["state"]),
                         ("temperature", "72"))
        self.assertEqual(body["state_attributes"]["unit_of_measurement"], "°F")
        for secret in ("private_token", "do-not-disclose", "private-user",
                       "private-timestamp", "entity_id"):
            self.assertNotIn(secret, json.dumps(body))
        self.assertNotIn("attributes", body)

    def test_verification_and_individual_sessions_gate_reads(self):
        first = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        second = "same-nat-second-session-1234567890"
        with self.sessions._connect() as db:
            key = sha256(second.encode()).hexdigest()
            db.execute("INSERT INTO guest_sessions VALUES(?,?,?,?)",
                       (key, "page-a", self.grant_v, int(self.expiry.timestamp())))
            db.execute("INSERT INTO guest_session_grants VALUES(?,?)",
                       (key, sha256(self.secret_v.encode()).hexdigest()))
        self.assertEqual(self.read(first, grant_id=self.grant_v)[0], 403)
        ha_broker.HA_CLIENT.get_states.assert_not_called()
        self.assertEqual(self.challenge(first)[0], 200)
        code = self.sent_codes[-1][2]
        self.assertEqual(self.verify(first, code)[0], 200)
        ha_broker.HA_CLIENT.get_states.return_value = []
        self.assertEqual(self.read(first, grant_id=self.grant_v)[0], 200)
        self.assertEqual(self.read(second, grant_id=self.grant_v)[0], 403)

    def test_read_fails_for_unpublished_camera_or_substituted_entity(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        other = self.exchange(
            self.cap_b, "page-b", self.grant_c, self.secret_c,
        )[1]["session"]
        for resource_id in ("draft", "front_camera", "other", "secret"):
            self.assertEqual(self.read(session, resource_id=resource_id)[0], 404)
        self.assertEqual(self.read(
            session, entity_id="sensor.secret",
        )[0], 400)
        self.assertEqual(self.read(
            session, verified=True,
        )[0], 400)
        self.assertEqual(self.read(
            "missing-session-1234567890",
        )[0], 401)
        self.assertEqual(self.read(
            session, capability="missing-capability-123456",
        )[0], 401)
        self.assertEqual(self.read(
            session, capability=self.cap_b, page_id="page-b",
            resource_id="other",
        )[0], 401)
        self.assertEqual(self.read(
            session, grant_id=self.grant_b,
        )[0], 401)
        self.assertEqual(self.read(
            other, grant_id=self.grant_c,
        )[0], 401)
        self.assert_wrong_peer_uid_rejected(lambda: self.read(session))
        ha_broker.HA_CLIENT.get_states.assert_not_called()

    def test_revocation_expiry_and_policy_removal_denies_next_read(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        ha_broker.HA_CLIENT.get_states.return_value = []
        self.assertEqual(self.read(session)[0], 200)
        page = self.policy.load("page-a")
        page["resources"] = [item for item in page["resources"]
                             if item["id"] != "temperature"]
        self.policy.replace("page-a", page)
        self.assertEqual(self.read(session)[0], 404)
        page["resources"] = self.pages.load("page-a")["resources"][:1]
        self.policy.replace("page-a", page)
        current = self.pages.load("page-a")
        for grant in current["access_grants"]:
            if grant["id"] == self.grant_a:
                grant["expires_at"] = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                ).isoformat()
        self.pages.replace("page-a", current)
        self.assertEqual(self.read(session)[0], 401)
        for grant in current["access_grants"]:
            if grant["id"] == self.grant_a:
                grant["expires_at"] = self.expiry.isoformat()
        self.pages.replace("page-a", current)
        self.pages.remove_access_grant("page-a", self.grant_a)
        # LayerV cleanup is deliberately left pending; local removal decides.
        self.assertEqual(self.read(session)[0], 401)
        self.assertEqual(ha_broker.HA_CLIENT.get_states.call_count, 1)

    def test_grant_removed_while_ha_reads_cannot_return_state(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]

        def remove_grant(_entities):
            self.pages.remove_access_grant("page-a", self.grant_a)
            return [{"entity_id": "sensor.temperature", "state": "72"}]

        ha_broker.HA_CLIENT.get_states.side_effect = remove_grant
        self.assertEqual(self.read(session)[0], 401)
        ha_broker.HA_CLIENT.get_states.assert_called_once_with(
            {"sensor.temperature"},
        )

    def test_guest_verification_is_individual_and_broker_owned(self):
        first = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        # A second session for the same grant is useful for shared-IP guests.
        second = "second-guest-session-1234567890"
        with self.sessions._connect() as db:
            db.execute(
                "INSERT INTO guest_sessions VALUES(?,?,?,?)",
                (sha256(second.encode()).hexdigest(), "page-a", self.grant_v,
                 int(self.expiry.timestamp())),
            )
            db.execute(
                "INSERT INTO guest_session_grants VALUES(?,?)",
                (sha256(second.encode()).hexdigest(),
                 sha256(self.secret_v.encode()).hexdigest()),
            )
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, first,
        )[1]["status"], "verification_required")
        status, response = self.challenge(first)
        self.assertEqual((status, response), (200, {"sent": True, "pending": True}))
        code = self.sent_codes[-1][2]
        self.assertNotIn(code, json.dumps(response))
        self.assertEqual(self.sent_codes[-1][:2], ("page-a", self.grant_v))
        self.assertEqual(self.verify(second, code)[0], 401)
        self.assertEqual(self.verify(first, code, grant_id=self.grant_a)[0], 401)
        self.assertEqual(self.verify(first, code, capability=self.cap_b,
                                     page_id="page-b")[0], 401)
        self.assertEqual(self.verify(first, "000000")[0], 401)
        self.assertEqual(self.verify(first, code)[1]["status"], "session_ready")
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, second,
        )[1]["status"], "verification_required")
        self.assertLessEqual(self.status(
            self.cap_a, "page-a", self.grant_v, first,
        )[1]["expires_at"], int(self.expiry.timestamp()))
        self.assertEqual(self.verify(first, code)[0], 401)
        self.pages.remove_access_grant("page-a", self.grant_v)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, first,
        )[0], 401)

    def test_attempt_resend_expiry_and_stale_delivery_safety(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        self.assertEqual(self.challenge(session)[0], 200)
        code = self.sent_codes[-1][2]
        self.assertEqual(self.challenge(session)[1]["sent"], False)
        self.assertEqual(self.challenge(session, replace=True)[0], 429)
        for _ in range(5):
            self.assertEqual(self.verify(session, "111111")[0], 401)
        self.assertEqual(self.verify(session, code)[0], 401)
        now = datetime.now(timezone.utc)
        with patch("verification._now", return_value=now + timedelta(seconds=61)):
            self.assertEqual(self.challenge(session, replace=True)[0], 200)
            newer = self.sent_codes[-1][2]
        self.assertNotEqual(code, newer)
        with self.sessions._connect() as db:
            new_id = db.execute(
                "SELECT challenge_id FROM guest_challenges"
            ).fetchone()[0]
        self.sessions.cancel_guest_challenge(session, "older-delivery-id")
        with self.sessions._connect() as db:
            self.assertEqual(db.execute(
                "SELECT challenge_id FROM guest_challenges"
            ).fetchone()[0], new_id)
        self.assertEqual(self.verify(session, newer)[1]["status"], "session_ready")
        self.assertEqual(self.sessions.path.stat().st_mode & 0o777, 0o600)

    def test_forged_flags_wrong_uid_and_no_verification_state(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[1]["session"]
        self.assertEqual(self.challenge(session, grant_id=self.grant_a)[0], 401)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_a, session,
        )[1]["status"], "session_ready")
        with self.sessions._connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM guest_verifications"
            ).fetchone()[0], 0)
        self.assertEqual(self.request(
            "/guest/v1/session-status", self.cap_a, "page-a",
            {"grant_id": self.grant_a, "session": session, "verified": True},
        )[0], 400)
        self.assert_wrong_peer_uid_rejected(lambda: self.challenge(session))
        with self.sessions._connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM guest_verifications"
            ).fetchone()[0], 0)
        self.assertEqual(self.sent_codes, [])

    def test_expired_challenge_and_reused_grant_id_fail_closed(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        self.assertEqual(self.challenge(session)[0], 200)
        code = self.sent_codes[-1][2]
        with patch("verification._now", return_value=(
            datetime.now(timezone.utc) + timedelta(seconds=601)
        )):
            self.assertEqual(self.verify(session, code)[0], 401)
        page = self.pages.load("page-a")
        for grant in page["access_grants"]:
            if grant["id"] == self.grant_v:
                grant["token_hash"] = sha256(b"new-invitation-secret").hexdigest()
        self.pages.replace("page-a", page)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, session,
        )[0], 401)
        self.assertEqual(self.challenge(session)[0], 401)

    def test_failed_delivery_cannot_cancel_replacement(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v,
        )[1]["session"]
        original = self.sessions.issue_guest_challenge(
            session, "page-a", self.grant_v,
        )
        later = datetime.now(timezone.utc) + timedelta(seconds=61)
        with patch("verification._now", return_value=later):
            replacement = self.sessions.issue_guest_challenge(
                session, "page-a", self.grant_v, replace=True,
            )
        self.sessions.cancel_guest_challenge(session, original[1])
        self.assertEqual(self.verify(session, replacement[0])[1]["status"],
                         "session_ready")

    def test_verification_lifetime_is_clamped_to_twelve_hours_and_session(self):
        far_expiry = datetime.now(timezone.utc) + timedelta(days=2)
        secret = "long-lived-bootstrap-secret-123456"
        session, session_expiry = self.sessions.consume_bootstrap(
            "page-a", self.grant_v, secret, sha256(secret.encode()).hexdigest(),
            far_expiry,
        )
        code, _identifier = self.sessions.issue_guest_challenge(
            session, "page-a", self.grant_v,
        )
        verified_expiry = self.sessions.verify_guest_challenge(
            session, "page-a", self.grant_v, code, session_expiry,
        )
        self.assertLessEqual(verified_expiry, session_expiry)
        self.assertLessEqual(verified_expiry,
                             int(datetime.now(timezone.utc).timestamp()) + 12 * 3600)

    def test_delivery_uses_the_admin_broker_credential_and_fixed_route(self):
        with patch("ha_broker.HTTPConnection") as connection_type:
            connection = connection_type.return_value
            connection.getresponse.return_value.status = 200
            SEND_GUEST_EMAIL("page-a", self.grant_v, "123456")
        args, kwargs = connection.request.call_args
        self.assertEqual(args[:2], (
            "POST", "/api/internal/email/guest-verification",
        ))
        self.assertEqual(kwargs["headers"]["X-HA-Broker-Token"],
                         ha_broker.ADMIN_TOKEN)
        self.assertEqual(json.loads(kwargs["body"]), {
            "page_id": "page-a", "grant_id": self.grant_v, "code": "123456",
        })

    def test_one_time_individual_sessions_are_bound_to_current_page_and_grant(self):
        page = self.pages.load("page-a")
        page["access_grants"][0]["one_time_use"] = True
        self.pages.replace("page-a", page)
        code, first = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a
        )
        self.assertEqual(code, 200)
        self.assertEqual(first["status"], "session_ready")
        self.assertLessEqual(first["expires_at"], int(self.expiry.timestamp()))
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a
        )[0], 401)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_a, first["session"]
        )[0], 200)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_b, first["session"]
        )[0], 401)
        self.assertEqual(self.status(
            self.cap_b, "page-b", self.grant_a, first["session"]
        )[0], 401)
        # Both sessions use the same Unix-socket origin; IP is never identity.
        second = self.exchange(
            self.cap_a, "page-a", self.grant_b, self.secret_b
        )[1]
        self.assertNotEqual(first["session"], second["session"])
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_b, second["session"]
        )[0], 200)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_b, first["session"]
        )[0], 401)

    def test_reusable_invitation_creates_independent_device_sessions(self):
        sessions = []
        for _ in range(2):
            status, result = self.exchange(
                self.cap_a, "page-a", self.grant_a, self.secret_a,
            )
            self.assertEqual(status, 200)
            self.assertEqual(result["status"], "session_ready")
            self.assertEqual(result["expires_at"], int(self.expiry.timestamp()))
            sessions.append(result["session"])
        self.assertNotEqual(*sessions)
        for session in sessions:
            self.assertEqual(self.status(
                self.cap_a, "page-a", self.grant_a, session,
            )[0], 200)
            self.assertEqual(self.status(
                self.cap_a, "page-a", self.grant_b, session,
            )[0], 401)
        self.pages.remove_access_grant("page-a", self.grant_a)
        for session in sessions:
            self.assertEqual(self.status(
                self.cap_a, "page-a", self.grant_a, session,
            )[0], 401)
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a,
        )[0], 401)

    def test_previously_consumed_reusable_invitation_works_after_upgrade(self):
        original, _ = self.sessions.consume_bootstrap(
            "page-a", self.grant_a, self.secret_a,
            sha256(self.secret_a.encode()).hexdigest(), self.expiry,
        )
        with patch("ha_broker.GUEST_SESSION_STORE", VerificationStore(self.sessions.path)):
            status, result = self.exchange(
                self.cap_a, "page-a", self.grant_a, self.secret_a,
            )
            self.assertEqual(status, 200)
            self.assertNotEqual(original, result["session"])
            for session in (original, result["session"]):
                self.assertEqual(self.status(
                    self.cap_a, "page-a", self.grant_a, session,
                )[0], 200)

    def test_reusable_invitation_requires_verification_on_each_device(self):
        sessions = []
        for _ in range(2):
            status, result = self.exchange(
                self.cap_a, "page-a", self.grant_v, self.secret_v,
            )
            self.assertEqual(status, 200)
            self.assertEqual(result["status"], "verification_required")
            sessions.append(result["session"])
        first, second = sessions
        with patch("verification.secrets.randbelow", side_effect=[123456, 654321]):
            self.assertEqual(self.challenge(first)[0], 200)
            first_code = self.sent_codes[-1][2]
            self.assertEqual(self.challenge(second)[0], 200)
            second_code = self.sent_codes[-1][2]
        self.assertEqual(self.verify(first, first_code)[1]["status"], "session_ready")
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, second,
        )[1]["status"], "verification_required")
        self.assertEqual(self.read(second, grant_id=self.grant_v)[0], 403)
        self.assertEqual(self.verify(second, first_code)[0], 401)
        self.assertEqual(self.verify(second, second_code)[1]["status"], "session_ready")

    def test_bootstrap_page_and_grant_claims_cannot_broaden_authority(self):
        self.assertEqual(self.exchange(
            self.cap_b, "page-b", self.grant_a, self.secret_a
        )[0], 401)
        self.assertEqual(self.exchange(
            self.cap_b, "page-a", self.grant_a, self.secret_a
        )[0], 403)
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", self.grant_b, self.secret_a
        )[0], 401)
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", "grant_" + "x" * 16, self.secret_a
        )[0], 401)
        self.assertEqual(self.status(
            "missing-capability-123456", "page-a", self.grant_a,
            "missing-session-123456",
        )[0], 401)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_a,
            "missing-session-123456",
        )[0], 401)

    def test_current_grant_and_verification_gate_are_rechecked(self):
        code, result = self.exchange(
            self.cap_a, "page-a", self.grant_v, self.secret_v
        )
        self.assertEqual(code, 200)
        self.assertEqual(result["status"], "verification_required")
        session = result["session"]
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, session
        )[1]["status"], "verification_required")
        shorter = datetime.now(timezone.utc) + timedelta(minutes=5)
        page = self.pages.load("page-a")
        for grant in page["access_grants"]:
            if grant["id"] == self.grant_v:
                grant["expires_at"] = shorter.isoformat()
        self.pages.replace("page-a", page)
        code, current = self.status(
            self.cap_a, "page-a", self.grant_v, session
        )
        self.assertEqual(code, 200)
        self.assertLessEqual(current["expires_at"], int(shorter.timestamp()))
        self.pages.remove_access_grant("page-a", self.grant_v)
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_v, session
        )[0], 401)
        self.pages.remove_access_grant("page-a", self.grant_a)
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a
        )[0], 401)
        page = self.pages.load("page-a")
        page["access_grants"][0]["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        self.pages.replace("page-a", page)
        self.assertEqual(self.exchange(
            self.cap_a, "page-a", self.grant_b, self.secret_b
        )[0], 401)

    def test_session_expires_and_removed_page_invalidates_it(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a
        )[1]["session"]
        with patch(
            "verification._now", return_value=self.expiry + timedelta(seconds=1)
        ):
            self.assertEqual(self.status(
                self.cap_a, "page-a", self.grant_a, session
            )[0], 401)
        self.pages.delete("page-a")
        self.assertEqual(self.status(
            self.cap_a, "page-a", self.grant_a, session
        )[0], 401)

    def test_scoped_session_cannot_reach_ha_or_bypass_peer_identity(self):
        session = self.exchange(
            self.cap_a, "page-a", self.grant_a, self.secret_a
        )[1]["session"]
        for route in (
            "/v1/states", "/v1/camera-image", "/v1/page-action",
            "/v1/proximity", "/v1/discovery", "/v1/notification-targets",
            "/v1/send-notification", "/v1/policy/publish",
        ):
            self.assertEqual(self.request(
                route, self.cap_a, "page-a",
                {"grant_id": self.grant_a, "session": session},
            )[0], 404)
        ha_broker.HA_CLIENT.assert_not_called()
        self.assert_wrong_peer_uid_rejected(
            lambda: self.status(self.cap_a, "page-a", self.grant_a, session)
        )
        ha_broker.HA_CLIENT.assert_not_called()
