"""Synthetic HTTP requests through Guest Service and the real Unix broker.

LayerV admission is intentionally outside this fixture; these are local
authorization/resource tests, not evidence of public qURL exploitability.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from http.cookies import SimpleCookie
import json
import secrets
import socket
import unittest
from unittest.mock import patch

import test_broker_guest_sessions as broker_tests
import test_guest_cutover as service_tests
import guest_service


class GuestAuthHardeningTests(unittest.TestCase):
    def setUp(self):
        self.broker = broker_tests.BrokerGuestSessionTests()
        self.broker.setUp()
        self.addCleanup(self.broker.tearDown)
        self.service = service_tests.GuestCutoverTests()
        self.service.setUp()
        self.addCleanup(self.service.tearDown)
        self.secret = secrets.token_urlsafe(32)
        page = self.broker.pages.load("page-a")
        page["access_grants"][0]["token_hash"] = sha256(self.secret.encode()).hexdigest()
        self.broker.pages.replace("page-a", page)

        def connect():
            # Production peer ownership is covered separately. This fixture
            # runs both real handlers as the test user on temporary sockets.
            connection = socket.socket(socket.AF_UNIX)
            try:
                connection.settimeout(5)
                connection.connect(str(self.broker.socket_path))
            except OSError:
                connection.close()
                raise
            return connection

        transport = patch.object(guest_service, "_connect_broker", side_effect=connect)
        transport.start()
        self.addCleanup(transport.stop)

    def request(self, method="GET", *, secret=None, cookie="", grant=None,
                suffix="", headers=None, body=None):
        connection = service_tests.UnixHTTPConnection(self.service.socket_path)
        grant = grant or self.broker.grant_a
        path = f"/g/page-a/{grant}/{suffix}"
        if secret is not None:
            path += "?bootstrap=" + secret
        fields = {
            "X-Access-Pages-Page-ID": "page-a",
            "X-Page-Capability": self.broker.cap_a,
            **(headers or {}),
        }
        if cookie:
            fields["Cookie"] = "access_pages_guest=" + cookie
        if body is not None:
            fields.update({"Content-Type": "application/json", "X-Guest-Request": "1"})
            body = json.dumps(body)
        try:
            connection.request(method, path, body=body, headers=fields)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def session(self, **kwargs):
        status, headers, _ = self.request(**kwargs)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Cache-Control"], "no-store")
        cookie = SimpleCookie(headers["Set-Cookie"])
        return cookie["access_pages_guest"].value

    def test_rotating_invalid_credentials_do_not_write_or_lock_out_valid_guests(self):
        store = self.broker.sessions
        session = self.session(secret=self.secret)
        with (patch.object(store, "_connect", wraps=store._connect) as connect,
              patch.object(store, "consume_bootstrap", wraps=store.consume_bootstrap) as consume):
            for _ in range(100):
                forged = {"X-Forwarded-For": "192.0.2.7", "X-Real-IP": "198.51.100.8"}
                self.assertEqual(self.request(secret=secrets.token_urlsafe(32), headers=forged)[0], 401)
                self.assertEqual(self.request(cookie=secrets.token_urlsafe(32), headers=forged)[0], 401)
            consume.assert_not_called()
            self.assertEqual(connect.call_count, 100)
            self.assertTrue(all(call.kwargs == {"read_only": True} for call in connect.call_args_list))
        # Guesses have not spent the authenticated grant's creation allowance.
        self.assertEqual(self.request(cookie=session)[0], 200)
        for _ in range(11):
            self.session(secret=self.secret)
        self.assertEqual(self.request(secret=self.secret)[0], 429)

    def test_creation_budget_preserves_polling_resume_other_grants_and_recovers(self):
        with patch("rate_limit.monotonic", return_value=1000) as clock:
            sessions = [self.session(secret=self.secret) for _ in range(12)]
            self.assertEqual(len(set(sessions)), 12)
            with patch.object(self.broker.sessions, "consume_bootstrap") as consume:
                for cookie in ("", secrets.token_urlsafe(32)):
                    status, headers, body = self.request(secret=self.secret, cookie=cookie)
                    self.assertEqual(status, 429)
                    self.assertEqual(headers["Retry-After"], "60")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertIn(b"Too many new guest sessions", body)
                consume.assert_not_called()
            # The fixture uses the same local origin for every browser.
            for index in range(24):
                self.assertEqual(self.request(cookie=sessions[index % 12])[0], 200)
            self.assertEqual(self.request(secret=self.secret, cookie=sessions[0])[0], 303)
            self.session(secret=self.broker.secret_b, grant=self.broker.grant_b)
            clock.return_value = 1061
            self.session(secret=self.secret)
            self.broker.pages.remove_access_grant("page-a", self.broker.grant_a)
            self.assertEqual(self.request(cookie=sessions[0])[0], 401)
            self.assertEqual(self.request(secret=self.secret)[0], 401)

    def test_parallel_session_creation_stops_before_extra_database_writes(self):
        # Stay inside the existing Unix accept backlog; exercise credential
        # concurrency independently of the separate transport overload guard.
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.request(secret=self.secret)[0], range(24)))
        self.assertEqual(Counter(results), {303: 12, 429: 12})
        with self.broker.sessions._connect(read_only=True) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM guest_sessions").fetchone()[0], 12)

    def test_rotating_sessions_bounds_new_verification_deliveries(self):
        for _ in range(12):
            session = self.session(secret=self.broker.secret_v, grant=self.broker.grant_v)
            status, _, _ = self.request("POST", cookie=session, grant=self.broker.grant_v,
                                        suffix="api/access/page-a/verification/send", body={"replace": False})
            self.assertEqual(status, 200)
        for _ in range(12):
            self.assertEqual(self.request(secret=self.broker.secret_v, grant=self.broker.grant_v)[0], 429)
        self.assertEqual(len(self.broker.sent_codes), 12)

    def test_single_use_transaction_and_head_behavior_are_preserved(self):
        page = self.broker.pages.load("page-a")
        page["access_grants"][0]["one_time_use"] = True
        self.broker.pages.replace("page-a", page)
        status, headers, body = self.request("HEAD", secret=self.secret)
        self.assertEqual(status, 501)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(body, b"")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.request(secret=self.secret)[0], range(4)))
        self.assertEqual(Counter(results), {303: 1, 401: 3})

    def test_preview_user_agent_is_not_treated_as_authority(self):
        page = self.broker.pages.load("page-a")
        page["access_grants"][0]["one_time_use"] = True
        self.broker.pages.replace("page-a", page)
        self.session(secret=self.secret, headers={"User-Agent": "Slackbot-LinkExpanding 1.0"})
        self.assertEqual(self.request(secret=self.secret)[0], 401)

    def test_broker_and_service_errors_are_not_cacheable(self):
        for kwargs, expected in (({}, 401), ({"method": "DELETE"}, 501),
                                  ({"secret": "bad!"}, 400), ({"suffix": "missing"}, 401)):
            with self.subTest(kwargs=kwargs):
                status, headers, _ = self.request(**kwargs)
                self.assertEqual(status, expected)
                self.assertEqual(headers["Cache-Control"], "no-store")
        for method, path, expected in (("HEAD", "/guest/v1/health", 501),
                                       ("GET", "/unknown", 404),
                                       ("POST", "/guest/v1/bootstrap", 400)):
            connection = service_tests.UnixHTTPConnection(str(self.broker.socket_path))
            try:
                connection.request(method, path)
                response = connection.getresponse()
                self.assertEqual(response.status, expected)
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                response.read()
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
