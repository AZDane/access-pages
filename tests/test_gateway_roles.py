"""Admin Gateway has no ordinary guest authority after cutover."""

import http.client
import json
import os
import threading
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-admin-token")

import server


class GatewayBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.page = {"id": "guest", "title": "Guest", "description": "", "resources": [], "access_grants": []}
        self.page_store = Mock()
        self.page_store.load.return_value = self.page
        self.page_store.list_pages.return_value = [self.page]
        self.ha_client = Mock()
        self.ha_client.get_states.return_value = []
        self.ha_client.notification_targets.return_value = []
        self.patches = [
            patch.object(server, "PAGE_STORE", self.page_store),
            patch.object(server, "HA_CLIENT", self.ha_client),
            patch.object(server.POLICY_PUBLISHER, "pending", return_value=False),
            patch.object(server.Handler, "log_message"),
        ]
        for item in self.patches:
            item.start()
        self.http = server.GatewayHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.thread.join()
        self.http.server_close()
        for item in reversed(self.patches):
            item.stop()

    def request(self, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.http.server_port)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_old_guest_routes_reject_endpoint_capability(self):
        headers = {"X-Page-Capability": "synthetic-page-secret", "X-Access-Pages-Page-ID": "guest"}
        for method, path in [
            ("GET", "/g/guest/grant_aaaaaaaaaaaaaaaa/"),
            ("GET", "/api/access/guest"),
            ("POST", "/api/access/guest/light/turn_on"),
            ("POST", "/api/access/guest/verification/send"),
            ("POST", "/api/internal/email/verification"),
            ("POST", "/api/internal/guest-notification"),
        ]:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path, headers)[0], 404)
        self.ha_client.call_service.assert_not_called()

    def test_admin_preview_is_separate_and_gateway_survives_guest_service_outage(self):
        preview = server.Handler._preview_token(server.Handler, "guest", 2_000_000_000)
        self.page["resources"] = [{
            "id": "lamp", "name": "Lamp", "entity_id": "switch.lamp", "domain": "switch", "widget": "auto",
            "actions": [{"id": "turn_on", "name": "On", "service": "turn_on"}],
        }]
        self.assertEqual(self.request("GET", "/admin")[0], 200)
        self.assertEqual(self.request("GET", "/health")[0], 200)
        self.assertEqual(self.request("GET", "/access/guest?preview_token=" + preview)[0], 200)
        self.assertEqual(self.request("GET", "/api/admin/preview/guest?preview_token=" + preview)[0], 200)
        self.assertEqual(self.request(
            "POST", "/api/admin/preview/guest/lamp/turn_on?preview_token=" + preview,
            {"Content-Type": "application/json"}, json.dumps({}),
        )[0], 200)
        self.ha_client.call_service.assert_called_once()
        self.assertEqual(self.request("GET", "/api/admin/preview/guest")[0], 401)
        self.assertEqual(self.request("GET", "/g/guest/grant_aaaaaaaaaaaaaaaa/?preview_token=" + preview)[0], 404)


if __name__ == "__main__":
    unittest.main()
