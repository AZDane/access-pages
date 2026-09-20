import http.client
import importlib.util
import json
import os
import threading
import tempfile
from hashlib import sha256
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("HA_BROKER_TOKEN", "synthetic-ha-broker-token")
os.environ.setdefault(
    "HA_BROKER_ADMIN_TOKEN", "synthetic-ha-admin-broker-token"
)
os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha-token")
os.environ.setdefault("ACCESS_PAGES_BROKER_TOKEN", "synthetic-access-pages-token")
os.environ.setdefault("LAYERV_API_BASE_URL", "https://layerv.invalid")
os.environ.setdefault("LAYERV_API_TOKEN", "lv_test_synthetic")
os.environ.setdefault("LAYERV_RESOURCE_ID", "r_synthetic")
os.environ.setdefault("POLICY_STORE_TOKEN", "synthetic-policy-token")

import ha_broker
import layerv_broker
import policy_store
from pages import PageStore

INGRESS_PATH = (
    Path(__file__).resolve().parents[1]
    / "homeassistant-app"
    / "ingress_proxy.py"
)
with patch.dict("os.environ", {"INGRESS_ADMIN_TOKEN": "synthetic-admin-token"}):
    INGRESS_SPEC = importlib.util.spec_from_file_location(
        "internal_listener_ingress_proxy",
        INGRESS_PATH,
    )
    ingress_proxy = importlib.util.module_from_spec(INGRESS_SPEC)
    INGRESS_SPEC.loader.exec_module(ingress_proxy)


@contextmanager
def running_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(port, method, path, *, headers=None, payload=b"{}"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(
            method,
            path,
            body=payload,
            headers=headers or {},
        )
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read()
    finally:
        connection.close()


class InternalListenerAuthenticationTests(unittest.TestCase):
    def assert_unauthorized(self, result, secret):
        status, headers, body = result
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "unauthorized"})
        self.assertEqual(dict(headers).get("Cache-Control"), "no-store")
        self.assertNotIn(secret.encode(), body)

    def test_ha_broker_rejects_missing_and_wrong_guest_credentials(self):
        client = Mock()
        secret = "synthetic-ha-broker-secret"
        with (
            patch("ha_broker.TOKEN", secret),
            patch("ha_broker.ADMIN_TOKEN", "synthetic-admin-secret"),
            patch("ha_broker.HA_CLIENT", client),
            running_server(ha_broker.Handler) as port,
        ):
            for headers in ({}, {"X-Broker-Token": "wrong"}):
                self.assert_unauthorized(
                    request(port, "POST", "/v1/states", headers=headers, payload=None),
                    secret,
                )
        client.assert_not_called()

    def test_camera_image_broker_rejects_missing_and_wrong_credentials(self):
        client = Mock()
        secret = "synthetic-ha-broker-secret"
        with (
            patch("ha_broker.TOKEN", secret),
            patch("ha_broker.HA_CLIENT", client),
            running_server(ha_broker.Handler) as port,
        ):
            for headers in ({}, {"X-Broker-Token": "wrong"}):
                self.assert_unauthorized(
                    request(port, "POST", "/v1/camera-image", headers=headers,
                            payload=None),
                    secret,
                )
        client.assert_not_called()

    def test_ha_discovery_rejects_guest_credential(self):
        client = Mock()
        guest_secret = "synthetic-guest-secret"
        with (
            patch("ha_broker.TOKEN", guest_secret),
            patch("ha_broker.ADMIN_TOKEN", "synthetic-admin-secret"),
            patch("ha_broker.HA_CLIENT", client),
            running_server(ha_broker.Handler) as port,
        ):
            self.assert_unauthorized(
                request(
                    port,
                    "POST",
                    "/v1/discovery",
                    headers={"X-Broker-Token": guest_secret},
                    payload=None,
                ),
                guest_secret,
            )
        client.assert_not_called()

    def test_page_capability_cannot_cross_into_another_page(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = PageStore(root / "policy")
            for page_id, resource_id, entity_id in (
                ("page-a", "light-a", "light.a"),
                ("page-b", "light-b", "light.b"),
            ):
                store.create({
                    "id": page_id,
                    "title": page_id,
                    "description": "",
                    "resources": [{
                        "id": resource_id,
                        "name": resource_id,
                        "entity_id": entity_id,
                        "domain": "light",
                        "actions": [{
                            "id": "turn_on", "name": "Turn on", "service": "turn_on",
                        }],
                    }],
                })
            capability = "page-a-only-capability"
            registry = root / "capabilities.json"
            registry.write_text(json.dumps({
                "page-a": sha256(capability.encode()).hexdigest(),
            }))
            client = Mock()
            with (
                patch("ha_broker.PAGE_STORE", store),
                patch("ha_broker.PAGE_CAPABILITY_REGISTRY", registry),
                patch("ha_broker.HA_CLIENT", client),
                running_server(ha_broker.Handler) as port,
            ):
                status, _headers, _body = request(
                    port,
                    "POST",
                    "/v1/page-action",
                    headers={
                        "X-Broker-Token": capability,
                        "X-Broker-Role": "guest",
                        "Content-Type": "application/json",
                    },
                    payload=json.dumps({
                        "page_id": "page-b",
                        "resource_id": "light-b",
                        "action_id": "turn_on",
                        "parameters": {},
                    }).encode(),
                )
            self.assertEqual(status, 404)
            client.call_service.assert_not_called()

    def test_layerv_broker_rejects_missing_and_wrong_credentials(self):
        client = Mock()
        secret = "synthetic-access-pages-broker-secret"
        with (
            patch("layerv_broker.TOKEN", secret),
            patch("layerv_broker.CLIENT", client),
            running_server(layerv_broker.Handler) as port,
        ):
            cases = (
                ("POST", "/v1/grants", {}),
                ("POST", "/v1/grants", {"X-Broker-Token": "wrong"}),
                ("DELETE", "/v1/grants/page/grant", {}),
                (
                    "DELETE",
                    "/v1/grants/page/grant",
                    {"X-Broker-Token": "wrong"},
                ),
            )
            for method, path, headers in cases:
                self.assert_unauthorized(
                    request(port, method, path, headers=headers, payload=None),
                    secret,
                )
        client.assert_not_called()

    def test_policy_store_rejects_missing_and_wrong_credentials(self):
        secret = "synthetic-policy-store-secret"
        with (
            patch("policy_store.TOKEN", secret),
            patch("policy_store.publish_page") as publish,
            patch("policy_store.delete_page") as delete,
            running_server(policy_store.Handler) as port,
        ):
            cases = (
                ("PUT", "/v1/pages/test", {}),
                ("PUT", "/v1/pages/test", {"X-Policy-Token": "wrong"}),
                ("DELETE", "/v1/pages/test", {}),
                (
                    "DELETE",
                    "/v1/pages/test",
                    {"X-Policy-Token": "wrong"},
                ),
            )
            for method, path, headers in cases:
                self.assert_unauthorized(
                    request(port, method, path, headers=headers, payload=None),
                    secret,
                )
        publish.assert_not_called()
        delete.assert_not_called()

    def test_ingress_rejects_loopback_even_with_forged_ingress_path(self):
        upstream = Mock()
        with (
            patch.object(ingress_proxy, "urlopen", upstream),
            running_server(ingress_proxy.Handler) as port,
        ):
            status, _headers, body = request(
                port,
                "GET",
                "/admin",
                headers={
                    "X-Ingress-Path":
                        "/api/hassio_ingress/synthetic-session",
                },
                payload=None,
            )
        self.assertEqual(status, 403)
        self.assertNotIn(b"synthetic-admin-token", body)
        upstream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
