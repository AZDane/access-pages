import json
import io
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.error import HTTPError

from layerv import BrokerLayerVClient, LayerVClient, LayerVError


class FakeResponse:
    def __init__(self, payload=b""):
        self.payload = payload
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.payload


class LayerVClientTests(unittest.TestCase):
    @patch("layerv.urlopen")
    def test_broker_recovery_status_is_visible_to_admin_health(self, urlopen):
        urlopen.side_effect = HTTPError(
            "http://broker.invalid/health", 503, "unavailable", {},
            io.BytesIO(b'{"status":"recovery required","recovery_required":true}'),
        )
        client = BrokerLayerVClient("http://broker.invalid", "private-token")
        self.assertTrue(client.recovery_required())

    @patch("layerv.urlopen")
    def test_mints_one_shot_agent_token_from_retained_key(self, urlopen):
        token = "lv_test_" + "t" * 43
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps({
            "data": {"kind": "enrollment_token", "target": "agent", "api_key": token}
        }).encode()
        client = LayerVClient("https://api.example", "retained-key", "unused")
        self.assertEqual(client.mint_agent_enrollment_token(), token)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.example/v1/api-keys")
        self.assertEqual(json.loads(request.data), {
            "kind": "enrollment_token", "name": "Access Pages agent enrollment", "target": "agent",
        })
        self.assertEqual(request.get_header("Authorization"), "Bearer retained-key")

    @patch("layerv.urlopen")
    def test_qurl_creation_rate_limit_preserves_retry_after_without_detail(self, urlopen):
        urlopen.side_effect = HTTPError("https://api.invalid", 429, "rate limit", {"Retry-After": "120"}, io.BytesIO(b'{"error":{"code":"rate_limit_exceeded","detail":"private-value"}}'))
        client = LayerVClient("https://api.invalid", "private-key", "resource")
        with self.assertRaises(LayerVError) as raised:
            client.create_qurl(label="Guest", expires_in="1h")
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertIn("rate limit", str(raised.exception))
        self.assertIn("120 seconds", str(raised.exception))
        self.assertNotIn("private-value", str(raised.exception))

    @patch("layerv.urlopen")
    def test_qurl_plan_quota_is_distinct_from_creation_rate(self, urlopen):
        urlopen.side_effect = HTTPError("https://api.invalid", 403, "quota", {}, io.BytesIO(b'{"error":{"code":"quota_exceeded","detail":"private-value"}}'))
        with self.assertRaises(LayerVError) as raised:
            LayerVClient("https://api.invalid", "key", "resource").create_qurl(label="Guest", expires_in="1h")
        self.assertIn("quota exceeded", str(raised.exception))
        self.assertEqual(raised.exception.status, 403)
        self.assertNotIn("rate limit", str(raised.exception))
        self.assertNotIn("private-value", str(raised.exception))

    @patch("layerv.urlopen")
    def test_private_broker_error_preserves_actionable_status_without_raw_detail(self, urlopen):
        body = {"error": "LayerV denied permission during login (Connector exit 6)", "layerv_status": 403, "detail": "private-credential"}
        urlopen.side_effect = HTTPError("http://broker.invalid", 502, "failed", {"Retry-After": "2"}, io.BytesIO(json.dumps(body).encode()))
        with self.assertRaises(LayerVError) as raised:
            BrokerLayerVClient("http://broker.invalid", "private-token")._request("POST", "/v1/grants", {})
        self.assertEqual(raised.exception.status, 403)
        self.assertEqual(raised.exception.retry_after, 2)
        self.assertEqual(str(raised.exception), body["error"])
        self.assertNotIn("private-credential", str(raised.exception))

    @patch("layerv.urlopen", side_effect=TimeoutError)
    def test_timeout_is_pending_cleanup_not_unhandled_success(self, _urlopen):
        client = LayerVClient("https://api.example", "token", "crid")
        broker = BrokerLayerVClient("http://broker.invalid", "private-token")
        for operation in (
            lambda: client.delete_resource(resource_crid="crid"),
            lambda: client.delete_qurl(resource_id="crid", qurl_id="q_aaaaaaaaaaa"),
            lambda: broker._request("DELETE", "/grant"),
        ):
            with self.subTest(operation=operation), self.assertRaises(LayerVError) as raised:
                operation()
            self.assertEqual(raised.exception.status, 503)
            self.assertEqual(raised.exception.retry_after, 2)

    @patch("layerv.urlopen")
    def test_modern_mint_confirms_effective_admission_settings_from_inventory(self, urlopen):
        path = "/g/page/grant_mmmmmmmmmmmmmmmm/?bootstrap=" + "a" * 43
        post = {"data": {"qurl_id": "q_aaaaaaaaaaa", "qurl_link": "https://example/q", "resource_id": "verification-key", "target_path": path, "expires_at": (datetime.now(timezone.utc) + timedelta(days=3) - timedelta(minutes=1)).isoformat()}}
        expected = {"qurl_id": "q_aaaaaaaaaaa", "one_time_use": False, "session_duration": 86400, "target_path": path}
        for change in ({"one_time_use": True}, {"session_duration": 3600}, {"target_path": "/foreign/"}, {}):
            urlopen.side_effect = [FakeResponse(json.dumps(post).encode()), FakeResponse(json.dumps({"data": [{**expected, **change}], "meta": {"has_more": False}}).encode())]
            client = LayerVClient("https://api.example", "token", "crid", resource_public_key="verification-key", resource_scope="guest")
            if change:
                with self.subTest(change=change), self.assertRaises(LayerVError):
                    client.create_qurl(label="Mary", expires_in="3d", target_path=path, target_path_supported=True, session_duration="24h")
            else:
                self.assertEqual(client.create_qurl(label="Mary", expires_in="3d", target_path=path, target_path_supported=True, session_duration="24h")["resource_crid"], "crid")

    @patch("layerv.urlopen")
    def test_inventory_follows_has_more_even_for_short_pages(self, urlopen):
        urlopen.side_effect = [
            FakeResponse(json.dumps({"data": [{"qurl_id": "mary"}], "meta": {"has_more": True, "next_cursor": "a/b+"}}).encode()),
            FakeResponse(json.dumps({"data": [{"qurl_id": "susan"}], "meta": {"has_more": False}}).encode()),
        ]
        result = LayerVClient("https://api.example", "token", "unused").list_qurls(resource_crid="a/b")
        self.assertEqual([x["qurl_id"] for x in result], ["mary", "susan"])
        self.assertIn("a%2Fb/qurls?", urlopen.call_args.args[0].full_url)
        self.assertIn("cursor=a%2Fb%2B", urlopen.call_args.args[0].full_url)

    @patch("layerv.urlopen")
    def test_create_captures_qurl_id(self, urlopen):
        urlopen.return_value = FakeResponse(json.dumps({"data": {
            "id": "q_abc", "qurl_link": "https://example/q", "resource_id": "r_abc"
        }}).encode())
        result = LayerVClient("https://api.example", "token", "r_abc").create_qurl(
            label="Cat", expires_in="1h"
        )
        self.assertEqual(result["qurl_id"], "q_abc")
        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertIs(payload["one_time_use"], False)
        self.assertEqual(payload["session_duration"], "1h")

    @patch("layerv.urlopen")
    def test_pending_revocation_retains_retry_after(self, urlopen):
        urlopen.side_effect = HTTPError("https://api.example", 503, "pending", {"Retry-After": "30"}, io.BytesIO(b"pending"))
        with self.assertRaises(LayerVError) as caught:
            LayerVClient("https://api.example", "token", "resource").delete_qurl(qurl_id="q_mary")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(caught.exception.retry_after, 30)

    @patch("layerv.urlopen")
    def test_scoped_mint_requires_confirmed_scope_resource_and_bounded_expiry(self, urlopen):
        path = "/g/page/grant_mmmmmmmmmmmmmmmm/?bootstrap=" + "a" * 43
        valid = {"qurl_id": "q_mary", "qurl_link": "https://example/q", "resource_id": "resource", "target_path": path, "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat()}
        for field, value in [("target_path", "/"), ("resource_id", "foreign"), ("expires_at", "bad"), ("expires_at", (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat())]:
            urlopen.return_value = FakeResponse(json.dumps({"data": {**valid, field: value}}).encode())
            with self.subTest(field=field, value=value), self.assertRaises(LayerVError):
                LayerVClient("https://api.example", "token", "resource").create_qurl(label="Mary", expires_in="1h", one_time_use=True, target_path=path, target_path_supported=True)
        urlopen.return_value = FakeResponse(json.dumps({"data": valid}).encode())
        result = LayerVClient("https://api.example", "token", "resource").create_qurl(label="Mary", expires_in="1h", one_time_use=True, target_path=path, target_path_supported=True)
        self.assertTrue(result["target_path_applied"])
        self.assertIs(json.loads(urlopen.call_args.args[0].data)["one_time_use"], True)

    @patch("layerv.urlopen")
    def test_target_path_is_reserved_until_layer_v_support_is_enabled(self, urlopen):
        urlopen.return_value = FakeResponse(json.dumps({"data": {
            "id": "q_abc", "qurl_link": "https://example/q", "resource_id": "r_abc"
        }}).encode())
        client = LayerVClient("https://api.example", "token", "r_abc")
        target_path = "/g/guest/grant_aaaaaaaaaaaaaaaa/?bootstrap=" + "a" * 43

        result = client.create_qurl(
            label="Guest",
            expires_in="1h",
            target_path=target_path,
        )
        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertNotIn("target_path", payload)
        self.assertFalse(result["target_path_applied"])

        urlopen.return_value = FakeResponse(json.dumps({"data": {
            "id": "q_abc", "qurl_link": "https://example/q", "resource_id": "r_abc",
            "target_path": target_path,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat(),
        }}).encode())

        result = client.create_qurl(
            label="Guest",
            expires_in="1h",
            target_path=target_path,
            target_path_supported=True,
        )
        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload["target_path"], target_path)
        self.assertTrue(result["target_path_applied"])

    @patch("layerv.urlopen")
    def test_delete_uses_documented_endpoint(self, urlopen):
        urlopen.return_value = FakeResponse()
        client = LayerVClient("https://api.example", "token", "r_default")
        already_missing = client.delete_qurl(
            resource_id="r_abc",
            qurl_id="q_xyz",
        )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.example/v1/resources/r_abc/qurls/q_xyz")
        self.assertEqual(request.method, "DELETE")
        self.assertFalse(already_missing)

    @patch("layerv.urlopen")
    def test_delete_treats_not_found_and_gone_as_already_revoked(
        self,
        urlopen,
    ):
        client = LayerVClient("https://api.example", "token", "r_default")
        for status in (404, 410):
            with self.subTest(status=status):
                urlopen.side_effect = HTTPError(
                    "https://api.example",
                    status,
                    "missing",
                    {},
                    io.BytesIO(b"Resource not found"),
                )
                self.assertTrue(
                    client.delete_qurl(
                        resource_id="r_abc",
                        qurl_id="q_xyz",
                    )
                )

    @patch("layerv.urlopen")
    def test_delete_preserves_other_layer_v_failures(self, urlopen):
        urlopen.side_effect = HTTPError(
            "https://api.example",
            401,
            "unauthorized",
            {},
            io.BytesIO(b"Unauthorized"),
        )
        client = LayerVClient("https://api.example", "token", "r_default")

        with self.assertRaises(LayerVError) as raised:
            client.delete_qurl(resource_id="r_abc", qurl_id="q_xyz")

        self.assertEqual(raised.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
