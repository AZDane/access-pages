import os
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("ACCESS_PAGES_BROKER_TOKEN", "synthetic-broker-token")
os.environ.setdefault("LAYERV_API_BASE_URL", "https://layerv.invalid")
os.environ.setdefault("LAYERV_API_TOKEN", "lv_test_synthetic")
os.environ.setdefault("LAYERV_RESOURCE_ID", "r_synthetic")

import layerv_broker
from guest_resources import AgentRecoveryRequired
from pages import PageStore


class LayerVBrokerPolicyTests(unittest.TestCase):
    def test_expected_agent_restore_failure_keeps_broker_listener_for_admin_reset(self):
        publisher = Mock()
        publisher.restore.side_effect = AgentRecoveryRequired("explicit reset required")
        manager = Mock(publisher=publisher)
        with (
            patch.object(layerv_broker, "ConnectorPublisher", return_value=publisher),
            patch.object(layerv_broker, "GuestResources", return_value=manager),
            patch.object(layerv_broker, "ThreadingHTTPServer") as listener,
            patch.object(layerv_broker.signal, "signal"),
            patch.object(layerv_broker, "RECOVERY_REQUIRED", False),
            patch.dict(os.environ, {"ACCESS_PAGES_INSTALLATION_ID": "synthetic"}),
        ):
            layerv_broker.run()
            listener.return_value.serve_forever.assert_called_once()
            handler = object.__new__(layerv_broker.Handler)
            handler.path = "/health"
            handler._send = Mock()
            handler.do_GET()
            self.assertEqual(handler._send.call_args.args[0], 503)
            self.assertTrue(handler._send.call_args.args[1]["recovery_required"])
            handler._authorized = Mock(return_value=True)
            handler.path = "/v1/grants"
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 503)
        publisher.close.assert_called_once()

    def test_deferred_revocation_is_durable_bounded_and_keeps_scope(self):
        with (
            patch.object(layerv_broker, "DATA_DIR", self.data_dir),
            patch.object(layerv_broker, "time") as clock,
            patch.object(layerv_broker, "_gateway_grant_live", return_value=False),
            patch.object(layerv_broker, "CLIENT", self.client),
        ):
            clock.time.return_value = 100
            layerv_broker._save_mapping("guest", "grant_a", {
                "qurl_id": "q_a", "resource_id": "r_a", "resource_crid": "crid_a", "upstream_scope": "page",
            })
            layerv_broker._save_mapping("guest", "grant_b", {
                "qurl_id": "q_b", "resource_id": "r_b", "resource_crid": "crid_b", "upstream_scope": "page",
            })
            self.assertTrue(layerv_broker.queue_revocation("guest", "grant_a")["pending"])
            clock.time.return_value = 110
            self.assertEqual(layerv_broker.queue_revocation("guest", "grant_a")["not_before"], 115)
            layerv_broker.drain_revocations()
            self.client.delete_qurl.assert_not_called()
            clock.time.return_value = 116
            layerv_broker.drain_revocations()
            self.client.delete_qurl.assert_called_once_with(resource_id="crid_a", qurl_id="q_a")
            self.assertTrue(layerv_broker._grant_file("guest", "grant_b").exists())
            self.assertFalse(layerv_broker._grant_file("guest", "grant_a").exists())
            with layerv_broker._revocation_db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM revocations").fetchone()[0], 0)

    def test_deferred_revocation_does_not_delete_live_grant(self):
        with (
            patch.object(layerv_broker, "DATA_DIR", self.data_dir),
            patch.object(layerv_broker, "time") as clock,
            patch.object(layerv_broker, "_gateway_grant_live", return_value=True),
            patch.object(layerv_broker, "GATEWAY_GRANTS_DIR", "synthetic-live-registry"),
            patch.object(layerv_broker, "delete_grant") as delete,
        ):
            clock.time.return_value = 100
            layerv_broker._save_mapping("guest", "grant_a", {"qurl_id": "q_a", "resource_id": "r_a"})
            layerv_broker.queue_revocation("guest", "grant_a")
            clock.time.return_value = 200
            layerv_broker.drain_revocations()
            delete.assert_not_called()

    def test_deferred_guest_resource_retries_without_individual_qurl_delete(self):
        manager = Mock()
        from layerv import LayerVError
        manager.revoke.side_effect = [LayerVError("temporarily unavailable", status=503, retry_after=30), False]
        with (
            patch.object(layerv_broker, "DATA_DIR", self.data_dir),
            patch.object(layerv_broker, "time") as clock,
            patch.object(layerv_broker, "_gateway_grant_live", return_value=False),
            patch.object(layerv_broker, "GUEST_RESOURCES", manager),
            patch.object(layerv_broker, "CLIENT", self.client),
        ):
            clock.time.return_value = 100
            layerv_broker._save_mapping("guest", "grant_a", {
                "qurl_id": "q_a", "resource_id": "r_a", "resource_crid": "crid_a", "upstream_scope": "guest",
            })
            layerv_broker.queue_revocation("guest", "grant_a")
            clock.time.return_value = 116
            layerv_broker.drain_revocations()
            self.assertTrue(layerv_broker._grant_file("guest", "grant_a").exists())
            clock.time.return_value = 140
            layerv_broker.drain_revocations()
            self.assertEqual(manager.revoke.call_count, 1)
            clock.time.return_value = 147
            layerv_broker.drain_revocations()
            self.assertEqual(manager.revoke.call_count, 2)
            manager.revoke.assert_called_with("guest", "grant_a", "crid_a", qurl_id="q_a")
            self.client.delete_qurl.assert_not_called()


    def test_disconnected_caller_logs_status_without_success_credentials(self):
        handler = object.__new__(layerv_broker.Handler)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = Mock()
        handler.wfile.write.side_effect = BrokenPipeError
        with patch("builtins.print") as output:
            handler._send(200, {"qurl_link": "https://private.invalid/#secret", "bootstrap": "private-secret"})
        event = json.loads(output.call_args.args[0])
        self.assertEqual(event["event"], "broker_response_client_disconnected")
        self.assertEqual(event["http_status"], 200)
        self.assertNotIn("secret", str(event))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = PageStore(root / "pages")
        self.store.create({
            "id": "guest",
            "title": "Guest",
            "description": "",
            "resources": [],
            "access_grants": [],
        })
        self.data_dir = root / "broker"
        self.registry = root / "page-connectors.json"
        self.registry.write_text(json.dumps({
            "version": 1,
            "pages": {
                "guest": {
                    "connector_id": "ha-test-p-guest",
                    "resource_id": "r_authoritative",
                },
            },
        }), encoding="utf-8")
        self.client = Mock()
        self.client.resource_id = "r_authoritative"
        self.client.create_qurl.return_value = {
            "qurl_id": "q_created",
            "qurl_link": "https://qurl.invalid/example",
            "resource_id": "r_authoritative",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_mapping_requires_matching_gateway_commit_for_orphan_recovery(self):
        gid = "grant_" + "a" * 16
        result = {"qurl_id": "q_aaaaaaaaaaa", "resource_id": "verification-key", "resource_crid": "a" * 59, "upstream_scope": "guest"}
        with patch("layerv_broker.DATA_DIR", self.data_dir), patch("layerv_broker.GATEWAY_GRANTS_DIR", str(self.store.directory)):
            layerv_broker._save_mapping("guest", gid, result)
            self.assertFalse(layerv_broker._gateway_grant_live("guest", gid))
            self.assertTrue(layerv_broker._live_mapping("guest", gid))
            now = datetime.now(timezone.utc)
            page = self.store.load("guest")
            page["access_grants"] = [{"id": gid, "token_hash": "a" * 64, "created_at": now.isoformat(), "expires_at": (now + timedelta(days=3)).isoformat(), "credential_flow": "bootstrap-v1", **result}]
            self.store.replace("guest", page)
            self.assertTrue(layerv_broker._live_mapping("guest", gid))
            layerv_broker._save_mapping("guest", gid, {**result, "qurl_id": "q_bbbbbbbbbbb"})
            self.assertFalse(layerv_broker._gateway_grant_live("guest", gid))
            self.assertTrue(layerv_broker._live_mapping("guest", gid))

    def test_stored_isolation_controls_revocation_after_configuration_changes(self):
        registry = json.loads(self.registry.read_text())
        registry["pages"]["guest"]["target_ip"] = "127.88.0.1"
        self.registry.write_text(json.dumps(registry))
        grant_id = "grant_" + "a" * 16
        target = f"/g/guest/{grant_id}/?bootstrap=" + "s" * 43
        for isolation in ("guest", "page"):
            with self.subTest(isolation=isolation):
                manager = Mock()
                manager.revoke.return_value = False
                scoped_client = Mock(resource_id="a" * 59, resource_public_key="verification-key")
                scoped_client.create_qurl.return_value = {
                    "qurl_id": "q_created", "qurl_link": "https://qurl.invalid/example",
                    "resource_id": "verification-key", "resource_crid": "a" * 59,
                    "upstream_scope": isolation,
                }
                manager.ensure.return_value = scoped_client
                with (
                    patch("layerv_broker.PAGE_STORE", self.store),
                    patch("layerv_broker.DATA_DIR", self.data_dir),
                    patch("layerv_broker.PAGE_CONNECTOR_REGISTRY", self.registry),
                    patch("layerv_broker.CLIENT", self.client),
                    patch("layerv_broker.GUEST_RESOURCES", manager),
                    patch("layerv_broker.RESOURCE_ISOLATION", isolation),
                ):
                    layerv_broker.create_grant("guest", grant_id, "Guest", "1h", target, True, "1h")
                    self.assertEqual(scoped_client.create_qurl.call_args.kwargs["target_path"], target)
                    self.assertTrue(scoped_client.create_qurl.call_args.kwargs["target_path_supported"])
                    with patch("layerv_broker.RESOURCE_ISOLATION", "page" if isolation == "guest" else "guest"):
                        layerv_broker.delete_grant("guest", grant_id)
                if isolation == "guest":
                    manager.revoke.assert_called_once_with("guest", grant_id, "a" * 59, qurl_id="q_created")
                else:
                    manager.revoke.assert_not_called()
                    self.client.delete_qurl.assert_called_with(resource_id="a" * 59, qurl_id="q_created")

    def test_scoped_foreign_resource_response_cannot_create_mapping(self):
        registry = json.loads(self.registry.read_text())
        registry["pages"]["guest"]["target_ip"] = "127.88.0.1"
        self.registry.write_text(json.dumps(registry))
        grant_id = "grant_" + "f" * 16
        target = f"/g/guest/{grant_id}/?bootstrap=" + "s" * 43
        scoped_client = Mock(resource_id="a" * 59, resource_public_key="verification-key")
        scoped_client.create_qurl.return_value = {
            "qurl_id": "q_foreign", "qurl_link": "https://qurl.invalid/foreign",
            "resource_id": "sibling-resource", "upstream_scope": "guest",
        }
        manager = Mock()
        manager.ensure.return_value = scoped_client
        with (
            patch("layerv_broker.PAGE_STORE", self.store),
            patch("layerv_broker.DATA_DIR", self.data_dir),
            patch("layerv_broker.PAGE_CONNECTOR_REGISTRY", self.registry),
            patch("layerv_broker.GUEST_RESOURCES", manager),
            self.assertRaisesRegex(layerv_broker.PolicyError, "does not match"),
        ):
            layerv_broker.create_grant("guest", grant_id, "Guest", "1h", target, False, "1h")
        self.assertFalse((self.data_dir / f"guest--{grant_id}.json").exists())
        scoped_client.delete_qurl.assert_not_called()



    def test_rejects_unknown_page_and_excessive_lifetime(self):
        with (
            patch("layerv_broker.PAGE_STORE", self.store),
            patch("layerv_broker.DATA_DIR", self.data_dir),
            patch("layerv_broker.PAGE_CONNECTOR_REGISTRY", self.registry),
            patch("layerv_broker.CLIENT", self.client),
        ):
            with self.assertRaisesRegex(
                layerv_broker.PolicyError,
                "Page not found",
            ):
                layerv_broker.create_grant(
                    "other",
                    "grant_one",
                    "Guest",
                    "24h",
                    "/access/other?access_token=" + "a" * 43,
                )
            with self.assertRaisesRegex(
                layerv_broker.PolicyError,
                "exceeds",
            ):
                layerv_broker.create_grant(
                    "guest",
                    "grant_two",
                    "Guest",
                    "4d",
                    "/access/guest?access_token=" + "a" * 43,
                )

        self.client.create_qurl.assert_not_called()

    def test_broker_requires_its_exact_internal_credential(self):
        handler = object.__new__(layerv_broker.Handler)
        with patch("layerv_broker.TOKEN", "synthetic-broker-token"):
            for supplied in ("", "wrong-token"):
                handler.headers = {"X-Broker-Token": supplied}
                self.assertFalse(handler._authorized())
            handler.headers = {
                "X-Broker-Token": "synthetic-broker-token",
            }
            self.assertTrue(handler._authorized())

    def test_target_path_is_bound_to_the_requested_page(self):
        for invalid in (
            "/g/other/grant_aaaaaaaaaaaaaaaa/?bootstrap=" + "a" * 43,
            "/g/guest/grant_aaaaaaaaaaaaaaaa/?bootstrap=" + "a" * 43 + "&admin=true",
            "/g/guest/grant_aaaaaaaaaaaaaaaa/?bootstrap=" + "a" * 43 + "#fragment",
            "/access/other?access_token=" + "a" * 43,
            "//access/guest?access_token=" + "a" * 43,
            "/access/guest?access_token=short",
            "/access/guest?access_token=" + "a" * 43 + "&admin=true",
            "/access/guest?access_token=" + "a" * 43 + "#fragment",
            "/access/guest;ignored?access_token=" + "a" * 43,
            "\n/access/guest?access_token=" + "a" * 43,
            "/access/guest?access_token=" + "a" * 43 + "\t",
            "/access/guest?access_token=" + "%61" * 43,
            "/access/guest?access_token=" + "a" * 43 + "&access_token=" + "b" * 43,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                layerv_broker.PolicyError
            ):
                layerv_broker._target_path("guest", invalid)



if __name__ == "__main__":
    unittest.main()
