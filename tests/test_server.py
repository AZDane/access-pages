import os
import tempfile
import sqlite3
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from unittest.mock import Mock, patch

os.environ.setdefault("HA_BASE_URL", "http://ha.example")
os.environ.setdefault("HA_TOKEN", "test-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")

from layerv import LayerVError
from pages import PageConfigError
from pages import PageStore
import server as gateway_server
from server import Handler, parse_qurl_lifetime


GRANT = {
    "id": "grant_one",
    "token_hash": "a" * 64,
    "created_at": "2026-07-23T00:00:00Z",
    "expires_at": "2026-07-24T00:00:00Z",
    "qurl_id": "q_one",
    "resource_id": "r_one",
    "label": "Guest",
}


class PageActionLockTests(unittest.TestCase):
    def test_unused_page_lock_is_removed(self):
        page_id = "temporary-page-lock"

        with gateway_server.page_action_lock(page_id):
            self.assertIn(page_id, gateway_server._PAGE_ACTION_LOCKS)

        self.assertNotIn(page_id, gateway_server._PAGE_ACTION_LOCKS)

    def test_waiting_requests_share_the_same_page_lock(self):
        page_id = "concurrent-page-lock"
        first_entered = Event()
        release_first = Event()
        second_entered = Event()

        def hold_first():
            with gateway_server.page_action_lock(page_id):
                first_entered.set()
                release_first.wait(1)

        def enter_second():
            with gateway_server.page_action_lock(page_id):
                second_entered.set()

        first = Thread(target=hold_first)
        second = Thread(target=enter_second)
        first.start()
        self.assertTrue(first_entered.wait(1))
        second.start()
        self.assertFalse(second_entered.wait(0.05))
        release_first.set()
        first.join(1)
        second.join(1)

        self.assertTrue(second_entered.is_set())
        self.assertNotIn(page_id, gateway_server._PAGE_ACTION_LOCKS)


class QurlLifetimeTests(unittest.TestCase):
    def test_accepts_custom_relative_durations(self):
        self.assertEqual(
            parse_qurl_lifetime("90m")[1].total_seconds(),
            90 * 60,
        )
        self.assertEqual(
            parse_qurl_lifetime("2d")[1].total_seconds(),
            2 * 24 * 60 * 60,
        )

    def test_rejects_invalid_or_over_limit_durations(self):
        with self.assertRaisesRegex(ValueError, "whole-number duration"):
            parse_qurl_lifetime("tomorrow")
        with self.assertRaisesRegex(ValueError, "configured maximum"):
            parse_qurl_lifetime("7d")




class FakePageStore:
    def __init__(self, events):
        self.events = events

    def load(self, page_id):
        return {"id": page_id, "access_grants": [GRANT]}

    def remove_access_grant(self, page_id, grant_id):
        self.events.append(("local", page_id, grant_id))

    def revoke_all_access_grants(self):
        self.events.append(("local-all",))
        return 1, [{**GRANT, "_page_id": "cat-sitter"}]

    def revoke_page_access_grants(self, page_id):
        self.events.append(("local-all", page_id))
        return self.load(page_id), [GRANT]

    def list_pages(self):
        return [{"id": "cat-sitter"}]


class FakeLayerVClient:
    def __init__(self, events, error=None, already_missing=False):
        self.events = events
        self.error = error
        self.already_missing = already_missing

    def delete_qurl(
        self,
        *,
        resource_id,
        qurl_id,
        page_id="",
        grant_id="",
    ):
        self.events.append(("remote", resource_id, qurl_id))
        if self.error:
            raise self.error
        return self.already_missing


class IndividualRevokeTests(unittest.TestCase):
    def handler(self, responses):
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        return handler

    def test_native_revocation_denies_locally_before_durable_queue_request(self):
        from layerv import BrokerLayerVClient
        events = []
        responses = []
        broker = Mock(spec=BrokerLayerVClient)
        def enqueue(**kw):
            events.append(("queued", kw["page_id"], kw["grant_id"]))
            return {"pending": True}
        broker.queue_revocation.side_effect = enqueue
        with (
            patch("server.PAGE_STORE", FakePageStore(events)),
            patch("server.LAYERV_CLIENT", broker),
            patch("server.audit"),
        ):
            self.handler(responses)._revoke_grant("cat-sitter", "grant_one")
        self.assertEqual(events, [("local", "cat-sitter", "grant_one"), ("queued", "cat-sitter", "grant_one")])
        self.assertTrue(responses[0][1]["local_access_revoked"])
        self.assertTrue(responses[0][1]["remote_revocation_pending"])
        self.assertFalse(responses[0][1]["remote_access_revoked"])
        broker.delete_qurl.assert_not_called()

    def test_revokes_local_grant_before_remote_qurl(self):
        """Make local denial authoritative before attempting remote cleanup.

        Reordering these operations would leave a usable local grant whenever
        LayerV deletion is slow or unavailable.
        """
        events = []
        responses = []

        with (
            patch("server.PAGE_STORE", FakePageStore(events)),
            patch("server.LAYERV_CLIENT", FakeLayerVClient(events)),
            patch("server.cleanup_guest_sessions",
                  side_effect=lambda page, grant: events.append(("session-cleanup", page, grant))),
            patch("server.audit") as audit_mock,
        ):
            self.handler(responses)._revoke_grant("cat-sitter", "grant_one")

        self.assertEqual(
            events,
            [
                ("local", "cat-sitter", "grant_one"),
                ("session-cleanup", "cat-sitter", "grant_one"),
                ("remote", "r_one", "q_one"),
            ],
        )
        self.assertEqual(responses[0][0], 200)
        self.assertTrue(responses[0][1]["remote_access_revoked"])
        self.assertFalse(responses[0][1]["remote_already_missing"])
        self.assertNotIn("label", audit_mock.call_args.kwargs)

    def test_already_missing_remote_qurl_is_a_success(self):
        events = []
        responses = []

        with (
            patch("server.PAGE_STORE", FakePageStore(events)),
            patch(
                "server.LAYERV_CLIENT",
                FakeLayerVClient(events, already_missing=True),
            ),
            patch("server.audit"),
        ):
            self.handler(responses)._revoke_grant(
                "cat-sitter",
                "grant_one",
            )

        self.assertEqual(responses[0][0], 200)
        self.assertTrue(responses[0][1]["remote_access_revoked"])
        self.assertTrue(responses[0][1]["remote_already_missing"])

    def test_remote_failure_keeps_local_access_revoked(self):
        """Never restore local authority after LayerV cleanup fails."""
        events = []
        responses = []
        error = LayerVError("LayerV unavailable")

        with (
            patch("server.PAGE_STORE", FakePageStore(events)),
            patch("server.LAYERV_CLIENT", FakeLayerVClient(events, error)),
            patch("server.audit"),
        ):
            self.handler(responses)._revoke_grant("cat-sitter", "grant_one")

        self.assertEqual(events[0], ("local", "cat-sitter", "grant_one"))
        self.assertEqual(responses[0][0], 502)
        self.assertTrue(responses[0][1]["local_access_revoked"])
        self.assertFalse(responses[0][1]["remote_access_revoked"])

    def test_revoke_all_broker_failure_reconciles_without_reviving_guests(self):
        from layerv import BrokerLayerVClient
        for scope in ("guest", "page"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temp:
                store = PageStore(Path(temp))
                grant = {
                    "id": "grant_" + "a" * 16, "token_hash": "a" * 64,
                    "credential_flow": "bootstrap-v1",
                    "created_at": "2026-07-23T00:00:00Z",
                    "expires_at": "2026-07-24T00:00:00Z",
                    "resource_id": "r_shared" if scope == "page" else "r_guest",
                    "resource_crid": "c" * 59 if scope == "guest" else "",
                    "qurl_id": "q_guest", "upstream_scope": scope,
                }
                store.create({"id": "alpha", "title": "Alpha", "resources": [], "access_grants": [grant]})
                store.create({"id": "other", "title": "Other", "resources": [], "access_grants": [{
                    **grant, "id": "grant_" + "b" * 16, "qurl_id": "q_other",
                }]})
                broker = Mock(spec=BrokerLayerVClient)
                broker.queue_revocation.side_effect = LayerVError("broker unavailable", status=503)
                responses = []
                handler = self.handler(responses)
                handler._load_page = store.load
                with (
                    patch("server.PAGE_STORE", store),
                    patch("server.LAYERV_CLIENT", broker),
                    patch("server.VERIFICATION_RECIPIENTS", Mock()),
                    patch("server.ACTIVITY_STORE", Mock()),
                    patch("server.cleanup_guest_sessions"),
                    patch("server.audit"),
                ):
                    handler._revoke_all_grants("alpha")
                self.assertEqual(responses[0][0], 502)
                self.assertEqual(PageStore(Path(temp)).load("alpha")["access_grants"], [])
                self.assertEqual(len(store.load("other")["access_grants"]), 1)
                with sqlite3.connect(store.cleanup.path) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM cleanup").fetchone()[0], 1)
                broker.delete_qurl.side_effect = LayerVError("LayerV unavailable", status=503, retry_after=1)
                store.cleanup.drain(broker)
                with sqlite3.connect(store.cleanup.path) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM cleanup").fetchone()[0], 1)
                broker.delete_qurl.side_effect = None
                with patch("upstream_cleanup.time.time", return_value=time.time() + 10):
                    PageStore(Path(temp)).cleanup.drain(broker)
                self.assertEqual(PageStore(Path(temp)).load("alpha")["access_grants"], [])
                self.assertEqual(len(store.load("other")["access_grants"]), 1)
                with sqlite3.connect(store.cleanup.path) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM cleanup").fetchone()[0], 0)
                self.assertEqual(broker.delete_qurl.call_args.kwargs["resource_id"],
                                 ("c" * 59) if scope == "guest" else "r_shared")


class GuestActivityRouteTests(unittest.TestCase):
    def test_delete_route_removes_revoked_guest_record(self):
        responses = []
        activity_store = Mock()
        activity_store.delete_revoked_guest.return_value = True
        handler = object.__new__(Handler)
        handler.path = (
            "/api/admin/pages/cat-sitter/activity/grant_one"
        )
        handler.headers = {}
        handler._require_admin = lambda: True
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )

        with (
            patch("server.ACTIVITY_STORE", activity_store),
            patch("server.audit"),
        ):
            handler.do_DELETE()

        activity_store.delete_revoked_guest.assert_called_once_with(
            "cat-sitter",
            "grant_one",
        )
        self.assertEqual(
            responses,
            [(200, {"success": True, "guest_deleted": True})],
        )


class ConnectionResetTests(unittest.TestCase):
    def handler(self, responses):
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        return handler

    def test_reset_requires_explicit_confirmation(self):
        responses = []
        self.handler(responses)._reset_layer_v_connection(
            {"confirmation": "reset"}
        )
        self.assertEqual(responses[0][0], 400)

    def test_reset_revokes_locally_before_remote_and_requests_restart(self):
        events = []
        responses = []
        with tempfile.TemporaryDirectory() as tmp:
            request_file = Path(tmp) / "reset.request"
            with (
                patch("server.PAGE_STORE", FakePageStore(events)),
                patch("server.LAYERV_CLIENT", FakeLayerVClient(events)),
                patch("server.cleanup_guest_sessions",
                      side_effect=lambda page, grant: events.append(("session-cleanup", page, grant))),
                patch("server.RESET_REQUEST_FILE", request_file),
                patch("server.audit"),
            ):
                self.handler(responses)._reset_layer_v_connection(
                    {"confirmation": "RESET"}
                )

            self.assertEqual(events[0], ("local-all",))
            self.assertEqual(events[1], ("session-cleanup", "cat-sitter", "grant_one"))
            self.assertEqual(events[2], ("remote", "r_one", "q_one"))
            self.assertTrue(request_file.is_file())
            self.assertEqual(
                request_file.stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(responses[0][0], 202)
            self.assertTrue(responses[0][1]["pages_preserved"])
            self.assertEqual(responses[0][1]["grants_revoked"], 1)


class EntityPolicyValidationTests(unittest.TestCase):
    @staticmethod
    def discovered_client():
        client = Mock()
        client.discover_entities.return_value = {
            "entities": [{
                "entity_id": "light.kitchen",
                "domain": "light",
                "device_class": "",
                "area_id": "kitchen",
                "actions": [
                    {"service": "turn_on", "name": "Turn on"},
                    {"service": "turn_off", "name": "Turn off"},
                ],
            }]
        }
        client.entity_allowed.return_value = True
        return client

    def test_rejects_entity_missing_from_policy_filtered_discovery(self):
        client = self.discovered_client()
        payload = {
            "resources": [{
                "entity_id": "lock.front_door",
                "domain": "lock",
            }]
        }

        with patch("server.HA_CLIENT", client):
            with self.assertRaises(PageConfigError):
                object.__new__(Handler)._validate_entity_policy(payload)

    def test_accepts_exact_curated_entity_action(self):
        payload = {
            "resources": [{
                "entity_id": "light.kitchen",
                "domain": "light",
                "actions": [{
                    "id": "turn_on",
                    "name": "Turn on",
                    "service": "turn_on",
                }],
            }]
        }
        with patch("server.HA_CLIENT", self.discovered_client()):
            object.__new__(Handler)._validate_entity_policy(payload)

    def test_rejects_unapproved_service_in_handcrafted_admin_payload(self):
        payload = {
            "resources": [{
                "entity_id": "light.kitchen",
                "domain": "light",
                "actions": [{
                    "id": "reload",
                    "name": "Reload",
                    "service": "reload",
                }],
            }]
        }
        with (
            patch("server.HA_CLIENT", self.discovered_client()),
            self.assertRaisesRegex(
                PageConfigError,
                "Action is unavailable",
            ),
        ):
            object.__new__(Handler)._validate_entity_policy(payload)

    def test_rejects_tampered_action_identity_or_display_name(self):
        base = {
            "entity_id": "light.kitchen",
            "domain": "light",
        }
        actions = (
            {
                "id": "turn_off",
                "name": "Turn on",
                "service": "turn_on",
            },
            {
                "id": "turn_on",
                "name": "Unlock",
                "service": "turn_on",
            },
        )
        for action in actions:
            with (
                self.subTest(action=action),
                patch("server.HA_CLIENT", self.discovered_client()),
                self.assertRaises(PageConfigError),
            ):
                object.__new__(Handler)._validate_entity_policy({
                    "resources": [{**base, "actions": [action]}],
                })

    def test_rejects_entity_domain_substitution(self):
        payload = {
            "resources": [{
                "entity_id": "light.kitchen",
                "domain": "lock",
                "actions": [],
            }]
        }
        with (
            patch("server.HA_CLIENT", self.discovered_client()),
            self.assertRaises(PageConfigError),
        ):
            object.__new__(Handler)._validate_entity_policy(payload)


class AuthorizationBoundaryTests(unittest.TestCase):
    def test_infinite_integer_parameters_fail_without_ha_mutation(self):
        for domain, service, parameter in (
            ("light", "turn_on", "brightness_pct"),
            ("fan", "set_percentage", "percentage"),
        ):
            for value in (float("inf"), float("-inf")):
                responses = []
                page = self.page()
                resource = page["resources"][0]
                resource.update(domain=domain, entity_id=f"{domain}.allowed")
                resource["actions"][0]["service"] = service
                client = Mock()
                with self.subTest(domain=domain, value=value), patch("server.HA_CLIENT", client):
                    self.handler(responses)._execute_public_action(
                        page, "kitchen", "turn_on", {parameter: value},
                    )
                self.assertEqual(responses[0][0], 400)
                client.call_service.assert_not_called()

    @staticmethod
    def handler(responses):
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        handler.client_address = ("127.0.0.1", 1234)
        return handler

    @staticmethod
    def page():
        return {
            "id": "guest",
            "resources": [{
                "id": "kitchen",
                "entity_id": "light.kitchen",
                "domain": "light",
                "actions": [{
                    "id": "turn_on",
                    "name": "Turn on",
                    "service": "turn_on",
                }],
            }],
        }

    def test_rejects_resource_from_another_page(self):
        responses = []
        client = Mock()
        with (
            patch("server.HA_CLIENT", client),
            patch("server.ACTIVITY_STORE"),
        ):
            self.handler(responses)._execute_public_action(
                self.page(),
                "front-door",
                "unlock",
                {},
            )

        self.assertEqual(responses, [(404, {"error": "Resource not found"})])
        client.call_service.assert_not_called()

    def test_camera_image_uses_only_the_assigned_camera_entity(self):
        """Resolve the upstream camera from the page-scoped resource ID."""
        responses = []
        sent = []
        client = Mock()
        client.get_camera_image.return_value = (b"jpeg", "image/jpeg")
        page = self.page()
        page["resources"].append({
            "id": "driveway",
            "entity_id": "camera.driveway",
            "domain": "camera",
            "actions": [],
        })
        handler = self.handler(responses)
        handler.camera_access_scope = "preview:one"
        handler._send_bytes = lambda *args: sent.append(args)
        with (
            patch("server.HA_CLIENT", client),
            patch("server.CAMERA_IMAGE_RATE_LIMITER") as limiter,
        ):
            limiter.allow.return_value = True
            handler._send_camera_image(page, "driveway")

        client.get_camera_image.assert_called_once_with(
            "camera.driveway",
            page_id="guest",
            resource_id="driveway",
        )
        self.assertEqual(sent[0][1:3], (b"jpeg", "image/jpeg"))

    def test_camera_image_rejects_non_camera_resource(self):
        """Do not let a generic saved entity enter the camera data path."""
        responses = []
        client = Mock()
        handler = self.handler(responses)
        with patch("server.HA_CLIENT", client):
            handler._send_camera_image(self.page(), "kitchen")

        self.assertEqual(responses, [(404, {"error": "Camera not found"})])
        client.get_camera_image.assert_not_called()

    def test_camera_image_enforces_saved_interval_and_isolates_scope(self):
        page = self.page()
        page["resources"].append({
            "id": "driveway", "entity_id": "camera.driveway",
            "domain": "camera", "camera_refresh_interval": 15, "actions": [],
        })
        client = Mock()
        client.get_camera_image.return_value = (b"jpeg", "image/jpeg")
        limiter = Mock()
        limiter.check.side_effect = [(True, 0), (False, 12), (True, 0)]
        responses = []
        sent = []
        handler = self.handler(responses)
        handler.camera_access_scope = "preview:one"
        handler._send_json = lambda status, payload, headers=None: responses.append(
            (status, payload, headers)
        )
        handler._send_bytes = lambda *args: sent.append(args)
        with (
            patch("server.HA_CLIENT", client),
            patch("server.CAMERA_REFRESH_RATE_LIMITER", limiter),
            patch("server.CAMERA_IMAGE_RATE_LIMITER") as broad,
        ):
            broad.allow.return_value = True
            handler._send_camera_image(page, "driveway")
            handler._send_camera_image(page, "driveway")
            handler.camera_access_scope = "preview:two"
            handler._send_camera_image(page, "driveway")

        self.assertEqual(limiter.check.call_args_list[0].args, (
            "guest:preview:one:driveway", 15,
        ))
        self.assertEqual(limiter.check.call_args_list[2].args, (
            "guest:preview:two:driveway", 15,
        ))
        self.assertEqual(responses[0][0], 429)
        self.assertEqual(responses[0][2], {"Retry-After": "12"})
        self.assertEqual(len(sent), 2)

    def test_rejects_unapproved_action_for_assigned_entity(self):
        responses = []
        client = Mock()
        with (
            patch("server.HA_CLIENT", client),
            patch("server.ACTIVITY_STORE"),
        ):
            self.handler(responses)._execute_public_action(
                self.page(),
                "kitchen",
                "turn_off",
                {},
            )

        self.assertEqual(responses, [(404, {"error": "Action not permitted"})])
        client.call_service.assert_not_called()

    def test_ignores_entity_service_and_unknown_parameter_substitution(self):
        responses = []
        client = Mock()
        client.call_service.return_value = {}
        activity_store = Mock()
        handler = self.handler(responses)
        handler.active_grant = {"id": "grant_guest"}
        with (
            patch("server.HA_CLIENT", client),
            patch("server.ACTIVITY_STORE", activity_store),
            patch("server.audit"),
        ):
            handler._execute_public_action(
                self.page(),
                "kitchen",
                "turn_on",
                {
                    "entity_id": "lock.front_door",
                    "service": "unlock",
                    "code": "1234",
                },
            )

        client.call_service.assert_called_once_with(
            "light",
            "turn_on",
            "light.kitchen",
            {},
            page_id="guest",
            resource_id="kitchen",
            action_id="turn_on",
        )
        self.assertEqual(responses[0][0], 200)

    def test_expired_qurl_cleanup_logs_safe_status_and_category(self):
        grant = {
            **GRANT,
            "expires_at": "2026-07-29T00:00:00Z",
        }
        page_store = Mock()
        page_store.expire_access_grants.return_value = (
            {**self.page(), "access_grants": []},
            [grant],
        )
        layer_v = Mock()
        layer_v.delete_qurl.side_effect = LayerVError(
            "LayerV rejected cleanup",
            status=429,
            detail="Bearer secret-must-not-be-logged",
        )
        handler = self.handler([])
        with (
            patch("server.PAGE_STORE", page_store),
            patch("server.ACTIVITY_STORE"),
            patch("server.LAYERV_CLIENT", layer_v),
            patch("server.audit") as audit_mock,
        ):
            handler._cleanup_expired_grants("guest")

        cleanup = next(
            call for call in audit_mock.call_args_list
            if call.args[0] == "expired_qurl_cleanup_failed"
        )
        self.assertEqual(cleanup.kwargs["http_status"], 429)
        self.assertEqual(cleanup.kwargs["error_category"], "rate_limit")
        self.assertNotIn("secret-must-not-be-logged", str(cleanup))




class ParameterValidationTests(unittest.TestCase):
    def proximity_handler(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        return handler, responses

    def test_proximity_accepts_recent_nearby_reading(self):
        handler, responses = self.proximity_handler()
        page = {
            "id": "guest",
            "proximity": {"enabled": True, "radius_meters": 500},
        }
        payload = {"proximity": {
            "latitude": 40.7128,
            "longitude": -74.0060,
            "accuracy_meters": 20,
            "measured_at": datetime.now(timezone.utc).timestamp(),
        }}
        client = Mock()
        client.verify_proximity.return_value = True
        with patch("server.HA_CLIENT", client):
            self.assertTrue(handler._require_proximity(page, payload))
        self.assertEqual(responses, [])

    def test_proximity_rejects_far_stale_or_inaccurate_readings(self):
        page = {
            "id": "guest",
            "proximity": {"enabled": True, "radius_meters": 500},
        }
        now = datetime.now(timezone.utc).timestamp()
        client = Mock()
        client.verify_proximity.return_value = False
        readings = (
            ({
                "latitude": 41.0,
                "longitude": -74.0060,
                "accuracy_meters": 20,
                "measured_at": now,
            }, "too far"),
            ({
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy_meters": 20,
                "measured_at": now - 301,
            }, "expired"),
            ({
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy_meters": 501,
                "measured_at": now,
            }, "not accurate"),
        )
        with patch("server.HA_CLIENT", client):
            for reading, message in readings:
                with self.subTest(message=message):
                    handler, responses = self.proximity_handler()
                    self.assertFalse(handler._require_proximity(
                        page,
                        {"proximity": reading},
                    ))
                    self.assertIn(message, responses[0][1]["error"])

    def test_proximity_is_not_required_when_page_option_is_off(self):
        handler, responses = self.proximity_handler()
        self.assertTrue(handler._require_proximity(
            {"proximity": {"enabled": False, "radius_meters": 500}},
            {},
        ))
        self.assertEqual(responses, [])

    def test_public_page_includes_normalized_capabilities(self):
        page = {
            "id": "guest",
            "title": "Guest",
            "description": "",
            "resources": [{
                "id": "fan",
                "name": "",
                "entity_id": "fan.test",
                "domain": "fan",
                "actions": [{
                    "id": "set_percentage",
                    "name": "Set speed",
                    "service": "set_percentage",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "fan.test",
            "state": "on",
            "attributes": {
                "friendly_name": "Test Fan",
                "percentage": 66,
                "percentage_step": 33.3333333333,
            },
        }]

        with patch("server.HA_CLIENT", client):
            result = object.__new__(Handler)._public_page(page)

        camera_page = {
            **page,
            "resources": [
                {
                    "id": "front", "name": "Front",
                    "entity_id": "camera.front", "domain": "camera",
                    "actions": [], "camera_refresh_interval": 120,
                },
                page["resources"][0],
            ],
        }
        with patch("server.HA_CLIENT") as camera_client:
            camera_client.get_states.return_value = []
            camera_result = object.__new__(Handler)._public_page(camera_page)
        self.assertEqual(
            camera_result["resources"][0]["camera_refresh_interval"], 120
        )
        self.assertNotIn(
            "camera_refresh_interval", camera_result["resources"][1]
        )

        self.assertEqual(
            result["resources"][0]["capabilities"]["fan_percentage"]["values"],
            [33, 66, 100],
        )

    def test_fan_percentage_is_forwarded_as_an_approved_value(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        handler.client_address = ("127.0.0.1", 1234)
        page = {
            "id": "guest",
            "resources": [{
                "id": "fan",
                "entity_id": "fan.test",
                "domain": "fan",
                "actions": [{
                    "id": "set_percentage",
                    "name": "Set speed",
                    "service": "set_percentage",
                }],
            }],
        }
        client = Mock()
        client.call_service.return_value = {}
        client.get_states.return_value = [{
            "entity_id": "fan.test",
            "state": "on",
            "attributes": {
                "percentage": 66,
                "percentage_step": 33.3333333333,
            },
        }]

        with (
            patch("server.HA_CLIENT", client),
            patch("server.audit"),
        ):
            handler._execute_public_action(
                page,
                "fan",
                "set_percentage",
                {"percentage": 66},
            )

        client.call_service.assert_called_once_with(
            "fan",
            "set_percentage",
            "fan.test",
            {"percentage": 66},
            page_id="guest",
            resource_id="fan",
            action_id="set_percentage",
        )
        self.assertEqual(responses[0][0], 200)

    def test_rejects_fan_percentage_not_advertised_by_home_assistant(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "fan",
                "entity_id": "fan.test",
                "domain": "fan",
                "actions": [{
                    "id": "set_percentage",
                    "name": "Set speed",
                    "service": "set_percentage",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "fan.test",
            "state": "on",
            "attributes": {
                "percentage": 66,
                "percentage_step": 33.3333333333,
            },
        }]

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "fan",
                "set_percentage",
                {"percentage": 50},
            )

        self.assertEqual(responses[0], (400, {
            "error": "Unsupported fan percentage",
        }))
        client.call_service.assert_not_called()

    def test_rejects_number_value_between_advertised_steps(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "number",
                "entity_id": "number.test",
                "domain": "number",
                "actions": [{
                    "id": "set_value",
                    "name": "Set value",
                    "service": "set_value",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "number.test",
            "state": "0.5",
            "attributes": {"min": 0, "max": 1, "step": 0.25},
        }]

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "number",
                "set_value",
                {"value": 0.6},
            )

        self.assertEqual(responses[0], (400, {
            "error": "Value must use a step of 0.25",
        }))
        client.call_service.assert_not_called()

    def test_rejects_temperature_between_advertised_steps(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "climate",
                "entity_id": "climate.test",
                "domain": "climate",
                "actions": [{
                    "id": "set_temperature",
                    "name": "Set temperature",
                    "service": "set_temperature",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "climate.test",
            "state": "cool",
            "attributes": {
                "temperature": 72.5,
                "min_temp": 60,
                "max_temp": 85,
                "target_temp_step": 0.5,
            },
        }]

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "climate",
                "set_temperature",
                {"temperature": 72.25},
            )

        self.assertEqual(responses[0], (400, {
            "error": "Temperature must use a step of 0.5",
        }))
        client.call_service.assert_not_called()

    def test_rejects_non_finite_temperature(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "climate",
                "entity_id": "climate.test",
                "domain": "climate",
                "actions": [{
                    "id": "set_temperature",
                    "name": "Set temperature",
                    "service": "set_temperature",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "climate.test",
            "state": "cool",
            "attributes": {
                "temperature": 72,
                "min_temp": 60,
                "max_temp": 85,
                "target_temp_step": 1,
            },
        }]

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "climate",
                "set_temperature",
                {"temperature": float("nan")},
            )

        self.assertEqual(responses[0], (400, {
            "error": "A finite temperature is required",
        }))
        client.call_service.assert_not_called()

    def test_rejects_non_finite_number(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "number",
                "entity_id": "number.test",
                "domain": "number",
                "actions": [{
                    "id": "set_value",
                    "name": "Set value",
                    "service": "set_value",
                }],
            }],
        }
        client = Mock()

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "number",
                "set_value",
                {"value": float("inf")},
            )

        self.assertEqual(responses[0], (400, {
            "error": "A finite value is required",
        }))
        client.get_states.assert_not_called()
        client.call_service.assert_not_called()

    def test_rejects_non_finite_media_volume(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        page = {
            "id": "guest",
            "resources": [{
                "id": "player",
                "entity_id": "media_player.test",
                "domain": "media_player",
                "actions": [{
                    "id": "volume_set",
                    "name": "Set volume",
                    "service": "volume_set",
                }],
            }],
        }
        client = Mock()

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "player",
                "volume_set",
                {"volume_level": float("-inf")},
            )

        self.assertEqual(responses[0], (400, {
            "error": "A finite volume level is required",
        }))
        client.call_service.assert_not_called()

    def test_rejects_select_option_not_reported_by_home_assistant(self):
        responses = []
        handler = object.__new__(Handler)
        handler._send_json = lambda status, payload: responses.append(
            (status, payload)
        )
        handler.client_address = ("127.0.0.1", 1234)
        page = {
            "id": "guest",
            "resources": [{
                "id": "mode",
                "entity_id": "select.mode",
                "domain": "select",
                "actions": [{
                    "id": "select_option",
                    "name": "Select option",
                    "service": "select_option",
                }],
            }],
        }
        client = Mock()
        client.get_states.return_value = [{
            "entity_id": "select.mode",
            "attributes": {"options": ["Home", "Away"]},
        }]

        with patch("server.HA_CLIENT", client):
            handler._execute_public_action(
                page,
                "mode",
                "select_option",
                {"option": "Disallowed"},
            )

        self.assertEqual(responses[0][0], 400)
        client.call_service.assert_not_called()





if __name__ == "__main__":
    unittest.main()


class GuestActivityAccessLogTests(unittest.TestCase):
    def test_existing_guest_callback_has_no_synchronous_access_log(self):
        handler = object.__new__(Handler)
        handler.path = "/api/internal/guest-event"
        handler.requestline = "POST /api/internal/guest-event HTTP/1.1"
        handler.stderr_write = Mock(side_effect=AssertionError("Guest polling reached synchronous stderr"))
        handler.client_address = ("127.0.0.1", 1234)
        for status in (200, 400, 401, 503):
            handler.log_request(status)
        handler.stderr_write.assert_not_called()
        handler.path = "/api/admin/pages"
        with self.assertRaises(AssertionError):
            handler.log_request(200)
