import tempfile
import unittest
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pages import (
    PageConfigError,
    PageStore,
    validate_access_grants,
    validate_page,
    validate_notifications,
)


VALID_PAGE = {
    "id": "cat-sitter",
    "title": "Cat Sitter",
    "description": "Front door only",
    "resources": [{
        "id": "front-door",
        "name": "Front Door",
        "entity_id": "lock.front_door",
        "domain": "lock",
        "widget": "auto",
        "actions": [
            {"id": "lock", "name": "Lock", "service": "lock"},
            {"id": "unlock", "name": "Unlock", "service": "unlock"},
        ],
    }],
}


class PageStoreTests(unittest.TestCase):
    def test_missing_and_legacy_credential_flows_fail_closed(self):
        grant = {
            "id": "grant_" + "a" * 16,
            "token_hash": "a" * 64,
            "created_at": "2026-09-01T00:00:00Z",
            "expires_at": "2026-09-02T00:00:00Z",
        }
        for flow in (None, "legacy", "bootstrap-v0", "unknown"):
            candidate = {**grant, **({"credential_flow": flow} if flow is not None else {})}
            with self.subTest(flow=flow), self.assertRaises(PageConfigError):
                validate_access_grants([candidate])

    def test_grant_tttttttttttttttts_fail_closed_before_persistence(self):
        grant = {
            "id": "grant_tttttttttttttttt", "credential_flow": "bootstrap-v1", "token_hash": "a" * 64,
            "created_at": "2026-09-01T00:00:00Z",
            "expires_at": "2026-09-02T00:00:00Z",
        }
        for field in ("created_at", "expires_at"):
            for value in ("tomorrow", "2026-09-02", "2026-09-02T00:00:00", "2026-99-01T00:00:00Z"):
                with self.subTest(field=field, value=value), self.assertRaises(PageConfigError):
                    validate_access_grants([{**grant, field: value}])
        valid = {**grant, "expires_at": "2026-09-02T01:00:00+01:00"}
        self.assertEqual(validate_access_grants([valid])[0]["expires_at"], valid["expires_at"])

    def test_guest_notification_settings_allow_only_registered_target_shapes(self):
        self.assertEqual(
            validate_notifications({
                "targets": ["email", "notify.mobile_app_johns_phone"],
                "events": ["initial_login", "successful_action", "failed_action"],
            })["targets"],
            ["email", "notify.mobile_app_johns_phone"],
        )
        with self.assertRaises(PageConfigError):
            validate_notifications({
                "targets": ["notify.everyone"],
                "events": ["initial_login"],
            })

    def test_camera_resource_is_valid_read_only_policy(self):
        page = validate_page({
            **VALID_PAGE,
            "resources": [{
                "id": "driveway",
                "name": "Driveway",
                "entity_id": "camera.driveway",
                "domain": "camera",
                "widget": "auto",
                "actions": [{
                    "id": "view",
                    "name": "Display",
                    "service": "view",
                }],
            }],
        })
        self.assertEqual(page["resources"][0]["domain"], "camera")
        self.assertEqual(page["resources"][0]["actions"][0]["service"], "view")
        self.assertEqual(page["resources"][0]["camera_refresh_interval"], 30)

    def test_camera_refresh_intervals_are_validated(self):
        camera = {
            "id": "driveway", "name": "Driveway",
            "entity_id": "camera.driveway", "domain": "camera",
            "actions": [{"id": "view", "name": "Display", "service": "view"}],
        }
        for interval in (0, 15, 30, 60, 120, 300):
            with self.subTest(interval=interval):
                page = validate_page({
                    **VALID_PAGE,
                    "resources": [{**camera, "camera_refresh_interval": interval}],
                })
                self.assertEqual(
                    page["resources"][0]["camera_refresh_interval"], interval
                )
        for interval in (-1, 10, "30", None, True):
            with self.subTest(interval=interval), self.assertRaises(PageConfigError):
                validate_page({
                    **VALID_PAGE,
                    "resources": [{**camera, "camera_refresh_interval": interval}],
                })

    def test_non_camera_rejects_camera_refresh_interval(self):
        resource = {**VALID_PAGE["resources"][0], "camera_refresh_interval": 30}
        with self.assertRaises(PageConfigError):
            validate_page({**VALID_PAGE, "resources": [resource]})

    def test_proximity_policy_defaults_and_round_trips(self):
        defaulted = validate_page(VALID_PAGE)
        self.assertEqual(
            defaulted["proximity"],
            {"enabled": False, "radius_meters": 500},
        )
        enabled = validate_page({
            **VALID_PAGE,
            "proximity": {"enabled": True, "radius_meters": 750},
        })
        self.assertEqual(
            enabled["proximity"],
            {"enabled": True, "radius_meters": 750},
        )

    def test_rejects_invalid_proximity_policy(self):
        for proximity in (
            True,
            {"enabled": "yes", "radius_meters": 500},
            {"enabled": True, "radius_meters": 49},
            {"enabled": True, "radius_meters": 50001},
        ):
            with self.subTest(proximity=proximity):
                with self.assertRaises(PageConfigError):
                    validate_page({**VALID_PAGE, "proximity": proximity})

    def test_resource_order_is_preserved(self):
        page = validate_page({
            "id": "ordered",
            "title": "Ordered",
            "resources": [
                {
                    "id": "z_resource",
                    "name": "Z resource",
                    "entity_id": "light.z_resource",
                    "domain": "light",
                    "actions": [{"id": "view", "name": "View", "service": "view"}],
                },
                {
                    "id": "a_resource",
                    "name": "A resource",
                    "entity_id": "light.a_resource",
                    "domain": "light",
                    "actions": [{"id": "view", "name": "View", "service": "view"}],
                },
            ],
        })

        self.assertEqual(
            [resource["id"] for resource in page["resources"]],
            ["z_resource", "a_resource"],
        )

    def test_create_load_update_preserves_grants(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PageStore(Path(tmp))
            page = store.create(VALID_PAGE)
            page["access_grants"] = [{
                "id": "grant_xxxxxxxxxxxxxxxx",
                "credential_flow": "bootstrap-v1", "token_hash": "a" * 64,
                "created_at": "2026-07-23T00:00:00Z",
                "expires_at": "2026-07-24T00:00:00Z",
                "qurl_id": "q_test",
                "resource_id": "r_test",
            }]
            store.replace(page["id"], page)
            edited = {**VALID_PAGE, "title": "Updated"}
            updated = store.update(page["id"], edited)
            self.assertEqual(updated["title"], "Updated")
            self.assertEqual(updated["access_grants"][0]["qurl_id"], "q_test")

    def test_remove_access_grant_preserves_other_grants(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PageStore(Path(tmp))
            page = store.create(VALID_PAGE)
            base = {
                "credential_flow": "bootstrap-v1", "token_hash": "c" * 64,
                "created_at": "2026-07-23T00:00:00Z",
                "expires_at": "2026-07-24T00:00:00Z",
            }
            page["access_grants"] = [
                {**base, "id": "grant_oooooooooooooooo"},
                {**base, "id": "grant_wwwwwwwwwwwwwwww"},
            ]
            store.replace(page["id"], page)

            updated = store.remove_access_grant(page["id"], "grant_oooooooooooooooo")

            self.assertEqual(
                [grant["id"] for grant in updated["access_grants"]],
                ["grant_wwwwwwwwwwwwwwww"],
            )

    def test_expire_access_grants_removes_only_elapsed_grants(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PageStore(Path(tmp))
            page = store.create({
                "id": "cat-sitter",
                "title": "Cat Sitter",
                "description": "",
                "resources": [],
            })
            grant = {
                "credential_flow": "bootstrap-v1", "token_hash": "c" * 64,
                "created_at": "2026-07-23T00:00:00Z",
            }
            expired = {
                **grant,
                "id": "grant_eeeeeeeeeeeeeeee",
                "expires_at": "2026-07-29T00:00:00Z",
            }
            active = {
                **grant,
                "id": "grant_aaaaaaaaaaaaaaaa",
                "expires_at": "2026-07-31T00:00:00Z",
            }
            page["access_grants"] = [expired, active]
            store.replace(page["id"], page)

            updated, removed = store.expire_access_grants(
                page["id"],
                now=datetime(2026, 7, 30, tzinfo=timezone.utc),
            )

            self.assertEqual(
                [grant["id"] for grant in removed],
                ["grant_eeeeeeeeeeeeeeee"],
            )
            self.assertEqual(
                [grant["id"] for grant in updated["access_grants"]],
                ["grant_aaaaaaaaaaaaaaaa"],
            )

    def test_revoke_all_grants_preserves_page_definitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PageStore(Path(tmp))
            page = store.create(VALID_PAGE)
            page["access_grants"] = [{
                "id": "grant_xxxxxxxxxxxxxxxx",
                "credential_flow": "bootstrap-v1", "token_hash": "a" * 64,
                "created_at": "2026-07-23T00:00:00Z",
                "expires_at": "2026-07-24T00:00:00Z",
                "qurl_id": "q_test",
                "resource_id": "r_test",
            }]
            store.replace(page["id"], page)

            pages_updated, grants = store.revoke_all_access_grants()

            preserved = store.load("cat-sitter")
            self.assertEqual(pages_updated, 1)
            self.assertEqual(grants[0]["qurl_id"], "q_test")
            self.assertEqual(preserved["resources"], page["resources"])
            self.assertEqual(preserved["access_grants"], [])

    def test_page_revoke_all_survives_crash_before_cleanup_queue_for_both_modes(self):
        for scope in ("guest", "page"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as tmp:
                store = PageStore(Path(tmp))
                page = store.create(VALID_PAGE)
                page["access_grants"] = [{
                    "id": "grant_" + "x" * 16,
                    "credential_flow": "bootstrap-v1", "token_hash": "a" * 64,
                    "created_at": "2026-07-23T00:00:00Z",
                    "expires_at": "2026-07-24T00:00:00Z",
                    "qurl_id": "q_test", "resource_id": "r_test",
                    "resource_crid": "c" * 59 if scope == "guest" else "",
                    "upstream_scope": scope,
                }]
                store.replace(page["id"], page)
                with patch.object(store.cleanup, "enqueue", side_effect=OSError("interrupted")):
                    with self.assertRaises(OSError):
                        store.revoke_page_access_grants(page["id"])
                restarted = PageStore(Path(tmp))
                self.assertEqual(restarted.load(page["id"])["access_grants"], [])
                self.assertTrue((Path(tmp) / "cat-sitter.revoking").exists())
                restarted.recover_pending_revocations()
                self.assertEqual(restarted.load(page["id"])["access_grants"], [])
                self.assertFalse((Path(tmp) / "cat-sitter.revoking").exists())
                with sqlite3.connect(restarted.cleanup.path) as db:
                    row = db.execute("SELECT resource,qurl FROM cleanup").fetchone()
                self.assertEqual(row, (("c" * 59) if scope == "guest" else "r_test", "q_test"))

    def test_page_revoke_all_survives_crash_after_queue_before_page_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PageStore(Path(tmp))
            page = store.create(VALID_PAGE)
            page["access_grants"] = [{
                "id": "grant_" + "x" * 16,
                "credential_flow": "bootstrap-v1", "token_hash": "a" * 64,
                "created_at": "2026-07-23T00:00:00Z",
                "expires_at": "2026-07-24T00:00:00Z",
                "qurl_id": "q_test", "resource_id": "r_test",
            }]
            store.replace(page["id"], page)
            write = store._write

            def interrupted(path, payload):
                if path.suffix == ".json":
                    raise OSError("crash before page replace")
                return write(path, payload)

            with patch.object(store, "_write", side_effect=interrupted):
                with self.assertRaises(OSError):
                    store.revoke_page_access_grants(page["id"])
            self.assertEqual(PageStore(Path(tmp)).load(page["id"])["access_grants"], [])
            restarted = PageStore(Path(tmp))
            restarted.recover_pending_revocations()
            self.assertEqual(restarted.load(page["id"])["access_grants"], [])
            with sqlite3.connect(restarted.cleanup.path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM cleanup").fetchone()[0], 1)

    def test_rejects_cross_domain_resource(self):
        bad = {**VALID_PAGE, "resources": [{**VALID_PAGE["resources"][0], "domain": "switch"}]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PageConfigError):
                PageStore(Path(tmp)).create(bad)

    def test_grant_round_trip_keeps_layer_v_identifiers(self):
        grants = validate_access_grants([{
            "id": "grant_xxxxxxxxxxxxxxxx",
            "credential_flow": "bootstrap-v1", "token_hash": "b" * 64,
            "created_at": "2026-07-23T00:00:00Z",
            "expires_at": "2026-07-24T00:00:00Z",
            "qurl_id": "q_123",
            "resource_id": "r_123",
            "type": "connector",
        }])
        self.assertEqual(grants[0]["qurl_id"], "q_123")
        self.assertEqual(grants[0]["resource_id"], "r_123")

    def test_rejects_unknown_access_grant_fields(self):
        with self.assertRaisesRegex(
            PageConfigError,
            "unsupported fields: access_path",
        ):
            validate_access_grants([{
                "id": "grant_iiiiiiiiiiiiiiii",
                "credential_flow": "bootstrap-v1", "token_hash": "d" * 64,
                "created_at": "2026-07-23T00:00:00Z",
                "expires_at": "2026-07-24T00:00:00Z",
                "access_path": (
                    "/access/cat-sitter?access_token=plaintext-secret"
                ),
            }])


if __name__ == "__main__":
    unittest.main()
