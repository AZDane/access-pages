import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from activity import GuestActivityStore


GRANT = {
    "id": "grant_test",
    "label": "Cat sitter",
    "created_at": "2026-07-30T00:00:00Z",
    "expires_at": "2026-07-31T00:00:00Z",
}


class GuestActivityStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "activity.sqlite3"
        self.store = GuestActivityStore(self.path)

    def test_database_remains_group_accessible(self):
        self.store.register_guest("cat-sitter", GRANT)

        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def test_records_only_safe_action_fields(self):
        self.store.register_guest("cat-sitter", GRANT)
        self.store.record_action(
            grant_id=GRANT["id"],
            entity_id="light.kitchen",
            entity_name="Kitchen",
            action_id="turn_on",
            parameters={
                "brightness_pct": 60,
                "code": "must-not-be-stored",
                "access_token": "must-not-be-stored",
            },
            outcome="success",
        )

        activity = self.store.guest_activity(
            "cat-sitter",
            GRANT["id"],
        )

        self.assertEqual(
            activity["actions"][0]["parameters"],
            {"brightness_pct": 60},
        )
        self.assertNotIn(
            "must-not-be-stored",
            self.path.read_bytes().decode("utf-8", errors="ignore"),
        )
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_initial_access_is_reported_only_once(self):
        self.assertTrue(self.store.record_initial_access("cat-sitter", GRANT))
        self.assertFalse(self.store.record_initial_access("cat-sitter", GRANT))

    def test_revocation_retains_then_explicitly_deletes_history(self):
        self.store.register_guest("cat-sitter", GRANT)
        self.assertFalse(
            self.store.delete_revoked_guest("cat-sitter", GRANT["id"])
        )

        self.store.mark_revoked("cat-sitter", GRANT)
        guests = self.store.page_guests("cat-sitter")

        self.assertIsNotNone(guests[0]["revoked_at"])
        self.assertTrue(
            self.store.delete_revoked_guest("cat-sitter", GRANT["id"])
        )
        self.assertEqual(self.store.page_guests("cat-sitter"), [])

    def test_automatically_purges_thirty_days_after_revocation(self):
        revoked_at = datetime(2026, 7, 30, tzinfo=timezone.utc)
        self.store.mark_revoked(
            "cat-sitter",
            GRANT,
            revoked_at=revoked_at,
        )

        with patch(
            "activity._now",
            return_value=revoked_at + timedelta(days=31),
        ):
            self.assertEqual(self.store.page_guests("cat-sitter"), [])

    def test_caps_activity_and_deleting_page_cascades(self):
        self.store.register_guest("cat-sitter", GRANT)
        with patch("activity.MAX_ACTIONS_PER_GUEST", 2):
            for value in range(3):
                self.store.record_action(
                    grant_id=GRANT["id"],
                    entity_id="number.test",
                    entity_name="Test",
                    action_id="set_value",
                    parameters={"value": value},
                    outcome="success",
                )

        activity = self.store.guest_activity("cat-sitter", GRANT["id"])
        self.assertEqual(len(activity["actions"]), 2)
        self.assertEqual(
            {item["parameters"]["value"] for item in activity["actions"]},
            {1, 2},
        )

        self.store.delete_page("cat-sitter")
        self.assertIsNone(
            self.store.guest_activity("cat-sitter", GRANT["id"])
        )

    def test_security_events_drop_sensitive_fields_and_follow_guest(self):
        self.store.register_guest("cat-sitter", GRANT)
        self.store.record_security_event(
            page_id="cat-sitter",
            grant_id=GRANT["id"],
            event_type="action_rate_limited",
            details={
                "action_id": "turn_on",
                "reason": "request_limit_exceeded",
                "access_token": "must-not-be-stored",
                "client_ip": "192.0.2.1",
            },
        )

        activity = self.store.guest_activity(
            "cat-sitter",
            GRANT["id"],
        )
        events = self.store.page_security_events("cat-sitter")

        self.assertEqual(len(activity["security_events"]), 1)
        self.assertEqual(
            events[0]["details"],
            {
                "action_id": "turn_on",
                "reason": "request_limit_exceeded",
            },
        )
        database = self.path.read_bytes().decode("utf-8", errors="ignore")
        self.assertNotIn("must-not-be-stored", database)
        self.assertNotIn("192.0.2.1", database)

        self.store.mark_revoked("cat-sitter", GRANT)
        self.store.delete_revoked_guest("cat-sitter", GRANT["id"])
        self.assertEqual(
            self.store.page_security_events("cat-sitter"),
            [],
        )

    def test_security_events_are_purged_after_thirty_days(self):
        occurred_at = datetime(2026, 7, 1, tzinfo=timezone.utc)
        with patch("activity._now", return_value=occurred_at):
            self.store.record_security_event(
                page_id="cat-sitter",
                event_type="action_rate_limited",
            )

        with patch(
            "activity._now",
            return_value=occurred_at + timedelta(days=31),
        ):
            self.assertEqual(
                self.store.page_security_events("cat-sitter"),
                [],
            )


if __name__ == "__main__":
    unittest.main()
