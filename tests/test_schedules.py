"""Schedule boundaries and durable recovery using real stores, fake transports."""
from contextlib import nullcontext
from datetime import date, datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from activity import GuestActivityStore
from email_delivery import EmailConfigError, VerificationRecipientStore
from layerv import BrokerLayerVClient, LayerVError
from pages import PageStore
from schedules import ScheduleStore, Scheduler, occurrence_window, upcoming, validate_schedule
from tests.test_pages import VALID_PAGE


def instant(value):
    return datetime.fromisoformat(value).timestamp()


def definition(**changes):
    return validate_schedule({"label": "Visitor", "email": "guest@example.test", "timezone": "UTC", "kind": "weekly",
                              "weekdays": list(range(7)), "start_time": "09:00", "end_time": "12:00", **changes})


class CalendarTests(unittest.TestCase):
    def test_dates_weekdays_and_inclusive_start_date_limits(self):
        d = definition(weekdays=[0], first_date="2026-11-16", last_date="2026-11-23")
        for day in ("2026-11-16", "2026-11-23"):
            self.assertIsNotNone(occurrence_window(d, date.fromisoformat(day)))
        for day in ("2026-11-09", "2026-11-17", "2026-11-30"):
            self.assertIsNone(occurrence_window(d, date.fromisoformat(day)))

    def test_overnight_belongs_to_start_date(self):
        d = definition(kind="once", date="2026-11-14", start_time="22:00", end_time="02:00", next_day=True)
        window = occurrence_window(d, date(2026, 11, 14))
        self.assertEqual(window["end"], instant("2026-11-15T02:00:00+00:00"))
        self.assertIsNone(occurrence_window(d, date(2026, 11, 15)))

    def test_dst_gaps_and_folds_skip_instead_of_guessing(self):
        for day, clock in ((date(2026, 3, 8), "02:30"), (date(2026, 11, 1), "01:30")):
            window = occurrence_window(definition(timezone="America/New_York", start_time=clock), day)
            self.assertIn("daylight-saving", window["reason"])
            self.assertIsNone(window["start"])

    def test_dst_changes_utc_but_preserves_local_time(self):
        d = definition(timezone="America/New_York")
        before = occurrence_window(d, date(2026, 3, 7))
        after = occurrence_window(d, date(2026, 3, 8))
        self.assertEqual(after["start"] - before["start"], 23 * 3600)

    def test_long_dst_window_skipped_and_leap_date_supported(self):
        d = definition(timezone="America/New_York", start_time="12:00", end_time="12:00", next_day=True)
        self.assertIn("duration", occurrence_window(d, date(2026, 10, 31))["reason"])
        d = definition(kind="once", date="2028-02-29")
        self.assertEqual(upcoming(d, instant("2026-01-01T00:00:00+00:00"))[0]["local_date"], "2028-02-29")

    def test_input_boundaries(self):
        for changes in ({"email": "bad"}, {"timezone": "../UTC"}, {"start_time": "24:00"},
                        {"end_time": "08:00"}, {"next_day": "false"}, {"weekdays": [True]},
                        {"first_date": "2026-02-30"}, {"weekdays": []}, {"label": ""},
                        {"end_time": "10:00", "next_day": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                definition(**changes)


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = instant("2026-11-14T08:59:00+00:00")
        pages = PageStore(self.root / "pages")
        pages.create(VALID_PAGE)
        self.store = ScheduleStore(self.root / "admin" / "schedules.sqlite3")
        self.client = Mock(spec=BrokerLayerVClient)
        self.client.create_qurl.side_effect = self.mint
        self.r = SimpleNamespace(PAGE_STORE=pages, LAYERV_CLIENT=self.client,
                                 SMTP_CONFIG_STORE=Mock(), VERIFICATION_RECIPIENTS=VerificationRecipientStore(self.root / "recipients.json"),
                                 ACTIVITY_STORE=GuestActivityStore(self.root / "activity.sqlite3"), cleanup_guest_sessions=Mock(),
                                 page_action_lock=lambda _: nullcontext(), audit=Mock())
        self.r.SMTP_CONFIG_STORE.configured.return_value = True
        self.scheduler = Scheduler(self.r, self.store, clock=lambda: self.now)
        self.schedule_id = self.store.save("cat-sitter", definition(), self.now)
        self.sender = self.enterContext(patch("schedules.send_email"))

    def mint(self, **kwargs):
        return {"qurl_link": "https://qurl.invalid/#synthetic", "qurl_id": "q_synthetic", "resource_id": "synthetic-resource",
                "resource_crid": "synthetic-crid", "upstream_scope": "guest", "target_path_applied": True,
                "expires_at": datetime.fromtimestamp(self.now + 86400, timezone.utc).isoformat()}

    def start_window(self):
        self.now = instant("2026-11-14T09:00:00+00:00")
        self.scheduler.tick()

    def grants(self):
        return self.r.PAGE_STORE.load("cat-sitter")["access_grants"]

    def row(self):
        return self.store.work()[0]

    def test_fresh_grant_at_start_exact_end_and_new_grant_next_day(self):
        self.scheduler.tick()
        self.client.create_qurl.assert_not_called()
        self.start_window()
        first = self.grants()[0]
        self.assertEqual(instant(first["expires_at"]), instant("2026-11-14T12:00:00+00:00"))
        self.assertEqual(self.row()["state"], "ready")
        self.scheduler.tick(delivery=True)
        self.assertEqual(self.row()["state"], "accepted")
        self.assertEqual(self.grants()[0]["qurl_link"], "")
        self.assertNotIn("grant", self.row()["record"])
        self.now += 86400
        self.scheduler.tick()
        self.assertEqual(len(self.grants()), 1)
        self.assertNotEqual(self.grants()[0]["id"], first["id"])
        self.assertEqual(self.client.create_qurl.call_count, 2)

    def test_offline_late_delivery_preserves_end_and_skips_old_windows(self):
        self.now = instant("2026-11-14T09:10:00+00:00")
        self.scheduler.tick()
        self.assertEqual(instant(self.grants()[0]["expires_at"]), instant("2026-11-14T12:00:00+00:00"))
        self.now = instant("2026-11-15T09:16:00+00:00")
        self.scheduler.tick()
        self.assertEqual(self.client.create_qurl.call_count, 1)
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "skipped")

    def test_missing_smtp_blocks_until_explicit_resume(self):
        self.r.SMTP_CONFIG_STORE.configured.return_value = False
        self.start_window()
        self.assertEqual(self.store.get(self.schedule_id)["status"], "blocked")
        self.client.create_qurl.assert_not_called()
        self.r.SMTP_CONFIG_STORE.configured.return_value = True
        self.scheduler.tick()
        self.client.create_qurl.assert_not_called()
        self.store.status(self.schedule_id, "enabled", self.now)
        self.now += 86400
        self.scheduler.tick()
        self.client.create_qurl.assert_called_once()

    def test_email_retry_reuses_link_and_message_id_across_restart(self):
        self.start_window()
        self.sender.side_effect = EmailConfigError("synthetic failure")
        self.scheduler.tick(delivery=True)
        first = self.sender.call_args
        self.now += 100
        self.scheduler = Scheduler(self.r, ScheduleStore(self.store.path), clock=lambda: self.now)
        self.sender.side_effect = None
        self.scheduler.tick(delivery=True)
        self.assertEqual(first, self.sender.call_args)
        self.client.create_qurl.assert_called_once()
        self.assertEqual(self.row()["state"], "accepted")

    def test_permanent_email_failure_revokes_before_remote_cleanup(self):
        self.start_window()
        failure = EmailConfigError("synthetic rejection")
        failure.permanent = True
        self.sender.side_effect = failure
        self.client.queue_revocation.side_effect = lambda **kw: self.assertEqual(self.grants(), [])
        self.scheduler.tick(delivery=True)
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "failed")
        self.assertEqual(json.loads((self.root / "recipients.json").read_text()), {})

    def test_ambiguous_mint_is_retired_before_new_attempt(self):
        self.client.create_qurl.side_effect = LayerVError("lost reply", status=503)
        self.start_window()
        old_id = self.row()["record"]["grant_id"]
        self.assertEqual(self.grants(), [])
        self.now += 100
        self.scheduler.tick()
        self.client.queue_revocation.assert_called_with(page_id="cat-sitter", grant_id=old_id)
        self.client.create_qurl.side_effect = self.mint
        self.now += 10
        self.scheduler.tick()
        self.assertNotEqual(self.grants()[0]["id"], old_id)

    def test_cleanup_outage_retries_without_reenabling_access(self):
        self.start_window()
        self.store.status(self.schedule_id, "paused", self.now)
        self.client.queue_revocation.side_effect = LayerVError("offline")
        self.scheduler.tick()
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.row()["state"], "cancelling")
        self.client.queue_revocation.side_effect = None
        self.scheduler.tick()
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "cancelled")

    def test_expired_slow_creation_never_sends(self):
        def slow(**kwargs):
            self.now += 901
            return self.mint(**kwargs)
        self.client.create_qurl.side_effect = slow
        self.start_window()
        self.scheduler.tick(delivery=True)
        self.sender.assert_not_called()
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "failed")

    def test_pause_preserves_accepted_but_revoke_option_ends_it(self):
        self.start_window()
        self.scheduler.tick(delivery=True)
        self.store.status(self.schedule_id, "paused", self.now)
        self.scheduler.tick()
        self.assertEqual(len(self.grants()), 1)
        self.store.status(self.schedule_id, "paused", self.now, revoke=True)
        self.scheduler.tick()
        self.assertEqual(self.grants(), [])

    def test_cancel_between_commit_and_send_and_owner_revocation(self):
        self.start_window()
        grant_id = self.grants()[0]["id"]
        self.r.PAGE_STORE.remove_access_grant("cat-sitter", grant_id)
        self.scheduler.tick(delivery=True)
        self.sender.assert_not_called()
        self.assertEqual(self.grants(), [])

    def test_interrupted_commit_cannot_restore_revoked_grant(self):
        self.start_window()
        row = self.row()
        self.store.put(row, "committing")
        self.r.PAGE_STORE.remove_access_grant("cat-sitter", row["record"]["grant_id"])
        self.scheduler.tick()
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "cancelled")

    def test_interrupted_commit_with_saved_grant_can_continue(self):
        self.start_window()
        self.store.put(self.row(), "committing")
        self.scheduler.tick()
        self.scheduler.tick(delivery=True)
        self.sender.assert_called_once()
        self.client.create_qurl.assert_called_once()

    def test_crash_after_smtp_acceptance_may_repeat_same_message(self):
        self.start_window()
        self.store.put(self.row(), "sending")
        self.scheduler.tick(delivery=True)
        self.sender.assert_called_once()
        self.client.create_qurl.assert_called_once()

    def test_history_contains_no_invitation_secrets_or_recipient(self):
        self.start_window()
        history = json.dumps(self.store.history("cat-sitter"))
        for secret in ("qurl.invalid", "token_hash", "guest@example.test", "synthetic-crid"):
            self.assertNotIn(secret, history)

    def test_normal_restart_retains_jobs_restore_blocks_and_revokes(self):
        self.store.check_recovery(self.r.PAGE_STORE)
        self.start_window()
        self.scheduler.tick(delivery=True)
        self.assertFalse(self.store.check_recovery(self.r.PAGE_STORE))
        self.assertEqual(self.store.get(self.schedule_id)["status"], "enabled")
        self.store.path.with_name("schedule-authorization").unlink()
        self.assertTrue(self.store.check_recovery(self.r.PAGE_STORE))
        self.assertEqual(self.store.get(self.schedule_id)["status"], "blocked")
        self.assertEqual(self.grants(), [])
        self.scheduler.tick()
        self.assertEqual(self.client.create_qurl.call_count, 1)

    def test_old_database_and_new_permit_detect_rollback(self):
        self.store.check_recovery(self.r.PAGE_STORE)
        backup = self.root / "backup.sqlite3"
        shutil.copy2(self.store.path, backup)
        self.store.check_recovery(self.r.PAGE_STORE)
        shutil.copy2(backup, self.store.path)
        self.assertTrue(self.store.check_recovery(self.r.PAGE_STORE))

    def test_clock_rollback_blocks_and_revokes(self):
        self.start_window()
        self.scheduler.tick(delivery=True)
        self.now -= 120
        self.scheduler.tick()
        self.assertEqual(self.store.get(self.schedule_id)["status"], "blocked")
        self.assertEqual(self.grants(), [])

    def test_dst_skip_is_recorded_once(self):
        self.now = instant("2026-03-08T06:59:00+00:00")
        self.store.save("cat-sitter", definition(timezone="America/New_York", start_time="02:30"), self.now, self.schedule_id)
        self.now += 3600
        self.scheduler.tick()
        self.scheduler.tick()
        self.client.create_qurl.assert_not_called()
        self.assertEqual(len(self.store.history("cat-sitter")), 1)
        self.assertEqual(self.store.history("cat-sitter")[0]["state"], "skipped")

    def test_two_guests_and_repeated_ticks_never_duplicate_occurrence(self):
        self.store.save("cat-sitter", definition(label="Second"), self.now)
        self.start_window()
        self.scheduler.tick()
        self.scheduler.tick(delivery=True)
        self.scheduler.tick(delivery=True)
        self.assertEqual(len(self.grants()), 2)
        self.assertEqual(self.client.create_qurl.call_count, 2)
        self.assertEqual(self.sender.call_count, 2)

    def test_schema_future_version_fails_closed(self):
        with self.store.connect() as db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            self.scheduler.tick()

class ScheduleRoutesTests(unittest.TestCase):
    setUp = SchedulerTests.setUp
    mint = SchedulerTests.mint
    start_window = SchedulerTests.start_window
    grants = SchedulerTests.grants

    def route(self, payload=None, suffix="", authorized=True):
        import schedule_routes
        import sqlite3
        from pages import PageConfigError, PageNotFoundError
        self.r.SCHEDULE_STORE = self.store
        self.r.SCHEDULE_TIMEZONE = "America/Phoenix"
        self.r.NOTIFICATION_TARGET_STORE = Mock(load=Mock(return_value=[]))
        self.r.sqlite3 = sqlite3
        self.r.PageConfigError = PageConfigError
        self.r.PageNotFoundError = PageNotFoundError
        handler = SimpleNamespace(_require_admin=Mock(return_value=authorized), _send_json=Mock())
        with patch("schedule_routes.time.time", return_value=self.now):
            handled = schedule_routes.handle(handler, "/api/admin/pages/cat-sitter/schedules" + suffix, self.r, payload)
        self.assertTrue(handled)
        return handler._send_json

    def test_admin_authentication_required(self):
        reply = self.route(authorized=False)
        reply.assert_not_called()

    def test_listing_never_exposes_pending_outbox_secret(self):
        self.start_window()
        reply = self.route()
        self.assertEqual(reply.call_args.args[0], 200)
        self.assertNotIn("qurl.invalid", json.dumps(reply.call_args.args[1]))

    def test_cannot_edit_schedule_from_another_page(self):
        self.r.PAGE_STORE.create({**VALID_PAGE, "id": "other-page"})
        other = self.store.save("other-page", definition(), self.now)
        reply = self.route({"action": "pause"}, "/" + other)
        self.assertEqual(reply.call_args.args[0], 400)
        self.assertEqual(self.store.get(other)["status"], "enabled")

    def test_explicit_pause_and_revoke_denies_before_worker_tick(self):
        self.start_window()
        self.scheduler.tick(delivery=True)
        reply = self.route({"action": "pause", "revoke_active": True}, "/" + self.schedule_id)
        self.assertEqual(reply.call_args.args[0], 200)
        self.assertEqual(self.grants(), [])

    def test_missing_smtp_prevents_creation_and_resume_but_allows_edit(self):
        self.r.SMTP_CONFIG_STORE.configured.return_value = False
        reply = self.route({"definition": definition()})
        self.assertEqual(reply.call_args.args[0], 400)
        reply = self.route({"action": "resume"}, "/" + self.schedule_id)
        self.assertEqual(reply.call_args.args[0], 400)
        reply = self.route({"definition": definition(label="Updated")}, "/" + self.schedule_id)
        self.assertEqual(reply.call_args.args[0], 200)

    def test_preview_has_timezone_and_duplicate_guest_warning_without_minting(self):
        reply = self.route({"action": "preview", "definition": definition()})
        self.assertEqual(reply.call_args.args[0], 200)
        self.assertTrue(reply.call_args.args[1]["warning"])
        self.client.create_qurl.assert_not_called()
