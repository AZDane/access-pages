"""Advance delivery, replacements and local admission use deterministic clocks."""
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from invitations import grant_window_open, scheduled_window
from schedules import ScheduleStore, Scheduler, validate_schedule
from tests.test_schedules import SchedulerFixture, definition, instant


class AdvanceDeliveryTests(SchedulerFixture, unittest.TestCase):
    def advance(self, **changes):
        return self.store.save('cat-sitter', definition(delivery='day_before', **changes), self.now, self.schedule_id)

    def test_default_and_explicit_legacy_delivery(self):
        payload = definition()
        del payload['delivery']
        self.assertEqual(validate_schedule(payload)['delivery'], 'day_before')
        self.assertEqual(validate_schedule(payload, default_delivery='at_start')['delivery'], 'at_start')
        with self.assertRaises(ValueError):
            definition(delivery='immediate')

    def test_delivers_before_start_absolute_boundaries_and_same_link_retries(self):
        self.advance(kind='once', date='2026-11-15')
        self.scheduler.tick()
        self.client.create_qurl.assert_not_called()
        self.now += 60
        self.scheduler.tick()
        grant = self.grants()[0]
        call = self.client.create_qurl.call_args.kwargs
        self.assertEqual(call['not_before'], '2026-11-15T09:00:00+00:00')
        self.assertEqual(call['expires_at'], '2026-11-15T12:00:00+00:00')
        self.assertEqual(call['session_duration'], '10800s')
        self.assertEqual(call['expires_in'], '1620m')
        self.assertFalse(grant_window_open(grant, datetime.fromtimestamp(self.now, timezone.utc)))
        self.scheduler.tick(True)
        self.assertEqual(self.row()['state'], 'accepted')
        self.assertIn('Opening early', self.sender.call_args.args[3])
        self.assertNotIn('grant', self.row()['record'])

    def test_near_term_queues_after_save_and_no_synchronous_email(self):
        self.advance(kind='once', date='2026-11-14')
        self.sender.assert_not_called()
        preview = self.store.upcoming(self.store.get(self.schedule_id)['definition'], self.now)[0]
        self.assertTrue(preview['send_immediately'])
        self.assertTrue(preview['delivery_overdue'])
        self.assertEqual(preview['send_at'], self.now)
        self.scheduler.tick()
        self.assertEqual(len(self.grants()), 1)
        self.assertLess(self.row()['send_at'], self.now)
        self.scheduler.tick(True)
        self.sender.assert_called_once()

    def test_once_immediate_horizon_and_preview(self):
        d = definition(kind='once', date='2026-11-14', delivery='immediate')
        d = validate_schedule(d, now=self.now)
        preview = self.store.upcoming(d, self.now, editing=True)
        self.assertEqual(preview[0]['send_at'], self.now)
        self.assertTrue(preview[0]['send_immediately'])
        self.assertFalse(preview[0]['delivery_overdue'])
        with self.assertRaisesRegex(ValueError, 'configured 30-day horizon'):
            validate_schedule({**d, 'date': '2026-12-20'}, now=self.now)
        # A far future event is valid when delivery occurs close enough to its start.
        validate_schedule({**d, 'date': '2028-12-20', 'delivery': 'hour_before'}, now=self.now)
        validate_schedule({**d, 'date': '2028-12-20', 'delivery': 'day_before'}, now=self.now)
        validate_schedule(definition(delivery='day_before'), now=self.now)

    def test_weekly_delivery_crosses_date_boundary(self):
        self.advance(start_time='00:30', end_time='01:30', weekdays=[6])
        self.scheduler.tick()
        self.assertEqual(self.row()['local_date'], '2026-11-15')
        self.assertEqual(self.row()['send_at'], instant('2026-11-14T00:30:00+00:00'))

    def test_edit_same_date_waits_for_confirmed_upstream_retirement(self):
        from layerv import LayerVError
        self.advance(kind='once', date='2026-11-14')
        self.scheduler.tick()
        self.scheduler.tick(True)
        old = self.row()['id']
        self.advance(kind='once', date='2026-11-14', end_time='13:00')
        self.client.retire_grant.side_effect = LayerVError('retry', status=503)
        self.scheduler.tick()
        self.assertEqual(self.client.create_qurl.call_count, 1)
        self.assertFalse(self.grants())
        self.client.retire_grant.side_effect = None
        self.scheduler.tick()
        self.scheduler.tick(True)
        self.assertEqual(self.client.create_qurl.call_count, 2)
        history = self.store.history('cat-sitter')
        self.assertEqual(len(history), 2)
        self.assertEqual(next(row for row in history if row['id'] == old)['state'], 'cancelled')
        self.assertEqual(self.row()['state'], 'accepted')
        self.assertNotEqual(self.row()['id'], old)

    def test_pause_delete_revoke_future_but_preserve_active_by_default(self):
        for action in ('paused', 'deleted'):
            with self.subTest(action=action):
                schedule = self.store.save('cat-sitter', definition(delivery='hour_before'), self.now)
                self.scheduler.tick()
                self.scheduler.tick(True)
                self.store.status(schedule, action, self.now)
                self.scheduler.tick()
                rows = [r for r in self.store.history('cat-sitter') if r['schedule'] == schedule]
                self.assertEqual(rows[0]['state'], 'cancelled')
        self.advance(kind='once', date='2026-11-14')
        self.scheduler.tick()
        self.scheduler.tick(True)
        self.now = instant('2026-11-14T09:01:00+00:00')
        self.store.status(self.schedule_id, 'paused', self.now)
        self.scheduler.tick()
        self.assertEqual(self.row()['state'], 'accepted')
        guest = self.store.get(self.schedule_id)['guest_id']
        self.store.revoke_guest('cat-sitter', guest, self.now)
        self.scheduler.tick()
        self.assertFalse(self.grants())

    def test_restart_keeps_send_time_and_revision_no_second_invitation(self):
        self.advance(kind='once', date='2026-11-14')
        self.scheduler.tick()
        self.scheduler.tick(True)
        before = self.row()
        self.store = ScheduleStore(self.store.path)
        self.scheduler = Scheduler(self.r, self.store, clock=lambda: self.now)
        self.scheduler.tick()
        self.scheduler.tick(True)
        self.assertEqual(self.row()['id'], before['id'])
        self.assertEqual(self.row()['send_at'], before['send_at'])
        self.client.create_qurl.assert_called_once()
        self.sender.assert_called_once()

    def test_late_creation_keeps_original_local_start_and_absolute_end(self):
        self.now = instant('2026-11-14T09:10:00+00:00')
        self.scheduler.tick()
        args = self.client.create_qurl.call_args.kwargs
        self.assertIsNone(args['not_before'])
        self.assertEqual(args['expires_at'], '2026-11-14T12:00:00+00:00')
        self.assertEqual(self.grants()[0]['not_before'], '2026-11-14T09:00:00+00:00')

    def test_admin_cancellation_serializes_with_delivery_and_denies_future_grant(self):
        lock = threading.RLock()
        self.r.page_action_lock = lambda _: lock
        self.advance(kind='once', date='2026-11-14')
        self.scheduler.tick()
        sending, release, editing = threading.Event(), threading.Event(), threading.Event()

        def send(*args, **kwargs):
            sending.set()
            if not release.wait(5):
                raise AssertionError('Test did not release synthetic SMTP')

        def pause():
            editing.set()
            with lock:
                self.store.status(self.schedule_id, 'paused', self.now)
                for row in self.store.work():
                    if row['state'] == 'cancelling':
                        self.scheduler.deny(row)

        self.sender.side_effect = send
        with ThreadPoolExecutor(max_workers=2) as pool:
            delivery = pool.submit(self.scheduler.tick, True)
            try:
                self.assertTrue(sending.wait(5))
                edit = pool.submit(pause)
                self.assertTrue(editing.wait(5))
                self.assertFalse(edit.done())
            finally:
                release.set()
            delivery.result(timeout=5)
            edit.result(timeout=5)
        self.assertFalse(self.grants())
        self.scheduler.tick()
        self.assertEqual(self.store.history('cat-sitter')[0]['state'], 'cancelled')
        self.client.create_qurl.assert_called_once()
        self.sender.assert_called_once()

    def test_migration_keeps_old_delivery_on_edit(self):
        # Real v2 table, including a processed occurrence, migrates atomically.
        path = self.root / 'old.sqlite3'
        with sqlite3.connect(path) as db:
            d = definition()
            d.pop('delivery')
            db.execute('CREATE TABLE schedules(id TEXT PRIMARY KEY,page TEXT,definition TEXT,status TEXT,revision INTEGER,cursor REAL,guest_id TEXT)')
            db.execute('INSERT INTO schedules VALUES(?,?,?,?,?,?,?)', ('old','cat-sitter',json.dumps(d),'enabled',1,self.now,'guest_old'))
            db.execute('CREATE TABLE occurrences(id TEXT PRIMARY KEY,schedule TEXT,page TEXT,local_date TEXT,start REAL,end REAL,state TEXT,due REAL,record TEXT,UNIQUE(schedule,local_date))')
            db.execute('INSERT INTO occurrences VALUES(?,?,?,?,?,?,?,?,?)', ('preserved','old','cat-sitter','2026-11-14',self.now+60,self.now+3660,'accepted',self.now,json.dumps({'revision': 1, 'accepted_at': self.now})))
            db.execute('PRAGMA user_version=2')
        migrated = ScheduleStore(path)
        self.assertEqual(migrated.get('old')['definition']['delivery'], 'at_start')
        row = migrated.work()[0]
        self.assertEqual((row['id'], row['state'], row['send_at'], row['revision']), ('preserved', 'accepted', self.now+60, 1))


class WindowValidationTests(unittest.TestCase):
    def test_boundaries_legacy_and_malformed_start(self):
        now = datetime(2026, 11, 14, 9, tzinfo=timezone.utc)
        grant = {'not_before': now.isoformat(), 'expires_at': (now + timedelta(hours=1)).isoformat()}
        self.assertFalse(grant_window_open(grant, now - timedelta(seconds=1)))
        self.assertTrue(grant_window_open(grant, now))
        self.assertFalse(grant_window_open(grant, now + timedelta(hours=1)))
        self.assertTrue(grant_window_open({'expires_at': grant['expires_at']}, now))
        for value in ('', None, '2026-11-14T09:00:00', '2026-11-14T09:00:00.1Z', '2026-11-14T09:00:00+01:99', '9999-12-31T23:59:59-23:59', 'invalid'):
            self.assertFalse(grant_window_open({**grant, 'not_before': value}, now))
        self.assertFalse(grant_window_open({**grant, 'expires_at': None}, now))

    def test_whole_second_utc_and_lifetime_vs_window(self):
        now = datetime(2026, 11, 14, 9, tzinfo=timezone.utc)
        start, end = scheduled_window('2026-11-15T02:00:00-07:00', '2026-11-15T03:00:00-07:00', now)
        self.assertEqual((end - now).total_seconds(), 25*3600)
        self.assertEqual((end - start).total_seconds(), 3600)
        with self.assertRaises(ValueError):
            scheduled_window(start.isoformat(), end.isoformat(), now, max_days=1)
