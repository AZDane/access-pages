from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, BrokenBarrierError
from unittest.mock import patch
import sqlite3

from verification import VerificationStore


class VerificationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = VerificationStore(Path(self.temporary.name) / "verification.sqlite3")

    def tearDown(self):
        self.temporary.cleanup()

    def test_code_is_single_use_and_creates_bound_session(self):
        code = self.store.issue_challenge("page-a", "grant-a")
        token, _ = self.store.verify(
            "page-a", "grant-a", code,
            datetime.now(timezone.utc) + timedelta(hours=24),
        )
        self.assertTrue(self.store.valid_session(token, "page-a", "grant-a"))
        self.assertFalse(self.store.valid_session(token, "page-b", "grant-a"))
        with self.assertRaises(ValueError):
            self.store.verify(
                "page-a", "grant-a", code,
                datetime.now(timezone.utc) + timedelta(hours=24),
            )

    def test_five_wrong_attempts_lock_the_challenge(self):
        code = self.store.issue_challenge("page-a", "grant-a")
        wrong_code = "000001" if code == "000000" else "000000"
        for _ in range(5):
            with self.assertRaises(ValueError):
                self.store.verify(
                    "page-a", "grant-a", wrong_code,
                    datetime.now(timezone.utc) + timedelta(hours=24),
                )
        with self.assertRaises(ValueError):
            self.store.verify(
                "page-a", "grant-a", code,
                datetime.now(timezone.utc) + timedelta(hours=24),
            )

    def test_resend_is_limited_and_revocation_removes_session(self):
        code = self.store.issue_challenge("page-a", "grant-a")
        self.assertIsNone(
            self.store.issue_challenge("page-a", "grant-a")
        )
        with self.assertRaisesRegex(ValueError, "60 seconds"):
            self.store.issue_challenge(
                "page-a", "grant-a", replace=True,
            )
        token, _ = self.store.verify(
            "page-a", "grant-a", code,
            datetime.now(timezone.utc) + timedelta(hours=24),
        )
        self.store.revoke("page-a", "grant-a")
        self.assertFalse(self.store.valid_session(token, "page-a", "grant-a"))

    def test_concurrent_redemption_has_only_one_winner_across_store_instances(self):
        code = self.store.issue_challenge("page-a", "grant-a")
        readers = Barrier(4)

        class ReadCursor(sqlite3.Cursor):
            def fetchone(self):
                row = super().fetchone()
                # Without a write transaction all readers obtain the live
                # challenge before any consumes it. With serialization the
                # first reader times out and the others see its deletion.
                try:
                    readers.wait(timeout=0.2)
                except BrokenBarrierError:
                    pass
                return row

        class Connection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("SELECT code_hash"):
                    return self.cursor(ReadCursor).execute(sql, parameters)
                return super().execute(sql, parameters)

        def redeem(_index):
            store = VerificationStore(self.store.path)
            store._initialize()
            with patch.object(store, "_connect", lambda: sqlite3.connect(
                store.path, timeout=10, factory=Connection,
            )):
                try:
                    return store.verify(
                        "page-a", "grant-a", code,
                        datetime.now(timezone.utc) + timedelta(hours=1),
                    )[0]
                except ValueError:
                    return None

        with ThreadPoolExecutor(max_workers=4) as pool:
            tokens = list(pool.map(redeem, range(4)))
        self.assertEqual(sum(token is not None for token in tokens), 1)

    def test_expired_grant_cannot_create_verification_session(self):
        code = self.store.issue_challenge("page-a", "grant-a")
        with self.assertRaises(ValueError):
            self.store.verify(
                "page-a", "grant-a", code,
                datetime.now(timezone.utc) - timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
