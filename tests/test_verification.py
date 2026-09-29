from datetime import datetime, timedelta, timezone
from hashlib import sha256
import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from verification import VerificationStore


class VerificationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = VerificationStore(Path(self.temporary.name) / "verification.sqlite3")

    def tearDown(self):
        self.temporary.cleanup()

    def test_bootstrap_reuse_policy_is_atomic_and_survives_restart(self):
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        for one_time_use in (True, False):
            with self.subTest(one_time_use=one_time_use):
                secret = "single-use-secret" if one_time_use else "reusable-secret"
                digest = sha256(secret.encode()).hexdigest()
                ready = Barrier(4)

                def exchange(_index):
                    store = VerificationStore(self.store.path)
                    store._initialize()
                    ready.wait(timeout=5)
                    try:
                        return store.consume_bootstrap(
                            "page-a", "grant-a", secret, digest, expiry,
                            one_time_use=one_time_use,
                        )[0]
                    except ValueError:
                        return None

                with ThreadPoolExecutor(max_workers=4) as pool:
                    tokens = [token for token in pool.map(exchange, range(4)) if token]
                self.assertEqual(len(tokens), 1 if one_time_use else 4)
                self.assertEqual(len(set(tokens)), len(tokens))
                reopened = VerificationStore(self.store.path)
                for token in tokens:
                    self.assertEqual(reopened.guest_session_info(token, "page-a"),
                                     ("grant-a", int(expiry.timestamp()), digest))
                if one_time_use:
                    with self.assertRaises(ValueError):
                        reopened.consume_bootstrap(
                            "page-a", "grant-a", secret, digest, expiry,
                            one_time_use=True,
                        )
                else:
                    token, _ = reopened.consume_bootstrap(
                        "page-a", "grant-a", secret, digest, expiry,
                        one_time_use=False,
                    )
                    self.assertNotIn(token, tokens)


if __name__ == "__main__":
    unittest.main()
