import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from rate_limit import MinimumIntervalRateLimiter, SlidingWindowRateLimiter

class RateLimitTests(unittest.TestCase):
    def test_bounded_window_does_not_evict_active_keys_and_recovers_capacity(self):
        with patch("rate_limit.monotonic", return_value=100) as clock:
            limiter = SlidingWindowRateLimiter(2, 60, max_keys=2)
            self.assertTrue(limiter.allow("a"))
            self.assertTrue(limiter.allow("a"))
            clock.return_value = 101
            self.assertTrue(limiter.allow("b"))
            for index in range(100):
                self.assertFalse(limiter.allow(f"rotating-{index}"))
            self.assertFalse(limiter.allow("a"))
            self.assertTrue(limiter.allow("b"))
            self.assertEqual(len(limiter._events), 2)
            clock.return_value = 160
            self.assertTrue(limiter.allow("new"))
            self.assertFalse(limiter.allow("b"))
            self.assertEqual(len(limiter._events), 2)

    def test_bounded_window_is_atomic_under_parallel_attempts(self):
        limiter = SlidingWindowRateLimiter(12, 60, max_keys=2)
        with ThreadPoolExecutor(max_workers=24) as pool:
            allowed = list(pool.map(lambda _: limiter.allow("same-grant"), range(100)))
        self.assertEqual(sum(allowed), 12)

    def test_minimum_interval_is_per_key_and_reports_retry(self):
        now = [100.0]
        limiter = MinimumIntervalRateLimiter(clock=lambda: now[0])
        self.assertEqual(limiter.check("a", 15), (True, 0))
        self.assertEqual(limiter.check("b", 15), (True, 0))
        now[0] = 110.1
        self.assertEqual(limiter.check("a", 15), (False, 5))
        now[0] = 115.0
        self.assertEqual(limiter.check("a", 15), (True, 0))

    def test_blocks_after_limit(self):
        limiter = SlidingWindowRateLimiter(2, 60)
        self.assertTrue(limiter.allow("x"))
        self.assertTrue(limiter.allow("x"))
        self.assertFalse(limiter.allow("x"))

    def test_expired_keys_are_removed_during_periodic_cleanup(self):
        with patch("rate_limit.monotonic", side_effect=[0, 0, 1, 61]):
            limiter = SlidingWindowRateLimiter(2, 60)
            self.assertTrue(limiter.allow("attacker-a"))
            self.assertTrue(limiter.allow("attacker-b"))
            self.assertTrue(limiter.allow("current"))

        self.assertNotIn("attacker-a", limiter._events)
        self.assertNotIn("attacker-b", limiter._events)
        self.assertEqual(set(limiter._events), {"current"})

if __name__ == "__main__":
    unittest.main()
