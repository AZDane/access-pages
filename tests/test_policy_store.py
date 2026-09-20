import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("POLICY_STORE_TOKEN", "synthetic-policy-token")

import policy_store
from pages import PageNotFoundError, PageStore


PAGE = {
    "id": "guest",
    "title": "Guest",
    "description": "",
    "resources": [{
        "id": "light",
        "name": "Light",
        "entity_id": "light.allowed",
        "domain": "light",
        "widget": "auto",
        "actions": [{
            "id": "turn_on",
            "name": "Turn on",
            "service": "turn_on",
        }],
    }],
    "access_grants": [],
}


class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = PageStore(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_authoritative_store_strips_grants(self):
        page = {
            **PAGE,
            "access_grants": [{
                "id": "grant_one",
                "token_hash": "a" * 64,
                "created_at": "2026-07-30T00:00:00Z",
                "expires_at": "2026-07-31T00:00:00Z",
            }],
        }
        with patch("policy_store.STORE", self.store):
            policy_store.publish_page("guest", page)
        self.assertEqual(
            self.store.load("guest")["access_grants"],
            [],
        )

    def test_delete_is_idempotent(self):
        with patch("policy_store.STORE", self.store):
            policy_store.publish_page("guest", PAGE)
            policy_store.delete_page("guest")
            policy_store.delete_page("guest")
            with self.assertRaises(PageNotFoundError):
                self.store.load("guest")

    def test_store_requires_its_exact_internal_credential(self):
        handler = object.__new__(policy_store.Handler)
        with patch("policy_store.TOKEN", "synthetic-policy-token"):
            for supplied in ("", "wrong-token"):
                handler.headers = {"X-Policy-Token": supplied}
                self.assertFalse(handler._authorized())
            handler.headers = {
                "X-Policy-Token": "synthetic-policy-token",
            }
            self.assertTrue(handler._authorized())


if __name__ == "__main__":
    unittest.main()
