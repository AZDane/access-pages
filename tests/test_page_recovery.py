"""Fault injection at durable page/policy mutation boundaries; no providers."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("HA_BASE_URL", "http://ha.example")
os.environ.setdefault("HA_TOKEN", "test-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")

import admin
import server
from pages import PageStore
from policy import PolicyPublisher, PolicyPublishError
from test_pages import VALID_PAGE


GRANT = {
    "id": "grant_" + "a" * 16, "credential_flow": "bootstrap-v1",
    "token_hash": "a" * 64, "created_at": "2026-09-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z", "qurl_id": "q-one",
    "resource_id": "r-one",
}


class PageRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = PageStore(self.directory)
        self.page = self.store.create({**VALID_PAGE, "access_grants": [GRANT]})
        self.path = self.directory / (self.page["id"] + ".json")

    def test_interrupted_delete_journal_masks_grants_and_recovers_cleanup(self):
        with patch.object(self.store.cleanup, "enqueue", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.store.delete(self.page["id"])
        restarted = PageStore(self.directory)
        self.assertEqual(restarted.load(self.page["id"])["access_grants"], [])
        restarted.recover_pending_revocations()
        self.assertEqual(restarted.load(self.page["id"])["access_grants"], [])
        client = Mock()
        restarted.cleanup.drain(client)
        client.delete_qurl.assert_called_once_with(
            page_id=self.page["id"], grant_id=GRANT["id"], resource_id="r-one", qurl_id="q-one",
        )

    def test_failed_unlink_sync_cannot_restore_live_grants(self):
        original_unlink, original_sync = Path.unlink, os.fsync
        durable = []
        def unlink(path, *args, **kwargs):
            if path == self.path:
                durable.append(path.read_bytes())
            return original_unlink(path, *args, **kwargs)
        def sync(fd):
            if not self.path.exists():
                raise OSError("directory sync failed")
            return original_sync(fd)
        with patch("pages.os.fsync", side_effect=sync), patch.object(Path, "unlink", unlink):
            with self.assertRaises(OSError):
                self.store.delete(self.page["id"])
        # Model a lost directory update after power loss using the last synced file.
        self.path.write_bytes(durable[0])
        self.assertEqual(PageStore(self.directory).load(self.page["id"])["access_grants"], [])
        self.assertEqual(json.loads(durable[0])["access_grants"], [])

    def test_successful_delete_syncs_after_unlink_including_policy_only_pages(self):
        self.store.replace(self.page["id"], {**self.page, "access_grants": []})
        observations = []
        original_sync = os.fsync
        def sync(fd):
            observations.append(self.path.exists())
            return original_sync(fd)
        with patch("pages.os.fsync", side_effect=sync):
            self.store.delete(self.page["id"])
        self.assertEqual(observations, [False])


class PolicyMutationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = PageStore(self.directory)
        self.publisher = PolicyPublisher("http://policy.invalid", "synthetic", self.directory)
        for name, value in {
            "PAGE_STORE": self.store, "POLICY_PUBLISHER": self.publisher,
            "VERIFICATION_RECIPIENTS": Mock(), "ACTIVITY_STORE": Mock(),
            "LAYERV_CLIENT": Mock(), "cleanup_guest_sessions": Mock(), "audit": Mock(),
        }.items():
            patcher = patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.handler = Mock()
        self.handler._require_admin.return_value = True

    def mutate(self, method, payload):
        route = "/api/admin/pages/" + VALID_PAGE["id"]
        if method == "create":
            admin.handle_post(self.handler, "/api/admin/pages", payload, server)
        elif method == "post":
            admin.handle_post(self.handler, route, payload, server)
        elif method == "put":
            self.handler._read_json.return_value = payload
            admin.handle_put(self.handler, route, server)
        else:
            admin.handle_delete(self.handler, route, server)

    def test_crash_before_publication_reconciles_committed_local_truth(self):
        for method in ("create", "post", "put", "delete"):
            with self.subTest(method=method):
                if self.store._path(VALID_PAGE["id"]).exists():
                    self.store.delete(VALID_PAGE["id"])
                if method != "create":
                    self.store.create(VALID_PAGE)
                changed = {**VALID_PAGE, "title": "Updated"}
                operation = "delete" if method == "delete" else "publish"
                # BaseException models abrupt termination: normal rollback never runs.
                with patch.object(self.publisher, operation, side_effect=SystemExit("crash")):
                    with self.assertRaises(SystemExit):
                        self.mutate(method, changed)
                self.assertTrue(self.publisher.pending(VALID_PAGE["id"]))
                with patch.object(self.publisher, "_request") as sent:
                    server.retry_pending_policies()
                self.assertFalse(self.publisher.pending(VALID_PAGE["id"]))
                if method == "delete":
                    sent.assert_called_once_with("DELETE", VALID_PAGE["id"])
                else:
                    self.assertEqual(sent.call_args.args[2]["title"], "Updated")
                    self.assertEqual(sent.call_args.args[2]["access_grants"], [])

    def test_failed_intent_leaves_local_policy_unchanged(self):
        self.store.create(VALID_PAGE)
        for method in ("post", "put", "delete"):
            with self.subTest(method=method), patch.object(self.publisher, "_mark", side_effect=OSError("disk")):
                self.mutate(method, {**VALID_PAGE, "title": "Must not persist"})
                self.assertEqual(self.store.load(VALID_PAGE["id"])["title"], VALID_PAGE["title"])
                self.assertEqual(self.handler._send_json.call_args.args[0], 502)
        self.store.delete(VALID_PAGE["id"])
        with patch.object(self.publisher, "_mark", side_effect=OSError("disk")):
            self.mutate("create", VALID_PAGE)
        self.assertFalse(self.store._path(VALID_PAGE["id"]).exists())

    def test_ambiguous_update_rolls_back_and_republishes_previous_policy(self):
        self.store.create(VALID_PAGE)
        with patch.object(self.publisher, "_request", side_effect=PolicyPublishError("lost acknowledgement")):
            self.mutate("put", {**VALID_PAGE, "title": "Unconfirmed"})
        self.assertTrue(self.publisher.pending(VALID_PAGE["id"]))
        with patch.object(self.publisher, "_request") as sent:
            server.retry_pending_policies()
        self.assertEqual(sent.call_args.args[2]["title"], VALID_PAGE["title"])

    def test_policy_outage_does_not_undo_local_delete_or_skip_remote_cleanup(self):
        self.store.create({**VALID_PAGE, "access_grants": [GRANT]})
        with patch.object(self.publisher, "_request", side_effect=PolicyPublishError("offline")):
            self.mutate("delete", {})
        status, response = self.handler._send_json.call_args.args
        self.assertEqual(status, 502)
        self.assertTrue(response["page_deleted"])
        self.assertTrue(response["policy_cleanup_pending"])
        self.assertFalse(self.store._path(VALID_PAGE["id"]).exists())
        server.cleanup_guest_sessions.assert_called_once()
        server.LAYERV_CLIENT.delete_qurl.assert_called_once()
        with patch.object(self.publisher, "_request") as sent:
            server.retry_pending_policies()
        sent.assert_called_once_with("DELETE", VALID_PAGE["id"])
