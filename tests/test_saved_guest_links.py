"""Explicit removal of the owner's invitation copy, using real page storage."""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import admin
from pages import PageStore, page_admin_view
from policy import PolicyPublishError

os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-admin")

import server


class SavedGuestLinkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = PageStore(self.root / "pages")
        now = datetime.now(timezone.utc)
        self.grant_id = "grant_" + "a" * 16
        self.link = "https://qurl.invalid/#saved-invitation-secret"
        grant = {
            "id": self.grant_id, "credential_flow": "bootstrap-v1",
            "token_hash": "a" * 64, "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "qurl_id": "q-one", "resource_id": "resource-one",
            "resource_crid": "crid-one", "upstream_scope": "guest",
            "qurl_link": self.link, "verification_required": True,
            "one_time_use": True, "target_path_applied": True,
            "notifications": {"targets": ["email"], "events": ["initial_login"]},
        }
        self.initial = self.store.create({
            "id": "page", "title": "Page", "resources": [],
            "access_grants": [grant, {**grant, "id": "grant_" + "b" * 16,
                                     "qurl_id": "q-two", "qurl_link": "https://qurl.invalid/#other"}],
        })
        self.path = self.root / "pages" / "page.json"
        self.route = f"/api/admin/pages/page/grants/{self.grant_id}/finish-sharing"
        self.handler = object.__new__(server.Handler)
        self.handler.headers = {"X-Admin-Token": "owner-token"}
        self.handler._send_json = Mock()
        self.handler._validate_entity_policy = Mock()
        self.client = Mock(resource_id="resource-one", configured=True)
        self.policy = Mock()
        self.stack = self.enterContext(ExitStack())
        for name, value in {
            "PAGE_STORE": self.store, "ADMIN_TOKEN": "owner-token",
            "LAYERV_CLIENT": self.client, "POLICY_PUBLISHER": self.policy,
            "ACTIVITY_STORE": Mock(), "VERIFICATION_RECIPIENTS": Mock(),
            "SMTP_CONFIG_STORE": Mock(), "audit": Mock(),
            "RESET_REQUEST_FILE": self.root / "reset-request",
            "cleanup_guest_sessions": Mock(),
        }.items():
            self.stack.enter_context(patch.object(server, name, value))

    def finish(self):
        admin.handle_post(self.handler, self.route, {}, server)
        status, data = self.handler._send_json.call_args.args
        self.assertEqual(status, 200, data)
        return data

    def test_confirmation_only_removes_saved_copy_and_is_idempotent(self):
        # Accept and discard a response alias even if it reached an older file.
        raw = json.loads(self.path.read_text())
        raw["access_grants"][0]["access_url"] = self.link
        self.path.write_text(json.dumps(raw))
        expected = deepcopy(self.initial)
        expected["access_grants"][0]["qurl_link"] = ""
        replacements = []
        original_replace = Path.replace

        def replace(source, destination):
            replacements.append(source.read_text())
            self.assertNotIn(self.link, replacements[-1])
            return original_replace(source, destination)

        with patch.object(Path, "replace", replace):
            result = self.finish()
            self.assertEqual(self.finish(), result)
        self.assertEqual(len(replacements), 2)
        self.assertEqual(self.store.load("page"), expected)
        self.assertEqual(result, page_admin_view(expected))
        self.assertNotIn("access_url", self.path.read_text())
        self.assertNotIn(self.link, json.dumps(result))
        self.assertEqual(list(self.store.directory.iterdir()), [self.path])
        for dependency in (self.client, self.policy, server.ACTIVITY_STORE,
                           server.VERIFICATION_RECIPIENTS, server.cleanup_guest_sessions):
            self.assertEqual(dependency.mock_calls, [])

    def test_admin_reads_and_stale_post_put_edits_cannot_restore_link(self):
        stale = page_admin_view(self.initial)
        stale["access_grants"][0]["access_url"] = self.link
        self.finish()
        for method in ("POST", "PUT"):
            with self.subTest(method=method):
                stale["title"] = f"Edited by {method}"
                if method == "POST":
                    admin.handle_post(self.handler, "/api/admin/pages/page", stale, server)
                else:
                    self.handler._read_json = Mock(return_value=stale)
                    admin.handle_put(self.handler, "/api/admin/pages/page", server)
                status, data = self.handler._send_json.call_args.args
                self.assertEqual(status, 200)
                self.assertEqual(data["title"], stale["title"])
                self.assertNotIn(self.link, json.dumps(data))
                self.assertNotIn("access_url", json.dumps(data))
        admin.handle_get(self.handler, urlparse("/api/admin/pages/page"),
                         "/api/admin/pages/page", server)
        self.assertNotIn(self.link, json.dumps(self.handler._send_json.call_args.args))
        restarted = PageStore(self.store.directory)
        restarted.recover_pending_revocations()
        self.assertEqual(restarted.load("page")["access_grants"][0]["qurl_link"], "")
        self.assertEqual(restarted.load("page")["access_grants"][0]["expires_at"],
                         self.initial["access_grants"][0]["expires_at"])

    def test_failed_page_publication_rollback_cannot_restore_finalized_link(self):
        self.finish()
        self.policy.publish.side_effect = PolicyPublishError("unavailable")
        admin.handle_post(self.handler, "/api/admin/pages/page",
                          page_admin_view(self.initial), server)
        self.assertEqual(self.handler._send_json.call_args.args[0], 502)
        self.assertNotIn(self.link, self.path.read_text())

    def test_authentication_method_and_missing_grant_checks(self):
        self.handler.headers = {}
        admin.handle_post(self.handler, self.route, {}, server)
        self.assertEqual(self.handler._send_json.call_args.args[0], 401)
        self.handler.headers = {"X-Admin-Token": "owner-token"}
        admin.handle_get(self.handler, urlparse(self.route), self.route, server)
        self.assertEqual(self.handler._send_json.call_args.args[0], 404)
        for route in (self.route.replace(self.grant_id, "missing"),
                      self.route.replace("/page/", "/missing/"),
                      self.route.replace("/grants/", "/qurls/")):
            admin.handle_post(self.handler, route, {}, server)
            self.assertEqual(self.handler._send_json.call_args.args[0], 404)
        self.assertEqual(self.store.load("page"), self.initial)
        self.assertEqual(self.client.mock_calls, [])

    def test_failed_atomic_replacement_does_not_report_success_or_copy_secret(self):
        with patch.object(Path, "replace", side_effect=OSError("disk failure")):
            admin.handle_post(self.handler, self.route, {}, server)
        self.assertEqual(self.handler._send_json.call_args.args[0], 500)
        self.assertEqual(self.store.load("page"), self.initial)
        for path in self.store.directory.iterdir():
            if path != self.path:
                self.assertNotIn(self.link, path.read_text())
        self.finish()
        self.assertNotIn(self.link, self.path.read_text())

    def test_missing_or_empty_link_already_has_finalized_state(self):
        for missing in (True, False):
            raw = deepcopy(self.initial)
            if missing:
                del raw["access_grants"][0]["qurl_link"]
            else:
                raw["access_grants"][0]["qurl_link"] = ""
            self.path.write_text(json.dumps(raw))
            self.assertEqual(self.finish()["access_grants"][0]["qurl_link"], "")

    def test_creation_and_smtp_delivery_keep_link_until_explicit_confirmation(self):
        self.client.create_qurl.return_value = {
            "qurl_link": "https://qurl.invalid/#new-invitation", "qurl_id": "q-new",
            "expires_at": self.initial["access_grants"][0]["expires_at"],
        }
        for sent in (True, False):
            self.handler._send_guest_invitation = Mock(return_value=sent)
            admin.handle_post(self.handler, "/api/admin/pages/page/qurls", {
                "label": "New guest", "lifetime": "1h", "send_invitation": True,
                "invitation_email": "guest@example.test",
            }, server)
            status, data = self.handler._send_json.call_args.args
            self.assertEqual(status, 201, data)
            self.assertEqual(data["email_delivery"]["sent"], sent)
            grant = data["grant"]
            self.assertEqual(grant["qurl_link"], self.client.create_qurl.return_value["qurl_link"])
            self.assertEqual(grant["access_url"], grant["qurl_link"])
            stored = next(item for item in PageStore(self.store.directory).load("page")["access_grants"]
                          if item["id"] == grant["id"])
            self.assertEqual(stored["qurl_link"], grant["qurl_link"])
            self.assertNotIn("access_url", stored)
        self.client.delete_qurl.assert_not_called()

    def test_revoke_all_page_delete_and_connection_reset_after_finalization(self):
        for operation in ("individual", "all", "delete", "reset"):
            with self.subTest(operation=operation):
                self.store.replace("page", self.initial) if self.path.exists() else self.store.create(self.initial)
                self.finish()
                self.client.reset_mock()
                if operation == "individual":
                    self.handler._revoke_grant("page", self.grant_id)
                elif operation == "all":
                    self.handler._revoke_all_grants("page")
                elif operation == "delete":
                    admin.handle_delete(self.handler, "/api/admin/pages/page", server)
                else:
                    self.handler._reset_layer_v_connection({"confirmation": "RESET"})
                status, data = self.handler._send_json.call_args.args
                self.assertIn(status, (200, 202), data)
                self.client.delete_qurl.assert_any_call(
                    resource_id="resource-one", qurl_id="q-one",
                    page_id="page", grant_id=self.grant_id,
                )
                if operation == "delete":
                    self.assertFalse(self.path.exists())
                else:
                    self.assertNotIn(self.grant_id, [grant["id"] for grant in self.store.load("page")["access_grants"]])
                if operation == "reset":
                    self.assertTrue((self.root / "reset-request").exists())


if __name__ == "__main__":
    unittest.main()
