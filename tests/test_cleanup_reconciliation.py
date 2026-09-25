"""Local-first revocation through the real durable broker retry path."""

import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("ACCESS_PAGES_BROKER_TOKEN", "synthetic-broker-token")
os.environ.setdefault("HA_BROKER_TOKEN", "synthetic-ha-broker-token")
os.environ.setdefault("HA_BROKER_ADMIN_TOKEN", "synthetic-ha-broker-admin-token")
os.environ.setdefault("LAYERV_API_BASE_URL", "https://layerv.invalid")
os.environ.setdefault("LAYERV_API_TOKEN", "lv_test_synthetic")
os.environ.setdefault("LAYERV_RESOURCE_ID", "r_synthetic")
os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha-token")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-owner-token")

import ha_broker
import layerv_broker
import server
from guest_resources import GuestResources
from layerv import BrokerLayerVClient, LayerVError
from pages import PageStore
from verification import VerificationStore


class CleanupReconciliationTests(unittest.TestCase):
    def test_remote_outage_never_restores_guest_or_retires_other_resources(self):
        for mode in ("guest", "page"):
            with self.subTest(resource_isolation=mode):
                self._exercise(mode)

    def test_finalized_invitations_keep_both_cleanup_modes_and_durable_retries(self):
        for mode in ("guest", "page"):
            with self.subTest(resource_isolation=mode):
                self._exercise(mode, finalize=True)

    def _exercise(self, mode, *, finalize=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pages = PageStore(root / "pages")
            sessions = VerificationStore(root / "sessions.sqlite3")
            data_dir = root / "broker"
            management = Mock()
            management.api_base_url = "https://layerv.invalid"
            management.api_token = "synthetic-management-key"
            published = iter("abc")
            publisher = Mock()
            publisher.native_retirement = False

            def publish(_connector_id, target_url):
                letter = next(published)
                return {
                    "crid": letter * 59, "resource_id": "resource-" + letter,
                    "target_url": target_url, "status": "serving",
                }

            publisher.side_effect = publish
            manager = GuestResources(
                data_dir / "guest-resources.sqlite3", installation_id="installation-a",
                publisher=publisher, management_client=management,
            )
            identities = (
                ("page-a", "grant_" + "a" * 16, "a" * 43, "q_aaaaaaaaaaa"),
                ("page-a", "grant_" + "b" * 16, "b" * 43, "q_bbbbbbbbbbb"),
                ("page-b", "grant_" + "c" * 16, "c" * 43, "q_ccccccccccc"),
            )
            now = datetime.now(timezone.utc)
            grants = {}
            for page_id, grant_id, secret, qurl_id in identities:
                target = "http://127.88.0.1:8080" if page_id == "page-a" else "http://127.88.0.2:8080"
                client = manager.ensure(page_id, grant_id, target, isolation=mode)
                grants[grant_id] = {
                    "id": grant_id, "label": grant_id,
                    "token_hash": sha256(secret.encode()).hexdigest(),
                    "created_at": now.isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                    "credential_flow": "bootstrap-v1",
                    "verification_required": False,
                    "resource_id": client.resource_public_key,
                    "resource_crid": client.resource_id,
                    "upstream_scope": mode,
                    "qurl_id": qurl_id,
                    "qurl_link": f"https://qurl.invalid/#{secret}",
                }
            guest_a, guest_b, other_page = (item[1] for item in identities)
            pages.create({"id": "page-a", "title": "Page A", "resources": [],
                          "access_grants": [grants[guest_a], grants[guest_b]]})
            pages.create({"id": "page-b", "title": "Page B", "resources": [],
                          "access_grants": [grants[other_page]]})
            clock = [100]
            original_queue = layerv_broker.queue_revocation
            queue_checked = []

            def queue_after_local_commit(page_id, grant_id):
                self.assertNotIn(grant_id, [
                    grant["id"] for grant in pages.load(page_id)["access_grants"]
                ])
                queue_checked.append((page_id, grant_id))
                return original_queue(page_id, grant_id)

            with (
                patch.object(layerv_broker, "DATA_DIR", data_dir),
                patch.object(layerv_broker, "GATEWAY_GRANTS_DIR", str(pages.directory)),
                patch.object(layerv_broker, "GUEST_RESOURCES", manager),
                patch.object(layerv_broker, "CLIENT", management),
                patch.object(layerv_broker, "TOKEN", "synthetic-broker-token"),
                patch.object(layerv_broker, "time", SimpleNamespace(time=lambda: clock[0])),
                patch.object(ha_broker, "GUEST_GRANT_STORE", pages),
                patch.object(ha_broker, "GUEST_SESSION_STORE", sessions),
                patch.object(server, "PAGE_STORE", pages),
                patch.object(server, "VERIFICATION_RECIPIENTS", Mock()),
                patch.object(server, "ACTIVITY_STORE", Mock()),
                patch.object(server, "HA_CLIENT", Mock()),
                patch.object(server, "audit"),
            ):
                for page_id, grant_id, _secret, _qurl in identities:
                    layerv_broker._save_mapping(page_id, grant_id, grants[grant_id])
                session_a = ha_broker._exchange_guest_bootstrap(
                    "page-a", guest_a, "a" * 43,
                )["session"]
                session_b = ha_broker._exchange_guest_bootstrap(
                    "page-a", guest_b, "b" * 43,
                )["session"]
                self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_a, session_a))
                self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_b, session_b))
                if finalize:
                    for page_id, grant_id, _secret, _qurl in identities:
                        pages.remove_saved_guest_link(page_id, grant_id)
                    management.delete_qurl.assert_not_called()
                    management.delete_resource.assert_not_called()
                    self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_a, session_a))
                    self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_b, session_b))
                with sessions._connect() as db:
                    session_count = db.execute("SELECT COUNT(*) FROM guest_sessions").fetchone()[0]
                self.assertEqual(session_count, 2)

                failed = [True]

                def remote_delete(*_args, **_kwargs):
                    if failed[0]:
                        raise LayerVError("LayerV temporarily unavailable", status=503, retry_after=5)
                    return False

                if mode == "guest":
                    management.delete_resource.side_effect = remote_delete
                else:
                    management.delete_qurl.side_effect = remote_delete
                broker = ThreadingHTTPServer(("127.0.0.1", 0), layerv_broker.Handler)
                broker.daemon_threads = True
                thread = threading.Thread(target=broker.serve_forever)
                thread.start()
                try:
                    client = BrokerLayerVClient(
                        f"http://127.0.0.1:{broker.server_port}", "synthetic-broker-token",
                    )
                    responses = []
                    handler = object.__new__(server.Handler)
                    handler._send_json = lambda status, payload: responses.append((status, payload))
                    with patch.object(server, "LAYERV_CLIENT", client), patch.object(
                        layerv_broker, "queue_revocation", side_effect=queue_after_local_commit,
                    ):
                        handler._revoke_grant("page-a", guest_a)
                    self.assertEqual(queue_checked, [("page-a", guest_a)])
                    self.assertTrue(responses[0][1]["local_access_revoked"])
                    self.assertTrue(responses[0][1]["remote_revocation_pending"])
                    self.assertIsNone(ha_broker._guest_session_status("page-a", guest_a, session_a))
                    self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_b, session_b))
                    with pages.cleanup._connect() as db:
                        self.assertEqual(db.execute("SELECT grant_id FROM cleanup").fetchall(), [(guest_a,)])
                    # The Admin retry hands durable ownership to the broker.
                    pages.cleanup.drain(client)
                    with pages.cleanup._connect() as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM cleanup").fetchone()[0], 0)
                    with layerv_broker._revocation_db() as db:
                        self.assertEqual(db.execute("SELECT grant_id FROM revocations").fetchall(), [(guest_a,)])

                    clock[0] = 116
                    layerv_broker.drain_revocations()
                    self.assertTrue(layerv_broker._grant_file("page-a", guest_a).exists())
                    with layerv_broker._revocation_db() as db:
                        self.assertEqual(db.execute("SELECT attempts FROM revocations").fetchone()[0], 1)
                    if mode == "guest":
                        with manager._connect() as db:
                            self.assertEqual(db.execute(
                                "SELECT phase FROM resources WHERE page='page-a' AND grant_id=?",
                                (guest_a,),
                            ).fetchone()[0], "retiring")
                            self.assertEqual(db.execute(
                                "SELECT COUNT(*) FROM retirements WHERE grant_id=?", (guest_a,),
                            ).fetchone()[0], 1)
                    self.assertIsNone(ha_broker._guest_session_status("page-a", guest_a, session_a))
                    self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_b, session_b))

                    # Reopen both durable stores as a restarted process would.
                    reopened_pages = PageStore(pages.directory)
                    reopened_manager = GuestResources(
                        manager.path, installation_id="installation-a",
                        publisher=publisher, management_client=management,
                    )
                    with (
                        patch.object(layerv_broker, "GUEST_RESOURCES", reopened_manager),
                        patch.object(ha_broker, "GUEST_GRANT_STORE", reopened_pages),
                    ):
                        failed[0] = False
                        clock[0] = 122
                        layerv_broker.drain_revocations()
                        reopened_manager.drain_retirements()
                        self.assertIsNone(ha_broker._guest_session_status("page-a", guest_a, session_a))
                        self.assertIsNotNone(ha_broker._guest_session_status("page-a", guest_b, session_b))
                        self.assertEqual(
                            [grant["id"] for grant in reopened_pages.load("page-a")["access_grants"]],
                            [guest_b],
                        )
                        with sessions._connect() as db:
                            self.assertEqual(db.execute("SELECT COUNT(*) FROM guest_sessions").fetchone()[0], session_count)
                        with layerv_broker._revocation_db() as db:
                            self.assertEqual(db.execute("SELECT COUNT(*) FROM revocations").fetchone()[0], 0)
                        self.assertFalse(layerv_broker._grant_file("page-a", guest_a).exists())
                        self.assertTrue(layerv_broker._grant_file("page-a", guest_b).exists())
                        self.assertTrue(layerv_broker._grant_file("page-b", other_page).exists())
                        self.assertEqual(reopened_manager._binding("page-a", guest_b)[4] if mode == "guest"
                                         else reopened_manager._binding("page-a", "__page__")[4], "ready")
                        self.assertEqual(reopened_manager._binding("page-b", other_page if mode == "guest" else "__page__")[4], "ready")
                        if mode == "guest":
                            self.assertEqual(reopened_manager._binding("page-a", guest_a)[4], "revoked")
                            self.assertEqual(management.delete_resource.call_count, 2)
                            management.delete_resource.assert_called_with(
                                resource_crid=grants[guest_a]["resource_crid"],
                            )
                            management.delete_qurl.assert_not_called()
                        else:
                            self.assertEqual(reopened_manager._binding("page-a", "__page__")[2], grants[guest_b]["resource_crid"])
                            self.assertEqual(management.delete_qurl.call_count, 2)
                            management.delete_qurl.assert_called_with(
                                resource_id=grants[guest_a]["resource_crid"], qurl_id=grants[guest_a]["qurl_id"],
                            )
                            management.delete_resource.assert_not_called()
                        management.mint_agent_enrollment_token.assert_not_called()
                        publisher._bootstrap.assert_not_called()
                        self.assertEqual(publisher.call_count, 3 if mode == "guest" else 2)
                finally:
                    broker.shutdown()
                    thread.join()
                    broker.server_close()
