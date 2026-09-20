"""Guest resource ownership and restart-safe primary revocation."""

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from guest_resources import AgentRecoveryRequired, ConnectorPublisher, GuestResources, PendingInvitations
from layerv import LayerVClient, LayerVError


class DeviceRecoveryTests(unittest.TestCase):
    def _enroll_fixture(self, publisher, *, shares=False):
        publisher.agent_state.write_text("sealed-device", encoding="utf-8")
        publisher.runtime_mode.write_text('{"schema_version":1,"supervision":"external"}', encoding="utf-8")
        publisher.wrapping_key.write_bytes(b"k" * 32)
        publisher.wrapping_key.chmod(0o600)
        publisher.bootstrap_complete.touch()
        if shares:
            (publisher.state / "local_shares.json").write_text("{}", encoding="utf-8")

    @patch("guest_resources.subprocess.run")
    def test_native_rate_limit_is_not_a_plan_quota_and_uses_local_cooldown(self, run):
        run.return_value = Mock(returncode=9, stdout="", stderr="private protocol detail")
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="key")
            self._enroll_fixture(publisher)
            with self.assertRaises(LayerVError) as raised:
                publisher._run(["publish", "http://127.0.0.2:8080", "--id", "private-binding"])
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(raised.exception.retry_after, 60)
        self.assertIn("rate limit", str(raised.exception))
        self.assertNotIn("plan", str(raised.exception))
        self.assertNotIn("private", str(raised.exception))

    @patch("guest_resources.subprocess.run")
    def test_login_failure_never_discloses_vendor_stderr(self, run):
        key = "lv_live_" + "k" * 43
        run.return_value = Mock(returncode=1, stdout="private identity output", stderr=(
            "verbose private output\nError: open /data/access-pages-broker/native/agent_state.json: "
            "permission denied; " + key + " https://qurl.link/#private-invitation "
            "person@example.com token=short-secret " + "x" * 64 + "\n"))
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key=key)
            publisher.wrapping_key.write_bytes(b"k" * 32)
            publisher.wrapping_key.chmod(0o600)
            with self.assertRaises(LayerVError) as raised:
                publisher._run(["login", "--enrollment-token-file", "/tmp/token"])
        message = str(raised.exception)
        self.assertIn("during login (Connector exit 1)", message)
        for private in (key, "private identity", "verbose private", "private-invitation", "person@example.com", "short-secret", "x" * 64):
            self.assertNotIn(private, message)
        self.assertLess(len(message), 512)

    @patch("guest_resources.subprocess.run")
    def test_connector_failure_diagnostics_never_return_private_stderr(self, run):
        run.return_value = Mock(returncode=6, stdout="private-output", stderr="credential private-key; secret invitation")
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            with self.assertRaises(LayerVError) as raised:
                publisher._run(["publish", "http://127.0.0.2:8080", "--id", "private-binding"])
        self.assertIn("permission", str(raised.exception))
        self.assertIn("publish", str(raised.exception))
        self.assertIn("exit 6", str(raised.exception))
        for private in ("private-key", "private-output", "invitation", "private-binding", "isolated-key"):
            self.assertNotIn(private, str(raised.exception))

    @patch("guest_resources.subprocess.run")
    def test_remote_delete_success_with_failed_local_cleanup_remains_pending(self, run):
        run.return_value = Mock(returncode=0, stdout='{"deleted":true}', stderr='Warning: The resource was deleted, but local sharing cleanup did not finish: reload unavailable')
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            with self.assertRaises(LayerVError) as raised:
                publisher.cleanup("owned-resource")
            self.assertEqual(raised.exception.status, 503)
            self.assertEqual(raised.exception.retry_after, 2)

    @patch("guest_resources.subprocess.run")
    def test_rejected_device_fails_closed_without_login_or_state_change(self, run):
        run.return_value = Mock(returncode=4, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            state = publisher.agent_state
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher._run(["publish", "http://127.0.0.2:8080", "--id", "binding"])
            self.assertEqual(state.read_bytes(), b"sealed-device")
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher.cleanup("resource")
            self.assertEqual(state.read_bytes(), b"sealed-device")
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all("login" not in call.args[0] for call in run.call_args_list))
        self.assertTrue(all("input" not in call.kwargs for call in run.call_args_list))

    @patch("layerv.LayerVClient.mint_agent_enrollment_token", return_value="lv_test_" + "t" * 43)
    @patch("guest_resources.subprocess.run")
    def test_first_publication_bootstraps_once_and_reuses_state(self, run, mint):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            state = publisher.agent_state

            def command(args, **_kwargs):
                if "login" in args:
                    self.assertNotIn("isolated-key", " ".join(args))
                    self.assertNotIn("QURL_API_KEY", _kwargs["env"])
                    self.assertEqual(Path(args[-1]).read_text().strip(), "lv_test_" + "t" * 43)
                    state.write_text("device", encoding="utf-8")
                    publisher.runtime_mode.write_text('{"schema_version":1,"supervision":"external"}')
                    return Mock(returncode=0, stdout="{}", stderr="")
                return Mock(returncode=0, stdout='{"status":"serving"}', stderr="")

            run.side_effect = command
            with patch.object(publisher, "_start"), patch.object(publisher, "_ipc", return_value={}):
                publisher("first", "http://127.0.0.2:8080")
                publisher("second", "http://127.0.0.2:8080")
            self.assertTrue(publisher.bootstrap_complete.is_file())
            self.assertEqual(len(publisher.wrapping_key.read_bytes()), 32)
            self.assertFalse(list(Path(temp).glob("agent-enrollment-*")))
            restarted = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            with patch.object(restarted, "_start"), patch.object(restarted, "_ipc", return_value={}):
                restarted("third", "http://127.0.0.2:8080")
            self.assertEqual(sum("login" in call.args[0] for call in run.call_args_list), 1)
            mint.assert_called_once()
            self.assertTrue(all(call.kwargs["env"]["LAYERV_KEY_PROVIDER"] == "local-key" for call in run.call_args_list))

    @patch("layerv.LayerVClient.mint_agent_enrollment_token", return_value="lv_test_" + "t" * 43)
    @patch("guest_resources.subprocess.run")
    def test_virgin_resource_allocation_allows_one_bootstrap(self, run, mint):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(
                Path(temp) / "state", api_base_url="https://api.invalid",
                enrollment_key="management-key",
            )
            resources = GuestResources(
                Path(temp) / "guest-resources.sqlite3", installation_id="fresh-installation",
                publisher=publisher,
                management_client=Mock(api_base_url="https://api.invalid", api_token="management-key"),
            )

            def command(args, **_kwargs):
                if "login" in args:
                    publisher.agent_state.write_text("sealed", encoding="utf-8")
                    publisher.runtime_mode.write_text("external", encoding="utf-8")
                    return Mock(returncode=0, stdout="{}", stderr="")
                return Mock(returncode=0, stdout=(
                    '{"crid":"' + "a" * 59 + '","resource_id":"public-key",'
                    '"target_url":"http://127.0.0.2:8080","status":"serving"}'
                ), stderr="")

            run.side_effect = command
            with (
                patch.object(publisher, "_start"),
                patch.object(publisher, "_ipc", return_value={}),
                patch.object(publisher, "ensure_ready"),
            ):
                resources.ensure("page", "grant_" + "a" * 16, "http://127.0.0.2:8080")
            mint.assert_called_once()
            self.assertEqual(sum("login" in call.args[0] for call in run.call_args_list), 1)
            with resources._connect() as db:
                self.assertEqual(db.execute(
                    "SELECT status FROM enrollment_state WHERE name='agent'"
                ).fetchone()[0], "enrolled")

    @patch("guest_resources.subprocess.run")
    def test_missing_state_after_bootstrap_fails_closed(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            publisher.bootstrap_complete.touch()
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher("first", "http://127.0.0.2:8080")
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher._run(["login", "--enrollment-token-file", "/tmp/token"])
            run.assert_not_called()

    @patch("guest_resources.subprocess.run")
    def test_interrupted_initial_enrollment_requires_explicit_reset(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            publisher.wrapping_key.write_bytes(b"k" * 32)
            publisher.wrapping_key.chmod(0o600)
            with self.assertRaises(AgentRecoveryRequired):
                publisher.restore()
            self.assertTrue(publisher.recovery_required)
            run.assert_not_called()

    @patch("guest_resources.subprocess.run")
    def test_lost_all_agent_files_with_active_resource_is_not_fresh(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            resources = GuestResources(
                Path(temp) / "guest-resources.sqlite3", installation_id="old",
                publisher=Mock(), management_client=Mock(),
            )
            with resources._connect() as db:
                db.execute(
                    "INSERT INTO resources(page,grant_id,connector_id,target,phase) "
                    "VALUES('page','__page__','old-binding','http://127.0.0.2:8080','ready')"
                )
            with self.assertRaises(AgentRecoveryRequired):
                publisher.restore()
            self.assertTrue(publisher.recovery_required)
            run.assert_not_called()
            resources.invalidate_for_reset()
            self.assertTrue(publisher._fresh())

    @patch("guest_resources.subprocess.run")
    @patch("layerv.LayerVClient.mint_agent_enrollment_token")
    def test_established_agent_loss_without_reset_forbids_bootstrap_even_without_active_guests(self, mint, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(
                Path(temp) / "state", api_base_url="https://api.invalid",
                enrollment_key="same-valid-management-key",
            )
            resources = GuestResources(
                Path(temp) / "guest-resources.sqlite3", installation_id="old",
                publisher=Mock(), management_client=Mock(),
            )
            with resources._connect() as db:
                db.execute(
                    "UPDATE enrollment_state SET status='enrolled' WHERE name='agent'"
                )
                db.execute(
                    "INSERT INTO resources(page,grant_id,connector_id,target,phase) "
                    "VALUES('page','__page__','old-binding','http://127.0.0.2:8080','revoked')"
                )
            self._enroll_fixture(publisher)
            for path in (publisher.agent_state, publisher.runtime_mode,
                         publisher.wrapping_key, publisher.bootstrap_complete):
                path.unlink()
            with self.assertRaises(AgentRecoveryRequired):
                publisher.restore()
            with self.assertRaises(AgentRecoveryRequired):
                publisher("new-guest", "http://127.0.0.2:8080")
            self.assertTrue(publisher.recovery_required)
            mint.assert_not_called()
            run.assert_not_called()

    def test_unsafe_agent_symlink_is_integrity_failure_not_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            publisher.agent_state.unlink()
            publisher.agent_state.symlink_to(publisher.wrapping_key)
            with self.assertRaises(LayerVError) as raised:
                publisher.restore()
            self.assertNotIsInstance(raised.exception, AgentRecoveryRequired)

    @patch("guest_resources.subprocess.Popen")
    def test_restore_with_lost_state_never_starts_daemon(self, popen):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            (publisher.state / "local_shares.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher.restore()
            popen.assert_not_called()

    @patch("guest_resources.subprocess.Popen")
    def test_daemon_uses_external_supervision_and_inherited_key_pipe(self, popen):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="retained-secret")
            self._enroll_fixture(publisher, shares=True)
            popen.return_value.poll.return_value = None
            with patch.object(publisher, "_ipc", return_value={"job_version": "5/2.6.0/per-share"}):
                publisher._start()
            args = popen.call_args.args[0]
            self.assertIn("--supervision", args)
            self.assertEqual(args[args.index("--supervision") + 1], "external")
            self.assertIn("--share-group-mode", args)
            self.assertEqual(args[args.index("--share-group-mode") + 1], "per-share")
            self.assertNotIn("retained-secret", " ".join(args))
            self.assertNotIn("QURL_API_KEY", popen.call_args.kwargs["env"])
            self.assertEqual(popen.call_args.kwargs["env"]["LAYERV_KEY_PROVIDER"], "local-key")
            self.assertEqual(len(popen.call_args.kwargs["pass_fds"]), 1)

    @patch("guest_resources.subprocess.run")
    def test_lost_wrapping_key_fails_closed_without_cli_or_token_mint(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="retained-secret")
            self._enroll_fixture(publisher)
            publisher.wrapping_key.unlink()
            with patch.object(publisher.management, "mint_agent_enrollment_token") as mint:
                with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                    publisher("second", "http://127.0.0.2:8080")
                mint.assert_not_called()
            run.assert_not_called()

    @patch("layerv.LayerVClient.mint_agent_enrollment_token", return_value="lv_test_" + "t" * 43)
    @patch("guest_resources.subprocess.run")
    def test_first_publication_exit_four_cannot_login_twice(self, run, mint):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")

            def command(args, **_kwargs):
                if "login" in args:
                    publisher.agent_state.write_text("device", encoding="utf-8")
                    publisher.runtime_mode.write_text('{"schema_version":1,"supervision":"external"}')
                    return Mock(returncode=0, stdout="{}", stderr="")
                return Mock(returncode=4, stdout="", stderr="")

            run.side_effect = command
            with patch.object(publisher, "_start"), patch.object(publisher, "_ipc", return_value={}):
                with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                    publisher("first", "http://127.0.0.2:8080")
            self.assertEqual(sum("login" in call.args[0] for call in run.call_args_list), 1)
            self.assertEqual(publisher.agent_state.read_text(), "device")
            self.assertTrue(publisher.bootstrap_complete.exists())
            mint.assert_called_once()

    @patch("guest_resources.subprocess.run")
    def test_existing_state_is_reused_without_login(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher, shares=True)
            run.return_value = Mock(returncode=0, stdout='{"status":"serving"}', stderr="")
            with patch.object(publisher, "_start"), patch.object(publisher, "_ipc", return_value={}):
                publisher("second", "http://127.0.0.2:8080")
            self.assertTrue(publisher.bootstrap_complete.is_file())
            self.assertEqual(run.call_count, 1)
            self.assertNotIn("login", run.call_args.args[0])

    @patch("guest_resources.subprocess.run")
    def test_broker_and_connector_restore_reuse_existing_state(self, run):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp) / "state"
            state_dir.mkdir()
            for _ in range(2):
                publisher = ConnectorPublisher(state_dir, api_base_url="https://api.invalid", enrollment_key="isolated-key")
                if not publisher.bootstrap_complete.exists():
                    self._enroll_fixture(publisher, shares=True)
                with patch.object(publisher, "_start") as start:
                    publisher.restore()
                    start.assert_called_once_with()
                self.assertTrue(publisher.bootstrap_complete.exists())
            run.assert_not_called()

    @patch("guest_resources.subprocess.run")
    def test_other_runtime_errors_never_trigger_login(self, run):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            for exit_code in (1, 6, 9, 11):
                run.return_value = Mock(returncode=exit_code, stdout="", stderr="")
                with self.subTest(exit_code=exit_code), self.assertRaises(LayerVError):
                    publisher._run(["publish", "http://127.0.0.2:8080", "--id", "binding"])
            self.assertEqual(run.call_count, 4)
            self.assertTrue(all("login" not in call.args[0] for call in run.call_args_list))

    @patch("layerv.LayerVClient.mint_agent_enrollment_token", return_value="lv_test_" + "t" * 43)
    @patch("guest_resources.subprocess.run")
    def test_failed_fresh_login_requires_explicit_reset(self, run, mint):
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            run.return_value = Mock(returncode=11, stdout="", stderr="")
            with self.assertRaises(LayerVError):
                publisher("first", "http://127.0.0.2:8080")
            with self.assertRaisesRegex(LayerVError, "explicit administrator recovery"):
                publisher("first", "http://127.0.0.2:8080")
            self.assertEqual(run.call_count, 1)
            mint.assert_called_once()
            self.assertFalse(publisher.bootstrap_complete.exists())

    @patch("guest_resources.subprocess.run")
    def test_forbidden_operation_does_not_reenroll(self, run):
        run.return_value = Mock(returncode=6)
        with tempfile.TemporaryDirectory() as temp:
            publisher = ConnectorPublisher(Path(temp) / "state", api_base_url="https://api.invalid", enrollment_key="isolated-key")
            self._enroll_fixture(publisher)
            with self.assertRaises(LayerVError):
                publisher._run(["delete", "owned-resource", "--yes"])
        run.assert_called_once()


class GuestResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "resources.sqlite3"
        self.client = Mock(
            api_base_url="https://api.invalid", api_token="private-management"
        )
        self.client.delete_resource.return_value = False
        self.publisher = Mock(
            return_value={
                "crid": "a" * 59,
                "resource_id": "public-verification-key",
                "target_url": "http://127.0.0.2:8080",
                "status": "serving",
            }
        )
        self.manager = self.reopen()
        self.mary = "grant_" + "m" * 16
        self.susan = "grant_" + "s" * 16

    def reopen(self):
        return GuestResources(
            self.path,
            installation_id="installation",
            publisher=self.publisher,
            management_client=self.client,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_restart_and_replacement_keep_resource_but_never_share_across_guests(self):
        first = self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        second = self.reopen().ensure("page", self.mary, "http://127.0.0.2:8080")
        self.assertEqual(first.resource_id, second.resource_id)
        self.assertEqual(first.api_token, "private-management")
        self.assertEqual(first.resource_public_key, "public-verification-key")
        self.assertEqual(self.publisher.call_count, 1)
        with self.assertRaisesRegex(LayerVError, "another guest"):
            self.manager.ensure("page", self.susan, "http://127.0.0.2:8080")
        self.assertNotEqual(
            self.publisher.call_args_list[0].args[0],
            self.publisher.call_args_list[1].args[0],
        )

    def _assert_reset_allocates_fresh_resource(self, isolation):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080", isolation=isolation)
        old_connector = self.publisher.call_args.args[0]
        self.manager.invalidate_for_reset()
        with self.manager._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM resources WHERE phase='ready'").fetchone()[0], 0)
        self.publisher.return_value = {
            **self.publisher.return_value,
            "crid": "b" * 59,
            "resource_id": "new-public-key",
        }
        after = GuestResources(
            self.path, installation_id="new-installation",
            publisher=self.publisher, management_client=self.client,
        ).ensure("page", self.susan, "http://127.0.0.2:8080", isolation=isolation)
        self.assertEqual(after.resource_public_key, "new-public-key")
        self.assertNotEqual(self.publisher.call_args.args[0], old_connector)
        with self.manager._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 1)
        if isolation == "page":
            newer = GuestResources(
                self.path, installation_id="new-installation",
                publisher=self.publisher, management_client=self.client,
            )
            newer.invalidate_for_reset()
            self.publisher.return_value = {
                **self.publisher.return_value,
                "crid": "c" * 59,
                "resource_id": "third-public-key",
            }
            third = GuestResources(
                self.path, installation_id="third-installation",
                publisher=self.publisher, management_client=self.client,
            ).ensure("page", self.mary, "http://127.0.0.2:8080", isolation="page")
            self.assertEqual(third.resource_public_key, "third-public-key")
            with self.manager._connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 2)

    def test_explicit_reset_rotates_page_pool_binding(self):
        self._assert_reset_allocates_fresh_resource("page")

    def test_explicit_reset_rotates_guest_binding(self):
        self._assert_reset_allocates_fresh_resource("guest")

    def test_interrupted_publication_retries_same_connector_identity(self):
        self.publisher.side_effect = LayerVError("interrupted response")
        with self.assertRaises(LayerVError):
            self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        connector_id = self.publisher.call_args.args[0]
        self.publisher.side_effect = None
        self.reopen().ensure("page", self.mary, "http://127.0.0.2:8080")
        self.assertEqual(self.publisher.call_args.args[0], connector_id)

    def test_page_pool_reuses_resource_and_switch_does_not_move_old_bindings(self):
        mary = self.manager.ensure(
            "page", self.mary, "http://127.0.0.2:8080", isolation="page"
        )
        susan = self.reopen().ensure(
            "page", self.susan, "http://127.0.0.2:8080", isolation="page"
        )
        self.assertEqual(mary.resource_scope, "page")
        self.assertEqual(mary.resource_id, susan.resource_id)
        self.assertEqual(self.publisher.call_count, 1)
        self.publisher.return_value = {
            **self.publisher.return_value,
            "crid": "b" * 59,
            "resource_id": "guest-verification-key",
        }
        isolated = self.manager.ensure(
            "page", self.mary, "http://127.0.0.2:8080", isolation="guest"
        )
        self.assertNotEqual(isolated.resource_id, mary.resource_id)
        old_pool = self.reopen().ensure(
            "page", self.susan, "http://127.0.0.2:8080", isolation="page"
        )
        self.assertEqual(old_pool.resource_id, susan.resource_id)
        with self.assertRaisesRegex(LayerVError, "private binding"):
            self.manager.revoke("page", self.susan, old_pool.resource_id)
        self.client.delete_resource.assert_not_called()

    def test_page_deletion_retires_pool_and_recreation_gets_new_native_identity(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080", isolation="page")
        first_id = self.publisher.call_args.args[0]
        self.manager.retire_deleted_page_pools(lambda _: True)
        self.client.delete_resource.assert_not_called()
        self.reopen().retire_deleted_page_pools(lambda _: False)
        self.client.delete_resource.assert_called_once_with(resource_crid="a" * 59)
        self.publisher.return_value = {**self.publisher.return_value, "crid": "b" * 59}
        new = self.reopen().ensure("page", self.mary, "http://127.0.0.2:8080", isolation="page")
        self.assertEqual(new.resource_id, "b" * 59)
        self.assertNotEqual(first_id, self.publisher.call_args.args[0])
        self.reopen().ensure("page", self.susan, "http://127.0.0.2:8080", isolation="page")
        self.assertEqual(self.publisher.call_count, 2)

    def test_missing_invitation_recovers_from_owned_resource(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.assertFalse(self.reopen().revoke_owned("page", self.mary))
        self.client.delete_resource.assert_called_once_with(resource_crid="a" * 59)
        self.assertTrue(self.reopen().revoke_owned("page", self.mary))
        self.assertTrue(self.reopen().revoke_owned("page", self.susan))

    def test_device_resource_revocation_without_individual_qurl_delete(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.publisher.native_retirement = True
        self.publisher.revoke_resource.return_value = False
        events = Mock()
        events.attach_mock(self.client.delete_qurl, "qurl")
        events.attach_mock(self.publisher.revoke_resource, "resource")
        self.manager.revoke("page", self.mary, "a" * 59, qurl_id="q_aaaaaaaaaaa")
        self.assertEqual([c[0] for c in events.method_calls], ["resource"])
        self.client.delete_qurl.assert_not_called()
        self.client.delete_resource.assert_not_called()

    def test_management_fallback_retains_queue_until_native_cleanup_confirmed(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.publisher.native_retirement = True
        self.publisher.revoke_resource.side_effect = LayerVError("unavailable", status=503)
        self.publisher.cleanup.side_effect = LayerVError("pending", status=503)
        with self.assertRaises(LayerVError):
            self.manager.revoke_owned("page", self.mary)
        with self.assertRaisesRegex(LayerVError, "revoked"):
            self.reopen().ensure("page", self.mary, "http://127.0.0.2:8080")
        self.publisher.cleanup.side_effect = None
        self.reopen().drain_retirements()
        self.assertTrue(self.reopen().revoke_owned("page", self.mary))

    def test_pending_revocation_survives_restart_and_cannot_be_reissued(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.client.delete_resource.side_effect = LayerVError(
            "pending enforcement", status=503, retry_after=7
        )
        with self.assertRaises(LayerVError) as raised:
            self.manager.revoke("page", self.mary, "a" * 59)
        self.assertEqual(raised.exception.retry_after, 7)
        reopened = self.reopen()
        with self.assertRaisesRegex(LayerVError, "revoked"):
            reopened.ensure("page", self.mary, "http://127.0.0.2:8080")
        with self.assertRaisesRegex(LayerVError, "private binding"):
            reopened.revoke("page", self.mary, "b" * 59)
        self.client.delete_resource.side_effect = None
        self.assertFalse(reopened.revoke("page", self.mary, "a" * 59))
        self.assertTrue(self.reopen().revoke("page", self.mary, "a" * 59))
        self.assertEqual(self.client.delete_resource.call_count, 2)

    def test_resource_only_retirement_survives_restart_with_recorded_qurl(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.client.delete_qurl.side_effect = LayerVError("pending qURL enforcement", status=503, retry_after=5)
        self.client.delete_resource.side_effect = LayerVError("pending resource enforcement", status=503, retry_after=7)
        with self.assertRaises(LayerVError):
            self.manager.revoke("page", self.mary, "a" * 59, qurl_id="q_aaaaaaaaaaa")
        self.assertEqual([call[0] for call in self.client.method_calls], ["delete_resource"])
        self.client.delete_resource.side_effect = None
        self.reopen().drain_retirements()
        self.client.delete_qurl.assert_not_called()
        self.assertEqual(self.client.delete_resource.call_count, 2)
        self.assertTrue(self.reopen().revoke("page", self.mary, "a" * 59))

    @patch("layerv.urlopen")
    def test_retirement_retries_without_invitation_mapping_and_honors_retry_after(self, _urlopen):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.client.delete_resource.side_effect = LayerVError("pending", status=503, retry_after=11)
        with patch("guest_resources.time.time", return_value=100):
            with self.assertRaises(LayerVError):
                self.manager.revoke("page", self.mary, "a" * 59)
            self.reopen().drain_retirements()
        self.assertEqual(self.client.delete_resource.call_count, 2)
        self.client.delete_resource.side_effect = None
        with patch("guest_resources.time.time", return_value=110):
            self.reopen().drain_retirements()
        self.assertEqual(self.client.delete_resource.call_count, 2)
        with patch("guest_resources.time.time", return_value=111):
            self.reopen().drain_retirements()
        self.assertEqual(self.client.delete_resource.call_count, 3)
        self.assertTrue(self.reopen().revoke("page", self.mary, "a" * 59))

    def test_orphan_scan_recovers_interrupted_creation_but_preserves_live_grants_and_page_pool(self):
        with patch("guest_resources.time.time", return_value=100):
            self.publisher.side_effect = LayerVError("lost publication reply")
            with self.assertRaises(LayerVError):
                self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        original_id = self.publisher.call_args.args[0]
        self.publisher.side_effect = None
        with patch("guest_resources.time.time", return_value=399):
            self.reopen().retire_orphans(lambda *_: False)
        self.client.delete_resource.assert_not_called()
        with patch("guest_resources.time.time", return_value=400):
            self.reopen().retire_orphans(lambda *_: False)
        self.assertEqual(self.publisher.call_args.args[0], original_id)
        self.client.delete_resource.assert_called_once_with(resource_crid="a" * 59)
        self.publisher.return_value = {**self.publisher.return_value, "crid": "b" * 59}
        with patch("guest_resources.time.time", return_value=100):
            self.manager.ensure("page", self.susan, "http://127.0.0.2:8080")
        self.publisher.return_value = {**self.publisher.return_value, "crid": "c" * 59}
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080", isolation="page")
        with patch("guest_resources.time.time", return_value=10000000000):
            self.reopen().retire_orphans(lambda page, grant: grant == self.susan)
        self.assertEqual(self.client.delete_resource.call_count, 1)

    def test_orphan_rate_backoff_survives_restart_and_pauses_other_allocations(self):
        self.publisher.side_effect = LayerVError("publication rate limited", status=429, retry_after=90)
        with patch("guest_resources.time.time", return_value=100):
            for grant in (self.mary, self.susan):
                with self.assertRaises(LayerVError):
                    self.manager.ensure("page", grant, "http://127.0.0.2:8080")
        self.publisher.reset_mock()
        with patch("guest_resources.time.time", return_value=400):
            self.reopen().retire_orphans(lambda *_: False)
        self.assertEqual(self.publisher.call_count, 1)
        with patch("guest_resources.time.time", return_value=489):
            self.reopen().retire_orphans(lambda *_: False)
        self.assertEqual(self.publisher.call_count, 1)
        with patch("guest_resources.time.time", return_value=490):
            self.reopen().retire_orphans(lambda *_: False)
        self.assertEqual(self.publisher.call_count, 2)
        with patch("guest_resources.time.time", return_value=609):
            self.reopen().retire_orphans(lambda *_: False)
        self.assertEqual(self.publisher.call_count, 2)
        self.client.delete_resource.assert_not_called()
        with self.manager._connect() as db:
            due, attempts = db.execute("SELECT recovery_due,recovery_attempts FROM resources WHERE grant_id=?", (self.mary,)).fetchone()
        self.assertEqual((due, attempts), (610, 2))

    def test_non_rate_orphan_publication_failure_also_backs_off_durably(self):
        self.publisher.side_effect = LayerVError("publication unavailable", status=503, retry_after=2)
        with patch("guest_resources.time.time", return_value=100):
            with self.assertRaises(LayerVError):
                self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        self.publisher.reset_mock()
        for now, expected in ((400, 1), (404, 1), (405, 2), (414, 2)):
            with patch("guest_resources.time.time", return_value=now):
                self.reopen().retire_orphans(lambda *_: False)
            self.assertEqual(self.publisher.call_count, expected)

    def test_recovery_schedule_upgrade_preserves_existing_resource_ownership(self):
        self.manager.ensure("page", self.mary, "http://127.0.0.2:8080")
        before = self.manager._binding("page", self.mary)
        with self.manager._connect() as db:
            db.execute("ALTER TABLE resources DROP COLUMN recovery_due")
            db.execute("ALTER TABLE resources DROP COLUMN recovery_attempts")
            db.execute("DROP TABLE recovery_gates")
        upgraded = self.reopen()
        self.assertEqual(upgraded._binding("page", self.mary), before)
        with upgraded._connect() as db:
            self.assertEqual(db.execute("SELECT recovery_due,recovery_attempts FROM resources").fetchone(), (0, 0))

    @patch("layerv.urlopen")
    def test_resource_delete_preserves_pending_enforcement_and_escapes_locator(
        self, urlopen
    ):
        client = LayerVClient("https://api.invalid", "private", "unused")
        urlopen.side_effect = HTTPError(
            "https://api.invalid",
            503,
            "pending",
            {"Retry-After": "11"},
            io.BytesIO(b""),
        )
        with self.assertRaises(LayerVError) as raised:
            client.delete_resource(resource_crid="a/b")
        self.assertEqual(raised.exception.retry_after, 11)
        self.assertTrue(urlopen.call_args.args[0].full_url.endswith("/a%2Fb"))
        urlopen.side_effect = HTTPError(
            "https://api.invalid", 410, "gone", {}, io.BytesIO(b"")
        )
        self.assertTrue(client.delete_resource(resource_crid="a/b"))


class PendingInvitationTests(unittest.TestCase):
    def test_lost_page_mint_recovers_after_restart_without_revoking_other_guests(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mints.sqlite3"
            client = Mock()
            with patch("guest_resources.time.time", return_value=100):
                label = PendingInvitations(path).prepare("p", "mary", "crid")
            client.list_qurls.return_value = [
                {"qurl_id": "q_aaaaaaaaaaa", "label": label},
                {"qurl_id": "q_bbbbbbbbbbb", "label": "Susan"},
            ]
            client.delete_qurl.side_effect = LayerVError("pending", status=503, retry_after=9)
            with patch("guest_resources.time.time", return_value=400):
                PendingInvitations(path).drain(client, lambda *_: False)
            client.delete_qurl.assert_called_once_with(resource_id="crid", qurl_id="q_aaaaaaaaaaa")
            client.delete_qurl.side_effect = None
            with patch("guest_resources.time.time", return_value=408):
                PendingInvitations(path).drain(client, lambda *_: False)
            self.assertEqual(client.delete_qurl.call_count, 1)
            with patch("guest_resources.time.time", return_value=409):
                PendingInvitations(path).drain(client, lambda *_: False)
                PendingInvitations(path).drain(client, lambda *_: False)
            self.assertEqual(client.delete_qurl.call_count, 2)
            client.delete_resource.assert_not_called()

    def test_saved_mapping_preserves_invitation_even_if_journal_completion_was_lost(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mints.sqlite3"
            with patch("guest_resources.time.time", return_value=100):
                PendingInvitations(path).prepare("p", "mary", "crid")
            client = Mock()
            with patch("guest_resources.time.time", return_value=400):
                PendingInvitations(path).drain(client, lambda *_: True)
            client.list_qurls.assert_not_called()
