import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from guest_resources import ConnectorPublisher


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "homeassistant-app"
    / "app_runner.py"
)
SPEC = importlib.util.spec_from_file_location("app_runner", MODULE_PATH)
app_runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app_runner)


class AppRunnerTests(unittest.TestCase):
    def test_resource_isolation_configuration_is_validated_and_explicit(self):
        default = app_runner._resource_isolation_environment({})
        self.assertEqual(default["ACCESS_PAGES_RESOURCE_ISOLATION"], "guest")
        selected = app_runner._resource_isolation_environment({"resource_isolation": "page"})
        self.assertEqual(selected["ACCESS_PAGES_RESOURCE_ISOLATION"], "page")
        with self.assertRaises(app_runner.SetupError):
            app_runner._resource_isolation_environment({"resource_isolation": "automatic"})

    def test_diagnostics_duration_is_one_shot_across_restart(self):
        for selection, seconds in (("30 minutes", 1800), ("1 hour", 3600), ("4 hours", 14400)):
            with self.subTest(selection=selection), patch.object(app_runner, "clock_ns", return_value=123):
                self.assertEqual(app_runner._diagnostic_environment({}), {})
                env = app_runner._diagnostic_environment({"diagnostic_logging": selection})
                self.assertEqual(int(env["ACCESS_PAGES_DIAGNOSTICS_UNTIL_NS"]), 123 + seconds * 1_000_000_000)
                self.assertEqual((self.paths["DATA_DIR"] / "diagnostics-consumed").read_bytes(), b"1")
                self.assertEqual(app_runner._diagnostic_environment({"diagnostic_logging": selection}), {})
                # Changing the selected duration cannot silently rearm either.
                self.assertEqual(app_runner._diagnostic_environment({"diagnostic_logging": "4 hours"}), {})
        with patch.object(app_runner.os, "fsync", side_effect=OSError):
            self.assertEqual(app_runner._diagnostic_environment({}), {})
            self.assertEqual(app_runner._diagnostic_environment({"diagnostic_logging": "30 minutes"}), {})

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.paths = {
            "DATA_DIR": root,
            "OPTIONS_FILE": root / "options.json",
            "APP_CONFIG_FILE": root / "app-config.json",
            "INSTALLATION_ID_FILE": root / "installation-id",
            "SECRET_DIR": root / "secrets",
            "LAYERV_TOKEN_FILE": root / "secrets" / "layerv-api-key",
            "CONNECTOR_STATE_DIR": root / "connector-state",
            "CONNECTOR_LOG_DIR": root / "logs" / "layer-v-connector",
            "PAGE_CONNECTOR_DIR": root / "page-connectors",
            "PAGE_CONNECTOR_HISTORY": root
            / "page-connectors"
            / "history.json",
            "PAGE_CONNECTOR_REGISTRY": root
            / "access-pages-broker"
            / "page-connectors.json",
            "CONNECTOR_CONFIG_FILE": root
            / "connector-config"
            / "qurl-proxy.yaml",
            "RESET_REQUEST_FILE": root / "reset-connection.request",
            "POLICY_DIR": root / "policy-pages",
            "ACTIVITY_DIR": root / "guest-runtime",
            "ACTIVITY_DB_FILE": root
            / "guest-runtime"
            / "guest-activity.sqlite3",
            "GUEST_PAGE_DIR": root / "guest-pages",
            "PAGE_CAPABILITY_SECRETS": root / "page-capabilities.json",
            "HA_CAPABILITY_DIR": root / "ha-broker-runtime",
            "HA_GUEST_SESSION_DIR": root / "ha-broker-runtime" / "guest-auth",
            "HA_GUEST_SESSION_DB": root / "ha-broker-runtime" / "guest-auth" / "sessions.sqlite3",
            "HA_CAPABILITY_REGISTRY": root
            / "ha-broker-runtime"
            / "page-capabilities.json",
            "HA_GUEST_CAPABILITY_REGISTRY": root
            / "ha-broker-runtime"
            / "guest-page-capabilities.json",
            "ACCESS_PAGES_BROKER_DATA_DIR": root / "access-pages-broker",
            "ADMIN_RUNTIME_DIR": root / "admin-runtime",
            "CONNECTOR_STATUS_FILE": root
            / "admin-runtime"
            / "page-connector-status.json",
        }
        self.patchers = [
            patch.object(app_runner, name, value)
            for name, value in self.paths.items()
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def test_base_configuration_does_not_create_a_shared_connector(self):
        options = {}
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir(parents=True)
        self.paths["LAYERV_TOKEN_FILE"].write_text(
            "synthetic-key\n", encoding="utf-8"
        )
        with patch.object(app_runner, "_connector_id", return_value="ha-test"):
            first = app_runner._load_or_register(options)
            second = app_runner._load_or_register(options)

        self.assertEqual(first["resource_id"], "")
        self.assertEqual(second["resource_id"], "")
        self.assertEqual(first["version"], 2)
        saved = json.loads(
            self.paths["APP_CONFIG_FILE"].read_text(encoding="utf-8")
        )
        self.assertNotIn("api_token", saved)
        self.assertNotIn("bootstrap_key", saved)
        self.assertTrue(saved["ha_broker_token"])
        self.assertTrue(saved["ha_broker_admin_token"])
        self.assertTrue(saved["access_pages_broker_token"])
        self.assertTrue(saved["policy_store_token"])

    def test_registration_can_retain_ingress_token_during_reset(self):
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir(parents=True)
        self.paths["LAYERV_TOKEN_FILE"].write_text(
            "synthetic-key\n", encoding="utf-8"
        )
        with patch.object(app_runner, "_connector_id", return_value="ha-test"):
            config = app_runner._load_or_register(
                {},
                retained_admin_token="retained-ingress-token",
            )

        self.assertEqual(
            config["admin_token"],
            "retained-ingress-token",
        )

    def test_api_key_is_read_only_from_protected_key_file(self):
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir(parents=True)
        self.paths["LAYERV_TOKEN_FILE"].write_text(
            "synthetic-key\n", encoding="utf-8"
        )
        self.assertEqual(app_runner._layer_v_token(), "synthetic-key")

    def test_first_run_requires_onboarding_without_key(self):
        self.assertFalse(app_runner._configured_key_available())
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir(parents=True)
        self.paths["LAYERV_TOKEN_FILE"].write_text(
            "synthetic-key\n",
            encoding="utf-8",
        )
        self.assertTrue(app_runner._configured_key_available())

    def test_onboarding_does_not_stop_borrowed_ingress_proxy(self):
        borrowed_ingress = type(
            "Process",
            (),
            {"poll": lambda self: None, "returncode": None},
        )()
        onboarding = type(
            "Process",
            (),
            {"poll": Mock(side_effect=[None, 0, 0]), "returncode": 0},
        )()

        ack_fds = []

        def start_onboarding(_command, **kwargs):
            ack_fds.append(os.dup(kwargs["pass_fds"][1]))
            os.write(kwargs["pass_fds"][0], b"synthetic-key\n")
            return onboarding

        with (
            patch.object(
                app_runner.subprocess,
                "Popen",
                side_effect=start_onboarding,
            ),
            patch.object(app_runner, "_stop") as stop,
            patch.object(app_runner, "_store_onboarding_key") as store,
        ):
            result = app_runner._run_onboarding(
                ingress=borrowed_ingress
            )

        self.assertEqual(result, 0)
        self.assertEqual(os.read(ack_fds[0], 1), b"1")
        os.close(ack_fds[0])
        store.assert_called_once_with("synthetic-key")
        stop.assert_called_once_with([onboarding])

    def test_runner_rejects_failed_persistence_without_success_ack(self):
        ingress = type(
            "Process", (), {"poll": lambda self: None, "returncode": None}
        )()
        onboarding = type(
            "Process",
            (),
            {"poll": Mock(side_effect=[None, 0, 0]), "returncode": 0},
        )()
        ack_fds = []

        def start_onboarding(_command, **kwargs):
            ack_fds.append(os.dup(kwargs["pass_fds"][1]))
            os.write(kwargs["pass_fds"][0], b"synthetic-key\n")
            return onboarding

        with (
            patch.object(app_runner.subprocess, "Popen", side_effect=start_onboarding),
            patch.object(app_runner, "_stop"),
            patch.object(
                app_runner,
                "_store_onboarding_key",
                side_effect=app_runner.SetupError("disk unavailable"),
            ),
        ):
            with self.assertRaises(app_runner.SetupError):
                app_runner._run_onboarding(ingress=ingress)

        self.assertEqual(os.read(ack_fds[0], 1), b"0")
        os.close(ack_fds[0])

    def test_onboarding_shutdown_stops_without_storing_a_key(self):
        borrowed_ingress = type(
            "Process",
            (),
            {"poll": lambda self: None, "returncode": None},
        )()
        onboarding = type(
            "Process",
            (),
            {"poll": lambda self: None, "returncode": None},
        )()
        with (
            patch.object(
                app_runner.subprocess,
                "Popen",
                return_value=onboarding,
            ),
            patch.object(app_runner, "_stop") as stop,
            patch.object(app_runner, "_store_onboarding_key") as store,
        ):
            result = app_runner._run_onboarding(
                ingress=borrowed_ingress,
                shutdown_requested=lambda: True,
            )

        self.assertEqual(result, 0)
        store.assert_not_called()
        stop.assert_called_once_with([onboarding])

    def test_root_helper_stores_protected_onboarding_key(self):
        with patch.object(app_runner.os, "chown") as chown:
            app_runner._store_onboarding_key("synthetic-key")

        self.assertEqual(
            self.paths["LAYERV_TOKEN_FILE"].read_text(encoding="utf-8"),
            "synthetic-key\n",
        )
        self.assertEqual(
            self.paths["LAYERV_TOKEN_FILE"].stat().st_mode & 0o777,
            0o640,
        )
        chown.assert_called_once_with(
            self.paths["LAYERV_TOKEN_FILE"],
            0,
            2003,
        )

    def test_runtime_permissions_prepare_connector_audit_directory(self):
        with (
            patch.object(app_runner.os, "fchown"),
            patch.object(app_runner, "_prepare_ha_guest_session_dir"),
        ):
            app_runner._prepare_runtime_permissions()

        connector_log_dir = self.paths["CONNECTOR_LOG_DIR"]
        self.assertTrue(connector_log_dir.is_dir())
        self.assertEqual(
            connector_log_dir.stat().st_mode & 0o777,
            0o700,
        )







    def test_connector_id_change_fails_closed(self):
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir(parents=True)
        self.paths["LAYERV_TOKEN_FILE"].write_text(
            "synthetic-key\n", encoding="utf-8"
        )
        self.paths["APP_CONFIG_FILE"].write_text(
            json.dumps(
                {
                    "version": 2,
                    "connector_id": "original",
                    "resource_id": "r_synthetic",
                    "admin_token": "admin-synthetic",
                }
            ),
            encoding="utf-8",
        )
        with (
            patch.object(
                app_runner,
                "_connector_id",
                return_value="different",
            ),
            self.assertRaisesRegex(app_runner.SetupError, "differs"),
        ):
            app_runner._load_or_register({})

    def test_connection_reset_preserves_pages_and_removes_identity(self):
        pages = self.paths["DATA_DIR"] / "pages"
        pages.mkdir()
        page_file = pages / "cat-sitter.json"
        page_file.write_text('{"id":"cat-sitter"}', encoding="utf-8")

        for path in (
            self.paths["LAYERV_TOKEN_FILE"],
            self.paths["APP_CONFIG_FILE"],
            self.paths["CONNECTOR_CONFIG_FILE"],
            self.paths["INSTALLATION_ID_FILE"],
            self.paths["RESET_REQUEST_FILE"],
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic", encoding="utf-8")
        self.paths["CONNECTOR_STATE_DIR"].mkdir()
        (self.paths["CONNECTOR_STATE_DIR"] / "agent.json").write_text(
            "{}", encoding="utf-8"
        )
        broker = self.paths["DATA_DIR"] / "access-pages-broker"
        (broker / "shared-state").mkdir(parents=True)
        (broker / "shared-state" / "agent_state.sealed.json").write_text("sealed")
        (broker / "agent-bootstrap-complete").touch()
        (broker / "agent-wrapping-key").write_bytes(b"k" * 32)
        publisher = Mock(return_value={
            "crid": "a" * 59, "resource_id": "old-public-key",
            "target_url": "http://127.0.0.2:8080", "status": "serving",
        })
        management = Mock(api_base_url="https://api.invalid", api_token="key")
        resources = app_runner.GuestResources(
            broker / "guest-resources.sqlite3", installation_id="old-installation",
            publisher=publisher, management_client=management,
        )
        resources.ensure("cat-sitter", "grant_" + "a" * 16,
                         "http://127.0.0.2:8080", isolation="page")

        app_runner._reset_connection_files()

        self.assertTrue(page_file.is_file())
        for path in (
            self.paths["LAYERV_TOKEN_FILE"],
            self.paths["APP_CONFIG_FILE"],
            self.paths["CONNECTOR_CONFIG_FILE"],
            self.paths["INSTALLATION_ID_FILE"],
            self.paths["RESET_REQUEST_FILE"],
            self.paths["CONNECTOR_STATE_DIR"],
            broker / "shared-state",
            broker / "connector-home",
            broker / "agent-bootstrap-complete",
            broker / "agent-wrapping-key",
        ):
            self.assertFalse(path.exists())
        with resources._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM resources WHERE phase='ready'").fetchone()[0], 0)
        publisher.return_value = {
            **publisher.return_value, "crid": "b" * 59,
            "resource_id": "new-public-key",
        }
        fresh = app_runner.GuestResources(
            resources.path, installation_id="new-installation",
            publisher=publisher, management_client=management,
        ).ensure("cat-sitter", "grant_" + "b" * 16,
                 "http://127.0.0.2:8080", isolation="page")
        self.assertEqual(fresh.resource_public_key, "new-public-key")

    def test_established_reset_same_key_first_invitation_bootstraps_once(self):
        with patch.dict(os.environ, {
            "ACCESS_PAGES_BROKER_TOKEN": "synthetic-broker-token",
            "LAYERV_API_BASE_URL": "https://api.invalid",
            "LAYERV_API_TOKEN": "synthetic-token",
            "LAYERV_RESOURCE_ID": "synthetic-resource",
        }):
            import layerv_broker

        root = self.paths["DATA_DIR"]
        broker = root / "access-pages-broker"
        key = "same-valid-management-key"
        self.paths["LAYERV_TOKEN_FILE"].parent.mkdir()
        self.paths["LAYERV_TOKEN_FILE"].write_text(key + "\n", encoding="utf-8")
        self.paths["INSTALLATION_ID_FILE"].write_text(
            "11111111-1111-4111-8111-111111111111\n", encoding="utf-8"
        )
        old = ConnectorPublisher(
            broker / "shared-state", api_base_url="https://api.invalid",
            enrollment_key=key,
        )
        old.agent_state.write_text("old sealed Agent", encoding="utf-8")
        old.runtime_mode.write_text("old external supervisor", encoding="utf-8")
        (old.state / "local_shares.json").write_text("old local route", encoding="utf-8")
        old.wrapping_key.write_bytes(b"k" * 32)
        old.bootstrap_complete.touch()
        old_publisher = Mock(return_value={
            "crid": "a" * 59, "resource_id": "old-public-key",
            "target_url": "http://127.0.0.2:8080", "status": "serving",
        })
        management = Mock(api_base_url="https://api.invalid", api_token=key)
        old_resources = app_runner.GuestResources(
            broker / "guest-resources.sqlite3",
            installation_id="11111111-1111-4111-8111-111111111111",
            publisher=old_publisher, management_client=management,
        )
        old_resources.ensure("guest", "grant_" + "a" * 16,
                             "http://127.0.0.2:8080")
        # Green's 0.1.120 database predates the enrollment and cleanup fields.
        with old_resources._connect() as db:
            db.execute("DROP TABLE enrollment_state")
            db.execute("ALTER TABLE retirements DROP COLUMN management_only")

        app_runner._reset_connection_files()
        self.assertFalse((broker / "connector-home").exists())
        self.paths["LAYERV_TOKEN_FILE"].write_text(key + "\n", encoding="utf-8")
        config = app_runner._load_or_register({})
        self.assertNotEqual(config["installation_id"],
                            "11111111-1111-4111-8111-111111111111")
        self.assertEqual(config["api_token"], key)
        fresh_publisher = ConnectorPublisher(
            broker / "shared-state", api_base_url="https://api.invalid",
            enrollment_key=config["api_token"],
        )
        fresh_resources = app_runner.GuestResources(
            old_resources.path, installation_id=config["installation_id"],
            publisher=fresh_publisher, management_client=management,
        )
        fresh_publisher.restore()
        with old_resources._connect() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM enrollment_state WHERE name='agent'"
            ).fetchone()[0], "reset-authorized")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 1)
        with (
            patch.object(layerv_broker, "GUEST_RESOURCES", fresh_resources),
            patch.object(layerv_broker, "RECOVERY_REQUIRED", False),
            patch.object(layerv_broker, "drain_revocations") as drain,
        ):
            layerv_broker.reconcile_once(fresh_publisher)
            drain.assert_not_called()
        self.assertFalse(fresh_publisher.recovery_required)

        new_crids = iter(("b" * 59, "c" * 59))

        def cli(args, **_kwargs):
            if "login" in args:
                fresh_publisher.agent_state.write_text("new sealed Agent", encoding="utf-8")
                fresh_publisher.runtime_mode.write_text("new external supervisor", encoding="utf-8")
                return Mock(returncode=0, stdout="{}", stderr="")
            return Mock(returncode=0, stdout=json.dumps({
                "crid": next(new_crids), "resource_id": "new-public-key",
                "target_url": "http://127.0.0.2:8080", "status": "serving",
            }), stderr="")

        with (
            patch("layerv.LayerVClient.mint_agent_enrollment_token",
                  return_value="lv_test_" + "t" * 43) as mint,
            patch("guest_resources.subprocess.run", side_effect=cli) as run,
            patch.object(fresh_publisher, "_start"),
            patch.object(fresh_publisher, "_ipc", return_value={}),
            patch.object(fresh_publisher, "ensure_ready"),
            patch.object(layerv_broker, "GUEST_RESOURCES", fresh_resources),
            patch.object(layerv_broker, "RECOVERY_REQUIRED", False),
            patch.object(layerv_broker, "create_grant", side_effect=lambda *_args: fresh_resources.ensure(
                "guest", "grant_" + "b" * 16, "http://127.0.0.2:8080"
            )),
        ):
            handler = object.__new__(layerv_broker.Handler)
            handler.path = "/v1/grants"
            handler._authorized = Mock(return_value=True)
            handler._payload = Mock(return_value={})
            handler._send = Mock()
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 200)
            first = handler._send.call_args.args[1]
            fresh_resources.ensure(
                "guest", "grant_" + "c" * 16, "http://127.0.0.2:8080"
            )
        self.assertEqual(first.resource_public_key, "new-public-key")
        self.assertEqual(sum("login" in call.args[0] for call in run.call_args_list), 1)
        mint.assert_called_once()
        self.assertFalse(fresh_publisher.recovery_required)
        management.delete_resource.return_value = False
        with patch.object(fresh_publisher, "cleanup", side_effect=AssertionError(
            "reset retirement must not use the new Agent"
        )):
            fresh_resources.drain_retirements()
        management.delete_resource.assert_called_once_with(resource_crid="a" * 59)
        self.assertFalse(fresh_publisher.recovery_required)
        with fresh_resources._connect() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM enrollment_state WHERE name='agent'"
            ).fetchone()[0], "enrolled")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0], 0)

    def test_existing_pages_and_grants_seed_isolated_stores(self):
        pages = app_runner.PageStore(self.paths["DATA_DIR"] / "pages")
        pages.create({
            "id": "guest",
            "title": "Guest",
            "description": "",
            "resources": [],
            "access_grants": [{
                "id": "grant_" + "o" * 16,
                "credential_flow": "bootstrap-v1",
                "token_hash": "a" * 64,
                "created_at": "2026-07-30T00:00:00Z",
                "expires_at": "2026-07-31T00:00:00Z",
                "qurl_id": "q_one",
                "resource_id": "r_one",
            }],
        })

        self.assertEqual(app_runner._seed_authoritative_policy(), 1)

        policy = app_runner.PageStore(
            self.paths["POLICY_DIR"]
        ).load("guest")
        self.assertEqual(policy["access_grants"], [])
        mapping = json.loads(
            (
                self.paths["ACCESS_PAGES_BROKER_DATA_DIR"]
                / ("guest--grant_" + "o" * 16 + ".json")
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(mapping["qurl_id"], "q_one")

    def test_only_ha_broker_uses_supervisor_credentials(self):
        options = {
            "include_domains": "light,cover",
            "exclude_domains": "camera",
        }
        config = {
            "admin_token": "admin-synthetic",
            "api_token": "layerv-synthetic",
            "resource_id": "r_synthetic",
            "ha_broker_token": "ha-broker-synthetic",
            "ha_broker_admin_token": "ha-admin-synthetic",
            "access_pages_broker_token": "access-pages-broker-synthetic",
            "policy_store_token": "policy-synthetic",
            "verification_broker_token": "verification-synthetic",
        }
        with patch.dict(
            os.environ,
            {
                "SUPERVISOR_TOKEN": "supervisor-synthetic",
                "GATEWAY_VERSION": "0.1.test",
            },
            clear=True,
        ):
            admin = app_runner._admin_gateway_environment(options, config)
            guest = app_runner._page_endpoint_environment(
                page_id="guest-page",
                capability_token="page-capability",
                host="127.77.0.1",
            )
            broker = app_runner._ha_broker_environment(config)

        self.assertEqual(broker["HA_BASE_URL"], "http://supervisor/core")
        self.assertEqual(
            broker["HA_TOKEN"], "supervisor-synthetic"
        )
        self.assertEqual(
            broker["HA_GUEST_GRANTS_DIR"], str(self.paths["DATA_DIR"] / "pages")
        )
        self.assertEqual(
            broker["HA_GUEST_SESSION_DB"], str(self.paths["HA_GUEST_SESSION_DB"])
        )
        self.assertNotIn("HA_TOKEN", admin)
        self.assertNotIn("HA_TOKEN", guest)
        self.assertNotIn("GATEWAY_ROLE", admin)
        self.assertEqual(guest["GATEWAY_BOUND_PAGE_ID"], "guest-page")
        self.assertNotIn("GUEST_ENDPOINT_TRANSPORT", guest)
        self.assertEqual(guest["GUEST_ENDPOINT_GUEST_SERVICE_SOCKET"],
                         "/run/access-pages/guest/http.sock")
        self.assertNotIn("GUEST_ENDPOINT_UPSTREAM", guest)
        for secret in ("HA_TOKEN", "HA_BROKER_TOKEN", "HA_BROKER_ADMIN_TOKEN",
                       "ADMIN_TOKEN", "POLICY_PUBLISH_TOKEN", "LAYERV_API_TOKEN"):
            self.assertNotIn(secret, guest)
        self.assertEqual(
            admin["HA_ENTITY_INCLUDE_DOMAINS"], "light,cover"
        )
        self.assertEqual(admin["QURL_MAX_LIFETIME_DAYS"], "3")
        self.assertEqual(admin["GATEWAY_VERSION"], "0.1.test")

    def test_gateway_does_not_inherit_unrelated_secrets(self):
        config = {
            "admin_token": "admin-synthetic",
            "resource_id": "r_synthetic",
            "ha_broker_token": "ha-broker-synthetic",
            "ha_broker_admin_token": "ha-admin-synthetic",
            "access_pages_broker_token": "access-pages-broker-synthetic",
            "policy_store_token": "policy-synthetic",
            "verification_broker_token": "verification-synthetic",
        }
        with patch.dict(
            os.environ,
            {
                "SUPERVISOR_TOKEN": "supervisor-synthetic",
                "UNRELATED_SECRET": "must-not-leak",
                "QURL_API_KEY": "connector-secret",
            },
            clear=True,
        ):
            environment = app_runner._gateway_environment({}, config)

        self.assertNotIn("UNRELATED_SECRET", environment)
        self.assertNotIn("QURL_API_KEY", environment)


    def test_shared_storage_uses_primary_process_groups(self):
        admin = app_runner.PROCESS_IDENTITIES["admin"]
        ha_broker = app_runner.PROCESS_IDENTITIES["ha_broker"]
        layerv_broker = app_runner.PROCESS_IDENTITIES["access_pages_broker"]
        policy_store = app_runner.PROCESS_IDENTITIES["policy_store"]

        self.assertEqual(admin[1:3], (2000, []))
        self.assertNotIn("guest", app_runner.PROCESS_IDENTITIES)
        self.assertEqual(
            app_runner.PROCESS_IDENTITIES["guest_service"],
            (2101, 2101, [], 0o077),
        )
        self.assertEqual(ha_broker[1:3], (2001, [2000, 2102]))
        self.assertEqual(layerv_broker[0], 2103)
        self.assertEqual(policy_store[1:3], (2001, []))

    def test_guest_service_environment_is_an_explicit_allowlist(self):
        secrets = {
            name: "must-not-leak" for name in (
                "HA_TOKEN", "SUPERVISOR_TOKEN", "HA_BROKER_ADMIN_TOKEN",
                "ADMIN_TOKEN", "POLICY_PUBLISH_TOKEN", "LAYERV_API_TOKEN",
                "QURL_API_KEY", "SMTP_PASSWORD", "POLICY_STORE_TOKEN",
            )
        }
        with patch.dict(os.environ, secrets):
            environment = app_runner._guest_service_environment()
        self.assertEqual(set(environment), {
            "PATH", "LANG", "PYTHONDONTWRITEBYTECODE",
            "PYTHONUNBUFFERED", "GUEST_SERVICE_SOCKET",
            "HA_BROKER_GUEST_SOCKET",
        })
        self.assertEqual(
            environment["GUEST_SERVICE_SOCKET"],
            "/run/access-pages/guest/http.sock",
        )
        self.assertEqual(
            environment["HA_BROKER_GUEST_SOCKET"],
            "/run/access-pages/ha-guest/http.sock",
        )
        self.assertFalse(set(secrets) & set(environment))
        self.assertNotIn("GUEST_ENDPOINT_UPSTREAM", app_runner._page_endpoint_environment(
            page_id="p", capability_token="c", host="127.77.0.1"
        ))

    def test_ha_guest_socket_directory_rejects_symlink(self):
        root = self.paths["DATA_DIR"]
        target = root / "target"
        target.mkdir()
        link = root / "ha-guest"
        link.symlink_to(target)
        with (
            patch.object(app_runner, "HA_GUEST_DIR", link),
            patch.object(app_runner, "HA_GUEST_SOCKET", link / "http.sock"),
            self.assertRaisesRegex(app_runner.SetupError, "Unsafe"),
        ):
            app_runner._prepare_ha_guest_socket()

    def test_broker_guest_session_directory_rejects_symlink(self):
        parent = self.paths["HA_CAPABILITY_DIR"]
        parent.mkdir()
        target = self.paths["DATA_DIR"] / "target"
        target.mkdir()
        self.paths["HA_GUEST_SESSION_DIR"].symlink_to(target)
        with self.assertRaisesRegex(app_runner.SetupError, "Unsafe"):
            app_runner._prepare_ha_guest_session_dir()

    def test_gateway_uses_configured_qurl_lifetime_limit(self):
        options = {"qurl_max_lifetime_days": 30}
        config = {
            "admin_token": "admin-synthetic",
            "api_token": "layerv-synthetic",
            "resource_id": "r_synthetic",
            "ha_broker_token": "ha-broker-synthetic",
            "ha_broker_admin_token": "ha-admin-synthetic",
            "access_pages_broker_token": "access-pages-broker-synthetic",
            "policy_store_token": "policy-synthetic",
            "verification_broker_token": "verification-synthetic",
        }
        with patch.dict(
            os.environ,
            {"SUPERVISOR_TOKEN": "supervisor-synthetic"},
            clear=True,
        ):
            environment = app_runner._gateway_environment(options, config)

        self.assertEqual(environment["QURL_MAX_LIFETIME_DAYS"], "30")

    def test_connector_id_uses_layer_v_slug_rules(self):
        installation_id = "12345678-1234-1234-1234-123456789abc"
        self.assertEqual(
            app_runner._connector_id({}, installation_id),
            "ha-1234567812341234",
        )
        for invalid in ("HA-Test", "ha_test", "ab", "ha-test-"):
            with self.subTest(invalid=invalid), self.assertRaises(
                app_runner.SetupError
            ):
                app_runner._connector_id(
                    {"connector_id": invalid}, installation_id
                )

    def test_page_connector_ids_are_stable_distinct_and_bounded(self):
        first = app_runner._page_connector_id("ha-installation", "cat-sitter")
        second = app_runner._page_connector_id("ha-installation", "pool-guy")
        self.assertEqual(
            first,
            app_runner._page_connector_id("ha-installation", "cat-sitter"),
        )
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 64)
        self.assertRegex(first, r"^[a-z][a-z0-9-]+[a-z0-9]$")
        self.assertNotEqual(
            first,
            app_runner._page_connector_id(
                "ha-installation", "cat-sitter", generation=1
            ),
        )



    def test_page_endpoints_receive_distinct_page_bound_capabilities(self):
        pages = app_runner.PageStore(self.paths["DATA_DIR"] / "pages")
        entries = {}
        for offset, page_id in enumerate(("cat-sitter", "pool-guy")):
            pages.create({
                "id": page_id,
                "title": page_id,
                "description": "",
                "resources": [],
                "access_grants": [{
                    "id": "grant_" + str(offset) * 16,
                    "credential_flow": "bootstrap-v1",
                    "token_hash": "a" * 64,
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "label": page_id,
                    "lifetime": "1d",
                }],
            })
            entries[page_id] = {
                "runtime_uid": 22000 + offset,
                "target_ip": f"127.77.0.{offset + 1}",
            }
        process = Mock()
        process.poll.return_value = None
        with (
            patch.object(app_runner, "_spawn", return_value=process) as spawn,
            patch.object(app_runner.os, "chown"),
        ):
            processes = {}
            app_runner._reconcile_page_endpoints({}, {}, entries, processes)
        environments = [call.args[1] for call in spawn.call_args_list]
        self.assertEqual(
            {item["GATEWAY_BOUND_PAGE_ID"] for item in environments},
            {"cat-sitter", "pool-guy"},
        )
        self.assertEqual(
            len({item["PAGE_CAPABILITY_TOKEN"] for item in environments}), 2,
        )
        self.assertNotIn("VERIFICATION_BROKER_TOKEN", environments[0])
        identities = [call.args[2] for call in spawn.call_args_list]
        self.assertEqual(
            {(uid, gid, tuple(groups)) for uid, gid, groups, _mask in identities},
            {(23000, 23000, (2004,)), (23001, 23001, (2004,))},
        )
        self.assertFalse(self.paths["GUEST_PAGE_DIR"].exists())
        raw = json.loads(self.paths["PAGE_CAPABILITY_SECRETS"].read_text())
        from hashlib import sha256
        hashed = {key: sha256(value.encode()).hexdigest() for key, value in raw.items()}
        self.assertNotEqual(raw["cat-sitter"], hashed["cat-sitter"])
        self.assertEqual(json.loads(self.paths["HA_CAPABILITY_REGISTRY"].read_text()), {})
        self.assertEqual(
            json.loads(self.paths["HA_GUEST_CAPABILITY_REGISTRY"].read_text()),
            hashed,
        )
        self.assertEqual(
            self.paths["HA_GUEST_CAPABILITY_REGISTRY"].stat().st_mode & 0o777,
            0o640,
        )

    def test_endpoint_capability_cannot_authenticate_to_ha_broker_after_reconcile(self):
        from hashlib import sha256
        with patch.dict(os.environ, {
            "HA_BROKER_TOKEN": "synthetic-guest-broker",
            "HA_BROKER_ADMIN_TOKEN": "synthetic-admin-broker",
            "HA_BASE_URL": "http://ha.invalid",
            "HA_TOKEN": "synthetic-ha",
        }):
            import ha_broker

        # Model an existing installation that issued the same credential to
        # both boundaries; reconciliation must remove that old authority too.
        secret = "synthetic-old-endpoint-capability"
        self.paths["PAGE_CAPABILITY_SECRETS"].write_text(json.dumps({"cat-sitter": secret}))
        self.paths["HA_CAPABILITY_DIR"].mkdir(parents=True, exist_ok=True)
        self.paths["HA_CAPABILITY_REGISTRY"].write_text(json.dumps({
            "cat-sitter": sha256(secret.encode()).hexdigest(),
        }))
        with patch.object(app_runner.os, "chown"):
            capabilities = app_runner._page_capabilities({"cat-sitter"})
        self.assertEqual(capabilities["cat-sitter"], secret)
        handler = object.__new__(ha_broker.Handler)
        handler.headers = {"X-Broker-Token": secret}
        with patch.object(ha_broker, "PAGE_CAPABILITY_REGISTRY", self.paths["HA_CAPABILITY_REGISTRY"]):
            self.assertEqual(handler._authorized_page(), "")
        self.assertEqual(
            json.loads(self.paths["HA_GUEST_CAPABILITY_REGISTRY"].read_text())["cat-sitter"],
            sha256(secret.encode()).hexdigest(),
        )


    def test_modern_page_endpoints_are_not_reported_as_dormant_connectors(self):
        pages = app_runner.PageStore(self.paths["DATA_DIR"] / "pages")
        pages.create({
            "id": "cat-sitter", "title": "Cat sitter", "description": "",
            "resources": [], "access_grants": [],
        })
        with patch.object(app_runner.os, "chown"):
            for _ in range(2):
                app_runner._reconcile_page_connectors({"connector_id": "ha-installation"})
        self.assertEqual(
            json.loads(self.paths["CONNECTOR_STATUS_FILE"].read_text()),
            {"total": 1, "active": 0, "mode": "shared", "page_endpoints": 1},
        )



    def test_page_connector_identity_is_stable_and_collision_safe(self):
        previous = {
            "cat-sitter": {"runtime_uid": 22004, "runtime_gid": 22004},
        }
        history = {
            "retired-page": {"runtime_uid": 22000, "runtime_gid": 22000},
        }
        self.assertEqual(
            app_runner._page_connector_identity(
                "cat-sitter", previous, history
            ),
            (22004, 22004),
        )
        self.assertEqual(
            app_runner._page_connector_identity("new-page", previous, history),
            (22001, 22001),
        )
        with self.assertRaises(app_runner.SetupError):
            app_runner._page_connector_identity(
                "new-page",
                {
                    "one": {"runtime_uid": 22000},
                    "two": {"runtime_uid": 22000},
                },
                {},
            )









    def test_ingress_and_onboarding_receive_minimal_environments(self):
        process = type(
            "Process",
            (),
            {"poll": Mock(side_effect=[None, 0, 0]), "returncode": 0},
        )()

        ack_fds = []

        def start_process(_command, **kwargs):
            if kwargs.get("pass_fds"):
                ack_fds.append(os.dup(kwargs["pass_fds"][1]))
                os.write(kwargs["pass_fds"][0], b"synthetic-key\n")
            return process

        with (
            patch.dict(
                os.environ,
                {
                    "SUPERVISOR_TOKEN": "must-not-leak",
                    "QURL_API_KEY": "must-not-leak",
                },
                clear=True,
            ),
            patch.object(
                app_runner.subprocess,
                "Popen",
                side_effect=start_process,
            ) as popen,
            patch.object(app_runner, "_stop"),
            patch.object(app_runner, "_store_onboarding_key"),
        ):
            app_runner._start_ingress("admin-synthetic")
            ingress_environment = popen.call_args.kwargs["env"]
            app_runner._run_onboarding(ingress=process)
            onboarding_environment = popen.call_args.kwargs["env"]

        os.close(ack_fds[0])

        for environment in (ingress_environment, onboarding_environment):
            self.assertNotIn("SUPERVISOR_TOKEN", environment)
            self.assertNotIn("QURL_API_KEY", environment)
        self.assertNotIn(
            "ONBOARDING_TOKEN_FILE",
            onboarding_environment,
        )
        self.assertEqual(
            popen.call_args.kwargs["preexec_fn"].__name__,
            "apply_identity",
        )


if __name__ == "__main__":
    unittest.main()
