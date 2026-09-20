import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "homeassistant-app" / "apparmor.txt"


class AppArmorProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = PROFILE.read_text(encoding="utf-8")

    def test_profile_is_enforced_after_acceptance_testing(self):
        self.assertIn(
            "flags=(attach_disconnected,mediate_deleted)",
            self.profile,
        )
        self.assertNotIn("complain", self.profile)

    def test_only_embedded_qurl_binary_is_executable(self):
        self.assertIn("/usr/local/bin/qurl rix,", self.profile)
        self.assertNotIn("/usr/local/bin/qurl-connector", self.profile)

    def test_blanket_permissions_are_not_present(self):
        rules = {
            line.strip()
            for line in self.profile.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertNotIn("file,", rules)
        self.assertNotIn("network,", rules)
        self.assertNotIn("capability,", rules)

    def test_persistent_state_has_explicit_rules(self):
        for path in (
            "/data/pages/",
            "/data/secrets/",
            "/data/connector-config/",
            "/data/connector-state/",
            "/data/page-connectors/",
            "/data/guest-activity.sqlite3",
        ):
            self.assertIn(path, self.profile)

    def test_upgrade_can_create_only_allowlisted_top_level_stores(self):
        self.assertIn("/data/ rw,", self.profile)
        self.assertNotIn("/data/** rw", self.profile)
        for path in (
            "/data/policy-pages/{,**} rwk,",
            "/data/guest-runtime/{,**} rwk,",
            "/data/access-pages-broker/{,**} rwk,",
            "/data/admin-runtime/{,**} rwk,",
        ):
            self.assertIn(path, self.profile)

    def test_sqlite_rollback_and_wal_sidecars_are_allowed(self):
        self.assertIn(
            "/data/guest-activity.sqlite3{,-journal,-shm,-wal} rwk,",
            self.profile,
        )

    def test_atomic_reset_request_paths_are_allowed(self):
        self.assertIn("/data/reset-connection.request rwk,", self.profile)
        self.assertIn(
            "/data/.reset-connection.request.tmp rwk,",
            self.profile,
        )

    def test_atomic_page_capability_paths_are_allowed(self):
        self.assertIn("/data/page-capabilities.json rwk,", self.profile)
        self.assertIn(
            "/data/.page-capabilities.json.tmp rwk,",
            self.profile,
        )

    def test_network_is_limited_to_tcp_and_udp_families(self):
        self.assertIn("network inet stream,", self.profile)
        self.assertIn("network inet6 stream,", self.profile)
        self.assertIn("network inet dgram,", self.profile)
        self.assertIn("network inet6 dgram,", self.profile)

    def test_process_identity_capabilities_are_narrow(self):
        self.assertIn("capability setuid,", self.profile)
        self.assertIn("capability setgid,", self.profile)
        self.assertIn("capability fsetid,", self.profile)
        self.assertIn("capability kill,", self.profile)
        self.assertNotIn("capability sys_admin", self.profile)
        self.assertNotIn("capability sys_ptrace", self.profile)


if __name__ == "__main__":
    unittest.main()
