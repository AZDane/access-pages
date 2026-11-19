import unittest
import json
import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_ha_image_uses_identical_evaluated_runtime_and_verified_qurl(self):
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text()
        candidate = (ROOT / "Dockerfile.ha-minimal").read_text()
        def instructions(source):
            return [line for line in source.splitlines() if not line.startswith('#')]
        self.assertEqual(instructions(dockerfile), instructions(candidate))
        self.assertIn("ghcr.io/azdane/access-pages-app:0.1.163@sha256:99259c306ff6b918249d5304202e7a64acd0e0c4a9a01eb7dba93cab9a9bd2cd", dockerfile)
        for checksum in ('07e53ea1301531b4f873776f08cd02bcbe36ae728a71049a8b7f74b8840c84d9',
                         '78eb88774f2b05bfab0f3afa7963e6fa70ea5e82a64d5032e9ee0a37b34f45e7'):
            self.assertIn(checksum, dockerfile)
        self.assertNotIn("LEGACY_PUBLIC_PUBLISH", (ROOT / "guest_resources.py").read_text())

    def test_final_image_asserts_system_tunnel_trust_store(self):
        runtime = (ROOT / "Dockerfile.ha-app").read_text().split("FROM cgr.dev/chainguard/python:", 1)[1]
        self.assertIn('"/opt/build/prepare.py"', runtime)
        preparation = (ROOT / "packaging/minimal/prepare.py").read_text()
        self.assertIn("ssl.create_default_context().cert_store_stats()['x509_ca']", preparation)
        self.assertIn("raise ValueError('Empty system CA trust store')", preparation)

    def test_pinned_license_bundle_is_copied_into_final_image(self):
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text(encoding="utf-8")
        self.assertIn("COPY LICENSE THIRD_PARTY_NOTICES.md ./", dockerfile)
        self.assertIn("COPY third_party_licenses ./third_party_licenses", dockerfile)
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        directory = ROOT / "third_party_licenses"
        go_license = (directory / "Go-1.26.11-and-1.27.3-LICENSE").read_text(encoding="utf-8")
        self.assertIn("Copyright 2009 The Go Authors", go_license)
        self.assertIn("Redistributions in binary form must reproduce", go_license)
        self.assertIn("LayerV", (directory / "qurl-4.2.0-LICENSE").read_text(encoding="utf-8"))
        self.assertIn("PYTHON SOFTWARE FOUNDATION", (directory / "Python-3.15.2-LICENSE").read_text(encoding="utf-8"))
        self.assertTrue((directory / "yamux-source" / "session.go").is_file())
        for arch in ("amd64", "arm64"):
            packages = json.loads((directory / f"qurl-4.2.0-linux-{arch}.spdx.json").read_text())["packages"]
            for package in packages:
                name = package["name"]
                if name == "stdlib" or name.startswith("qurl_4.2.0_"):
                    continue
                module = directory / "qurl-modules" / f"{name}@{package['versionInfo']}"
                self.assertTrue(module.is_dir(), name)
                self.assertTrue(any(module.rglob("LICENSE*")), name)
                self.assertIn(f"`{name}`", notices)

    def test_supported_images_include_local_import_dependency_closure(self):
        local = {path.stem for path in ROOT.glob('*.py')}
        manifests = []
        for definition in ('Dockerfile', 'Dockerfile.ha-app'):
            source = (ROOT / definition).read_text()
            modules = set()
            for line in source.splitlines():
                if line.startswith('COPY '):
                    modules.update(re.findall(r'(?<![/\w-])([\w_]+)\.py\b', line))
            modules &= local
            manifests.append(modules)
            for module in modules:
                tree = ast.parse((ROOT / f'{module}.py').read_text())
                imports = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imports.update(alias.name.split('.')[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imports.add(node.module.split('.')[0])
                self.assertFalse((imports & local) - modules, (definition, module, imports - modules))
            self.assertIn('guest_diagnostics', modules)
            self.assertNotIn('tests/', source)
        self.assertEqual(manifests[1] - manifests[0], {'guest_service'})
        self.assertFalse(manifests[0] - manifests[1])

    def test_endpoint_has_no_gateway_upstream_switch(self):
        source = (ROOT / "cmd" / "guest-endpoint" / "main.go").read_text(encoding="utf-8")
        runner = (ROOT / "homeassistant-app" / "app_runner.py").read_text(encoding="utf-8")
        self.assertNotIn("GUEST_ENDPOINT_UPSTREAM", source + runner)
        self.assertNotIn("GUEST_ENDPOINT_TRANSPORT", source + runner)
        self.assertIn("newGuestServiceProxy(guestSocket", source)

    def test_home_assistant_runner_can_import_gateway_modules(self):
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text(
            encoding="utf-8"
        )
        self.assertIn("PYTHONPATH=/app", dockerfile)

    def test_connector_audit_path_uses_restricted_persistent_store(self):
        preparation = (ROOT / "packaging/minimal/prepare.py").read_text()
        self.assertIn("Path('/var/log/layerv').symlink_to('/data/logs/layer-v-connector')", preparation)
        self.assertIn("'/data/logs/layer-v-connector': (2105, 2105, 0o700)", preparation)

    def test_home_assistant_app_does_not_advertise_public_gateway_port(self):
        config = (ROOT / "homeassistant-app" / "config.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("8080/tcp", config)

    def test_home_assistant_backup_stops_mutable_state_writers(self):
        config = (ROOT / "homeassistant-app" / "config.yaml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(config, r"(?m)^backup: cold$")


if __name__ == "__main__":
    unittest.main()
