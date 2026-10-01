import unittest
import json
import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_ha_image_pins_qurl_300_without_standalone_connector(self):
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text(encoding="utf-8")
        self.assertIn("qurl_3.0.0_linux_${TARGETARCH}.tar.gz", dockerfile)
        self.assertIn("c6ce79a75c84d2ed378793028c51aab83a12780bb9d5580400caba258fc836f6", dockerfile)
        self.assertIn("30972dd3804a8bf02a4f948451e37ecb6d482872ac44fc017e44bd554158dd6f", dockerfile)
        self.assertNotIn("qurl-connector", dockerfile)
        self.assertNotIn("2.5.4", dockerfile)

    def test_final_image_asserts_system_tunnel_trust_store(self):
        runtime = (ROOT / "Dockerfile.ha-app").read_text().split("FROM python:", 1)[1]
        self.assertIn("dpkg-query -W ca-certificates", runtime)
        self.assertIn("test -s /etc/ssl/certs/ca-certificates.crt", runtime)
        self.assertIn("ssl.create_default_context().cert_store_stats()", runtime)

    def test_pinned_license_bundle_is_copied_into_final_image(self):
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text(encoding="utf-8")
        self.assertIn("COPY LICENSE THIRD_PARTY_NOTICES.md ./", dockerfile)
        self.assertIn("COPY third_party_licenses ./third_party_licenses", dockerfile)
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        directory = ROOT / "third_party_licenses"
        go_license = (directory / "Go-1.26.6-and-1.27.0-LICENSE").read_text(encoding="utf-8")
        self.assertIn("Copyright 2009 The Go Authors", go_license)
        self.assertIn("Redistributions in binary form must reproduce", go_license)
        self.assertIn("LayerV", (directory / "qurl-3.0.0-LICENSE").read_text(encoding="utf-8"))
        self.assertIn("PYTHON SOFTWARE FOUNDATION", (directory / "Python-3.14.7-LICENSE").read_text(encoding="utf-8"))
        self.assertTrue((directory / "yamux-source" / "session.go").is_file())
        for arch in ("amd64", "arm64"):
            packages = json.loads((directory / f"qurl-3.0.0-linux-{arch}.spdx.json").read_text())["packages"]
            for package in packages:
                name = package["name"]
                if name == "stdlib" or name.startswith("qurl_3.0.0_"):
                    continue
                module = directory / "qurl-modules" / f"{name}@{package['versionInfo']}"
                self.assertTrue(module.is_dir(), name)
                self.assertTrue(any(module.rglob("LICENSE*")), name)
                self.assertIn(f"`{name}`", notices)

    def test_development_image_contains_every_gateway_module(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

        for module in (
            "server.py",
            "actions.py",
            "admin.py",
            "access.py",
            "upstream_cleanup.py",
            "guest_resources.py",
            "internal.py",
            "config.py",
            "ha.py",
            "guest_diagnostics.py",
            "guest_request.py",
            "ha_broker.py",
            "layerv_broker.py",
            "policy.py",
            "policy_store.py",
            "pages.py",
            "layerv.py",
            "audit.py",
            "activity.py",
            "rate_limit.py",
        ):
            self.assertIn(f"COPY {module} .", dockerfile)

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
        dockerfile = (ROOT / "Dockerfile.ha-app").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "ln -s /data/logs/layer-v-connector /var/log/layerv",
            dockerfile,
        )
        self.assertIn("chmod 0700", dockerfile)

    def test_home_assistant_app_does_not_advertise_public_gateway_port(self):
        config = (ROOT / "homeassistant-app" / "config.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("8080/tcp", config)


if __name__ == "__main__":
    unittest.main()
