import importlib.util
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "homeassistant-app"
    / "ingress_proxy.py"
)

with patch.dict(
    "os.environ",
    {"INGRESS_ADMIN_TOKEN": "synthetic-admin-token"},
):
    SPEC = importlib.util.spec_from_file_location(
        "ingress_proxy", MODULE_PATH
    )
    ingress_proxy = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(ingress_proxy)


class IngressProxyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is required for browser API path test")
    def test_admin_preview_requests_stay_under_the_ingress_base(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static/access.html").read_bytes()
        rendered = ingress_proxy._inject_ingress_base(
            html, "text/html; charset=utf-8",
            "/api/hassio_ingress/synthetic-session",
        )
        base = re.search(rb'<base href="([^"]+)">', rendered).group(1).decode()
        script = r'''
import {readFileSync} from "node:fs";
const source = readFileSync(process.argv[1], "utf8");
globalThis.document = {querySelector: selector => selector === "base" ? {} : null};
const urls = [];
globalThis.window = {fetch: async (url) => {
  urls.push(url);
  return new Response("{}", {status: 200});
}};
const {createAccessApi} = await import(
  "data:text/javascript;base64," + Buffer.from(source).toString("base64")
);
const api = createAccessApi({search: "?preview_token=preview-token"});
await api.fetchPage("guest");
await api.runAction("guest", "lamp", "turn_on", {});
urls.push(api.cameraUrl("guest", "camera", 1));
for (const url of urls) {
  const resolved = new URL(url, "https://ha.example" + process.argv[2]);
  if (!resolved.pathname.startsWith(process.argv[2] + "api/admin/preview/guest"))
    throw new Error(resolved.href);
  if (resolved.searchParams.get("preview_token") !== "preview-token")
    throw new Error("Preview capability missing");
}
'''
        result = subprocess.run(
            ["node", "--input-type=module", "-e", script,
             str(root / "static/access-api.js"), base],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_home_assistant_ingress_is_trusted(self):
        path = "/api/hassio_ingress/synthetic-session"
        self.assertTrue(
            ingress_proxy._trusted_ingress_request("172.30.32.2", path)
        )
        self.assertFalse(
            ingress_proxy._trusted_ingress_request("172.30.32.3", path)
        )
        self.assertFalse(
            ingress_proxy._trusted_ingress_request("172.30.32.2", "")
        )
        self.assertFalse(
            ingress_proxy._trusted_ingress_request(
                "172.30.32.2",
                "/api/hassio_ingress/session\r\nX-Forged: yes",
            )
        )

    def test_ingress_root_opens_admin_shell(self):
        self.assertEqual(ingress_proxy._upstream_path("/"), "/admin")
        self.assertEqual(
            ingress_proxy._upstream_path("/?source=ingress"),
            "/admin?source=ingress",
        )
        self.assertEqual(
            ingress_proxy._upstream_path("/api/admin/pages"),
            "/api/admin/pages",
        )

    def test_ingress_allows_only_same_origin_framing(self):
        public_policy = (
            "default-src 'self'; script-src 'self'; "
            "frame-ancestors 'none';"
        )

        policy = ingress_proxy._ingress_csp(public_policy)

        self.assertIn("default-src 'self'", policy)
        self.assertIn("script-src 'self'", policy)
        self.assertIn("frame-ancestors 'self'", policy)
        self.assertNotIn("frame-ancestors 'none'", policy)

    def test_ingress_base_uses_supervisor_provided_path(self):
        html = (
            b'<html><head><link href="/static/access.css"></head>'
            b'<body><script src="/static/access.js"></script></body></html>'
        )

        result = ingress_proxy._inject_ingress_base(
            html,
            "text/html; charset=utf-8",
            "/api/hassio_ingress/synthetic-session",
        )

        self.assertIn(
            b'<base href="/api/hassio_ingress/synthetic-session/">',
            result,
        )
        self.assertIn(b'href="static/access.css"', result)
        self.assertIn(b'src="static/access.js"', result)

    def test_ingress_base_rejects_unsafe_or_non_html_input(self):
        html = b"<html><head></head></html>"

        self.assertEqual(
            ingress_proxy._inject_ingress_base(
                html,
                "text/html",
                "/unsafe\r\npath",
            ),
            html,
        )
        self.assertEqual(
            ingress_proxy._inject_ingress_base(
                b"{}",
                "application/json",
                "/api/hassio_ingress/session",
            ),
            b"{}",
        )

    def test_transition_page_contains_no_upstream_details(self):
        payload = ingress_proxy._transition_payload().decode("utf-8")

        self.assertIn("transitioning", payload)
        self.assertIn('content="2"', payload)
        self.assertNotIn("127.0.0.1", payload)
        self.assertNotIn("Traceback", payload)

    def test_admin_client_paths_remain_under_ingress_prefix(self):
        static_dir = Path(__file__).resolve().parents[1] / "static"
        html = (static_dir / "admin.html").read_text(encoding="utf-8")
        javascript = (static_dir / "admin.js").read_text(encoding="utf-8")

        self.assertNotIn('href="/static/', html)
        self.assertNotIn('src="/static/', html)
        self.assertNotIn('"/api/admin', javascript)
        self.assertNotIn('`/api/admin', javascript)
        self.assertNotIn("if (!adminToken)", javascript)
        self.assertNotIn('editingExisting ? "PUT"', javascript)
        self.assertIn("navigator.clipboard?.writeText", javascript)
        self.assertLess(
            javascript.index("legacyCopyText(value, button)"),
            javascript.index("navigator.clipboard?.writeText"),
        )
        self.assertIn(
            'button.closest("dialog") || document.body',
            javascript,
        )
        self.assertIn("editor-users-bottom", html)
        self.assertIn("save-bottom", html)
        self.assertIn("https://layerv.ai", html)
        self.assertIn(
            "window.location.assign(data.preview_url)",
            javascript,
        )
        self.assertIn(
            'waitForServiceStatus("setup_required")',
            javascript,
        )
        self.assertNotIn(
            "window.setTimeout(() => window.location.reload(), 3500)",
            javascript,
        )
        self.assertNotIn(
            'window.open(data.preview_url, "_blank"',
            javascript,
        )
        access_javascript = (
            static_dir / "access.js"
        ).read_text(encoding="utf-8")
        access_html = (
            static_dir / "access.html"
        ).read_text(encoding="utf-8")
        access_css = (
            static_dir / "access.css"
        ).read_text(encoding="utf-8")
        self.assertIn('id="preview-toolbar"', access_html)
        self.assertIn('class="preview-toolbar hidden"', access_html)
        self.assertIn(
            '.has("preview_token")',
            access_javascript,
        )
        self.assertIn(
            "window.history.back()",
            access_javascript,
        )
        self.assertIn(
            "window.location.assign(adminRootUrl())",
            access_javascript,
        )
        self.assertIn("custom-lifetime-value", html)
        self.assertIn("qurlMaxLifetimeDays", javascript)
        self.assertIn("qurl_max_lifetime_days", javascript)
        self.assertIn("range-parameter", access_javascript)
        self.assertIn("@media (max-width: 520px)", access_css)
        self.assertIn(
            "grid-template-columns: repeat(2, minmax(0, 1fr))",
            access_css,
        )


if __name__ == "__main__":
    unittest.main()
