import os
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from themes import THEMES, render_theme


ROOT = Path(__file__).resolve().parents[1]


class ThemeTests(unittest.TestCase):
    def test_default_and_untrusted_values_keep_original_theme(self):
        html = (ROOT / "static/access.html").read_text()
        for value in (None, "", "unknown", '"><script>alert(1)</script>'):
            with self.subTest(value=value), patch.dict(os.environ, {}, clear=True):
                if value is not None:
                    os.environ["ACCESS_PAGES_THEME"] = value
                rendered = render_theme(html)
                self.assertIn('data-theme="midnight"', rendered)
                self.assertIn('name="theme-color" content="#08152e"', rendered)
                self.assertNotIn("<script>alert", rendered)

    def test_admin_and_preview_shells_include_selected_theme(self):
        # Use the existing server test setup's synthetic credentials.
        from test_server import Handler

        handler = object.__new__(Handler)
        for theme, color in THEMES.items():
            with (self.subTest(theme=theme),
                  patch.dict(os.environ, {"ACCESS_PAGES_THEME": theme}),
                  patch.object(handler, "_send_bytes") as send):
                handler._send_static_file("admin.html")
                admin = send.call_args.args[1].decode()
                self.assertIn(f'data-theme="{theme}"', admin)
                self.assertIn(f'name="theme-color" content="{color}"', admin)
                self.assertIn('href="static/themes.css"', admin)
                handler._send_access_shell("garden")
                preview = send.call_args.args[1].decode()
                self.assertIn(f'data-theme="{theme}"', preview)
                self.assertIn('data-page-id="garden"', preview)

    def test_guest_shell_and_stylesheet_work_under_scoped_link(self):
        import guest_service

        handler = object.__new__(guest_service.GuestHandler)
        prefix = "/g/garden/grant_abcdefghijklmnop/"
        handler.path = prefix
        handler.headers = Message()
        handler.headers["X-Access-Pages-Page-ID"] = "garden"
        handler.headers["X-Page-Capability"] = "test-capability"
        handler.headers["Cookie"] = "access_pages_guest=abcdefghijklmnop"
        with (patch.dict(os.environ, {"ACCESS_PAGES_THEME": "daylight"}),
              patch.object(guest_service, "STATIC_DIR", ROOT / "static"),
              patch.object(guest_service, "_connector_healthy", return_value=True),
              patch.object(guest_service, "_broker_guest_auth", return_value=(200, {})),
              patch.object(handler, "_send") as send):
            handler._serve_guest("GET")
            self.assertEqual(send.call_args.args[0], 200)
            html = send.call_args.args[1].decode()
            self.assertIn('data-theme="daylight" data-page-id="garden"', html)
            self.assertIn(f'href="{prefix}static/themes.css"', html)
            handler.path = prefix + "static/themes.css"
            handler._serve_guest("GET")
            self.assertEqual(send.call_args.args[0], 200)
            self.assertEqual(send.call_args.args[2], "text/css")
            self.assertEqual(send.call_args.args[1], (ROOT / "static/themes.css").read_bytes())
