import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from email_delivery import (
    EmailConfigError,
    NotificationTargetStore,
    SMTPConfigStore,
    VerificationRecipientStore,
    guest_invitation_email_content,
    send_email,
    validate_smtp_config,
    verification_email_content,
)


class EmailDeliveryTests(unittest.TestCase):
    def payload(self, **overrides):
        value = {
            "host": "smtp.example.test",
            "port": 587,
            "security": "starttls",
            "username": "gateway@example.test",
            "password": "synthetic-app-password",
            "sender_email": "gateway@example.test",
            "sender_name": "Access Pages",
        }
        value.update(overrides)
        return value

    def test_rejects_plaintext_smtp_port_25(self):
        with self.assertRaisesRegex(EmailConfigError, "TLS SMTP"):
            validate_smtp_config(self.payload(port=25), require_password=True)

    def test_rejects_unknown_security_mode(self):
        with self.assertRaisesRegex(EmailConfigError, "STARTTLS"):
            validate_smtp_config(
                self.payload(security="none"), require_password=True,
            )

    def test_store_is_owner_only_and_public_view_omits_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "smtp.json"
            store = SMTPConfigStore(path)
            store.save(self.payload())
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            public = store.public_view()
            self.assertTrue(public["configured"])
            self.assertTrue(public["password_configured"])
            self.assertNotIn("password", public)
            self.assertEqual(
                public["administrator_email"], "gateway@example.test"
            )
            self.assertEqual(
                json.loads(path.read_text())["password"],
                "synthetic-app-password",
            )

    def test_administrator_alert_email_is_configurable(self):
        config = validate_smtp_config(
            self.payload(administrator_email="owner@example.test"),
            require_password=True,
        )
        self.assertEqual(config.administrator_email, "owner@example.test")

    def test_blank_password_preserves_existing_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SMTPConfigStore(Path(directory) / "smtp.json")
            store.save(self.payload())
            store.save(self.payload(password="", sender_name="New name"))
            self.assertEqual(store.load().password, "synthetic-app-password")
            self.assertEqual(store.load().sender_name, "New name")

    def test_recipient_mapping_is_owner_only_and_separate_from_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recipients.json"
            store = VerificationRecipientStore(path)
            store.set("page-a", "grant-a", "guest@example.test")
            self.assertEqual(store.get("page-a", "grant-a"), "guest@example.test")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            store.delete("page-a", "grant-a")
            with self.assertRaises(EmailConfigError):
                store.get("page-a", "grant-a")

    @patch("email_delivery.smtplib.SMTP")
    def test_starttls_is_required_before_authentication(self, smtp_class):
        client = MagicMock()
        smtp_class.return_value = client
        client.__enter__.return_value = client
        config = validate_smtp_config(self.payload(), require_password=True)
        send_email(config, "guest@example.test", "Test", "Body")
        client.starttls.assert_called_once()
        client.login.assert_called_once_with(
            "gateway@example.test", "synthetic-app-password",
        )
        client.send_message.assert_called_once()
        method_names = [item[0] for item in client.method_calls]
        self.assertLess(
            method_names.index("starttls"),
            method_names.index("login"),
        )

    @patch("email_delivery.smtplib.SMTP")
    def test_html_email_keeps_plain_text_fallback(self, smtp_class):
        client = MagicMock()
        smtp_class.return_value = client
        client.__enter__.return_value = client
        config = validate_smtp_config(self.payload(), require_password=True)
        text, html = verification_email_content("123456")

        send_email(
            config,
            "guest@example.test",
            "Verification",
            text,
            html_body=html,
        )

        message = client.send_message.call_args.args[0]
        self.assertTrue(message.is_multipart())
        self.assertIn("123456", message.get_body(preferencelist=("plain",)).get_content())
        html_part = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("123456", html_part)
        self.assertNotIn("<script", html_part.lower())
        self.assertEqual([part.get_content_type() for part in message.iter_parts()], ["text/plain", "text/html"])
        self.assertNotIn("<img", html_part)
        self.assertNotIn("cid:", html_part)

    def test_invitation_template_escapes_links_in_html(self):
        qurl = 'https://qurl.example/a?x=1&label="test"'
        text, html = guest_invitation_email_content(qurl)

        self.assertIn(qurl, text)
        self.assertIn("&amp;", html)
        self.assertIn("&quot;test&quot;", html)
        self.assertNotIn('label="test"', html)

    def test_invitation_template_supports_one_target_path_link(self):
        qurl = "https://qurl.example/private"
        text, html = guest_invitation_email_content(qurl)

        self.assertEqual(text.count(qurl), 1)
        self.assertIn("Open Guest Controls", html)
        self.assertNotIn("Step 2", html)

    def test_verification_template_rejects_non_six_digit_code(self):
        with self.assertRaises(EmailConfigError):
            verification_email_content("12345<script>")

    def test_unverified_invitation_has_button_text_branding_and_plain_text_link(self):
        qurl = "https://qurl.example/private"
        text, html = guest_invitation_email_content(qurl, verification_required=False)
        self.assertIn(qurl, text)
        self.assertEqual(html.count(qurl), 1)
        self.assertIn('href="' + qurl + '"', html)
        self.assertIn("Access Pages", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("verification code", text)
        self.assertNotIn("verification code", html)

    def test_scheduled_window_is_inside_email_before_link_and_escaped(self):
        qurl = "https://qurl.example/private"
        window = ("Nov 14, 2026 at 10:00 PM MST (-0700)", "Nov 15, 2026 at 02:00 AM MST (-0700)", "America/Phoenix")
        text, html = guest_invitation_email_content(qurl, access_window=window)
        for value in window:
            self.assertIn(value, text)
            self.assertIn(value, html)
            self.assertLess(text.index(value), text.index(qurl))
            self.assertLess(html.index(value), html.index('href='))
        self.assertTrue(html.rstrip().endswith("</html>"))
        self.assertIn("including already-open sessions", html)
        self.assertIn("Opening early", text)
        _, escaped = guest_invitation_email_content(qurl, access_window=("<start>", "<end>", "<zone>"))
        self.assertIn("&lt;start&gt;", escaped)
        self.assertIn("&lt;end&gt;", escaped)
        self.assertIn("&lt;zone&gt;", escaped)

    def test_unscheduled_invitation_does_not_invent_access_window(self):
        text, html = guest_invitation_email_content("https://qurl.example/private")
        self.assertNotIn("Access window", text)
        self.assertNotIn("Access window", html)


class NotificationTargetStoreTests(unittest.TestCase):
    def test_saves_only_registered_mobile_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = NotificationTargetStore(Path(directory) / "alerts.json")
            selected = store.save(
                ["notify.mobile_app_johnr_iphone"],
                {
                    "notify.mobile_app_johnr_iphone",
                    "notify.mobile_app_wall_tablet",
                },
            )
            self.assertEqual(selected, ["notify.mobile_app_johnr_iphone"])
            self.assertEqual(store.load(), selected)

    def test_rejects_unregistered_or_non_mobile_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            store = NotificationTargetStore(Path(directory) / "alerts.json")
            for target in ("notify.mobile_app_unknown", "notify.everyone"):
                with self.subTest(target=target):
                    with self.assertRaises(EmailConfigError):
                        store.save([target], {"notify.mobile_app_johnr_iphone"})


if __name__ == "__main__":
    unittest.main()
