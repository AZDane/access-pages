"""The broker email operation cannot select a recipient or broaden authority."""

from datetime import datetime, timedelta, timezone
from http import HTTPStatus
import hmac
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import internal
from email_delivery import EmailConfigError


class GuestVerificationEmailTests(unittest.TestCase):
    def setUp(self):
        self.expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        self.page = {"access_grants": [{
            "id": "grant_" + "a" * 16, "verification_required": True,
            "credential_flow": "bootstrap-v1",
            "expires_at": self.expiry.isoformat(),
        }]}
        self.handler = Mock()
        self.handler.headers.get_all.return_value = ["broker-admin-secret"]
        self.handler._load_page.return_value = self.page
        self.runtime = SimpleNamespace(
            HTTPStatus=HTTPStatus, HA_BROKER_TOKEN="broker-admin-secret",
            hmac=hmac, re=re, EmailConfigError=EmailConfigError,
            parse_time=datetime.fromisoformat,
            utc_now=lambda: datetime.now(timezone.utc),
            verification_email_content=lambda code: (f"Code {code}", "html"),
            SMTP_CONFIG_STORE=Mock(), VERIFICATION_RECIPIENTS=Mock(),
            send_email=Mock(),
        )
        self.runtime.VERIFICATION_RECIPIENTS.get.return_value = "stored@example.test"

    def send(self, **changes):
        payload = {
            "page_id": "page-a", "grant_id": "grant_" + "a" * 16,
            "code": "123456", **changes,
        }
        internal.handle_post(
            self.handler, "/api/internal/email/guest-verification",
            payload, self.runtime,
        )

    def test_authenticated_delivery_uses_stored_recipient_and_fixed_content(self):
        self.send()
        self.handler._send_json.assert_called_once_with(200, {"success": True})
        self.runtime.VERIFICATION_RECIPIENTS.get.assert_called_once_with(
            "page-a", "grant_" + "a" * 16,
        )
        args = self.runtime.send_email.call_args
        self.assertEqual(args.args[1:4], (
            "stored@example.test", "Your Access Pages verification code",
            "Code 123456",
        ))

    def test_caller_cannot_supply_recipient_or_message(self):
        self.send(recipient="attacker@example.test", subject="attacker", body="bad")
        self.handler._send_json.assert_called_with(
            HTTPStatus.BAD_REQUEST, {"error": "Invalid delivery request"},
        )
        self.runtime.send_email.assert_not_called()

    def test_token_and_current_grant_are_required(self):
        self.handler.headers.get_all.return_value = ["wrong"]
        self.send()
        self.handler._send_json.assert_called_with(HTTPStatus.UNAUTHORIZED,
                                                   {"error": "not found"})
        self.runtime.send_email.assert_not_called()
        self.handler.reset_mock()
        self.handler.headers.get_all.return_value = ["broker-admin-secret"]
        self.page["access_grants"][0]["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        self.send()
        self.handler._send_json.assert_called_with(HTTPStatus.NOT_FOUND,
                                                   {"error": "not found"})
        self.runtime.send_email.assert_not_called()


if __name__ == "__main__":
    unittest.main()
