"""Invitation delivery is independent of verification; SMTP is mocked."""
import unittest
import os
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
os.environ.setdefault("HA_BASE_URL", "http://ha.invalid")
os.environ.setdefault("HA_TOKEN", "synthetic-ha")
os.environ.setdefault("ADMIN_TOKEN", "synthetic-admin")
import server


class InvitationEmailTests(unittest.TestCase):
    def create(self, payload, configured=True, sent=True):
        page = {'id': 'page', 'title': 'Fixture', 'resources': [], 'access_grants': []}
        handler = object.__new__(server.Handler)
        handler._load_page = Mock(return_value=page)
        handler._send_json = Mock()
        handler._send_guest_invitation = Mock(return_value=sent)
        client = Mock(resource_id='resource')
        client.create_qurl.return_value = {
            'qurl_link': 'https://qurl.invalid/#fixture', 'qurl_id': 'q_fixture',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
        with (
            patch('server.SMTP_CONFIG_STORE') as smtp,
            patch('server.LAYERV_CLIENT', client),
            patch('server.PAGE_STORE') as store,
            patch('server.ACTIVITY_STORE'),
            patch('server.audit'),
            patch('server.VERIFICATION_RECIPIENTS') as recipients,
        ):
            smtp.configured.return_value = configured
            store.load.return_value = page
            handler._create_qurl('page', {'label': 'Fixture', 'lifetime': '1h', **payload})
        return handler, client, recipients

    def test_invitation_without_verification_sends_and_does_not_store_recipient(self):
        handler, client, recipients = self.create({'send_invitation': True, 'invitation_email': 'guest@example.test'})
        self.assertEqual(handler._send_json.call_args.args[0], 201)
        result = handler._send_json.call_args.args[1]
        self.assertFalse(result['grant']['verification_required'])
        self.assertTrue(result['email_delivery']['sent'])
        target = client.create_qurl.call_args.kwargs['target_path']
        self.assertRegex(target, r'^/g/page/grant_[A-Za-z0-9_-]{16}/\?bootstrap=[A-Za-z0-9_-]{43}$')
        self.assertEqual(handler._send_guest_invitation.call_args.args[2], 'guest@example.test')
        recipients.set.assert_not_called()
        self.assertNotIn('guest@example.test', str(result['grant']))

    def test_disabled_smtp_or_invalid_email_rejects_before_allocation(self):
        for address, configured in [('guest@example.test', False), ('invalid', True)]:
            handler, client, _ = self.create({'send_invitation': True, 'invitation_email': address}, configured=configured)
            self.assertEqual(handler._send_json.call_args.args[0], 400)
            client.create_qurl.assert_not_called()
            handler._send_guest_invitation.assert_not_called()

    def test_failed_delivery_keeps_link_and_reports_failure_without_reminting(self):
        handler, client, _ = self.create({'send_invitation': True, 'invitation_email': 'guest@example.test'}, sent=False)
        self.assertEqual(handler._send_json.call_args.args[0], 201)
        self.assertFalse(handler._send_json.call_args.args[1]['email_delivery']['sent'])
        client.create_qurl.assert_called_once()
