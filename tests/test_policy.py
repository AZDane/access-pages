import json
import unittest
import tempfile
from pathlib import Path
from urllib.error import URLError
from unittest.mock import Mock, patch

from policy import PolicyPublisher, PolicyPublishError


class PolicyPublisherTests(unittest.TestCase):
    def test_ambiguous_publication_stays_closed_until_republished(self):
        with tempfile.TemporaryDirectory() as directory:
            publisher = PolicyPublisher("http://policy.invalid", "token", Path(directory))
            page = {"id": "guest", "title": "Guest", "resources": [], "access_grants": []}
            with patch("policy.urlopen", side_effect=URLError("lost response")), self.assertRaises(PolicyPublishError):
                publisher.publish(page)
            restarted = PolicyPublisher("http://policy.invalid", "token", Path(directory))
            self.assertTrue(restarted.pending("guest"))
            self.assertEqual(restarted.pending_pages(), ["guest"])
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            with patch("policy.urlopen", return_value=response):
                restarted.publish(page)
            self.assertFalse(restarted.pending("guest"))

    def test_publish_never_sends_guest_grants(self):
        response = Mock()
        response.read.return_value = b"{}"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        publisher = PolicyPublisher(
            "http://policy.invalid",
            "synthetic-token",
        )
        page = {
            "id": "guest",
            "title": "Guest",
            "resources": [],
            "access_grants": [{"id": "secret-bearing-grant"}],
        }

        with patch("policy.urlopen", return_value=response) as request:
            publisher.publish(page)

        sent = json.loads(request.call_args.args[0].data)
        self.assertEqual(sent["access_grants"], [])


if __name__ == "__main__":
    unittest.main()
