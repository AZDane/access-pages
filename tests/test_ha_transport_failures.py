import unittest
from http.client import IncompleteRead, RemoteDisconnected
from unittest.mock import Mock, patch

import guest_request as lifetime
from ha import BrokerHomeAssistantClient, HomeAssistantClient, HomeAssistantError


class TransportFailureTests(unittest.TestCase):
    def test_header_and_body_failures_are_normalized_without_replay(self):
        for client_type in (HomeAssistantClient, BrokerHomeAssistantClient):
            client = client_type("http://ha.invalid", "synthetic")
            for camera in (False, True):
                for stage in ("headers", "body"):
                    for error in (TimeoutError(), ConnectionResetError(), RemoteDisconnected(), IncompleteRead(b"part")):
                        with self.subTest(client=client_type, camera=camera, stage=stage, error=type(error)):
                            response = Mock()
                            response.__enter__ = Mock(return_value=response)
                            response.__exit__ = Mock(return_value=False)
                            response.headers.get_content_type.return_value = "image/jpeg"
                            response.headers.get.return_value = None
                            response.read.side_effect = error
                            with patch("ha.urlopen", return_value=response,
                                       side_effect=error if stage == "headers" else None) as request:
                                with self.assertRaises(HomeAssistantError):
                                    if camera:
                                        client.get_camera_image("camera.one", page_id="page", resource_id="camera")
                                    else:
                                        client._request("POST", "/api/services/light/turn_on", {})
                            self.assertEqual(request.call_count, 1)

    def test_expired_action_still_stops_before_ha_dispatch(self):
        client = HomeAssistantClient("http://ha.invalid", "synthetic")
        timing = lifetime.RequestTiming("a" * 32, 1, "action", action_deadline=True)
        token = lifetime.CURRENT.set(timing)
        try:
            with patch("ha.urlopen") as request, self.assertRaises(lifetime.ActionDeadlineExceeded):
                client.call_service("light", "turn_on", "light.one")
            request.assert_not_called()
        finally:
            lifetime.CURRENT.reset(token)
