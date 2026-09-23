import json
import unittest
from email.message import Message
from io import BytesIO
from unittest.mock import patch

from ha import (
    BrokerHomeAssistantClient,
    HomeAssistantClient,
    HomeAssistantError,
    normalize_capabilities,
)


SERVICES = [
    {
        "domain": "cover",
        "services": {
            "open_cover": {"target": {}, "description": "Open"},
            "close_cover": {"target": {}, "description": "Close"},
            "stop_cover": {"target": {}, "description": "Stop"},
        },
    },
    {
        "domain": "light",
        "services": {
            "turn_on": {"target": {}, "description": "On"},
            "turn_off": {"target": {}, "description": "Off"},
        },
    },
]

STATES = [
    {
        "entity_id": "cover.patio",
        "state": "open",
        "attributes": {
            "friendly_name": "Patio Awning",
            "device_class": "awning",
        },
    },
    {
        "entity_id": "cover.garage",
        "state": "closed",
        "attributes": {
            "friendly_name": "Garage",
            "device_class": "garage",
        },
    },
    {
        "entity_id": "light.kitchen",
        "state": "on",
        "attributes": {"friendly_name": "Kitchen"},
    },
]


class ProximityBoundaryTests(unittest.TestCase):
    def test_saved_radius_accepts_just_inside_and_denies_just_outside(self):
        client = HomeAssistantClient("http://ha.invalid", "synthetic-token")
        with patch.object(client, "get_location", return_value={
            "latitude": 33.0, "longitude": -111.0,
        }):
            self.assertTrue(client.verify_proximity("page-a", {
                "latitude": 33.0044, "longitude": -111.0,
            }, 500))
            self.assertFalse(client.verify_proximity("page-a", {
                "latitude": 33.0046, "longitude": -111.0,
            }, 500))


class ImageResponse:
    status = 200

    def __init__(self, body=b"jpeg", content_type="image/jpeg", length=None):
        self._body = BytesIO(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        if length is not None:
            self.headers["Content-Length"] = str(length)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self._body.read(size)


class JsonResponse:
    status = 200

    def __init__(self, value):
        self._body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


class CameraImageTests(unittest.TestCase):
    def test_direct_client_fetches_supported_image_with_ha_token(self):
        client = HomeAssistantClient("http://ha", "secret")
        with patch("ha.urlopen", return_value=ImageResponse()) as urlopen:
            self.assertEqual(
                client.get_camera_image("camera.front door"),
                (b"jpeg", "image/jpeg"),
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://ha/api/camera_proxy/camera.front%20door")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")

    def test_direct_client_accepts_home_assistant_demo_jpg_alias(self):
        client = HomeAssistantClient("http://ha", "secret")
        with patch(
            "ha.urlopen",
            return_value=ImageResponse(content_type="image/jpg"),
        ):
            self.assertEqual(
                client.get_camera_image("camera.demo_camera"),
                (b"jpeg", "image/jpg"),
            )

    def test_direct_client_rejects_unsupported_or_oversized_images(self):
        client = HomeAssistantClient("http://ha", "secret")
        for response in (
            ImageResponse(content_type="text/html"),
            ImageResponse(length=5 * 1024 * 1024 + 1),
        ):
            with self.subTest(content_type=response.headers.get_content_type()):
                with (
                    patch("ha.urlopen", return_value=response),
                    self.assertRaises(HomeAssistantError),
                ):
                    client.get_camera_image("camera.front")

    def test_broker_client_sends_only_saved_policy_identifiers(self):
        client = BrokerHomeAssistantClient("http://broker", "broker-secret")
        with patch("ha.urlopen", return_value=ImageResponse()) as urlopen:
            client.get_camera_image(
                "camera.forged",
                page_id="guest",
                resource_id="driveway",
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            json.loads(request.data),
            {"page_id": "guest", "resource_id": "driveway"},
        )
        self.assertNotIn(b"camera.forged", request.data)
        self.assertEqual(request.get_header("X-broker-token"), "broker-secret")
        self.assertEqual(request.get_header("X-broker-role"), "guest")

    def test_admin_broker_client_marks_requests_with_admin_role(self):
        client = BrokerHomeAssistantClient(
            "http://broker", "admin-secret", broker_role="admin",
        )
        with patch("ha.urlopen", return_value=JsonResponse([])) as urlopen:
            client.get_states({"light.test"})

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("X-broker-token"), "admin-secret")
        self.assertEqual(request.get_header("X-broker-role"), "admin")


class EntityPolicyTests(unittest.TestCase):
    def test_home_location_is_sanitized_from_ha_config(self):
        client = HomeAssistantClient("http://ha", "token")
        with patch.object(
            client,
            "_request",
            return_value={
                "latitude": 40.7128,
                "longitude": -74.006,
                "name": "Private Home Name",
            },
        ):
            self.assertEqual(
                client.get_location(),
                {"latitude": 40.7128, "longitude": -74.006},
            )

    def test_invalid_home_location_fails_closed(self):
        client = HomeAssistantClient("http://ha", "token")
        with patch.object(
            client,
            "_request",
            return_value={"latitude": 91, "longitude": 0},
        ):
            with self.assertRaisesRegex(Exception, "registered location"):
                client.get_location()

    def test_unrestricted_policy_allows_supported_entities(self):
        client = HomeAssistantClient("http://ha", "token")
        self.assertTrue(client.entity_allowed("light.kitchen", "light"))

    def test_include_matches_domain_entity_or_device_class(self):
        client = HomeAssistantClient(
            "http://ha",
            "token",
            include_domains=frozenset({"light"}),
            include_device_classes=frozenset({"awning"}),
            include_entities=frozenset({"cover.garage"}),
        )
        self.assertTrue(client.entity_allowed("light.kitchen", "light"))
        self.assertTrue(
            client.entity_allowed("cover.patio", "cover", "awning")
        )
        self.assertTrue(
            client.entity_allowed("cover.garage", "cover", "garage")
        )
        self.assertFalse(
            client.entity_allowed("cover.bedroom", "cover", "blind")
        )

    def test_exclusion_wins_over_include(self):
        client = HomeAssistantClient(
            "http://ha",
            "token",
            include_domains=frozenset({"cover"}),
            exclude_entities=frozenset({"cover.garage"}),
        )
        self.assertFalse(
            client.entity_allowed("cover.garage", "cover", "garage")
        )

    def test_area_can_include_entity(self):
        client = HomeAssistantClient(
            "http://ha",
            "token",
            include_areas=frozenset({"kitchen"}),
        )
        self.assertTrue(
            client.entity_allowed(
                "light.counter",
                "light",
                "",
                "kitchen",
            )
        )
        self.assertFalse(
            client.entity_allowed(
                "light.bedroom",
                "light",
                "",
                "bedroom",
            )
        )

    def test_discovery_returns_type_metadata_and_applies_policy(self):
        client = HomeAssistantClient(
            "http://ha",
            "token",
            include_device_classes=frozenset({"awning"}),
        )
        with (
            patch.object(client, "get_states", return_value=STATES),
            patch.object(client, "get_services", return_value=SERVICES),
            patch.object(
                client,
                "get_entity_areas",
                return_value={
                    "cover.patio": {
                        "area_id": "patio",
                        "area_name": "Patio",
                    }
                },
            ),
        ):
            result = client.discover_entities()

        self.assertTrue(result["policy"]["restricted"])
        self.assertEqual(result["entity_count"], 1)
        self.assertEqual(result["entities"][0]["entity_id"], "cover.patio")
        self.assertEqual(result["entities"][0]["type"], "awning")
        self.assertEqual(result["entities"][0]["area_name"], "Patio")

    def test_unknown_domain_is_available_read_only(self):
        client = HomeAssistantClient("http://ha", "token")
        state = {
            "entity_id": "binary_sensor.front_door",
            "state": "off",
            "attributes": {
                "friendly_name": "Front Door",
                "device_class": "door",
            },
        }
        with (
            patch.object(client, "get_states", return_value=[state]),
            patch.object(client, "get_services", return_value=[]),
            patch.object(client, "get_entity_areas", return_value={}),
        ):
            result = client.discover_entities()

        self.assertEqual(result["entities"][0]["type"], "door")
        self.assertEqual(
            result["entities"][0]["actions"][0]["service"],
            "view",
        )

    def test_unknown_state_button_remains_available(self):
        client = HomeAssistantClient("http://ha", "token")
        state = {
            "entity_id": "button.restart",
            "state": "unknown",
            "attributes": {"friendly_name": "Restart"},
        }
        services = [{
            "domain": "button",
            "services": {
                "press": {"target": {}, "description": "Press"},
            },
        }]
        with (
            patch.object(client, "get_states", return_value=[state]),
            patch.object(client, "get_services", return_value=services),
            patch.object(client, "get_entity_areas", return_value={}),
        ):
            result = client.discover_entities()

        self.assertEqual(result["entities"][0]["entity_id"], "button.restart")
        self.assertEqual(
            result["entities"][0]["actions"][0]["service"],
            "press",
        )

    def test_discovery_cache_avoids_repeated_ha_calls(self):
        client = HomeAssistantClient("http://ha", "token")
        with (
            patch.object(
                client,
                "get_states",
                return_value=[STATES[0]],
            ) as get_states,
            patch.object(
                client,
                "get_services",
                return_value=SERVICES,
            ),
            patch.object(client, "get_entity_areas", return_value={}),
        ):
            client.discover_entities()
            client.discover_entities()
            client.discover_entities(force=True)

        self.assertEqual(get_states.call_count, 2)


class CapabilityNormalizationTests(unittest.TestCase):
    def test_fan_uses_home_assistant_speed_count(self):
        capabilities = normalize_capabilities(
            "fan",
            "on",
            {"percentage": 66, "percentage_step": 33.3333333333},
            {"set_percentage"},
        )

        self.assertEqual(
            capabilities["fan_percentage"]["values"],
            [33, 66, 100],
        )

    def test_fan_rejects_more_than_one_hundred_speed_levels(self):
        capabilities = normalize_capabilities(
            "fan",
            "on",
            {"percentage": 50, "percentage_step": 0.5},
            {"set_percentage"},
        )

        self.assertNotIn("fan_percentage", capabilities)

    def test_fractional_number_metadata_is_preserved(self):
        capabilities = normalize_capabilities(
            "number",
            "0.5",
            {"min": 0, "max": 1, "step": 0.25},
            {"set_value"},
        )

        self.assertEqual(
            capabilities["number"],
            {
                "min": 0.0,
                "max": 1.0,
                "step": 0.25,
                "value": 0.5,
                "values": [0, 0.25, 0.5, 0.75, 1],
            },
        )

    def test_invalid_metadata_falls_back_without_a_control(self):
        capabilities = normalize_capabilities(
            "number",
            "5",
            {"min": 0, "max": 10, "step": 0},
            {"set_value"},
        )

        self.assertNotIn("number", capabilities)

    def test_climate_choices_come_from_current_attributes(self):
        capabilities = normalize_capabilities(
            "climate",
            "cool",
            {
                "temperature": 72.5,
                "min_temp": 60,
                "max_temp": 85,
                "target_temp_step": 0.5,
                "temperature_unit": "°F",
                "hvac_modes": ["off", "cool"],
            },
            {"set_temperature", "set_hvac_mode"},
        )

        self.assertEqual(
            capabilities["climate"]["hvac_modes"],
            ["off", "cool"],
        )
        self.assertEqual(
            capabilities["climate"]["temperature"]["step"],
            0.5,
        )

    def test_climate_uses_whole_degree_step_when_ha_omits_it(self):
        capabilities = normalize_capabilities(
            "climate",
            "cool",
            {
                "temperature": 76,
                "min_temp": 50,
                "max_temp": 99,
                "target_temp_step": None,
            },
            {"set_temperature"},
        )

        self.assertEqual(
            capabilities["climate"]["temperature"]["step"],
            1.0,
        )


if __name__ == "__main__":
    unittest.main()
