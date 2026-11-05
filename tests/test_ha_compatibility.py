"""Compatibility contracts; fixtures are simulated HA API responses, not live HA."""
import unittest
from copy import deepcopy
from unittest.mock import patch

from ha import (
    ACTION_FEATURES, CURATED_ACTIONS, BrokerHomeAssistantClient,
    HomeAssistantClient, HomeAssistantError, action_supported,
    entity_display_name, public_resource_state, validate_action_state,
)


def cover(flags=112, state="open"):
    return {"entity_id": "cover.blind", "state": state,
            "attributes": {"supported_features": flags, "current_tilt_position": 40,
                           "friendly_name": "Old blind label"}}


class CompatibilityTests(unittest.TestCase):
    def test_names_and_fallbacks_do_not_change_saved_labels(self):
        state = cover()
        for metadata, expected in [
            ({"device_name": "Bedroom blind", "entity_name": "Tilt"}, "Bedroom blind Tilt"),
            ({"device_name": "Bedroom blind", "entity_name": ""}, "Bedroom blind"),
            ({"device_name": None, "entity_name": "Blind"}, "Blind"),
            ({}, "Old blind label"),
            ({"device_name": [], "entity_name": 42}, "Old blind label"),
        ]:
            with self.subTest(metadata=metadata):
                self.assertEqual(entity_display_name(state, metadata), expected)
        self.assertEqual(entity_display_name({"entity_id": "cover.blind"}, {}), "cover.blind")
        resource = {"id": "blind", "entity_id": "cover.blind", "domain": "cover",
                    "name": "Owner label", "actions": [
                        {"id": "open_cover", "service": "open_cover", "name": "Open"}]}
        before = deepcopy(resource)
        view = public_resource_state(resource, state)
        self.assertEqual(view["name"], "Owner label")
        self.assertEqual(view["actions"], [])
        self.assertEqual(resource, before)  # no migration and no automatic tilt grant

    def test_each_feature_gated_action_requires_its_own_flag(self):
        for domain, actions in ACTION_FEATURES.items():
            for service, flag in actions.items():
                for flags, supported in [(flag, True), (0, False), (None, False),
                                         (str(flag), False), (-1, False), (True, False)]:
                    with self.subTest(domain=domain, service=service, flags=flags):
                        state = {"state": "on", "attributes": {"supported_features": flags}}
                        self.assertEqual(action_supported(domain, service, state), supported)

    def test_missing_unavailable_and_changed_capabilities_fail_before_dispatch(self):
        for states in [[], [cover(0)], [cover(112, "unavailable")], [cover(112, "unknown")]]:
            with self.subTest(states=states), self.assertRaises(HomeAssistantError):
                validate_action_state("cover", "open_cover_tilt", "cover.blind", states)
        self.assertTrue(action_supported("button", "press", {"state": "unknown"}))
        self.assertFalse(action_supported("switch", "turn_on", {"state": "unknown"}))

    def discovery(self, client, states, areas, names=None, area_error=None, name_error=None):
        with (
            patch.object(client, "get_states", return_value=states),
            patch.object(client, "get_services", return_value=[{
                "domain": "cover", "services": {name: {"target": {}}
                                                  for name in CURATED_ACTIONS["cover"]}}]),
            patch.object(client, "get_entity_areas", return_value=areas, side_effect=area_error),
            patch.object(client, "get_entity_names", return_value=names or {}, side_effect=name_error),
        ):
            return client.discover_entities(force=True)

    def test_tilt_only_and_lift_discovery(self):
        client = HomeAssistantClient("http://ha.invalid", "test")
        for flags, expected in [(112, {"open_cover_tilt", "close_cover_tilt", "stop_cover_tilt"}),
                                (11, {"open_cover", "close_cover", "stop_cover"}),
                                (0, {"view"})]:
            result = self.discovery(client, [cover(flags)], {})
            self.assertEqual({a["service"] for a in result["entities"][0]["actions"]}, expected)

    def test_area_failure_or_partial_response_cannot_bypass_any_area_filter(self):
        for policy in [{"include_areas": {"bedroom"}}, {"exclude_areas": {"bedroom"}},
                       {"exclude_areas": {"bedroom"}, "include_entities": {"cover.blind"}}]:
            for areas, error in [({}, None), ({}, HomeAssistantError("offline"))]:
                with self.subTest(policy=policy, error=error), self.assertRaises(HomeAssistantError):
                    self.discovery(HomeAssistantClient("http://ha.invalid", "test", **policy),
                                   [cover()], areas, area_error=error)
        client = BrokerHomeAssistantClient("http://broker.invalid", "test", exclude_areas={"bedroom"})
        for available in [False, None]:
            with patch.object(client, "_request", return_value={
                "entities": [], "area_metadata_available": available,
            }), self.assertRaises(HomeAssistantError):
                client.discover_entities()

    def test_resolved_child_area_and_overrides_follow_ha_result(self):
        client = HomeAssistantClient("http://ha.invalid", "test", exclude_areas={"bedroom"})
        for resolved_area, allowed in [("bedroom", False), ("office", True), ("", True)]:
            # HA's area_id helper owns inheritance, including explicit overrides.
            result = self.discovery(client, [cover()], {"cover.blind": {
                "area_id": resolved_area, "area_name": resolved_area,
            }}, name_error=HomeAssistantError("optional naming unavailable"))
            self.assertEqual(bool(result["entities"]), allowed)
            self.assertTrue(result["area_metadata_available"])

    def test_area_template_and_response_validation(self):
        client = HomeAssistantClient("http://ha.invalid", "test")
        row = {"entity_id": "cover.blind", "area_id": "", "area_name": ""}
        with patch.object(client, "_request", return_value=[row]) as request:
            self.assertEqual(client.get_entity_areas()["cover.blind"]["area_id"], "")
            template = request.call_args.args[2]["template"]
            self.assertIn("area_id(state.entity_id)", template)
            self.assertNotIn("area_entities", template)
        for malformed in [{}, [row, row], [{"entity_id": "cover.blind"}], [None]]:
            with patch.object(client, "_request", return_value=malformed), self.assertRaises(HomeAssistantError):
                client.get_entity_areas()

    def test_optional_naming_failure_keeps_discovery_and_identity(self):
        client = HomeAssistantClient("http://ha.invalid", "test")
        names = {"cover.blind": {"device_name": "New device", "entity_name": "Tilt"}}
        result = self.discovery(client, [cover()], {}, names=names)
        self.assertEqual(result["entities"][0]["name"], "New device Tilt")
        self.assertEqual(result["entities"][0]["entity_id"], "cover.blind")
        result = self.discovery(client, [cover()], {}, name_error=HomeAssistantError("unsupported"))
        self.assertEqual(result["entities"][0]["name"], "Old blind label")


if __name__ == "__main__":
    unittest.main()
