"""Disposable real-Core probe. Run inside an official HA image; see compatibility docs.

Uses a synthetic cover entity in real HA, real REST/template/service calls, and
Access Pages' guest broker socket. No physical device, Supervisor or tunnel.
"""
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from types import MappingProxyType
from unittest.mock import patch

from homeassistant import bootstrap, loader
from homeassistant.auth.const import GROUP_ID_ADMIN
from homeassistant.components import cover
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import __version__
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry, device_registry, entity_registry
from homeassistant.setup import async_setup_component

from ha import HomeAssistantClient


class ProbeCover(cover.CoverEntity):
    _attr_name = "Tilt"
    _attr_unique_id = "access-pages-compatibility-cover"
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_is_closed = False
    _attr_current_cover_tilt_position = 40
    _attr_supported_features = (cover.CoverEntityFeature.OPEN_TILT
                                | cover.CoverEntityFeature.CLOSE_TILT
                                | cover.CoverEntityFeature.STOP_TILT)

    async def async_open_cover_tilt(self, **kwargs):
        self._attr_current_cover_tilt_position = 100
        self.async_write_ha_state()

    async def async_close_cover_tilt(self, **kwargs):
        self._attr_current_cover_tilt_position = 0
        self.async_write_ha_state()

    async def async_stop_cover_tilt(self, **kwargs):
        self.async_write_ha_state()


def broker_probe(client, entity_id, change_capability):
    # Reuse the real socket/session harness, replacing its mocked HA transport
    # with the candidate client's real REST connection to this disposable Core.
    from test_broker_guest_sessions import BrokerGuestSessionTests
    import ha_broker
    fixture = BrokerGuestSessionTests()
    fixture.setUp()
    try:
        with patch.object(ha_broker, "HA_CLIENT", client):
            page = fixture.policy.load("page-a")
            page["resources"] = [{
                "id": "blind", "entity_id": entity_id, "domain": "cover",
                "name": "Preserved owner label", "actions": [{
                    "id": "close_cover_tilt", "service": "close_cover_tilt", "name": "Close tilt",
                }],
            }]
            fixture.policy.replace("page-a", page)
            session = fixture.exchange(fixture.cap_a, "page-a", fixture.grant_a,
                                       fixture.secret_a)[1]["session"]
            status, view = fixture.request("/guest/v1/page-view", fixture.cap_a, "page-a", {
                "grant_id": fixture.grant_a, "session": session,
            })
            assert status == 200, (status, view)
            assert view["resources"][0]["name"] == "Preserved owner label"
            assert fixture.action(session, resource_id="blind", action_id="open_cover_tilt")[0] == 404
            assert fixture.action(session, resource_id="blind", action_id="close_cover_tilt")[0] == 200
            assert client.get_states({entity_id})[0]["attributes"]["current_tilt_position"] == 0
            change_capability()
            assert fixture.action(session, resource_id="blind", action_id="close_cover_tilt")[0] == 409
            status, view = fixture.request("/guest/v1/page-view", fixture.cap_a, "page-a", {
                "grant_id": fixture.grant_a, "session": session,
            })
            assert status == 200 and view["resources"][0]["actions"] == []
            assert fixture.policy.load("page-a")["resources"][0]["actions"][0]["service"] == "close_cover_tilt"
            fixture.pages.remove_access_grant("page-a", fixture.grant_a)
            assert fixture.action(session, resource_id="blind", action_id="close_cover_tilt")[0] == 401
    finally:
        fixture.tearDown()


async def main():
    with tempfile.TemporaryDirectory(prefix="access-pages-ha-compat-") as directory:
        os.environ["HA_BROKER_RUNTIME_DIR"] = directory
        os.environ["HA_BROKER_GUEST_SESSION_DB"] = str(Path(directory) / "sessions.sqlite3")
        hass = HomeAssistant(directory)
        loader.async_setup(hass)
        config = {"homeassistant": {"name": "Compatibility probe", "country": "US",
                                  "latitude": 33, "longitude": -111, "time_zone": "UTC"},
                  "http": {"server_host": "127.0.0.1", "server_port": 18123}, "api": {}}
        try:
            assert await bootstrap.async_from_config_dict(config, hass)
            assert await async_setup_component(hass, "cover", {})
            probe = ProbeCover()
            await hass.data[cover.DATA_COMPONENT].async_add_entities([probe])
            await hass.async_start()
            user = await hass.auth.async_create_system_user("Compatibility probe", group_ids=[GROUP_ID_ADMIN])
            refresh = await hass.auth.async_create_refresh_token(user)
            token = hass.auth.async_create_access_token(refresh)
            client = HomeAssistantClient("http://127.0.0.1:18123", token)

            areas = area_registry.async_get(hass)
            bedroom = areas.async_create("Bedroom")
            office = areas.async_create("Office")
            entry = ConfigEntry(version=1, minor_version=1, domain="cover", title="Probe",
                                data={}, options={}, source="user", unique_id="compatibility",
                                discovery_keys=MappingProxyType({}), subentries_data=None)
            await hass.config_entries.async_add(entry)
            devices = device_registry.async_get(hass)
            parent = devices.async_get_or_create(config_entry_id=entry.entry_id,
                                                identifiers={("cover", "probe")}, name="Blind")
            devices.async_update_device(parent.id, area_id=bedroom.id)
            child_supported = hasattr(devices, "async_get_or_create_child")
            device = parent
            if child_supported:
                device = devices.async_get_or_create_child(
                    config_entry_id=entry.entry_id, identifiers={("cover", "channel")},
                    parent_device_id=parent.id, name="Channel 1",
                )
            entities = entity_registry.async_get(hass)
            entities.async_update_entity(probe.entity_id, device_id=device.id)
            await hass.async_block_till_done()

            async def discover():
                return await asyncio.to_thread(client.discover_entities, force=True)

            result = await discover()
            found = next(item for item in result["entities"] if item["entity_id"] == probe.entity_id)
            assert found["area_id"] == bedroom.id, found
            assert {a["service"] for a in found["actions"]} == {
                "open_cover_tilt", "close_cover_tilt", "stop_cover_tilt"}, found
            names = await asyncio.to_thread(client.get_entity_names)
            if names:
                assert found["name"] == ("Channel 1 Tilt" if child_supported else "Blind Tilt"), found
            else:
                assert found["name"] == hass.states.get(probe.entity_id).attributes["friendly_name"]

            if child_supported:
                devices.async_update_child_device(device.id, area_id=office.id)
                result = await asyncio.to_thread(client.get_entity_areas)
                assert result[probe.entity_id]["area_id"] == office.id, result
            entities.async_update_entity(probe.entity_id, area_id=bedroom.id)
            result = await asyncio.to_thread(client.get_entity_areas)
            assert result[probe.entity_id]["area_id"] == bedroom.id, result
            filtered = HomeAssistantClient(client.base_url, token, exclude_areas={bedroom.id})
            result = await asyncio.to_thread(filtered.discover_entities)
            assert probe.entity_id not in {item["entity_id"] for item in result["entities"]}
            async def remove_tilt_capability():
                probe._attr_supported_features = cover.CoverEntityFeature.OPEN
                probe.async_write_ha_state()
                await hass.async_block_till_done()

            def change_capability():
                asyncio.run_coroutine_threadsafe(remove_tilt_capability(), hass.loop).result(timeout=10)

            await asyncio.to_thread(broker_probe, client, probe.entity_id, change_capability)
            print(json.dumps({"version": __version__, "passed": True,
                              "naming_helpers": bool(names), "child_devices": child_supported,
                              "checks": ["REST discovery", "names", "area overrides/exclusions",
                                         "tilt service", "guest broker socket", "saved labels",
                                         "unapproved action denied", "lost capability denied",
                                         "permissions unchanged", "revoked session denied"],
                              "limitations": ["synthetic cover; no physical device",
                                              "no Supervisor ingress or external tunnel"],
                              "utc": datetime.now(timezone.utc).isoformat()}))
        finally:
            await hass.async_stop()


if __name__ == "__main__":
    asyncio.run(main())
