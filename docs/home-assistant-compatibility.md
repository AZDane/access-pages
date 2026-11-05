# Home Assistant compatibility

## Supported versions

The oldest supported and runtime-tested Home Assistant Core version is
**2026.10.4**. The compatibility matrix currently tests **2026.10.4** and
**2026.11.0** in pinned official containers. This baseline also matches the
repository's earlier [HAOS acceptance](runtime-security-review.md#isolated-haos-acceptance).
Older versions may continue to work through feature detection and naming
fallbacks, but are outside the tested support range. No version-based startup
block or automatic page migration is introduced.

For each future monthly release, add its pinned official image to the matrix,
review its breaking changes and entity feature definitions, and run the checks
below before claiming support. Passing this matrix does not promise compatibility
with untested future releases or every third-party integration.

## Behavior and compatibility boundaries

- Default discovery labels combine HA's `device_name()` and `entity_name()`.
  HA's resolved area remains separately displayed in the picker. An unnamed main
  entity uses its device name. Missing helpers, failed naming requests, or absent
  names fall back to `friendly_name`, then entity ID. Naming requests are separate
  from area-policy requests. Existing saved labels, resource IDs, and explicit
  owner labels are preserved; names never identify or authorize a resource.
- Cover, fan, media-player, vacuum, and temperature actions require the entity's
  corresponding `supported_features` bit, in addition to a registered service
  during discovery. HVAC mode choices come from `hvac_modes`. Missing, malformed,
  zero, or unrelated feature bits do not enable an action. Basic actions without
  HA feature flags retain their domain contract. Parameter constraints remain
  checked against live state where applicable.
- Tilt-only covers offer Open tilt, Close tilt, and Stop tilt. Tilt position and
  movement are distinct from lift position and movement. New controls require
  owner selection; an existing Open grant is never converted to Open tilt.
- Every action fetches current entity state before dispatch, including basic
  switch/light actions. Missing/unavailable entities and unsupported actions
  fail closed. Guest grant, expiry, policy, and request-deadline rechecks still
  occur after potentially blocking preparation and before dispatch. HA remains
  the final authority if an entity changes after that check. No automatic retry
  or replacement entity is introduced.
- Guest page views expose only currently supported actions from the saved
  allowlist. Stored permissions are not rewritten when a device is unavailable
  or loses a capability; they remain available if that same entity recovers.
- The owner editor refreshes discovery on opening a page. Missing, unavailable,
  or excluded saved entities remain visible with their saved names. Unsupported
  saved actions remain visible and can be unchecked. Saving is blocked until the
  owner resolves these references. The owner can restore an entity in HA, remove
  a resource, or deliberately select a replacement. No name-based substitution
  or silent dropping of saved resources/actions occurs.
- Area lookup asks HA for `area_id(entity_id)` for every state, including an
  explicit empty area for unassigned entities. HA handles entity overrides,
  device areas, and child-device inheritance. Duplicate, malformed, failed, or
  incomplete metadata blocks discovery whenever inclusion or exclusion areas
  are configured, including through the broker. Without an area policy,
  discovery can continue without area metadata. Exclusions still take priority
  over explicit entity inclusion.

## Validation performed

On November 4, 2026 (America/Phoenix), the candidate passed the real-Core probe
on both official versions. The probe starts real HA inside a disposable container
with networking disabled and a read-only source mount. It creates a synthetic
cover in HA's real entity component and real registry records. It exercises:

- REST state/service discovery and template rendering, including naming helpers;
- inherited child-device areas, a child-area override, an entity-area override,
  and excluded-area discovery;
- the real guest broker Unix socket, persisted page policy, and guest sessions;
- a permitted tilt service that changes HA state;
- preservation of the saved guest label and explicit action list;
- rejection of an unapproved action and a previously approved action after its
  live capability disappears;
- rejection after the guest grant is revoked.

This is real HA API validation with a synthetic device, not a physical-device
or external-tunnel test. Unit tests separately simulate missing naming helpers,
legacy friendly-name responses, missing/malformed/partial area metadata,
per-entity feature flags, missing entities, and unchanged permissions. Browser
runtime tests exercise repair messages, blocked saves, explicit replacement
selection, label preservation, and tilt controls independent of lift state.
The existing ingress/authentication and revocation regressions remain required.

**Not verified by this change's real-Core probe:** installation/upgrading through
Supervisor, authenticated Supervisor ingress, HAOS restart/restore, physical
Matter or Tuya hardware, or a remote LayerV/qURL guest journey. The older HAOS
acceptance report is historical evidence, not a live test of this candidate.
Before release, smoke-test the candidate on disposable HAOS through ingress,
create/edit a page, exercise an authorized guest control, revoke its link, and
confirm previously saved labels and permissions survived the upgrade.

Run the same matrix as CI from the source root:

```sh
docker run --rm --network none --entrypoint python \
  --env PYTHONPATH=/workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "$PWD:/workspace:ro" \
  ghcr.io/home-assistant/home-assistant:2026.10.4@sha256:23f4dfbb69ce76315dbc4de7915504f1c2dcecd7ca2648113a493a385972e133 \
  /workspace/tests/live_ha_compatibility.py

docker run --rm --network none --entrypoint python \
  --env PYTHONPATH=/workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "$PWD:/workspace:ro" \
  ghcr.io/home-assistant/home-assistant:2026.11.0@sha256:c6c1ca9931036bf3a2c4cc088d8db25dfea3b33935a5ecc83c40349462e2f69e \
  /workspace/tests/live_ha_compatibility.py
```

The probe prints a JSON result without credentials. It adds no dependencies to
Access Pages' runtime. The containers remove their disposable configuration on
exit and do not mount any existing HA configuration.

## Official references reviewed

- [2026.11 breaking changes](https://www.home-assistant.io/blog/2026/11/04/release-202611/#backward-incompatible-changes)
- [Entity naming helper](https://www.home-assistant.io/template-functions/entity_name/)
  and [device naming helper](https://www.home-assistant.io/template-functions/device_name/)
- [Area ID helper](https://www.home-assistant.io/template-functions/area_id/)
  and [HA's area resolution implementation](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/helpers/template/helpers.py)
- Feature definitions for [covers](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/components/cover/const.py),
  [fans](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/components/fan/const.py),
  [media players](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/components/media_player/const.py),
  [vacuums](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/components/vacuum/const.py),
  and [climate entities](https://github.com/home-assistant/core/blob/2026.11.0/homeassistant/components/climate/const.py)
