# Access Pages for Home Assistant

Access Pages gives temporary guests access to a small, explicitly approved part
of Home Assistant without making Home Assistant or the home network publicly
reachable. Guests receive a purpose-built page with only the devices,
information, and controls they need, without a Home Assistant account, password,
or VPN access. No inbound router port needs to be opened.

Home Assistant, its devices, and its administrative interface remain inside the
home, preserving its local-first model.

## The protected path and guest capabilities

Remote guest connectivity uses [LayerV](https://layerv.ai) and the
**Network-Infrastructure Hiding Protocol (NHP)**. NHP follows an
**authenticate-before-connect** model: the protected endpoint remains invisible
and unreachable until access has been cryptographically verified. A valid qURL
opens the protected NHP/FRP path.

NHP is the open-source network-hiding technology developed by OpenNHP. The
LayerV team are core builders of OpenNHP, and its founding team co-authored the
Cloud Security Alliance (CSA) NHP specification. LayerV provides the external
managed NHP/qURL connectivity service and developer tools currently used by
Access Pages. The protocol is also documented in an IETF Internet-Draft. See
[LayerV's OpenNHP standards page](https://layerv.ai/standards/) for this history.

Access Pages is independently developed open-source software. Its Gateway
independently determines and enforces the Home Assistant capabilities available
after admission. The browser cannot obtain more capabilities by changing its
requests. Guest pages do not expose the regular Home Assistant dashboard,
configuration, history, or unrelated entities.

Depending on the integrated devices and categories enabled by the owner, a
page can offer selected lights, temperature readings and thermostat controls,
music controls, or read-only camera stills. Additional supported actions, such
as unlocking a selected door, require the owner's deliberate selection.

Each guest has an independent grant with expiration and individual revocation.
Optional email-code verification, proximity requirements for actions, guest
activity records, security events, and administrator alerts provide additional
controls. Proximity is an accidental-action safeguard, not proof of physical
presence.

## What it looks like

The owner creates purpose-specific pages and selects the entities and actions
each guest can use.

![Access Pages administration showing purpose-specific Home Assistant access pages](https://raw.githubusercontent.com/AZDane/access-pages/30ad2605ce7f4f0f4cc536fd1f4fb705041a991d/docs/images/admin.png)

The guest sees only the controls approved for that page.

![Access Pages guest view showing limited vacation-rental controls](https://raw.githubusercontent.com/AZDane/access-pages/30ad2605ce7f4f0f4cc536fd1f4fb705041a991d/docs/images/guest.png)

## Owner responsibility

Home Assistant owners control what guests can access and are responsible
for deciding what is appropriate and safe for their installation. Home
Assistant is highly customizable: entities and actions can control
physical equipment, locks, doors, gates, appliances, security equipment,
or other systems where unintended operation has real-world consequences.
Access Pages cannot determine whether an entity or action is safe for
guest use. Owners must review what each entity actually controls, the
actions they expose, and whether the available protections are appropriate.

The App defaults to `include_domains: "light"`, enabling only the Light
category. The owner must explicitly enable additional supported categories
in this setting before selecting them for guest pages. This is a
conservative configuration default, not a guarantee that any entity is safe.
Entity categories are configuration aids, not safety classifications;
even a `light` entity is not inherently safe.

Treat qURLs as access credentials. Once a qURL is provided for sharing,
Access Pages cannot control how an owner or guest stores, transmits,
forwards, screenshots, publishes, or otherwise distributes it. Someone
who obtains a valid qURL may be able to reach the associated guest access,
subject to any additional protections configured by the owner.

The owner is responsible for deciding who receives a qURL, how it is
distributed, how long access remains valid, and whether protections such
as email verification, proximity requirements for actions, expiration,
or revocation are appropriate.

## Getting started

1. Install and start **Access Pages**, then open its Web UI.
2. [Create or sign in to a LayerV account](https://layerv.ai/qurl/dashboard/keys/)
   and create a dedicated API key for this installation.
3. Complete **Connect to LayerV**.
4. Create an Access Page and select its entities and permitted actions.
5. Create a guest, choose the lifetime and optional protections, then share the
   generated qURL.

See [installation and operating documentation](https://github.com/AZDane/access-pages-app/blob/main/access_pages/DOCS.md)
or Home Assistant's **Documentation** tab for setup, configuration, and recovery.

## License and branding

The Access Pages Gateway source code is licensed under the MIT License.

The MIT License also covers the Gateway documentation. The App icon and logo
are Access Pages artwork. The license does not grant permission to use the
[LayerV](https://layerv.ai) name, trademarks, wordmarks, logos, or other brand assets except as
necessary to identify an unmodified copy of this software.

Files specifically covered by this exclusion include:

- `static/layerv.png`
- `static/layerv-wordmark.png`

Do not use LayerV branding to imply sponsorship, endorsement, affiliation, or
official status without prior written permission from LayerV.

See [BRAND_ASSETS.md](https://github.com/AZDane/access-pages/blob/main/BRAND_ASSETS.md)
for the full notice. For brand-use questions, visit [LayerV](https://layerv.ai).
