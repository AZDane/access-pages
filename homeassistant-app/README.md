# Access Pages for Home Assistant

Access Pages gives temporary guests access to a small, explicitly
approved part of Home Assistant without making Home Assistant or the
home network publicly reachable.

A guest can be given a purpose-built page containing only the devices,
information, and controls they need. They do not need a Home Assistant
account, password, or VPN access, and no inbound router port needs to be
opened.

## What it looks like

Access Pages lets you create purpose-specific pages for different guests,
then share only the controls that guest needs.

<p align="center">
  <img src="https://raw.githubusercontent.com/AZDane/access-pages/30ad2605ce7f4f0f4cc536fd1f4fb705041a991d/docs/images/admin.png"
       alt="Access Pages administration showing purpose-specific Home Assistant access pages"
       width="48%">
  <img src="https://raw.githubusercontent.com/AZDane/access-pages/30ad2605ce7f4f0f4cc536fd1f4fb705041a991d/docs/images/guest.png"
       alt="Access Pages guest view showing limited vacation-rental controls"
       width="32%">
</p>

## The challenge

Giving temporary guests access to Home Assistant creates a difficult set
of requirements:

-   Home Assistant and the home network should not become publicly
    reachable.
-   No inbound router ports should need to be opened.
-   Temporary visitors should not require Home Assistant accounts,
    passwords, or VPN access.
-   Guests should see only the devices and controls they need.
-   Access should expire automatically and remain revocable at any time.
-   Revoking one guest should not interrupt anyone else.

AI-assisted reconnaissance and exploitation are rapidly shrinking the
time between the discovery of a vulnerability and active attacks against
it. As attacks move toward machine speed, protecting a publicly
discoverable service becomes an increasingly difficult race.

**The safest endpoint is one an unauthorized attacker cannot discover or
reach. You cannot attack what you cannot see.**

## Local by design

This approach aligns with Home Assistant's vision of the Open Home,
which places privacy, choice, and sustainability at the heart of the
smart home.

Home Assistant states that devices should work locally and that cloud
connections should be additional and opt-in. Access Pages preserves that
local-first model: Home Assistant, its devices, and its administrative
interface remain inside the home.

The goal is not to move Home Assistant into the cloud. It is to let an
authorized guest reach a small, explicitly approved part of it without
exposing Home Assistant or the home network to the public internet.

## An invisible path to the home

Access Pages uses the **Network-Infrastructure Hiding Protocol (NHP)**,
a cryptography-powered Zero Trust protocol based on an
**authenticate-before-connect** model.

Traditional remote-access services expose an endpoint first and
authenticate the visitor after a connection has been made. NHP reverses
that order. The protected endpoint remains invisible and unreachable
until access has been cryptographically verified.

NHP is the open-source network-hiding technology developed by OpenNHP.
The [LayerV](https://layerv.ai) team are core builders of OpenNHP, and LayerV's founding team
co-authored the Cloud Security Alliance (CSA) NHP specification. LayerV
provides the external managed NHP/qURL connectivity service and developer
tools currently used by Access Pages. The protocol is also documented in
an IETF Internet-Draft.

For more about the relationship between LayerV, OpenNHP, the CSA
specification, and the IETF work, see
[LayerV's OpenNHP standards page](https://layerv.ai/standards/).

Access Pages is independently developed open-source software. It
determines and enforces the Home Assistant capabilities available
through that connection.

The Access Pages App establishes the protected NHP/FRP path. A guest
reaches that path through a valid LayerV qURL rather than through a
public Home Assistant or Gateway endpoint.

## Purpose-limited guest access

After the protected path is available, the Access Pages Gateway limits
what the guest can actually use.

Each guest receives an independent access grant. The grant determines
how long access lasts and whether the invitation is renewable or
single-use where supported.

The guest-facing page is narrowly limited to the capabilities selected
by the Home Assistant administrator.

Depending on the devices integrated with Home Assistant and the categories
enabled by the owner, a **Guest** page might allow someone to:

-   turn selected lights on or off;
-   check room temperature and adjust a thermostat;
-   turn a garden water feature on or off;
-   switch Jacuzzi jets on or off;
-   play or pause music on selected speakers; and
-   view periodic still images from a selected camera.

The owner can also choose additional supported actions, such as unlocking
a selected door, where appropriate for their installation.

It does not expose the regular Home Assistant dashboard, configuration,
history, or unrelated entities.

The Gateway enforces the approved capabilities on the server. The
browser cannot gain additional Home Assistant capabilities simply by
changing what it submits.

## Owner Responsibility

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

## More than a hidden URL

Access Pages does not rely on the secrecy of a public web address.

The NHP-controlled access path is kept out of reach until admission
succeeds, while the Gateway independently limits the capabilities
available after admission.

The guest-facing runtime is also isolated from privileged Gateway
functions. It is not given general Home Assistant administrative
authority or the credentials used to manage [LayerV](https://layerv.ai) access.

Additional controls include expiration, individual revocation, optional
email-code verification, optional proximity requirements for actions,
guest activity records, security events, administrator alerts, and
read-only camera stills.

## Getting started

Access Pages runs as a Home Assistant App. Remote guest access is
provided through [LayerV](https://layerv.ai).

1.  Install **Access Pages**.
2.  [Create or sign in to a LayerV account](https://layerv.ai/qurl/dashboard/keys/).
3.  Create a dedicated LayerV API key for this installation.
4.  Connect Access Pages to LayerV.
5.  Create an Access Page and choose its Home Assistant entities and
    permitted actions.
6.  Create a guest, choose the access lifetime and optional protections,
    and share the generated qURL.

See [DOCS.md](https://github.com/AZDane/access-pages-app/blob/main/access_pages/DOCS.md) for complete setup and operating instructions.

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
