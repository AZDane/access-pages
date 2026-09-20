# Access Pages for Home Assistant

## About Access Pages

Access Pages lets a Home Assistant administrator provide temporary
guests with remote access to a small, explicitly approved part of Home
Assistant while keeping Home Assistant and the home network from
becoming publicly reachable.

The guest receives a purpose-built page containing only the devices,
information, and controls selected by the administrator. Guests do not
need Home Assistant accounts, passwords, or VPN access.

The remote path is provided through LayerV using the
**Network-Infrastructure Hiding Protocol (NHP)** and qURL technology.
NHP follows an **authenticate-before-connect** model: instead of
exposing the protected endpoint first and authenticating after a
connection arrives, the protected path remains invisible and unreachable
until access has been cryptographically verified.

After admission, the Access Pages Gateway provides the purpose-limited
page and enforces the capabilities assigned to the guest.

## How the protected path works

Access Pages preserves Home Assistant's local-first design. Home
Assistant, its devices, and its administrative interface remain inside
the home.

The App runs the Access Pages Gateway and one shared qURL runtime with its
embedded LayerV Connector.
Remote guests do not reach the Gateway through a separately exposed
public Home Assistant or Access Pages endpoint. Their remote path is
established through LayerV/NHP.

A valid qURL packages the information required for the LayerV access
process. Once the NHP admission succeeds, the guest reaches a Go page
endpoint, which forwards guest requests to the isolated Guest Service.
The service uses the restricted Home Assistant Broker for Home Assistant
state and actions.

The Guest Service and Home Assistant Broker then apply the individual guest
grant and the Access Page policy. The page contains only the approved entities,
information, and actions.

The Gateway does not rely on the browser to enforce that policy. Home
Assistant actions are checked server-side before being performed.

## Gateway isolation

The Gateway is designed so that the guest-facing runtime is narrowly
limited.

The public guest-facing process is not given general Home Assistant
administrative authority and does not receive the privileged credentials
used to administer Home Assistant or manage LayerV lifecycle operations.

Page endpoints receive only the capability required for their page.
Privileged Home Assistant and LayerV operations are handled through
restricted internal interfaces rather than exposing those credentials to
the guest-facing process.

Guest page endpoints, the Home Assistant Ingress administration gateway,
and the Home Assistant broker run under distinct Linux identities. Unix
permissions and an enforced AppArmor policy provide additional isolation
inside the App.

This means that the component reached by an admitted guest is not itself
given unrestricted access to Home Assistant.

## Installation

1.  Add `https://github.com/AZDane/access-pages-app` to the Home Assistant App Store.
2.  Install **Access Pages**.
3.  Start the App.
4.  Open its Web UI.
5.  Complete **Connect to LayerV**.

Home Assistant provides local API access to the App automatically. You
do not need to create a long-lived Home Assistant token for guests or
open an inbound router port.

## Set up LayerV

Access Pages uses LayerV to provide the protected NHP/qURL path for
remote guest access.

NHP is the open-source network-hiding technology developed by OpenNHP.
The LayerV team are core builders of OpenNHP, and LayerV's founding team
co-authored the Cloud Security Alliance (CSA) NHP specification. LayerV
is the enterprise implementation of that foundation, providing the
managed access service and developer tools used by Access Pages. The
protocol is also documented in an IETF Internet-Draft.

For more about the relationship between LayerV, OpenNHP, the CSA
specification, and the IETF work, see
[LayerV's OpenNHP standards page](https://layerv.ai/standards/).

[Create or sign in to your LayerV account](https://layerv.ai/qurl/dashboard/keys/), then create a
**dedicated API key for this Access Pages installation** with these permissions:

-   **Read qURLs** — enable.
-   **Create, update & delete qURLs** — enable.
-   **Mint qURL Connector enrollment tokens** — enable.
-   **Redeem tokens and share by CRID (headless access)** — leave disabled;
    Access Pages does not require it.

Return to Access Pages and enter the key on **Connect to LayerV**.

Access Pages stores this API key in protected App data and retains it for
ongoing qURL read/write operations. When the first Connector enrollment is
required, Access Pages uses the key to mint a one-time Connector enrollment
token. That token, not the persistent API key, is supplied to qURL login.
qURL persists the resulting Agent/device identity. Subsequent guests and
normal restarts reuse that identity. If an established identity is lost or
rejected, Access Pages does not automatically re-enroll; explicit
administrator recovery through **Reset LayerV connection** is required.

## Create an Access Page

Open the Access Pages Web UI and create a page for a specific purpose.

Examples include:

-   Cat Sitter
-   House Guest
-   Pool Service
-   Cleaner

Select the Home Assistant entities that should appear. For controllable
entities, approve the actions the guest may perform.

The guest page does not provide the regular Home Assistant dashboard,
configuration, history, or unrelated entities.

Creating or saving a page does not itself create guest access. Access is
created when a guest invitation is issued.

## Create a guest

Open the page's **Guests** section and create a guest.

Choose:

-   the guest name;
-   how long access should last;
-   the available invitation type;
-   optional guest verification;
-   optional activity alerts.

Page security options such as proximity requirements are configured in the
page editor, rather than when creating a guest.

Access Pages creates the guest grant and the LayerV qURL required to
reach it.

Each guest receives an independent grant, so one guest can be revoked
without intentionally interrupting another.

With the default `resource_isolation: guest` setting, each guest grant
uses its own LayerV resource/CRID and qURL.

## Share the invitation

The guest-link result can be:

-   copied;
-   sent using the device's native share sheet;
-   displayed as a QR code; or
-   emailed when SMTP is configured.

QR codes are generated locally in the browser and are not uploaded to an
external QR service.

Treat the invitation as sensitive. Anyone who obtains it may attempt to
use it. Revoke the guest if delivery is uncertain.

## Invitation lifetime

The guest grant, LayerV qURL, and LayerV admission have separate
lifetimes.

Access Pages supports renewable invitations and, for eligible shorter
grants, LayerV-native single-use invitations.

### Renewable invitations

Renewable invitations use the same qURL when LayerV admission needs to
be renewed. The Gateway bootstrap used to establish the original guest
session is consumed only once.

### Single-use invitations

Single-use invitations use LayerV's native one-time-use behavior. After
the qURL has been redeemed, a fresh browser cannot redeem that same qURL
again.

The Access Pages grant expiration remains authoritative for protected
Gateway operations.

## Email verification

Configure email under **Gateway health → Configure email & alerts**.

When **Require guest verification** is enabled, the guest must enter a
six-digit code before protected state or actions are released.

This verification occurs at the Gateway after LayerV admission. It
proves access to the invited mailbox; it does not establish legal
identity or prove possession of a unique physical device.

Codes expire after ten minutes, allow at most five incorrect attempts,
and may be resent after sixty seconds. Successful verification lasts at
most twelve hours and never beyond the guest deadline.

SMTP requires certificate-validated STARTTLS or implicit TLS.

## Proximity controls

An Access Page can require the guest to be near Home before selected
actions are executed.

The guest can still view permitted status remotely. When an action
requires proximity, the browser requests location permission and the
Gateway sends the reading to the Home Assistant policy broker for
comparison with the configured Home location and page radius.

Home coordinates are not returned to the guest browser, and guest
coordinates are not stored in page data, activity history, or audit
events.

Browser location can be spoofed, so proximity should be treated as an
accidental-action safeguard rather than proof of physical presence.

## Cameras

Camera entities can be provided as read-only still images.

Each camera can use a refresh interval of:

-   15 seconds;
-   30 seconds;
-   1 minute;
-   2 minutes;
-   5 minutes; or
-   manual only.

Images pass through the page authorization boundary with `no-store`
caching and are not saved to the App data directory.

Live video and audio are not exposed.

## Guest activity and alerts

Access Pages can record activity associated with an individual guest
grant.

Activity can include the time, entity, approved action, safe action
parameters, and whether Home Assistant accepted the action.

Security events include recognized categories such as expired-link
attempts, rate limiting, unapproved entity/action requests, and actions
rejected by Home Assistant.

The activity system does not store guest tokens, access links, request
headers, arbitrary request data, or IP addresses.

With SMTP or approved Home Assistant Companion App notification targets
configured, administrators can choose alerts for events such as first
successful login, successful actions, and failed or blocked actions.

## Expiration and revocation

Access expires at the guest deadline even if later cleanup has not yet
run.

When a guest is revoked, Access Pages saves the local revocation first
and denies subsequent protected operations. The corresponding LayerV
cleanup is then performed and retried if necessary.

This allows the Gateway's local access decision to take effect without
waiting for successful upstream cleanup.

An action already dispatched to Home Assistant cannot be undone.

Revoked and expired guest records move to **Recently ended guests** and
are retained for 30 days unless deleted earlier.

## Configuration reference

### `resource_isolation`

Values: `guest` (default) or `page`.

`guest` allocates one LayerV resource for each new guest grant. Each
guest has its own resource and qURL.

`page` uses one LayerV resource/CRID per Access Page while retaining
individual guest qURLs and Gateway grants.

The setting applies to new invitations. Existing grants retain the mode
recorded when they were created.

### `connector_id`

Optional stable name for this Home Assistant installation's LayerV
Connector.

Leave it empty to generate one automatically. After successful
registration, do not change it unless intentionally resetting the App's
LayerV connection.

### `include_domains`

Optional comma-separated allowlist of Home Assistant domains.

### `include_areas`

Optional comma-separated list of Home Assistant area IDs.

### `exclude_domains`

Comma-separated domains that must not appear in the entity picker.
Exclusions take priority over inclusions.

### `exclude_entities`

Optional comma-separated entity IDs that must not appear in the picker.

### `qurl_max_lifetime_days`

Sets the maximum qURL lifetime Access Pages will offer for new
invitations.

Configure this to match the LayerV plan. LayerV remains authoritative
and may reject a duration outside the account's limits.

Restart the App after changing App configuration.

## Persistence and backups

Access Page definitions, guest grant information, token hashes, LayerV
revocation identifiers, Connector identity, and required secrets persist
under `/data`.

Guest access tokens are persisted only as SHA-256 hashes.

Activity history is stored in an administrator-only SQLite database.

Home Assistant App backups can contain LayerV credentials and Connector
private state. Protect backups accordingly.

## Resetting the LayerV connection

Use **Reset LayerV connection** only when this installation must
register as a new Connector.

The reset revokes local guest access, retires or queues cleanup of old
LayerV resources and qURLs, removes the existing LayerV credential and
Connector/Agent identity, and preserves the Access Page definitions.
The Admin UI immediately returns to the setup-required API-key form.

Reconnect Access Pages with a valid management API key; the same key may
be used again. The next first guest publication performs one explicitly
authorized fresh Connector bootstrap. Create new guest invitations;
existing guest links cannot be restored.

## Troubleshooting

If the Web UI does not open, verify that the App is running and review
its log.

If no Home Assistant entities appear, review the include/exclude
configuration and restart the App.

A guest-facing **This access link has expired or been revoked** message
is expected after expiration, revocation, reset, or token alteration.

Guest state normally refreshes every three seconds while the page is
visible. State and camera image refresh pause while the page is hidden.
Returning to the visible page triggers an immediate state refresh, then
normal polling and configured camera refresh resume.

A LayerV HTTP `429` or Connector rate-limit result means the request has
been rate limited. Wait before retrying. A plan-quota
rejection is separate from rate limiting.

Never paste LayerV API keys, qURLs, guest access links, preview tokens,
Connector private state, or other live credentials into public support
messages.

## Security reporting

Report suspected vulnerabilities privately using the process in
`SECURITY.md`. Do not include live credentials in a public issue.

## License and branding

The Access Pages Gateway source code is licensed under the MIT License.

The MIT License also covers the Gateway documentation. The App icon and logo
are Access Pages artwork. The license does not grant permission to use the
LayerV name, trademarks, wordmarks, logos, or other brand assets except as
necessary to identify an unmodified copy of this software.

Files specifically covered by this exclusion include:

- `static/layerv.png`
- `static/layerv-wordmark.png`

Do not use LayerV branding to imply sponsorship, endorsement, affiliation, or
official status without prior written permission from LayerV.

See [BRAND_ASSETS.md](https://github.com/AZDane/access-pages/blob/main/BRAND_ASSETS.md)
for the full notice. For brand-use questions, visit [LayerV](https://layerv.ai).
