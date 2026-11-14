# Access Pages for Home Assistant

## Home Assistant compatibility

Home Assistant Core 2026.10.4 and 2026.11.0 are supported and tested, with
2026.10.4 as the minimum supported version. Default entity labels follow Home
Assistant's naming metadata,
while saved guest labels and explicitly selected permissions stay unchanged.
Tilt-only covers require explicitly selected tilt controls.

After a Home Assistant upgrade, open affected pages in the Access Pages editor.
Missing entities and unsupported saved controls are shown for repair. Restore
the entity in Home Assistant, remove the affected resource/control, or select
a replacement deliberately. Access Pages does not replace entities by name or
automatically grant new controls. If area filtering is configured and HA cannot
provide complete area information, discovery is blocked until it recovers.

See the [compatibility matrix and validation limits](https://github.com/AZDane/access-pages/blob/main/docs/home-assistant-compatibility.md)
for tested behavior and the HAOS checks required before release.

## About Access Pages

Access Pages lets a Home Assistant administrator provide temporary
guests with remote access to a small, explicitly approved part of Home
Assistant while keeping Home Assistant and the home network from
becoming publicly reachable.

The guest receives a purpose-built page containing only the devices,
information, and controls selected by the administrator. Guests do not
need Home Assistant accounts, passwords, or VPN access.

The remote path is provided through [LayerV](https://layerv.ai) using the
**Network-Infrastructure Hiding Protocol (NHP)** and qURL technology.
NHP follows an **authenticate-before-connect** model: instead of
exposing the protected endpoint first and authenticating after a
connection arrives, the protected path remains invisible and unreachable
until access has been cryptographically verified.

Access Pages is independently developed open-source software.
After admission, the Access Pages Gateway provides the purpose-limited
page and enforces the capabilities assigned to the guest.

## How the protected path works

Access Pages preserves Home Assistant's local-first design. Home
Assistant, its devices, and its administrative interface remain inside
the home.

The App runs the Access Pages Gateway and one shared qURL runtime with its
embedded [LayerV](https://layerv.ai) Connector.
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
used to administer Home Assistant or manage [LayerV](https://layerv.ai) lifecycle operations.

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

Access Pages uses [LayerV](https://layerv.ai) to provide the protected NHP/qURL path for
remote guest access.

NHP is the open-source network-hiding technology developed by OpenNHP.
The LayerV team are core builders of OpenNHP, and LayerV's founding team
co-authored the Cloud Security Alliance (CSA) NHP specification. LayerV
provides the external managed NHP/qURL connectivity service and developer
tools currently used by Access Pages. The protocol is also documented in
an IETF Internet-Draft.

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

## Owner responsibility

Home Assistant owners control what guests can access and are responsible
for deciding what is appropriate and safe for their installation. Home
Assistant is highly customizable: entities and actions can control
physical equipment, locks, doors, gates, appliances, security equipment,
or other systems where unintended operation has real-world consequences.
Access Pages cannot determine whether an entity or action is safe for
guest use. Owners must review what each entity actually controls, the
actions they expose, and whether the available protections are appropriate.

The App defaults to
`include_domains: "light,switch,fan,media_player,climate,vacuum,sensor"`.
Edit this setting to choose domains, or leave it empty to allow all domains,
subject to other configured filters and exclusions. Entity categories are
configuration aids, not safety classifications; even a `light` entity is
not inherently safe.

Treat qURLs as access credentials. Once a qURL is provided for sharing,
Access Pages cannot control how an owner or guest stores, transmits,
forwards, screenshots, publishes, or otherwise distributes it. Someone
who obtains a valid qURL may be able to reach the associated guest access,
subject to any additional protections configured by the owner.

The owner is responsible for deciding who receives a qURL, how it is
distributed, how long access remains valid, and whether protections such
as email verification, proximity requirements for actions, expiration,
or revocation are appropriate.

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

Access Pages creates the guest grant and the [LayerV](https://layerv.ai) qURL required to
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

After sharing, choose **Finished Sharing**, then **Remove Saved Link** to
remove Access Pages' saved copy. The guest's invitation continues to work,
but you can no longer copy that same link from Access Pages. Create a new
guest invitation if you need another link later. Guest status, activity,
expiration, and revoke controls remain available.

Until you confirm, the link remains available across browser and App
restarts. Closing the dialog, copying, sharing, displaying a QR code, or
sending an email does not remove it automatically.

Treat qURLs as access credentials and review the owner responsibilities above
before sharing. Anyone who obtains an invitation may attempt to use it, subject
to its configured protections. Revoke the guest if delivery is uncertain.

## Invitation lifetime

The guest grant, [LayerV](https://layerv.ai) qURL, and LayerV admission have separate
lifetimes.

Access Pages supports renewable invitations and, for eligible shorter
grants, LayerV-native single-use invitations.

### Renewable invitations

Renewable invitations use the same qURL when [LayerV](https://layerv.ai) admission needs to
be renewed and can be opened on another device or browser while the grant
is active. Each browser receives its own guest session. If email verification
is required, each browser must verify separately. All sessions end when the
grant expires or is revoked.

The Gateway permits up to 12 new-session attempts per minute for each valid
invitation. If opening the invitation in another browser reaches this limit,
wait one minute and retry. Existing sessions and normal page refreshes continue
to work. Invalid credentials do not spend this allowance. The limit resets
when the broker restarts; it does not change invitation expiry or revocation.

### Single-use invitations

Single-use invitations use [LayerV](https://layerv.ai)'s native one-time-use behavior. After
the qURL has been redeemed, a fresh browser cannot redeem that same qURL
again.

The Access Pages grant expiration remains authoritative for protected
Gateway operations.

## Email verification

Configure email under **Gateway health → Configure email & alerts**.

When **Require guest verification** is enabled, the guest must enter a
six-digit code before protected state or actions are released.

This verification occurs at the Gateway after [LayerV](https://layerv.ai) admission. It
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
parameters, and whether the action could be confirmed.

Security events include recognized categories such as expired-link
attempts, rate limiting, unapproved entity/action requests, and actions whose
results could not be confirmed.

The activity system does not store guest tokens, access links, request
headers, arbitrary request data, or IP addresses.

With SMTP or approved Home Assistant Companion App notification targets
configured, administrators can choose alerts for events such as first
successful login, successful actions, and failed or blocked actions.

## Expiration and revocation

Access expires at the guest deadline even if later cleanup has not yet
run.

When a guest is revoked, Access Pages saves the local revocation first
and denies subsequent protected operations. The corresponding [LayerV](https://layerv.ai)
cleanup is then performed and retried if necessary.

This allows the Gateway's local access decision to take effect without
waiting for successful upstream cleanup.

An action already dispatched to Home Assistant cannot be undone.

Revoked and expired guest records move to **Recently ended guests** and
are retained for 30 days unless deleted earlier.

## Configuration reference

### `theme`

Choose a theme from **Configuration → Theme**, save, and restart the App.
The selection applies to the admin interface, previews, and all guest pages,
including existing guest links when reopened or refreshed.

| Theme | Appearance |
| --- | --- |
| `midnight` (default) | The original navy background with blue and violet accents. |
| `aurora` | Deep teal surfaces with mint accents and ocean-blue buttons. |
| `ember` | Warm charcoal and copper with rose-tinted buttons. |
| `amethyst` | Plum surfaces with lavender accents and violet-to-berry buttons. |
| `daylight` | Pale blue and white surfaces, dark text, and indigo buttons. |

Existing installations keep Midnight until a different theme is selected.
For a standalone deployment, set `ACCESS_PAGES_THEME` to one of these values.
An unrecognized standalone value falls back to Midnight.

### `resource_isolation`

Values: `guest` (default) or `page`.

`guest` allocates one [LayerV](https://layerv.ai) resource for each new guest grant. Each
guest has its own resource and qURL.

`page` uses one LayerV resource/CRID per Access Page while retaining
individual guest qURLs and Gateway grants.

The App keeps local page endpoints running and reuses its shared Connector;
it does not stop them when guests are inactive. In `guest` mode, minting each
invitation still requires publishing a new LayerV resource and waiting for
its route to be ready. In `page` mode, later invitations reuse the page's
resource, avoiding that allocation step. This trades per-guest upstream
resource isolation for less setup work; individual grants and local revocation
remain enforced in both modes. Deleting a qURL in `page` mode cannot guarantee
termination of an already established upstream connection.

The setting applies to new invitations. Existing grants retain the mode
recorded when they were created.

### `connector_id`

Optional stable name for this Home Assistant installation's [LayerV](https://layerv.ai)
Connector.

Leave it empty to generate one automatically. After successful
registration, do not change it unless intentionally resetting the App's
LayerV connection.

### `include_domains`

Comma-separated Home Assistant domains enabled for selection in guest
pages. Defaults to `light,switch,fan,media_player,climate,vacuum,sensor`
when the setting is missing. Leave the setting empty to allow all domains,
subject to other configured filters and exclusions. To choose specific
categories, list them, for example `light,sensor,camera`. Save the App
configuration and restart the App. Categories are configuration aids, not
safety classifications: review what each entity controls before sharing it.

This setting limits entity discovery and page creation or updates. It
does not remove controls from existing saved pages or revoke guest access.
Before saving an existing page, allow the domains it uses or remove those
controls from the page.

### `include_areas`

Optional comma-separated list of Home Assistant area IDs. When set,
only entities in those areas and enabled domains appear in the picker.
An area cannot enable a domain omitted from `include_domains`.

### `exclude_domains`

Comma-separated domains that must not appear in the entity picker.
Exclusions take priority over inclusions.

### `exclude_entities`

Optional comma-separated entity IDs that must not appear in the picker.

### `qurl_max_lifetime_days`

Sets the maximum qURL lifetime Access Pages will offer for new
invitations. Defaults to 30 days; existing configured values are preserved.

Configure this to match the [LayerV](https://layerv.ai) plan. LayerV remains authoritative
and may reject a duration outside the account's limits.

Restart the App after changing App configuration.

## Persistence and backups

Access Page definitions, guest grant information, token hashes, [LayerV](https://layerv.ai)
revocation identifiers, Connector identity, and required secrets persist
under `/data`.

Guest bootstrap secrets are stored as SHA-256 hashes. Access Pages also
retains the complete invitation while it remains available for owner sharing.
After the owner confirms sharing is finished, Access Pages removes its saved
copy. This does not revoke the guest invitation. Previously created backups
or distributed copies may still contain it; removal is not secure erasure.

Activity history is stored in an administrator-only SQLite database.

Home Assistant App backups can contain LayerV credentials and Connector
private state. Protect backups accordingly.

## Security update in App 0.1.138

App 0.1.138 packages qURL CLI 3.5.0 with LayerV Connector 0.14.2 and patched
Go dependencies. Back up the App, stop the previous version, then update and
start it. Saved pages, settings, and sealed Agent identity remain in place;
no account reset or reenrollment is required. Resource visibility and Access
Pages guest verification, expiry, and revocation behavior are preserved.
The ownership-lock and backup recovery guidance below also applies to this
update.

## Upgrading to qURL 3.0.0

App 0.1.131 packages qURL CLI 3.0.0 with [LayerV](https://layerv.ai) Connector 0.14.1. Upgrade
the App normally after that version is published, taking a Home Assistant
App backup first. Stop the old App completely before starting the updated
version; only one daemon may own its persisted state.

Saved Access Pages, Home Assistant settings, administrator configuration,
and the existing LayerV account and Connector identity are retained. This
upgrade introduces no guest-link migration. If old links need replacing,
revoke those guests using the existing guest controls and create new
invitations. Local revocation takes effect first; remote cleanup is retried
durably if LayerV is unavailable. Keep the App running to finish cleanup.

Tunnel TLS certificates are now verified using the packaged system CA store.
Do not disable verification or relax AppArmor to recover a failed connection.
Check network access, system time, and the connection status, then restart
the App. If an upgrade still fails, stop it and restore the matching App
version and data backup; reapply any guest revocations made since that backup.
Do not delete the Connector state, wrapping key, or ownership lock. An
ordinary upgrade does not require **Reset LayerV connection**.

## Resetting the LayerV connection

Use **Reset LayerV connection** only when this installation must
register as a new Connector.

The reset revokes local guest access, retires or queues cleanup of old
[LayerV](https://layerv.ai) resources and qURLs, removes the existing LayerV credential and
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

A [LayerV](https://layerv.ai) HTTP `429` or Connector rate-limit result means the request has
been rate limited. Wait before retrying. A plan-quota
rejection is separate from rate limiting.

Never paste LayerV API keys, qURLs, guest access links, preview tokens,
Connector private state, or other live credentials into public support
messages.

## Security reporting

Report suspected vulnerabilities privately using the process in
`SECURITY.md`. Do not include live credentials in a public issue.

## License and branding

Access Pages LLC owns the founder-owned Access Pages intellectual property
assigned to it by John Raahauge. Third-party and contributor-owned material
remains subject to its existing ownership and licenses.

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

## Guest link publishing errors

If creating a guest link reports `Connector exit 8`, qURL rejected a request
as invalid. This code alone does not establish that the API key is wrong.
The error identifies a known enrollment, recovery, or resource-request failure
when qURL supplies one. For API validation failures it includes the upstream
HTTP status and recognized invalid field names, without their values. Native
resource failures can also include a numeric LayerV support code.

The Home Assistant App log records the same safe message in a
`connector_operation_failed` event, even with temporary diagnostic logging off.
For support, provide that event and the installed App version. Unknown vendor
details remain hidden, so some failures still need investigation by LayerV.
Do not repeatedly reset the connection solely because of this exit code:
a connection reset revokes guest access and replaces the Connector identity.

## Temporary diagnostic logging

Normal operation emits no diagnostic records for healthy, fast guest requests.
Errors, observed disconnects, uncertain controls, rejected stale controls, and
requests taking at least five seconds inside Access Pages can produce a compact
summary. Ordinary startup and existing product activity logs are separate.

For a recurring problem, open the App's **Configuration** and set
**Temporary diagnostic capture request** (`diagnostic_logging`) to `30 minutes`,
`1 hour`, or `4 hours`, then save and restart
the App. The default is `off`. Timing observations include successful requests
while this temporary mode is active. It observes existing traffic; it does not
add polls, probes, HA calls, uploads, or [LayerV](https://layerv.ai) requests.

Completed requests normally produce one final Gateway summary with the fixed
timing vector. To retain some evidence for requests that never finish, one in
16 random request IDs also selects observations immediately before broker RPC
and HA invocation. Both components use the same selection; there is no request
history or overdue scanner. Other successful intermediate boundaries are kept
only in the timing vector. Detected abnormalities can emit immediate local
records even when their request was not selected. Sampled observations reserve
half the Python sink's burst allowance and queue capacity for abnormal/loss
records; Gateway summaries have no competing routine intermediate records.

The duration starts when the App starts and cannot be extended by traffic.
The saved duration may remain displayed after capture expires and runtime
diagnostics are Off. This option records a one-shot capture request, not current
logging status. Access Pages does not rewrite the Home Assistant configuration.
An App restart stops the capture: leaving the same selection configured does
**not** start another capture, even if you change its duration. To start another,
select `off`, save and restart, then select the desired duration, save and restart
again. Selecting `off` and restarting also stops a capture early. A failed
activation stays off. No invitation or session data is changed.

New diagnostic records include `timestamp`, an absolute UTC observation time
with millisecond precision, captured before asynchronous queuing. Standalone
loss reports are timestamped when created. It aids correlation with LayerV and
product logs; clocks on separate systems may differ. Action freshness, deadlines,
durations, expiration, and throttling continue to use monotonic time exclusively.
Older retained records may lack `timestamp`; no migration is needed. Access Pages
does not read historical diagnostics, and missing timestamps do not invalidate
their request IDs or timing vectors.

Use the Access Pages App **Logs** tab and Home Assistant's **Download logs**
control. The download contains the retained App output requested from Home
Assistant, including ordinary lifecycle messages; it is not an Access Pages
support archive. Choose enough lines to cover the incident. The displayed text
filter does not necessarily filter the downloaded log. Log history and retention
are managed by Home Assistant. Access Pages neither clears logs on restart nor
provides a clear-log action, diagnostic files, or automatic upload. Review any
whole-App log before sharing because other components' ordinary messages are
separate from the fixed, privacy-limited request diagnostic schema.

Emission is throttled per process, including loss reports. In normal mode the
allowance is one record initially, replenished once per minute. Detailed mode
allows 12 records initially, replenished once every two seconds. Each record is
at most 512 bytes. With P page Gateway processes, at most P+2 processes emit guest
diagnostics; the aggregate bound scales with that count. These are emission
bounds, not a disk quota or a promised complete trace. Counters and throttles
reset on process restart. The App owns emission; Home Assistant owns retention.

When output is blocked or the allowance is exhausted, evidence is dropped.
`lost` reports the cumulative suppressed/dropped count in that process (capped
at 2,147,483,647). It combines intentional admission/output throttling, queue or
output failure, oversized records, and expiration of queued detailed records;
it does not identify which cause occurred. Unselected pre-blocking observations
are not emission attempts and do not increment it. A quiet process with
unreported loss attempts a bounded loss summary once per minute. Normal-mode
healthy polling alone never causes a loss summary. Detailed-mode traffic can
still exceed the allowance with multiple guests, bursts, or blocked output.
Missing records therefore do not prove a request never reached a component.
Some problems will require enabling this mode and reproducing them again.

## Scheduled guest invitations

With SMTP configured, open an Access Page's **Guests** view and select
**Add guest → Scheduled access**. Enter a name and email address, then choose a one-time date
or selected weekdays. Set start/end times, an optional next-day end, and optional
first/last start dates for weekly recurrence. Review the upcoming times before
saving. Use **Duplicate** for additional individual dates. This release uses
native date/time pickers and an upcoming list; it does not synchronize external
calendars.

New schedules default to your browser's local timezone. Choose a different zone
from the timezone selector if needed; the selected IANA timezone is saved on each
schedule. If browser detection is unavailable, the App's `TZ` value is used
(UTC if unavailable). Editing or duplicating a schedule preserves its saved zone.
Click anywhere in a date field to open its calendar; keyboard date entry also
remains available. Check the timezone and upcoming windows before saving.
Changes to the installation or browser timezone do not move existing schedules.
Weekly schedules follow local wall-clock time. Nonexistent or ambiguous DST
boundaries are skipped and shown in previews/history. The weekday and final
recurrence date refer to the start date, including overnight windows. Windows
must be 2 minutes to 24 hours; a DST transition that makes the elapsed window
longer than 24 hours is skipped.

At each start, the App creates a fresh qURL and emails it. Creation and SMTP can
add delay. The local guest grant always expires no later than the original end,
including sessions already open. An already-dispatched Home Assistant action
cannot be recalled. Permissions and proximity continue to follow the Access
Page's current policy.

Verification is enabled by default and remains session-specific. Renewable
invitations are the default within each occurrence; single-use invitations are
optional. Neither setting reuses a link across occurrences. Sending the invitation
does not itself verify ownership of the email address.

If the App was offline, it may create/send within 15 minutes of the original
start, provided at least one minute remains. It never extends the end. Older
occurrences are skipped; up to 30 days of missed history is recorded after a
long outage. Paused occurrences are not replayed when resumed.

Temporary creation failures are reconciled through broker-owned retirement
before another grant is attempted. Email retries reuse the same qURL and
Message-ID. SMTP can accept an email and lose its acknowledgement, so duplicate
emails are possible. **Accepted by email server** does not confirm inbox delivery.
Permanent failures or exhausted delivery windows revoke local access and queue
upstream cleanup. An ambiguously accepted email can consequently contain an
already-ended invitation. Use **Refresh schedules** to see upcoming occurrences,
attempt counts, next retries, failures, and cleanup progress without displaying
invitation secrets. History is retained for 30 days after an occurrence ends.

Missing or invalid SMTP configuration blocks schedules until explicitly resumed.
An SMTP outage is retried within the original delivery window. Already-issued
invitations retain their expiry; guests needing a verification code must wait for
working SMTP, and verification is never bypassed. LayerV credential/quota failures
also block the affected schedule. Resolve the cause before resuming. There is a
limit of 200 schedules; simultaneous starts are queued, and provider limits may
prevent all guests receiving an invitation within the grace period.

**Edit**, **Pause**, and **Delete** affect future or not-yet-emailed invitations.
Already-emailed invitations retain their original recipient and end time. Use
**Duplicate** for another invitation on a date this schedule already processed;
editing or resuming does not issue that date a second time. Use
**Pause and end current access** to revoke them immediately. Revoking all guests
also revokes schedules. Page deletion or connection reset prevents scheduled
reissuance. Other schedules for the same email/page are flagged for overlap
review; independent grants remain independent, so revoking one does not end
another. No windows are silently combined.

### Guest form errors and unsaved changes

Guest add/edit forms show a red error panel and outline the field or group that
needs attention, with an explanation beside it. For activity alerts, choose both
a destination and at least one activity, or leave both unselected to disable alerts.
Server or connection errors appear in the form without erasing your entries.

Closing with the close button, Escape, or the dialog backdrop asks **Discard
unsaved changes?** only if current values differ from when the form opened or was
last saved successfully. **Cancel** returns to the form with edits intact;
**Discard changes** closes it. Untouched forms and edits reverted to their original
values close silently. Fields and dismissal are temporarily disabled while saving.

**Review upcoming times** is a preview, not a save. Failed saves leave changes
unsaved. **Save schedule** closes the dialog after the server confirms success.
A successful save remains successful even if the subsequent list refresh fails;
use **Refresh schedules** in that case. For immediate guests, successful link
creation clears the unsaved-change warning even if invitation email delivery fails.

### Guest cards, combined history, and retention

Each scheduled guest has a compact card matching the regular guest layout. Cards
start collapsed when opening the Guests view. The summary shows status and the
next access window; failures remain visible while collapsed. **View details**
reveals the latest invitation status, schedule controls, upcoming windows, and
**Activity and invitation history**. Refreshing preserves cards you have expanded.

**Revoke guest** is visible without expanding the card. After confirmation it ends
all current access and stops every future schedule for that guest on this Access
Page. The card moves to **Recently ended guests**, labeled **Revoked**, with
**View details** for retained history and no redundant revoke button. **Pause**
keeps the guest in the scheduled list; explicitly resuming a revoked schedule
returns the guest there. This includes outstanding invitations from deleted schedules. History is
retained; other guests and manual invitations are unaffected, even if their names
or email addresses match. The owner can explicitly resume individual schedules
later. Local access ends before remote cleanup, which can continue retrying.
Current invitations also have individual revoke controls inside **View details**.

Versions through 0.1.155 saved guest revocation as Paused. These records cannot be
distinguished from an intentional pause, so upgrading preserves them. Click
**Revoke guest** once again to move such a guest to Recently ended guests.

Use the history filter to separate guest activity from delivery status, **Show this access window** to inspect an occurrence, and
**Load older entries** to page through all retained records. Delivery history shows
the current outcome and retry counts for each occurrence, not a log of every
individual retry. Email acceptance is not proof of a guest visit or inbox delivery.

When adding scheduled access, select **New guest** or an existing guest on this
Access Page. **Duplicate schedule** keeps the same guest selected. Editing a
guest's name or email updates all of that guest's future schedules; invitations
already issued keep their original recipient. Guest identity is separate from
contact details: matching names or emails never merge histories automatically.
Each occurrence still has its own grant, expiration, and revocation. Pausing or
ending one schedule does not affect another schedule for the same guest.

On upgrade, each existing schedule receives its own guest identity. Activity for
invitations whose association is still available is linked automatically. Older
ended invitations without a reliable association remain under **Recently ended
guests** until their usual retention expires. Existing manual guests also keep
per-invitation history; they are not automatically merged into scheduled guests.

The App cleans history in the background, even when nobody opens the Guests view
or SMTP is unavailable:

- Actions, security events, and first-visit timestamps expire after 30 days.
  Existing limits also apply: at most 1,000 actions per invitation and 1,000
  security events per Access Page, so busy histories can be shorter.
- Ended/revoked guest records expire 30 days after their access ends. A small
  first-visit flag remains on an active grant so purging its old timestamp does
  not send another first-login alert.
- Invitation records expire 30 days after the scheduled end. Work still awaiting
  safe cleanup is retained until local access is denied and upstream cleanup has
  been durably handed off; the remote cleanup queue may continue retrying.
- Deleted or revoked schedules and their guest contact details are removed once
  at least 30 days have elapsed since deletion or revocation and no occurrence
  records remain. Guests
  with another enabled or paused schedule remain available for future use.

Deleting a schedule preserves already-issued access until its original end. Use
**Pause and end current access** first when access must stop immediately. History
cleanup affects the live App stores; copies in existing Home Assistant backups
remain until those backups expire or are deleted under your backup policy.

### Restart, upgrade, and restore

Schedules and delivery journals persist under `/data/admin-runtime`. Ordinary
restarts and upgrades resume eligible pending work. They do not recreate completed
occurrences. The App's existing cold-backup mode includes consistent persistent
stores and sensitive recipient/invitation data; protect those backups.

Home Assistant backups deliberately exclude `admin-runtime/schedule-authorization`.
On restore, its absence or mismatch blocks enabled schedules and revokes restored
scheduled grants locally **before guest services start**. Cleanup remains durable.
Review SMTP, the timezone, guest permissions, and LayerV state, then use **Resume
future invitations** on each intended schedule. Past occurrences are not replayed.
Revocations made after an older backup may need to be reapplied to manual guests.
Do not run the original App and a restored clone simultaneously.

For manual filesystem backups/restores, omit/remove the same authorization file
before starting the restored App. Copying the database together with a matching
permit outside Home Assistant bypasses automatic restore detection. A significant
backward clock jump also blocks schedules and cancels their outstanding access;
correct system time before resuming.
