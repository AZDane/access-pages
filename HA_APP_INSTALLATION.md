# Home Assistant App installation and release check

Use a Home Assistant OS or Supervised installation. Home Assistant Container
does not include Supervisor and cannot install Apps.

## Before Publishing

1. Confirm `homeassistant-app/config.yaml`, `Dockerfile.ha-app`, the public App
   repository metadata, and the release tag use the same version.
2. In `AZDane/access-pages`, enable GitHub private vulnerability reporting
   before publication so security reports can be submitted privately.
3. Confirm `AZDane/access-pages-app` contains byte-for-byte copies of
   `homeassistant-app/config.yaml`, `README.md`, `DOCS.md`, `CHANGELOG.md`,
   `apparmor.txt`, `icon.png`, and `logo.png` from this source repository.
   Home Assistant loads AppArmor from repository metadata, not from the image.
4. Merge the reviewed source changes into `main`.
5. Create the matching GitHub release. The release workflow publishes and signs
   `ghcr.io/azdane/access-pages-app:<version>` for AMD64 and ARM64.
6. In GitHub Packages, confirm the image is public before installing it.

## Installation

1. Create a full Home Assistant backup.
2. Open **Settings → Apps → App store → Repositories**.
3. Add `https://github.com/AZDane/access-pages-app`.
4. Refresh the store and install **Access Pages**.
5. Leave the optional Connector ID empty to generate a stable installation
   label. It does not create a separate Agent for each guest or page.
6. Start the App, open the Web UI, and enter a dedicated LayerV API key on the
   **Connect to LayerV** screen through Home Assistant Ingress. Enable
   **Read qURLs**, **Create, update & delete qURLs**, and **Mint qURL Connector
   enrollment tokens**. Leave **Redeem tokens and share by CRID (headless
   access)** disabled; Access Pages does not require it. The retained
   management API key supports ongoing qURL management.
7. Inspect the App logs. Never paste logs containing credentials
   into an issue.
8. Verify Home Assistant entity discovery.
9. Create a disposable page and first guest invitation. That first required
   publication uses the retained management API key to mint a one-time
   Connector enrollment token. It supplies that token, not the persistent
   management API key, to `qurl login`, which establishes one persistent Agent
   identity. Open the qURL in a separate private browser, exercise one harmless
   demo entity, then revoke that guest.
10. Open the same page through **Preview** and exercise one harmless action.
    This verifies that the isolated admin plane can use its separate discovery
    and preview-action authority.
11. Create a second guest and restart only the App. Confirm both operations
    reuse the same Agent identity without another enrollment or API-key entry,
    and that the page, active grants, and activity history remain available.
12. Run the reset test only after creating an App-only backup. Confirm every
    guest is revoked, page definitions remain, onboarding returns, and a new
    API key permits an explicitly requested clean enrollment.
13. Review the Home Assistant host audit journal for unexplained
    `apparmor="DENIED"` events associated with `access_pages`.

## Isolation acceptance checks

The App runs one administrative Python Gateway behind Ingress, separate
unprivileged Go page endpoints, an isolated Guest Service, restricted Home
Assistant and LayerV brokers, a policy store, one supervised Connector runtime,
and an Ingress proxy inside the App container. Ordinary guest requests never
enter the Admin Gateway.

The default `resource_isolation: guest` gives each guest a distinct LayerV
resource/CRID, including guests sharing a public IP. Optional
`resource_isolation: page` gives each Access Page one shared resource/CRID and
its guests independent qURLs, grants, and sessions. Check revocation of one
guest without interrupting another in the selected mode.

After updating:

1. Confirm the admin UI can list entities and save a page.
2. Confirm Preview can read state and execute one approved action.
3. Confirm an issued guest link can read state and execute only its approved
   actions.
4. Attempt an unapproved action from the guest page and confirm it is rejected
   and recorded without a token or request body in security history.
5. Restart the App and confirm pages, active guest links, and activity remain.
6. Check logs for startup failures from the policy store or either broker, and
   check the host audit journal for unexpected AppArmor denials.

The processes share one Home Assistant App container, its loopback network
namespace, and one AppArmor profile. Guest Python processing runs in the
isolated Guest Service, separate from the administrative Gateway.

Use a disposable page and guest grant for the first installation test; revoke
the grant after confirming the expected access and isolation behavior.

## Failure and Rollback

- If setup fails, stop the App and preserve its `/data` state for diagnosis.
- If an update appears on the App page but the update dialog remains stale,
  refresh the individual App page after checking for updates. Do not remove the
  repository or uninstall the App merely to refresh metadata.
- Do not repeatedly change the connector ID or delete connector state; both can
  create recovery problems.
- If established Agent state is lost or rejected, publication fails closed;
  normal restart never mints another enrollment token. Use explicit
  administrator recovery rather than deleting state to trigger a retry.
- A connection reset intentionally removes the LayerV key and Connector state,
  revokes every guest, and preserves page definitions. It cannot restore old
  guest links.
- If reset is confirmed but the dialog does not advance, record the visible
  dialog error and look for an AppArmor denial involving
  `.reset-connection.request.tmp`.
- Guest activity failures or guest-record deletion failures should be checked
  for an AppArmor denial involving a SQLite `-journal`, `-wal`, or `-shm`
  sidecar.
- Uninstalling the App does not automatically revoke the remote LayerV
  connector or qURLs.
- Restore the Home Assistant backup if the installation affected unrelated
  Home Assistant behavior.

## Safe diagnostics

When reporting a failure, include the App version, operation, timestamp, HTTP
status, and sanitized AppArmor operation/path if present. Never include the
LayerV API key, activation qURL, access link, preview token, Home Assistant
credential, authorization headers, Connector private state, or unredacted page
data.
