# Changelog

## 0.1.130

- Add Finished Sharing with an explicit Remove Saved Link confirmation. Remove
  Access Pages' saved invitation copy while keeping guest access, sessions,
  expiration, verification, and revocation working normally.
- Keep links available for copying, sharing, QR codes, and email until the owner
  confirms. Afterwards, show that the link is no longer stored and prevent stale
  page edits from restoring it. Existing backups and distributed copies remain.
- Correct the Email verification required label and describe unconfirmed Home
  Assistant action results without falsely reporting that the action was rejected.
- Describe proximity as device-reported and clarify the LayerV broker/qURL
  runtime's current shared identity and trust boundary.

## 0.1.129

- Keep paired guest actions such as Turn on and Turn off side-by-side on narrow
  mobile screens, including reduced effective widths with Display Zoom.
- Preserve equal-width buttons, readable wrapping labels, existing touch-target
  sizes, and the current tablet, desktop, and other control layouts.

## 0.1.128

- Owner-test prerelease for live acceptance; not approved for external beta.
- Retire page grants durably before deletion and persist policy publication
  intent before changes, allowing interrupted operations to recover safely.
- Require fresh authorized state before completing a guest action in the UI.
  Suppress obsolete responses and gate stale controls after reconnect,
  background return and browser restoration. Never replay a device action.
- Normalize interrupted Home Assistant requests while preserving uncertain
  action outcomes and the existing receipt-aged action deadline.
- Keep invitation validation and errors visible inside the dialog. Distinguish
  local revocation, queued cleanup and unconfirmed remote revocation.
- Include UTC timestamps in new `ap_diag` records and preserve Gateway startup
  when logging is unavailable. Synchronize native temporary-diagnostic help
  text explaining expiration, consumed selections and the Off/restart re-arm.
- Keep healthy logging quiet and diagnostic capture bounded. The historical
  timeout is not claimed resolved; target-device live acceptance remains pending.
- Publish new versioned images without moving existing `latest` tags for this
  prerelease. Existing release tags and images remain available unchanged.

## 0.1.127

- Owner-only HA-Nova acceptance prerelease; not approved for external beta.
  Preserve 0.1.126 as the reference for the live diagnostic-policy finding.
- Prefer one final Gateway timing summary per completed request in temporary
  diagnostic mode. Retain successful pre-RPC and pre-HA observations only for a
  consistent one-in-16 request sample, reserving capacity for abnormal evidence.
- Keep immediate failure, disconnect, deadline and uncertainty evidence. Normal
  healthy polling remains silent; timing, action freshness, expiration, restart
  protection and network behavior are unchanged.
- Accepted diagnostic limitation: an unsampled request that hangs indefinitely
  without a detected failure may leave no useful early-boundary evidence.
- Separate inherited issue: stderr already full before startup can block the
  Gateway's synchronous startup message. This release does not fix that issue
  or establish the cause of the historical timeout.
- External-beta promotion and the stable development baseline decision await
  the owner's live acceptance results and a separate assessment.

## 0.1.126

- Keep healthy guest polling silent. Replace buffered event histories and helper
  tracing with compact correlated boundary timings and throttled abnormal
  summaries through Home Assistant App logs. No diagnostic files or extra
  network requests are created.
- Add one-shot diagnostic logging for 30 minutes, one hour, or four hours through
  App configuration. It expires automatically and does not reactivate on restart.
- Keep eight-second action freshness independent of logging, retain disconnect
  and verification recovery fixes, and preserve a received request ID if browser
  response-body processing subsequently fails. Unconfirmed actions are never
  replayed.
- The historical timeout remains unresolved; another occurrence may require a
  temporary diagnostic capture and reproduction.

## 0.1.125

- Skip empty redirect-body writes and end response handling when a peer
  disconnects, preserving the session cookie and 303 redirect headers.
- Resume status polling when email verification succeeds but the following
  state read fails. Keep verification independent for each device.
- Add bounded, privacy-safe request-stage diagnostics across the Guest Gateway,
  guest service, broker, and HA client, separating broker wait from HA latency.
  Summarize ordinary successful state polls once; retain detailed slow/error
  evidence. Keep saved identifiers opaque and include the diagnostic dependency
  in both supported images.
- Reject queued guest actions after a non-renewable eight-second lifetime from
  Gateway receipt, with another check immediately before HA dispatch. Preserve
  all session, verification, policy, revocation, and authorization-expiry checks.
  Already-dispatched actions cannot be recalled and are never replayed.
- The historical 0.1.124 first-use timeout remains unexplained. These changes do
  not establish or fix its cause, and do not change LayerV behavior.

## 0.1.124

- Allow reusable guest invitations to open on multiple devices with independent
  sessions, including links already opened before upgrading. Preserve single-use
  consumption, grant expiry, revocation, and separate email verification on each
  device.
- Allow a valid reusable invitation to replace a stale browser session cookie.
- Replace the obsolete ten-minute Connector warm-up message with a simple page
  save confirmation.
- Clarify that page endpoints and the shared Connector stay running, and document
  the resource allocation tradeoff between guest and page isolation when minting
  invitations.

## 0.1.123

- Remove experimental hidden-page maintenance polling after testing showed
  it did not prevent the upstream connection-loss condition. State and camera
  refresh pause while hidden and resume when the guest page becomes visible.

## 0.1.122

- Open the current setup document automatically after an explicit LayerV
  connection reset is confirmed by the onboarding service.
- Refresh guest state every 60 seconds while hidden, then immediately when
  visible again; retain three-second visible polling and pause hidden cameras.

## 0.1.121

- Let an explicit LayerV connection reset authorize one fresh Agent bootstrap
  after old bindings are retired, including when the same management key is
  entered again. Preserve the single-bootstrap guard if established Agent
  state is lost without a reset.
- Defer old resource cleanup until the new Agent is enrolled, then retire old
  resources through the retained management credential without using the new
  Agent's cleared native route state.

## 0.1.120

- Reject service-controlled symlinks and unusual objects during privileged
  startup permission repair using descriptor-relative, no-follow operations.
- Include pinned qURL, Connector, Go, and embedded dependency license and
  notice texts in the App image and source distribution.
- Retire old resource bindings before an explicit LayerV identity reset;
  preserve cleanup intent and allocate fresh resources on later enrollment.
- Keep Admin and Ingress available for explicit reset when established Agent
  state needs recovery, while denying publication and guest access.
- Make per-page revoke-all crash safe with a durable local revocation marker
  and persistent upstream cleanup queue.

## 0.1.119

- Use qURL 2.6.0 with embedded Connector 0.14.0. Enroll one Agent on the first
  required publication using a one-shot token minted by the retained
  installation management key; reuse sealed Agent state and fail closed if
  established identity is lost or rejected.
- Route guest traffic through page-bound Go endpoints, isolated Guest Service,
  and the restricted HA Broker. Preserve the separate Ingress Admin authority,
  individual sessions, verification, policy enforcement, activity, alerts,
  Preview, and local-first revocation.
- Keep `resource_isolation: guest` as the default with one resource per guest;
  retain optional `page` mode with one shared resource per Access Page and
  independent guest qURLs and grants.
- Complete HA Green acceptance for the ARM64 candidate. Exercise temporary
  LayerV cleanup failure and durable reconciliation through deterministic
  local fault injection, without inducing a live LayerV outage on Green.

## 0.1.114

- Restore camera snapshots fetched through bounded AJAX by allowing browser-local
  blob URLs in the image Content Security Policy. Guest/page/camera authorization,
  refresh limits, revocation, and script/connect restrictions remain enforced.
- Verify the regression in Chrome with the actual response policy: the image
  was blocked before the fix and rendered afterward without CSP violations.

## 0.1.113

- Revoke Gateway authorization immediately and durably defer native LayerV
  cleanup for a 15-second minimum status-update window. Preserve guest/resource
  isolation and retry upstream failures without restoring local access. The
  window allows notification but does not require browser acknowledgement.
- Check stale guest status immediately when returning to a page or reconnecting,
  while retaining coalesced requests and background admission redirect protection.
- Correct shared Connector dashboard labeling: modern page endpoints no longer
  appear as dormant legacy Connectors. This is not a native route health probe.
- Reduce the inline email logo to 24 pixels. Choose invitation email delivery
  first, then optional verification; turning email off clears verification.

## 0.1.112

- Restore first-login activity alerts for scoped guest sessions and correct
  page attribution for action alerts. Successful authorized login is recorded
  once; previews, denied requests and repeated status polls do not trigger it.
- Add Email guest invitation independently of Require guest verification when
  SMTP is configured. Verify email/SMTP before allocation and report delivery
  failure while preserving the created link. Delivery-only recipients are not
  stored for verification.
- Style invitations with an inline Access Pages logo and button, hide long URLs
  in HTML, retain plain-text fallback links, and make code instructions conditional
  on verification. Explain sender and administrator email fields in the UI.

## 0.1.111

- Keep AJAX updates on the existing guest session. Background status, camera,
  verification and action requests explicitly use same-origin credentials and
  reject redirects, preventing silent navigation into upstream admission flows.
- Coalesce status requests, pause updates while hidden/offline, and back off
  reconnect polling from six seconds up to sixty seconds after failures.
  Camera requests now share the ten-second deadline and redirect protection.
- Preserve authorization on every request, resource isolation, entity/action
  restrictions, immediate local revocation and resource-only guest retirement.
- Test session reuse, concurrent guests, revocation, redirect rejection and
  browser reconnects. The production lockout's upstream trigger remains unproven.

## 0.1.110

- In per-guest isolation, revoke the Gateway grant locally and delete only the
  guest resource upstream. Resource deletion covers its single qURL; remove
  the redundant individual qURL DELETE, including on durable cleanup retries.
- Preserve per-page isolation: revoke only the guest's qURL, keeping the shared
  resource and other guests. Existing invitations retain their recorded mode.
- This simplifies revocation for testing the reported cross-host lockout; its
  effect on that upstream interruption has not yet been verified.

## 0.1.109

- Bound guest requests, including response bodies, to ten seconds. Clear stale
  controls and camera frames on connection failure and recover through status
  polling. Never automatically repeat a timed-out Home Assistant command.
- Preserve automatic removal of controls when polling confirms revoked or
  expired access; prevent a pending response from restoring revoked controls.
- Document browser behavior separately from LayerV revocation propagation.
  The reported pause affecting separate HA installations remains under
  investigation; this release does not claim to resolve its cause.

## 0.1.108

- Persist exponential backoff for failed abandoned-allocation recovery instead
  of retrying native publication at every five-second reconciliation tick.
- A rate-limited recovery pauses the whole orphan-publication scan, including
  other allocations, across broker restarts. Cleanup ownership remains intact.
- Correct Connector exit 9 to a rate-limit rejection, separate from plan quotas,
  with an HTTP 429 upstream status and a conservative local 60-second minimum
  retry recommendation. Retain 0.1.107 invitation deadline fixes.

## 0.1.107

- Give invitation creation up to six minutes at the private broker and six
  minutes thirty seconds at ingress, allowing cold Connector enrollment and
  publication to finish and return their result. Other request deadlines stay
  unchanged. Show initial-setup wait guidance in the UI.
- Preserve LayerV creation-rate-limit Retry-After instructions and distinguish
  HTTP 429 from a typed HTTP 403 plan-quota rejection. Do not retry minting
  automatically or return upstream private error details.
- Handle a disconnected broker caller without a BrokenPipe traceback; log
  only the safe error/status and retain existing durable reconciliation.

## 0.1.106

- Allow the native Connector to open the filesystem root directory read-only
  for its secure state-directory walk. Fix the reported login failure:
  `open pinned walk anchor /: open /: permission denied`.
- Keep file access under the existing explicit allowlist. The new `/ r,` rule
  permits the root directory itself; it does not grant access to its files
  or descendants. AppArmor remains enforced.

## 0.1.105

- Include a bounded, redacted Connector login error for otherwise unclassified
  exit-1 enrollment failures. Preserve the failure stage and exit code.
- Do not include successful identity output, verbose diagnostics, account keys,
  invitation URLs, email addresses, or long opaque credential values.
- This diagnostic update does not claim to resolve the reported installation
  failure; the underlying Connector explanation is required to identify it.

## 0.1.104

- Restore native One-time use for current Connector invitations after production
  first-admission/replay verification. Keep the 24-hour single-use grant limit.
- Restore the existing Gateway email-code verification control when SMTP and
  scoped invitations are available; remove the obsolete target_path warning.
- Preserve safe broker and Connector failure diagnostics instead of masking
  every minting failure as a generic broker rejection. Never expose raw stderr.
- Document Gateway verification versus upstream identity authentication and
  keep the separate Nova NHP plugin implementation out of this project.

## 0.1.103

- Keep resource cleanup pending when CLI 2.5.4 confirms remote deletion but
  warns that native binding retirement or daemon reload failed. Durable retries
  now require local convergence as well as the upstream deletion response.
- Carry forward the 0.1.102 migration's completed production and packaged
  acceptance checks; document the separate image scan's remaining findings.

## 0.1.102

- Use the pinned LayerV CLI 2.5.4 shared Connector for new invitations, with
  supported per-resource sessions and serving readiness checks.
- Default to one resource and one qURL per guest grant. Optional
  `resource_isolation: page` shares a resource and preserves other guests on
  individual qURL revocation, with documented limits for existing connections.
- Deliver a one-time Gateway bootstrap and establish independent, scoped guest
  sessions. Preserve required email verification and three-day guest grants,
  with renewable LayerV admission capped at 24 hours per session.
- Revoke locally before deleting the qURL and, in per-guest mode, its resource.
  Persist and retry cleanup, expired grants, interrupted allocations, and
  policy publication across restarts.
- Preserve existing legacy links and identifiers. Replace legacy invitations
  to adopt the new flow; review the migration and rollback documentation.

## 0.1.101

- Restore the original Access Pages logo proportions in the administrator and
  guest headers: the A-doorway mark is approximately 1.78 times the wordmark
  height while the overall lockup width remains stable.

## 0.1.100

- Match the Access Pages mark and wordmark heights across administrator and
  guest-page layouts, including narrow mobile screens.
- Replace remaining customer-facing Guest Access labels with Access Pages in
  link sharing, invitation emails, verification guidance, and expired-page
  errors.

## 0.1.99

- Rename the customer-facing product to **Access Pages for Home Assistant**
  while preserving the App slug, container image, and LayerV-specific technical
  identifiers.
- Replace the active Home Assistant, administrator, and guest-page artwork with
  the transparent Access Pages A-doorway logo package.

## 0.1.98

- Enlarge the outlined App-page lockup and make the interior of its mark
  transparent while preserving the white guest figure.

## 0.1.97

- Replace the App details-page banner with a transparent, high-contrast Guest
  Access lockup outlined for legibility on both light and dark themes.

## 0.1.96

- Give the Home Assistant App details page a padded black logo banner that
  remains consistent across light and dark themes.
- Use a transparent monochrome gray mark in the Apps listing to match Home
  Assistant's navigation icon treatment on light backgrounds.

## 0.1.95

- Fix guest and preview pages remaining on the loading screen after adding
  per-camera refresh scheduling.

## 0.1.94

- Add gateway-enforced, per-camera still-image refresh intervals, including
  manual-only refresh, without storing images or exposing video or audio.

## 0.1.93

- Replace the multi-line Home Assistant App-page artwork with a wide,
  transparent **Guest Access** lockup that makes full use of Home Assistant's
  fixed 40 px logo height.

## 0.1.92

- Keep the expanded brand treatment on the administrator Gateway while
  simplifying individual guest-page headers to only the mark and **Guest
  Access**.
- Reduce the guest-page mark to match the height of the Guest Access wordmark
  and reclaim vertical space for controls.

## 0.1.91

- Add **For Home Assistant** and **Share access. Not your system.** beneath the
  integrated Guest Access header on administrator and guest pages.
- Use the larger primary Guest Access lockup on the Home Assistant App page.
- Retain the **Guest Access** sidebar title and `mdi:shield-account` icon. If an
  existing sidebar shortcut still shows the former title or icon, switch
  **Show in sidebar** off and back on after updating to refresh its registration.

## 0.1.90

- Integrate the transparent Guest Access mark and wordmark directly into the
  administrator and guest page layouts instead of displaying a rectangular
  logo export.
- Move the smaller **Powered by LayerV** attribution to the bottom of both
  pages and remove duplicate Guest Access labeling from the administrator
  header.
- Use the `mdi:shield-account` menu icon and shorten the App title to
  **Guest Access** so Home Assistant can keep it on one line.
- Enlarge the App-page logo.

## 0.1.89

- Rename the customer-facing product to **Guest Access for Home Assistant**
  while retaining LayerV for the underlying connection and qURL terminology.
- Add the new Guest Access app icon, store logo, administrative lockup, and
  guest-page branding with the original LayerV wordmark as a small attribution.
- Use **Guest Access** for the Home Assistant sidebar, email defaults,
  invitations, alerts, and other user-facing labels.
- Allow the page-bound guest endpoint to serve the new branding assets.

## 0.1.88

- Build the lightweight page endpoint with Go 1.26.8 security fixes.
- Cross-compile the endpoint on the native CI runner architecture instead of
  running the compiler through arm64 emulation.

## 0.1.87

- Replace each active page's full Python guest gateway with a small compiled
  page-bound endpoint while retaining a separate process, Linux identity,
  listener, and capability for every externally reachable page.
- Revalidate the endpoint capability against its assigned page inside the
  trusted gateway on every request, and allow the endpoint to forward only
  guest access routes and required guest assets.
- Keep alert recipients, page policy, guest records, and Home Assistant
  authority exclusively in trusted processes; remove legacy per-page data
  copies during upgrade.
- Reduce measured idle endpoint memory to about 4.3 MB per active page on the
  development host.

## 0.1.86

- Start isolated guest endpoint processes only for pages with an unexpired
  guest grant, and remove their page capability and runtime copy when idle.
- Preserve one-process/one-UID isolation for every externally reachable page
  while avoiding roughly one full Python process per unused page.

## 0.1.85

- Fix the mobile-recipient layout in **Configure email & alerts**.
- Add per-recipient mobile notification tests after a destination is saved.
- Show immediate progress and confirmation on the Save button.

## 0.1.84

- Add a global mobile alert recipient allowlist under **Configure email &
  alerts**, so guest setup shows only administrator-approved destinations.
- Discover both `notify.mobile_app_*` actions and modern mobile notify entities;
  enforce the global allowlist again inside the trusted delivery broker.

## 0.1.83

- Fix page-bound guest endpoints so they bind their assigned `127.77.x.x`
  listener instead of entering the retired shared-route listener loop.

## 0.1.82

- Keep each page Connector running while it has any unexpired guest grant,
  including a guest awaiting first-login email verification.

## 0.1.81

- Allow the root supervisor to atomically persist the page-capability registry
  under the enforced Home Assistant AppArmor profile.

## 0.1.80

- Fix startup on Home Assistant by publishing the AppArmor permissions required
  for the page-bound guest endpoint and Home Assistant broker runtime stores.

## 0.1.79

- Add per-guest activity alerts through registered Home Assistant Companion
  App notification targets and a configured administrator email address.
- Let administrators choose alerts for first login, successful entity actions,
  and failed or blocked actions; show alert readiness in Gateway health.
- Replace the shared guest gateway with separately credentialed, page-bound
  endpoint processes; the Home Assistant broker now derives page authority
  from each endpoint's capability and rejects cross-page requests.

## 0.1.78

- Retry migration cleanup when LayerV briefly reports that the retired shared
  Connector resource is still active after an App upgrade.

## 0.1.77

- Show active, dormant, and total page Connector counts in Gateway health.

## 0.1.76

- Include a sanitized HTTP status and error category when automatic cleanup
  of an expired LayerV qURL fails, without logging response bodies or secrets.

## 0.1.75

- Migrate the Connector's separate `local_ip` field to its page-specific
  loopback listener so upgraded Connectors no longer dial the retired shared
  `127.0.0.1:8080` endpoint.

## 0.1.74

- Give every page Connector a unique loopback destination so the Connector
  itself selects the only capability page reachable through its qURL.
- Present one guest qURL instead of separate activation and gateway links;
  keep activity page-attributed until LayerV releases `target_path` support.
- Warm Connectors when pages are created, suspend them after ten guest-free
  minutes, and quickly resume persisted Connectors when a new guest is added.

## 0.1.73

- Preserve protected pages when an expired or insufficient LayerV API key
  blocks the shared-to-per-page Connector migration.
- Revoke legacy guest grants locally before remote cleanup, then return to
  secure onboarding to request a replacement key and retry the migration.

## 0.1.72

- Give every protected page its own LayerV Connector resource and persistent
  audit stream, while retiring the former shared Connector during migration.
- Run page Connectors under stable, unique Linux identities so they cannot
  read sibling Connector state or logs after bootstrap.
- Prepare guest-specific `target_path` tokens behind a disabled release gate
  for LayerV's upcoming Connector support.
- Keep guest invitations usable with per-page activation links and preserve
  capability-bound gateway tokens and revocation behavior.

## 0.1.71

- Replace browser-native confirmation prompts with an in-page confirmation
  dialog so revoke and delete operations work reliably inside Home Assistant
  Ingress.

## 0.1.70

- Separate browser HTTP transport from admin and guest rendering with native
  ES modules and no new runtime dependencies or build step.
- Preserve distinct Home Assistant broker credentials while allowing the
  administrator Preview flow to read state and execute saved actions.
- Add the independent admin-broker credential to disposable demo setup.

## 0.1.69

- Prepare mounted connector storage before dropping privileges so fresh HAOS
  installations can complete LayerV registration.
- Report bounded registration stage, exit-code, and failure categories without
  exposing connector output or credentials, and resume completed route writes.
- Return a controlled retry page while Ingress changes onboarding upstreams.

## 0.1.68

- Bound expired rate-limit buckets so attacker-controlled identifiers do not
  accumulate indefinitely in a long-running Gateway process.
- Release per-page action locks after all active and waiting operations finish
  while preserving action and revocation serialization.
- Consolidate historical feature notes and remove obsolete branding-generation
  infrastructure without changing Gateway behavior or App branding.

## 0.1.67

- Display read-only sensor values in compact, responsive cards instead of
  reserving full control panels for entities with no available actions.
- Keep cameras and actionable entities full-width while removing redundant
  read-only labels from compact sensor cards.

## 0.1.66

- Accept Home Assistant's legacy `image/jpg` camera response type so its JPEG
  demo cameras display alongside PNG, standard JPEG, and WebP cameras.

## 0.1.65

- Add polished, self-contained HTML invitation and verification emails with
  prominent action buttons and one-time-code presentation.
- Retain plain-text alternatives for compatibility while loading no remote
  images, fonts, scripts, or tracking resources.

## 0.1.64

- Allow camera entities to be shared as authenticated, read-only still images.
- Refresh camera stills every 30 seconds without saving them to gateway storage.
- Enforce saved page policy, image type and size checks, no-store caching, and
  per-guest camera refresh rate limits.

## 0.1.63

- Restore the replacement-code action after its cooldown even when a mobile
  WebView suspends the page while the guest checks email.

## 0.1.62

- Hide the replacement-code action while the initial resend cooldown is active.
- Reveal it after a failed verification or after one minute, with a visible
  countdown instead of an apparently nonresponsive button.

## 0.1.61

- Replace the mobile WebView confirmation popup with a reliable two-tap,
  six-second confirmation before invalidating and replacing a code.
- Automatically verify a complete six-digit code whether it is typed,
  AutoFilled, or pasted, removing the redundant visible Verify button.

## 0.1.60

- Format verification email bodies for clearer mobile one-time-code detection
  and add a permission-aware **Paste code** action.
- Confirm before sending a replacement code and clearly warn that the existing
  code will stop working.
- Scroll to, focus, announce, and briefly highlight newly created guest-link
  results so success details do not appear unnoticed below the visible dialog.

## 0.1.59

- Keep an existing unexpired verification challenge when a guest returns to
  the access page, so reopening the page does not invalidate the emailed code.
- Replace a verification code only when the guest explicitly selects
  **Resend code**, while preserving the resend rate limit.

## 0.1.58

- Send verified guests an invitation email containing the LayerV activation
  qURL and their one-time access link when the guest record is created.
- Show invitation delivery status first and place manual QR, copy, and share
  actions under backup sharing options after successful email delivery.
- Send guest verification codes through a direct authenticated loopback broker
  connection that does not depend on HTTP proxy discovery.

## 0.1.57

- Add locally stored, TLS-only SMTP configuration and a test-email action.
- Add optional per-guest email verification with six-digit, single-use codes,
  ten-minute expiry, resend throttling, and a five-attempt limit.
- Require a short-lived HttpOnly, Secure, SameSite session for every guest API
  after verification and invalidate that session when access is revoked.
- Keep SMTP credentials in the isolated administrator runtime; the public guest
  process can request only an email to the address saved with its active grant.

## 0.1.56

- Prefer the native share sheet on capable iPhone, iPad, Android, and desktop
  browsers instead of displaying unreliable email and SMS WebView links.
- Keep email and SMS compose controls as fallbacks when the browser does not
  provide native sharing; QR and copy controls remain available everywhere.

## 0.1.55

- Open email and Messages through real top-level links so iOS can hand their
  URL schemes out of the Home Assistant Ingress frame.
- Follow Apple's supported SMS URL format and copy the complete two-link
  message for the administrator to paste into Messages.

## 0.1.54

- Serve the locally bundled QR encoder from its nested static directory while
  preserving the existing resolved-path boundary against directory traversal.

## 0.1.53

- Generate activation and guest-access QR codes entirely in the administrator's
  browser without sending either bearer link to an external QR service.
- Open native share, email, and text-message compose screens with both links
  clearly numbered for the guest.
- Keep optional email addresses and mobile numbers ephemeral; the Gateway does
  not save, log, or transmit recipient details.

## 0.1.52

- Preserve proximity and other action-denial messages on the guest page
  instead of incorrectly replacing HTTP 403 responses with the expired or
  revoked-link screen.

## 0.1.51

- Add an optional page-level proximity safety check that keeps live status
  visible remotely while requiring guests to be near Home before actions.
- Explain location use before the browser permission prompt and reuse a recent
  successful reading for up to five minutes.
- Validate location freshness and accuracy in the Gateway, and calculate the
  distance inside the HA policy broker without exposing Home's coordinates to
  the guest browser or public Gateway process.

## 0.1.50

- Remove the ineffective optional public port mapping; the qURL Connector
  reaches the guest Gateway through container loopback and Home Assistant
  Ingress remains the administrator entry point.
- Persist Connector audit logs in a Connector-owned directory under App data
  instead of silently falling back to no logging when `/var/log` is not
  writable.
- Add real-socket regression coverage proving that internal brokers reject
  missing or incorrect credentials before invoking privileged backends.

## 0.1.49

- Run first-time LayerV credential onboarding under a dedicated unprivileged
  identity and pass the credential to the trusted App supervisor through a
  one-time inherited pipe.
- Run initial qURL Connector registration under the dedicated Connector
  identity and reject duplicate onboarding submissions.
- Handle shutdown signals during onboarding so the App stops cleanly without
  waiting for container termination.
- Immediately remove stale entity cards and values when a guest link expires
  or is revoked.
- Keep every qURL lifetime control anchored to its own visible label on touch
  devices and narrow browser layouts.

## 0.1.48

- Allow the root App runner to stop the fixed Ingress child after it has
  dropped to its dedicated unprivileged UID.
- Prevent fresh-install onboarding from failing with `PermissionError` while
  cleaning up its owned processes.

## 0.1.47

- Keep the guest activity database group-readable and group-writable for the
  isolated admin and guest processes.
- Prevent guest-page access from locking the admin process out of activity
  summaries and page management.

## 0.1.46

- Assign cooperating processes their required shared storage group as the
  primary GID instead of relying on supplementary container groups.
- Restore deterministic guest reads of existing page definitions and broker
  reads of authoritative policy.
- Continue restricting page and activity data to the admin and guest process
  identities.

## 0.1.45

- Publish the complete process-isolation AppArmor profile with the public
  Home Assistant App Store metadata.
- Permit creation and use of the isolated policy, activity, admin-runtime,
  and LayerV broker stores during upgrade.
- Permit the root supervisor to assign the fixed child-process identities
  before dropping their privileges.

## 0.1.44

- Permit the root App supervisor to create the explicitly allowlisted
  top-level isolation stores when upgrading an existing Home Assistant
  `/data` volume.
- Include the private LayerV broker store in fresh image initialization.
- Restore the 0.1.42 policy migration without broadening access to arbitrary
  `/data` descendants.

## 0.1.43

- Add `/app` to the packaged Python module path so the isolation supervisor
  can import the Gateway modules regardless of the working directory selected
  by Home Assistant Supervisor.
- Restore App startup after the 0.1.42 process-isolation update.

## 0.1.42

- Split the public guest gateway from the Home Assistant Ingress admin
  gateway.
- Move the Supervisor token and LayerV API key into narrow HA and LayerV
  policy brokers.
- Add a broker-owned authoritative policy store containing no guest grants,
  token hashes, qURL links, or activity history.
- Run admin, guest, broker, policy, Connector, and Ingress processes under
  separate Linux users with restrictive file ownership.
- Give the public guest process only the HA action-broker credential; it
  receives no admin, HA, LayerV, discovery, or policy-publication credential.
- Migrate existing pages, active qURL revocation mappings, and guest activity
  into their isolated stores without deleting configured pages.

## 0.1.41

- Close slow or incomplete client requests after a 15-second connection
  deadline.
- Reject more than 64 request headers or more than 32 KiB of aggregate header
  data with HTTP 431.
- Cap active request threads and the queued connection backlog at 64 each.
- Quietly rate-limit repeated unauthorized page reads without adding noisy
  security-history rows; normal authenticated mobile polling remains unlimited.
- Add real-socket adversarial coverage for slow clients, header abuse,
  connection saturation, invalid-read floods, and concurrent valid polling.

## 0.1.40

- Keep primary values and units visible for read-only sensors on narrow mobile
  screens.
- Give read-only entity state a full-width stacked mobile row so long values
  wrap instead of being hidden or truncated.
- Add regression coverage for the read-only mobile-state treatment.

## 0.1.39

- Add real threaded-HTTP adversarial tests for cross-page token isolation,
  forged targets, malformed bodies, replay, concurrency, and revocation races.
- Linearize guest actions with individual revocation, revoke-all, page
  deletion, and LayerV connection reset so no new action can succeed after
  local revocation returns.
- Reject non-object JSON bodies and apply Gateway security headers to
  unsupported-method and parser errors.
- Stop returning Home Assistant service response bodies to guest browsers.
- Increase the bounded HTTP accept queue and use daemon request threads for
  predictable shutdown under concurrent traffic.

## 0.1.38

- Permit the atomic `.reset-connection.request.tmp` file under the enforced
  AppArmor profile so confirmed LayerV connection resets can be scheduled.
- Show reset progress and API failures inside the open confirmation dialog
  instead of only in the obscured page-level status area.
- Add regression coverage for both the temporary and final reset request paths.

## 0.1.37

- Permit SQLite's `guest-activity.sqlite3-journal` rollback sidecar under the
  enforced AppArmor profile.
- Restore guest-activity loading, revoked-guest deletion, retention cleanup,
  and other activity-store transactions that need SQLite's default rollback
  journal.
- Add regression coverage for both rollback-journal and WAL sidecar paths.

## 0.1.36

- Promote the explicit AppArmor filesystem, network, and signal allowlist from
  complain mode to enforcement after Home Assistant startup, update, reset,
  onboarding, Connector bootstrap, page, guest, action, history, and restart
  acceptance testing produced no unexplained AppArmor events.
- Keep the former blanket `file`, `network`, and `capability` grants removed.
- Update regression coverage and operator documentation for enforced denial
  behavior and rollback.

## 0.1.35

- Supply the protected LayerV API-key file to the qURL Connector when its
  durable agent state is absent or incomplete, as required for the first
  bootstrap after onboarding or **Reset LayerV connection**.
- Stop supplying the bootstrap key-file path on later App starts once the
  Connector's agent identity, keys, tunnel identities, and configuration are
  complete.
- Add regression coverage for fresh, partial, and complete Connector state.

## 0.1.34

- Replace the blanket AppArmor `file`, `network`, and `capability` grants with
  an explicit first-pass allowlist for the packaged runtime, App data,
  ordinary TCP/UDP networking, and process supervision.
- Run the candidate profile in AppArmor complain mode so Home Assistant records
  missing permissions without blocking existing pages, guests, or Connector
  state during the acceptance-test phase.
- Document how to collect sanitized AppArmor audit evidence and promote the
  profile to enforcement only after complete onboarding, reset, guest-action,
  expiration, restart, and failure-path testing.
- Add regression coverage preventing blanket AppArmor permissions from being
  restored accidentally.

## 0.1.33

- Stop classifying read-only guest-page loads and automatic status polls as
  invalid-token security incidents.
- Record an invalid-token security event only when a client attempts a Home
  Assistant action with an unrecognized token.
- Remove the false-positive invalid-token rows generated by version 0.1.32.
- Add regression coverage proving reload and polling requests cannot create
  invalid-token history.

## 0.1.32

- Automatically remove expired grants from active page data on the next
  Gateway refresh or expired-link attempt and clean up their LayerV qURLs.
- Retain expired guests and their activity for the normal 30-day review period
  before automatic deletion.
- Add per-page and per-guest security history for invalid tokens, expired-link
  attempts, rate limiting, unapproved actions, and Home Assistant rejections.
- Exclude tokens, request bodies, headers, IP addresses, and arbitrary fields
  from security history, with 30-day and 1,000-event storage limits.

## 0.1.31

- Route revoked-guest deletion through the correct HTTP `DELETE` handler.
- Rename the action to **Delete guest record** and remove both the retained
  revoked-guest entry and all of its activity history.

## 0.1.30

- Add per-guest activity history for successful and failed Home Assistant
  actions, including time, entity, approved action, and safe action parameters.
- Keep the Gateway authoritative for activity attribution and exclude preview
  actions, credentials, access links, headers, and unrestricted request data.
- Show activity from each active guest and retain revoked-guest history for 30
  days, with an immediate **Delete history** option.
- Store activity in an owner-only SQLite database under persistent App data and
  automatically purge expired revoked-guest records.

## 0.1.29

- Treat LayerV `404 Not Found` and `410 Gone` deletion responses as successful,
  idempotent qURL revocation while preserving genuine remote failures.
- Add a read-only Gateway health panel showing the running version, Gateway
  state, LayerV API configuration, page count, and active guest-link count.
- Remove guest labels from qURL creation and revocation audit events while
  retaining non-secret page, grant, and qURL identifiers.

## 0.1.28

- Show a clear expired-or-revoked message when an open guest page loses
  access instead of exposing a JSON parsing error.
- Stop status polling and disable guest controls after access ends.
- Safely handle both JSON and plain-text error responses from the Gateway or
  LayerV edge while continuing to retry temporary failures.
- Rename user-facing “user” terminology to “guest” to reflect that a qURL is
  an access grant rather than a Home Assistant user account.

## 0.1.27

- Stop providing the LayerV API key to the Connector after its initial
  registration; normal starts now use only persistent Connector identity.
- Give the Gateway, Connector, Ingress proxy, and onboarding server explicit
  minimal environments so unrelated Home Assistant and App secrets are not
  inherited by sibling processes.
- Reject page definitions containing entities or actions that do not exactly
  match the Gateway's server-side Home Assistant discovery allowlist.
- Add regression coverage for Supervisor-token and LayerV-key separation.
- Add adversarial tests for cross-page resources, unapproved actions, forged
  Home Assistant targets, extra service parameters, and token separation.

## 0.1.26

- Remove unused JavaScript bindings, HTML hooks, and admin and guest CSS rules.
- Add regression checks for orphaned DOM references, JavaScript functions, and
  CSS classes.
- Add pinned CI checks for static analysis, secrets, dependencies,
  configuration, and the built Home Assistant App image.
- Add weekly Dependabot checks for GitHub Actions and Docker base images.

## 0.1.25

- Remove the unused legacy `/door` interface and pre-deployment plaintext-token
  migration path.
- Add a Home Assistant configuration ceiling for qURL lifetimes, defaulting to
  the LayerV Free-plan limit of three days.
- Support custom whole-number lifetimes in minutes, hours, or days and hide
  presets above the configured plan limit.

## 0.1.24

- Add a preview-only toolbar with a **Back to Gateway** action.
- Keep the toolbar out of issued guest access pages and provide an
  Ingress-root fallback when browser history is unavailable.

## 0.1.23

- Poll the Ingress upstream during reset and reload only after onboarding is
  actually ready, eliminating the remaining transient 404 race.
- After API-key submission, wait for the registered Gateway to become healthy
  before reloading back into its administration page.

## 0.1.22

- Open previews in the current Home Assistant App view so mobile Companion App
  WebViews retain their authenticated Ingress session.
- Use the Home Assistant Back action to return from a preview to the Gateway.

## 0.1.21

- Keep Home Assistant Ingress available while a LayerV connection reset
  transitions from the Gateway to onboarding.
- Preserve the internal Ingress authentication token across the transition so
  the existing App page reloads directly into **Connect to LayerV**.

## 0.1.20

- Add a confirmed LayerV connection reset that revokes every user locally
  before attempting remote qURL cleanup.
- Preserve access-page definitions while removing the old connector
  credential, identity, configuration, and state.
- Return directly to authenticated onboarding so a new connector can be
  registered and new user links issued.
- Remove the API-key recovery field from Home Assistant App configuration.

## 0.1.19

- Add a first-run **Connect to LayerV** screen inside authenticated Home
  Assistant Ingress.
- Write onboarding credentials directly to the owner-only secret file without
  placing them in Home Assistant App options.
- Retain the Configuration API-key field only as a recovery override.
- Shorten the Home Assistant sidebar title to **LayerV Gateway**.

## 0.1.18

- Replace the initial path-level AppArmor rules with a compatibility profile so
  Python can import packaged modules and the connector can initialize its
  private container audit log.

## 0.1.17

- Allow Python's shared runtime library under `/usr/local/lib` in the AppArmor
  profile so the App can start while remaining confined.

## 0.1.16

- Stop persisting plaintext guest bearer tokens and scrub legacy page records
  automatically at startup.
- Accept administrative Ingress traffic only from Home Assistant's trusted
  proxy and keep the gateway listener on the container loopback interface.
- Withhold upstream API response bodies and connector registration output that
  could contain authentication material.
- Add a custom AppArmor profile, a private vulnerability-reporting policy, and
  keyless Cosign signing for published container images.
- Document how to remove the duplicate LayerV API key from App options after
  its protected key file has been initialized.

## 0.1.15

- Link the App, gateway dashboard, guest footer, and documentation to
  LayerV.ai.
- Use a layered monochrome sidebar icon that echoes the LayerV mark.
- License the gateway code under MIT while reserving LayerV brand assets.

## 0.1.14

- Add LayerV App Store logo and icon assets.
- Explain LayerV, guest access, security, and every configuration option.
- Add branded context to the admin start page.
- Add sticky Users and Save page actions at the bottom of the editor.

## 0.1.13

- Stack range labels, sliders, and actions into touch-friendly mobile rows.
- Keep entity names and state text from squeezing or overflowing narrow cards.
- Adapt action, choice, select, climate, and parameter controls down to
  small-phone widths.

## 0.1.12

- Copy generated links from inside the active user dialog instead of an inert
  page element.

## 0.1.11

- Copy generated links synchronously while browser click permission is active.
- Make newly generated URLs directly selectable if browser policy blocks copying.

## 0.1.10

- Load guest preview assets and APIs through the Home Assistant Ingress path.
- Fall back when the Ingress Clipboard API exists but rejects writes.
- Display newly generated activation and access links as readable rows.

## 0.1.9

- Open preview pages inside the current Ingress session.
- Copy links on non-secure LAN origins where the Clipboard API is unavailable.
- Present generated activation and access links in a readable grid.

## 0.1.8

- Build browser asset and API URLs from Home Assistant's validated
  `X-Ingress-Path` instead of the outer App page URL.

## 0.1.7

- Save existing pages through an Ingress-compatible authenticated POST
  endpoint while retaining PUT compatibility.
- Report non-JSON proxy responses with their HTTP status and content type.

## 0.1.6

- Let private Home Assistant Ingress supply admin authentication without
  requiring an admin token in the browser URL.
- Preserve explicit token authentication for direct `/admin` access.

## 0.1.5

- Keep admin styles, scripts, and API requests under the Home Assistant
  Ingress URL prefix.

## 0.1.4

- Open the admin shell when Home Assistant requests the App Ingress root.
- Permit same-origin Home Assistant framing only on the private Ingress
  response while retaining the public gateway's frame prohibition.

## 0.1.3

- Keep the configured LayerV key file available to the embedded connector
  during startup so placement-cache files cannot be mistaken for a completed
  agent identity.
- Continue storing the key only in protected App storage and pass its file path,
  not its value, to the connector process.

## 0.1.2

- Store connector identity directly in `/data/connector-state` instead of
  presenting that directory through a symlink rejected by the connector.
- Pass the persistent state directory to connector registration and runtime.
- Preserve sanitized connector failure details without exposing API keys.

## 0.1.1

- Replace the unsupported `/v1/connectors` onboarding request with the LayerV
  Connector's supported tunnel registration flow.
- Reuse the saved route and agent identity on restart.
- Keep connector registration failures free of API response bodies and tokens.

## 0.1.0

- Add the initial Home Assistant App package.
- Use Supervisor-provided Home Assistant API authentication.
- Register and persist a LayerV qURL Connector during first-run setup.
- Separate Home Assistant Ingress administration from public qURL traffic.
