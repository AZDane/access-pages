# Advance scheduled invitations: implementation and validation

The hosted qURL API accepts `not_before` and `expires_at` as whole-second RFC 3339
values. Before the start, these are supplied together, normalized to UTC, without `expires_in`.
The creation response need not echo `not_before`. Access Pages verifies the
returned expiry, target path, resource, single-use setting and session duration;
it never retries by removing the scheduling fields. API refusal blocks delivery.

The live API rejects `not_before` at or before creation time. For the explicit
at-start/catch-up path, when the original start has already passed, creation
sends only the original absolute `expires_at`. This is selected before making
the request, never as a fallback from a rejected future invitation. The local
grant retains the original start. The session duration may exceed the remaining
window after a delay; the absolute end still terminates access.

## Durable state and migration

Schedule database version 3 adds occurrence `send_at` and `revision`, and changes
the uniqueness constraint to (schedule, local date, revision). Existing rows keep
their IDs and revision, and existing definitions receive `delivery=at_start`.
The schedule cursor becomes the revision authorization boundary. Planning looks
through two future local dates (or the selected one-time date), but creates a row
and link only when delivery is due. Old dates are not replayed when resumed.

Creation, commitment, and SMTP retain the existing durable journal. Cancellation
keeps the old grant ID until the broker confirms upstream retirement; a pending
cancellation blocks replacements for the same named guest. Ordinary startup also
finishes local denial for journaled cancellations before guest service starts.
Restore authorization remains separate and blocks restored schedules.

Gateway grants persist `not_before`. The HA broker's shared current-grant check
covers admission, session status, verification, reads, camera access, and the
final action dispatch check. The Admin verification-email and first-access event
paths also check the window. Invalid start timestamps fail closed. Legacy grants
without a lower boundary remain supported.

## Compatibility and limits

The public schema retrieved on 2026-11-14 describes a 30-day link lifetime and a
24-hour session duration. The disposable anonymous/no-sign-up identity test
observed `400 invalid_input: expiry cannot exceed 1 days` for 25-hour invitations,
for both single-use and renewable access. That identity has a separate one-day
limit and does **not** establish the limit for Access Pages' registered account.
No one-day restriction is imposed on registered schedules. New schedules retain
the requested 24-hour advance-delivery default.

The broker distinguishes the at-most-24-hour access/session window from the
creation-to-expiration horizon. The application preserves the owner's existing
`QURL_MAX_LIFETIME_DAYS` setting (default and ceiling 30 days). A far-future
immediate invitation outside that horizon is rejected. Provider account/quota
rejections block delivery with a visible error; no scheduling fields are removed
as a fallback and the original access end is preserved.

A registered-account probe of a link starting in 24 hours and expiring in 25 hours,
using a short session duration, remains unverified because registered credentials
were not available. The owner requested implementation proceed without that probe.

CLI 3.6.0 cannot supply the now-required public resource name. The official 4.2.0
release adds `publish --name`; the App supplies the generic name `Access Pages`,
not the guest's identity. The daemon protocol is 6; the App still requires its
own child PID and exact version/mode. The native enrollment, sealed local key,
external supervision and resource ownership model are preserved.

## Validation commands

- `python3 -m unittest discover -s tests -v`
- `node tests/frontend_runtime.cjs`
- `bash tests/check_packaged_image.sh access-pages-app:advance-test amd64`
- Required native amd64/arm64 CI packaging and complete vulnerability evidence.
- Opt-in `tests/live_advance_invitation_probe.py` uses disposable anonymous CLI
  state and a loopback adapter for its authenticated request bridge. It exercises
  real broker validation, resource publication, scheduled creation, read-back and
  retirement, without SMTP or Home Assistant. Private output must never be logged.

The signature of the official 4.2.0 checksums was verified with Cosign against
`https://github.com/layervai/qurl-integrations/.github/workflows/release-please.yml@refs/heads/main`
and GitHub's OIDC issuer. Both archives and SPDX inventories match those checksums.
Source commit: `168145d207f8fe4e1966590118a50136f6af0514`.

On 2026-11-14 the disposable broker probe and browser check confirmed early
blocking, successful opening of that same single-use invitation after its start,
a successful scoped active-session request, denial of reuse by a second browser,
and denial of the original session's request after the scheduled end. A fresh
control invitation still reached the dummy origin afterward. All disposable
resources were retired; no guest email or Home Assistant operation was used.
The same device-authenticated path rejected the two 25-hour lifetime probes
described above. Account-token limits remain unverified.
