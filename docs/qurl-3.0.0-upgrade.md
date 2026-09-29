# qURL 3.0.0 upgrade review

Prepared App version: **0.1.131**. This change ends at the tested PR stage;
it does not publish images, create a release, or update the public App Store.

## Verified upstream contract

- [qURL CLI release v3.0.0](https://github.com/layervai/qurl-integrations/releases/tag/v3.0.0),
  source commit `b640cb8f4fbd8a4c5045690ddfebadfd81d69a40`.
- [Connector release v0.14.1](https://github.com/layervai/qurl-connector/releases/tag/v0.14.1),
  source commit `640481232df9d9d9e209e869730969ba8edba6dc`.
- [Tagged CLI README](https://github.com/layervai/qurl-integrations/blob/v3.0.0/apps/cli/README.md),
  plus `cmd/daemon.go`, `internal/connector/daemon/{launchagent,runtime}.go`,
  `internal/connector/state/{shares,resource_lock_unix}.go`, and the Connector's
  `pkg/share/frp.go` were checked against Access Pages' publisher and packaging.

The supported CLI archives and their SPDX SBOMs were downloaded and hashed
against the release's `checksums.txt`. Its Sigstore bundle verified with
Cosign 3.0.6 using the exact upstream-documented identity
`https://github.com/layervai/qurl-integrations/.github/workflows/release-please.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`.

| Linux archive | SHA-256 |
| --- | --- |
| `qurl_3.0.0_linux_amd64.tar.gz` | `c6ce79a75c84d2ed378793028c51aab83a12780bb9d5580400caba258fc836f6` |
| `qurl_3.0.0_linux_arm64.tar.gz` | `30972dd3804a8bf02a4f948451e37ecb6d482872ac44fc017e44bd554158dd6f` |

The binary build information confirms Connector 0.14.1 and Go 1.26.6.
The guest endpoint continues to use the already pinned Go 1.27.0 builder;
the license bundle's previously stale toolchain label is corrected. Changed
module license/NOTICE files come from their exact Go module archive versions.
Both shipped SPDX inventories are the unmodified, checksum-verified release
files. The unchanged MPL yamux source distribution remains included.

## Runtime decisions

Every CLI command already carries `--supervision external`; this meets the
new requirement for read operations as well as lifecycle operations. The App
continues to use account-based onboarding, explicit one-time Agent enrollment,
sealed state, and one fresh inherited wrapping-key descriptor per child.
No account key is supplied to qURL. No anonymous enrollment, Unix-origin
conversion, custom trust configuration, or session-group redesign is added.

Health requires exactly `5/3.0.0/per-share` for the App's per-share daemon
and its launched PID. A second daemon can wait up to 60 seconds on upstream's
exclusive `daemon.lock` before IPC exists. Access Pages deliberately retains
a 10-second monotonic readiness budget, rejects a predecessor's status, and
cancels only its own waiting child on timeout. Each IPC attempt is limited to
the remaining budget. Shutdown sends SIGINT, waits up to five seconds, then
kills and reaps the child, leaving headroom in the runner's ten-second budget.
The lock is never removed to force ownership. A later retry can start once
the previous owner has stopped.

The pinned final Python image includes Debian `ca-certificates`
`20250419~deb12u1` and a usable store with 150 CA certificates. A final-stage
build assertion checks the package, bundle and loaded trust roots. qURL's
default tunnel certificate and hostname verification remain enabled.
AppArmor already allows read-only `/etc/ssl/certs/{,**}` and `rwk` inside
the private `/data/access-pages-broker/` tree, including the new lifetime
flock, plus Unix IPC and ordinary TCP/UDP. No permissions were broadened.

The CLI's local-share registry remains version 2. No App persistence schema
or guest-link compatibility machinery is changed, and no upgrade reset or
automatic reenrollment is introduced. Missing or rejected Agent state still
fails closed. Existing guest revocation and durable cleanup mechanisms are
used if the owner replaces links; identity is retained.

## Validation and limits

Local validation uses disposable state and no live Home Assistant or LayerV
credentials:

| Coverage | Evidence |
| --- | --- |
| App behavior and recovery | 409 Python tests pass, including one-time enrollment handoff, publication, per-guest access, expiry, revocation, durable cleanup, reconnect, saved settings and fail-closed identity loss |
| Actual packaged qURL | Offline probe as broker UID 2103: version, CA roots, startup/health, wrong-owner contention (~10 seconds), SIGINT exit 130, released-lock warm restart, brief lock overlap, killed-daemon restart, unchanged identity/registry files |
| Packaged application services | Existing security, startup and permission probes pass with real UIDs: guest access, sessions, expiry/revocation, service outages/restarts, retained settings, symlink/race rejection and queued retirement |
| Static validation | Pinned Ruff/Bandit, JavaScript syntax, Go endpoint tests, AppArmor parser and diff whitespace checks |
| Architecture validation | AMD64 built and exercised locally; the existing native ARM64 CI job builds and exercises ARM64, including the same new qURL probe |
| Required GitHub checks | Static analysis and tests; Secret scanning; Dependencies and repository configuration; Container image. PR results are authoritative for the final commit |

The native lifecycle probe deliberately uses an empty synthetic owner-bound
registry and an envelope sentinel: qURL defers loading credentials until a
route needs a session. It verifies the actual process/IPC/lock contract,
**not** a real enrollment or tunnel. Python publication/enrollment tests use
mocked remote services. Local ARM64 execution is unavailable on the current
host because no ARM64 emulator is registered; CI uses a native ARM runner.

Live acceptance remains separate: fresh enrollment with a disposable account,
new guest publication through the hosted verified TLS tunnel, phone/browser
access to real HA controls, warm restart, expiry, revoke, and network reconnect.
Home Assistant's enforced AppArmor audit logs must also be checked on the
target appliance. No live TLS handshake, NHP admission, account plan/quota,
target-device performance, or HA Supervisor update result is claimed here.

## Installation and recovery

Follow [the App upgrade instructions](../homeassistant-app/DOCS.md#upgrading-to-qurl-300)
after publication is separately authorized. Back up, stop the previous App,
then install and start the released version. Saved pages and settings remain.
Old guest links have no compatibility guarantee; revoke unwanted grants with
the normal controls and let durable remote cleanup finish before replacing
them. A LayerV account/Connector reset is not an upgrade step.

For an ownership timeout, ensure the old App process has stopped and restart;
do not delete `daemon.lock`. For connectivity failures, check time/network
and connection status while preserving TLS verification. For lost sealed
state or its wrapping key, restore the matching backup; do not silently
reenroll or discard the account identity. Rollback requires the matching App
version and data backup, with subsequent revocations reapplied.
