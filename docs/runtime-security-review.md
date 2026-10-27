# PR #61 runtime security review

Review date: 2026-10-26 (America/Phoenix). This is a point-in-time assessment,
not a vulnerability waiver. Reassess when the image, advisory database,
application features, or confinement changes.

## Runtime selection and actual versions

Use the official **Python 3.15.2 slim-Trixie** image. Both architecture manifests
are available and are selected through this immutable index:

| Object | SHA256 |
| --- | --- |
| Multi-architecture index | `197f6622a70b727a4e61bdac13a73b4e2b914b896aa5a729ceb1f45a09bde5fa` |
| amd64 | `7ce16513bf93a92cb89160580a412fa2735707ce2a312257b7a1fd8242cd11c6` |
| arm64 | `e9224bd0237eb3cee008ac91aeceb0a293f5983478283328d14005f826a34ba1` |

The packaged probes verified these versions in **both final architecture images**:

| Component | Runtime / Debian package version |
| --- | --- |
| Python | `3.15.2` |
| SQLite | `3.46.1` / `libsqlite3-0 3.46.1-7+deb13u2` |
| OpenSSL | `3.5.7` / `openssl`, `libssl3t64`, `openssl-provider-legacy 3.5.7-1~deb13u3` |
| glibc | `2.41` / `libc6`, `libc-bin 2.41-12+deb13u4` |
| CA certificates | `20250419+deb13u1` |
| util-linux | `2.41.5-0+deb13u1` |
| ncurses | `6.5+20250216-2` |
| systemd libraries | `257.13-1~deb13u1` |
| libacl1 | `2.3.2-2+b1` |
| perl-base | `5.40.1-6+deb13u1` |
| zlib1g | `1:1.3.dfsg+really1.3.1-1+b1` |

Python 3.15.2 supplies the previously missing interpreter security fixes,
including compromised-intermediate rejection and tar filtering. The default CA
probe still checks that the affected emSign ECC Root CA - G3 fingerprint is
absent. Trixie supplies backported fixes for the three HIGH/CRITICAL SQLite
advisories and the current OpenSSL fix; SQLite's upstream version alone does
not identify Debian's backports. Build assertions enforce minimum Debian
versions for SQLite, OpenSSL, pcre2 and Perl.

The exact Python license bytes match the installed interpreter (SHA256
`b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231`).
Notices and packaging assertions use the 3.15.2 license name. The development
Alpine image also advances to pinned 3.15.2. The production executable remains
`/usr/local/bin/python3.15`; the exact AppArmor rule requires no further change
for this patch release. No new executable, capability or file-access grant was
added for Trixie.

Sources: [Python releases](https://www.python.org/downloads/),
[Python security release announcement](https://blog.python.org/2026/10/python-3152-31410-31318-31216-31118/),
[Debian SQLite tracker](https://security-tracker.debian.org/tracker/source-package/sqlite3),
and [OpenSSL CVE-2026-84782](https://security-tracker.debian.org/tracker/CVE-2026-84782).

## Standalone mount removal

The pinned Trixie base contains 88 installed Debian packages. Its `mount`
package is non-Essential and has no installed reverse dependency requiring it.
APT's simulated purge selected only that package. The actual final image
contains 87 Debian packages: **only mount is removed**, with no other package
added or version changed from the pinned base. `apt-get check` and
`dpkg --audit` pass; both mount and umount executables are absent.

The application does not invoke these commands. HAOS/Supervisor supplies
container mounts externally; installation, upgrade, startup, ingress, actions
and restart passed after removal. Shared libmount/libblkid dependencies and
Debian's Essential packages, maintenance tools, libraries and metadata remain.
There is no forced removal, autoremove or cross-distribution package mixing.
The existing multi-stage build continues to keep qURL download tools and the
Go compiler out of the final image; pip/ensurepip remain removed.

This is a small reduction in available privileged utility code. It does not
remove util-linux's shared libraries or every utility from that source package,
and is not a claim that every corresponding scanner record is eliminated.

## Same-database vulnerability comparison

Trivy 0.76.1 scanned the previous final Bookworm image and the final Trixie image
with the same refreshed database, all severities, and without ignoring unfixed
findings. Local scan timestamps were 2026-10-27 06:40 UTC. Native AMD64 and ARM64
CI scans independently reproduced the Trixie totals below.

| Inventory | Previous Bookworm | Trixie |
| --- | ---: | ---: |
| CRITICAL records | 2 | 0 |
| HIGH records | 59 | 40 |
| MEDIUM records | 91 | 57 |
| LOW records | 89 | 60 |
| UNKNOWN records | 5 | 4 |
| All package/advisory records | 246 | 161 |
| Unique advisory IDs, all severities | 111 | 72 |
| Unique HIGH/CRITICAL CVEs | 15 | 8 |

**No new advisory IDs at any severity** appeared in the same-database
comparison. There are no reported fixed versions for the remaining findings
in that snapshot. This is not a promise that all future databases will agree.

Seven HIGH/CRITICAL IDs disappear: SQLite CVE-2025-7458, CVE-2026-11822 and
CVE-2026-11824; util-linux CVE-2026-53613 and CVE-2026-53615; gzip
CVE-2026-41992; and zlib/MiniZip CVE-2023-45853. The first six have Trixie fixes.
The MiniZip component was absent from the old binary too, so its disappearance
is a scanner-attribution change, not removal of an exploitable old zlib path.
SQLite still has two MEDIUM and two LOW findings; do not describe it as free of
vulnerabilities. The MEDIUM changeset/session-extension findings have no
identified application path: Access Pages does not apply external changesets
or accept uploaded databases. Ordinary persistence uses fixed SQL and bound
values. Future use of those APIs requires reassessment.

The existing blocking gate remains HIGH/CRITICAL with `ignore-unfixed: true`.
It passes because remaining findings lack a reported distribution fix, not
because they are absent. The ignore file and blocking policy are unchanged.
The additional all-severity unfiltered reports deliberately exit zero to
preserve visibility; they are not vulnerability waivers.

## Remaining HIGH findings and changed applicability

| CVE | Records | Applicability and actual exposure | Fix status |
| --- | ---: | --- | --- |
| [2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | 4 | `infocmp` parser overflow. Executable present, no application invocation, AppArmor denies execution. ncurses libraries also support Python terminal modules and Debian utilities. | Upstream ncurses `6.5-20251213`; no reported Trixie fix. |
| [2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | 2 | Requires systemd-homed managed login. That component/service is absent; findings attach to libsystemd/libudev from the same source. | Unstable systemd 261.2; no reported Trixie fix. |
| [2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | 1 | Privileged pathname ACL API symlink traversal. Application permission repair uses descriptor-based ownership/mode operations, not this API. No identified application call path. | Upstream libacl 2.4.0 changes ABI; no reported Trixie fix. |
| [2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | 8 | Mount-helper ownership/idmap hooks require a privileged mount workflow. App supplies none; standalone mount is removed, profile disallows remaining helpers and SYS_ADMIN. | Upstream util-linux 2.42.3; no reported Trixie fix. |
| [2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | 8 | **Trixie's nsenter has `--join-cgroup`; Bookworm lacked it.** Treat the affected feature as present. Application does not invoke it; enforced AppArmor denies even `nsenter --help`, including as container root. No SYS_ADMIN grant. | Upstream util-linux 2.42.3; no reported Trixie fix. |
| [2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | 8 | `X-mount.subdir` detached mount path requires an authorized mount workflow. Rely on absent workflow and executable/capability restrictions, not an assumed host kernel version. | Upstream util-linux 2.42.3; no reported Trixie fix. |
| [2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | 8 | Restricted bind-source fstab race with mount ownership options; same absent mount workflow and confinement. | Upstream util-linux 2.42.3; no reported Trixie fix. |
| [2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | 1 | Perl Archive::Tar entry-size exhaustion. Archive/Tar.pm is absent from perl-base and the application does not execute Perl. | Archive::Tar 3.10 / Perl 5.42.3; no reported Trixie fix. |

The util-linux records repeat against bsdutils, libblkid1, liblastlog2-2,
libmount1, libsmartcols1, libuuid1, login and util-linux. Trixie adds login and
liblastlog2 source attribution while removing the old mount/util-linux-extra
attribution. Equal CVE identifiers therefore do not imply identical installed
code. The ncurses records repeat against libncursesw6, libtinfo6, ncurses-base
and ncurses-bin. Dependencies needed for Debian packaging remain supported;
absence of observed application use alone is not grounds for deleting them.

The nsenter change is additional dormant code exposure, explicitly tested
behind unchanged confinement. No newly reachable application trigger was
identified. Required SQLite fixes, patched Python and the broader reduction
in findings make Trixie the safer practical choice on the evidence tested.
This is not proof against arbitrary application compromise or future features.

## Verification and limits

[Security run 40462870304](https://github.com/AZDane/access-pages/actions/runs/40462870304)
passed all five jobs at implementation commit `9ea8859`: secret scanning,
static analysis/tests, dependency/configuration checks, native ARM64 packaging,
and AMD64 container checks. Both architectures built successfully and verified
the runtime versions, license bytes, package integrity, CA distrust, security,
permissions and qURL probes. The full **428-test suite** passed in hosted Python
and the shipped runtime (Node added only to a disposable test derivative).
Local Ruff, Bandit, JavaScript syntax checks, the 428-test shipped-runtime suite,
and Go tests with the pinned Go 1.27.3 compiler passed.

The real packaged supervisor probe covers onboarding, service startup, denied
unauthenticated/forged-ingress requests, discovery, policy publication,
authorized/rejected actions and restart persistence with disposable fixtures.
New TLS probes complete real loopback TLS 1.2/1.3 handshakes and reject untrusted
certificates and wrong hostnames. CI actually enforced AppArmor for application,
security, startup and TLS probes; it did not take the runner-unavailable skip.
Package inventory tools deliberately run outside confinement.

### Isolated HAOS acceptance

The existing disposable AMD64 QEMU/KVM sandbox runs HAOS 18.3, Supervisor
2026.10.3 and Core 2026.10.4, with localhost-only access, 2 vCPUs, 4 GiB RAM and
a 32 GiB virtual disk. No other project's HA instance was used.

The locally built candidate image index was
`sha256:21a5520be4071ce654f2d555ae2a245a4a996f289c498e8c0f1e37ccf2f019cd`.
Its AMD64 image was imported into the VM and installed through a sandbox-only
local App fixture inheriting that image from a VM-loopback registry. The fixture
omits the public image setting; application files, profile, command, service
identities and privileges remain unchanged. Nothing was publicly published.

Verified after upgrading the existing Bookworm App to Trixie:

- Supervisor installation/startup, unchanged configuration hash and retained
  pre-upgrade page.
- Authenticated ingress, real HA entity discovery, creation of another page,
  preview action changing `input_boolean.access61_probe` from off to on, and
  rejection of unauthenticated ingress and unapproved actions.
- Supervisor restart retained both pages and restored authenticated access.
- Container inspection and the kernel list show `local_access_pages` enforced.
  Shell and nsenter execution are denied even for a root process inside the App.
- Application, security, startup and TLS probes passed under the unchanged
  `access_pages` profile inside HAOS. Runtime inspection confirmed 3.15.2,
  SQLite 3.46.1 and OpenSSL 3.5.7.

Audit logs are not empty: interpreter-directory, `/etc/ssl/openssl.cnf`, process
fd/cgroup and backlog metadata reads are denied. Exercised flows and actual
TLS handshakes/certificate-rejection checks passed. Do not broaden the profile
to silence these events; live Connector acceptance must still observe them.
A synthetic LayerV key was used, with no enrollment or public guest URL.
ARM64 has native container coverage, not a second HAOS acceptance VM.

**Merge assessment:** the patched-runtime availability blocker is resolved and
no tested Trixie regression warrants reverting to Bookworm. The implementation
is technically ready for owner review and merge after final-head required
checks pass; keep PR #61 draft as requested. Remaining package findings have
bounded exposure assessments, not blanket acceptance or suppression.

**External beta is not ready:** live disposable LayerV enrollment, external
guest access/revocation, SMTP delivery/verification, real outbound service TLS
under confinement, and backup/restore acceptance remain incomplete. Loopback
TLS, an actual Bookworm-to-Trixie App upgrade, and restart persistence are
verified; they do not substitute for those external-service/restore tests.
No merge, public deployment or release was performed.
