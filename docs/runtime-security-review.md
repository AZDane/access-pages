# PR #61 runtime security review

Review date: 2026-10-26. This is a point-in-time assessment of the pinned
Home Assistant image, not a vulnerability waiver. Reassess when the image,
advisory database, application features, or confinement changes.

## Runtime selection

The official Python release is 3.15.2; the corresponding security release on
the previous feature line is 3.14.10. Registry checks found no official
`3.15.2-slim-bookworm`, `3.15.2-slim-trixie`, `3.15.2-alpine`, or
`3.14.10-slim-bookworm` manifest. The `3.15-slim-bookworm` manifest still resolves
to the pinned 3.15.1 index, with both amd64 and arm64 children:

| Object | SHA256 |
| --- | --- |
| Multi-architecture index | `575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853` |
| amd64 | `57f8539684eacb0932ead2cb9ed1f5fc9a5995a0ed6a8cd48d6819804c9133e6` |
| arm64 | `068056ab73253c7e73f337bdd9655d6ab243b0a27c2c7800dc5b65fedfebe2e1` |

Keep the reviewed image pinned while the patched official image is unavailable.
Returning to the available 3.14.9 image would retain the same missing fixes and
require another interpreter, license, and AppArmor change. It is not a verified
security improvement. Do not substitute a floating tag or unofficial build.
Before advancing to external beta, recheck the registry and move to a patched
official release with both architectures, matching license bytes, exact Python
AppArmor execution path, and all packaging checks.

The missing fixes have distinct applicability:

* **CVE-2026-115557, emSign incident:** 3.15.2 adds compromised-intermediate SPKI
  rejection, including cases involving explicitly supplied trust. The packaged
  `ca-certificates` is `20250419~deb12u2`; the affected emSign ECC Root CA - G3
  is already absent from the system bundle and Python's default SSL context.
  Its SHA256 fingerprint is
  `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`.
  The runtime probe checks this absence. Python and qURL use the system CA
  configuration. This mitigates their default trust path; it does **not** make
  Python 3.15.1 equivalent to the patched interpreter when other trust is supplied.
  Certifi's corrected 2026.10.19 release retains the unaffected G1, C1 and C3
  roots. Deleting those roots would not be justified by the reviewed incident.
* **CVE-2026-114583, tar filtering:** production sources do not import `tarfile`
  or expose archive extraction. The affected symlink extraction path has no
  identified application entry point.
* **Cookie jar version validation:** production code does not use
  `http.cookiejar` or an HTTP cookie processor. This missing fix has no identified
  application entry point. Bundled pip and ensurepip are removed from the image.

Sources: [Python releases](https://www.python.org/downloads/),
[release announcement](https://blog.python.org/2026/10/python-3152-31410-31318-31216-31118/),
[CPython CA fix](https://github.com/python/cpython/issues/160040),
[CPython tar fix](https://github.com/python/cpython/issues/160097), and
[Certifi corrected root selection](https://github.com/certifi/python-certifi/compare/2026.10.18...2026.10.19).

## Why the existing scan passes

The existing image gate uses `ignore-unfixed: true`, severity HIGH/CRITICAL,
and exit code 1. The 61 unfiltered records all have an empty Bookworm fixed
version in the reviewed Trivy database, including affected, deferred, and
will-not-fix statuses. They are therefore excluded from that gate. Passing it
does not mean the image has zero vulnerabilities.

The gate and existing ignore file remain unchanged. Additional non-blocking
unfiltered inventory steps expose these findings for both architectures in CI.
Those report steps deliberately exit zero; they are visibility, not evidence
that the reported vulnerabilities were fixed or accepted.

The refreshed amd64 scan with Trivy 0.76.1 reports **59 HIGH + 2 CRITICAL package
records, representing 15 distinct CVEs across 8 source-package families**.
For example, six util-linux CVEs are repeated against eight binary packages,
accounting for 48 records. Count unique CVEs separately from affected packages.
Both native architecture CI scans reproduced the same 61-record inventory.

## Finding-by-finding assessment

The following rows link to Debian's advisory evidence. None has an available
fixed Bookworm candidate in the configured repositories at review time.
References to Trixie/unstable/upstream fixes are not an instruction to mix
distribution packages or bypass package verification.

| CVE | Records | Applicability and actual exposure | Available fix outside Bookworm |
| --- | ---: | --- | --- |
| [2023-45853](https://security-tracker.debian.org/tracker/CVE-2023-45853) | 1 CRITICAL | MiniZip component is absent; no MiniZip files, pyminizip, or `zipOpenNewFileInZip4_64` symbol in the packaged zlib. Debian explicitly distinguishes the vulnerable source contribution from the Bookworm binary, which does not build it. This is not an exploitable zlib compression path in this image. | Fix exists in MiniZip; replacing the unrelated zlib binary is not a remedy for an absent component. |
| [2025-7458](https://security-tracker.debian.org/tracker/CVE-2025-7458) | 1 CRITICAL | Installed SQLite is affected by crafted SQL involving many ORDER BY expressions. Application SQL statements inspected in the persistent stores are fixed strings with bound values; there is no raw SQL or database upload endpoint. No reachable trigger identified. This remains a vulnerable library, not a claim of immunity to future SQL features. | SQLite 3.42+; Trixie `3.46.1-7+deb13u2`. |
| [2026-11822](https://security-tracker.debian.org/tracker/CVE-2026-11822) | 1 HIGH | SQLite FTS5 malformed database/MATCH path. FTS5 **is compiled in**, but the application does not create FTS5 tables, run MATCH queries, or import untrusted databases. Data stores are protected by service ownership. An ability to replace database files or add such features invalidates this assessment. | SQLite 3.53.2; Trixie `3.46.1-7+deb13u2` backport. |
| [2026-11824](https://security-tracker.debian.org/tracker/CVE-2026-11824) | 1 HIGH | Same FTS5 exposure constraints as above; not dismissed merely because ordinary SQLite queries succeed. | SQLite 3.53.2; Trixie `3.46.1-7+deb13u2` backport. |
| [2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | 4 HIGH | `infocmp` analyze_string overflow. The executable is present but is not called by the app and is not executable under its AppArmor profile. ncurses package presence alone does not expose the command's input parser through the web app. | Upstream ncurses `6.5-20251213`; Trixie also affected. |
| [2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | 2 HIGH | Requires systemd-homed managed login. `systemd-homed` is absent and no such service runs; the findings are attached to libsystemd/libudev binaries from the same source package. | Unstable systemd 261.2; Trixie also affected. |
| [2026-41992](https://security-tracker.debian.org/tracker/CVE-2026-41992) | 1 HIGH | Crafted LZW then LZH input to `gzip -d`. No application invocation/upload extraction path; profile denies gzip execution. Python's gzip module is a separate implementation. | Trixie gzip `1.13-1+deb13u1`. |
| [2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | 1 HIGH | Privileged pathname ACL API symlink traversal. Application permission repair uses descriptor-based ownership/mode operations, not the libacl pathname API. No identified application call path. | libacl 2.4.0 in unstable introduces ABI changes; Trixie also affected. |
| [2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613) | 8 HIGH | fstab user/users mount-target race needs an authorized mount and writable path ancestor. No such fstab entries, mount invocation, raw-device grant, or SYS_ADMIN permission is supplied by the App. Mount execution is denied by the profile. | Trixie util-linux `2.41.5-0+deb13u1`. |
| [2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615) | 8 HIGH | Crafted extended-partition metadata in libblkid. Application neither probes disk images nor uses libblkid; App configuration exposes no raw devices. No identified input path. | Trixie util-linux `2.41.5-0+deb13u1`. |
| [2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | 8 HIGH | Failed mount-helper ownership/idmap hooks. Requires privileged mount workflow and relevant options. Neither exists in the App; profile denies mount helpers and SYS_ADMIN. | Upstream util-linux 2.42.3; Trixie also affected. |
| [2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | 8 HIGH | `nsenter --join-cgroup` descriptor inheritance. Installed nsenter 2.38.1 does not have this option (verified help and binary); it is also not an allowed executable. A source-family match does not establish that this later feature exists. | Upstream util-linux 2.42.3; Trixie also affected. |
| [2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | 8 HIGH | `X-mount.subdir` detached mount path, requiring Linux 6.15+ and a configured authorized mount. Do not assume a safe host kernel version: rely on the absent mount workflow and enforced executable/capability restrictions. | Upstream util-linux 2.42.3; Trixie also affected. |
| [2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | 8 HIGH | Restricted bind-source fstab race with mount ownership options. Same absent mount workflow and profile restrictions. | Upstream util-linux 2.42.3; Trixie also affected. |
| [2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | 1 HIGH | Perl Archive::Tar entry-size exhaustion. `Archive/Tar.pm` is absent from perl-base and the application does not execute Perl. | Archive::Tar 3.10 / Perl 5.42.3; Trixie also affected. |

The eight util-linux binaries are bsdutils, libblkid1, libmount1, libsmartcols1,
libuuid1, mount, util-linux, and util-linux-extra. The four ncurses binaries are
libncursesw6, libtinfo6, ncurses-base, and ncurses-bin.

The OpenSSL issue with an available Bookworm fix, CVE-2026-84782, was remediated
in this PR by updating both openssl and libssl3 to `3.0.22-1~deb12u2`. Runtime
checks enforce that minimum. The base already includes the reviewed pcre2 and
Perl fixes; version assertions preserve those minimums. No extra package removal,
cross-distribution package replacement, vulnerability ignore, or security-boundary
relaxation was introduced to make the remaining counts disappear. A Trixie move
would fix some SQLite/gzip/util-linux findings but leave other findings and change
the entire runtime base. It needs a separately validated base migration rather
than being presented as a targeted complete fix.

## Verification and limits

`packaged_runtime_probe.py` checks the actual interpreter, executable aliases,
OpenSSL package versions, omitted pip/ensurepip, shipped notices, exact Python
license bytes, and default CA distrust. It runs outside AppArmor because package
inspection executables are intentionally not allowed by the product profile.

`packaged_app_probe.py` starts the unmodified packaged supervisor with disposable
data and a synthetic loopback HA API. It verifies onboarding, all service startup,
unauthenticated denial, forged ingress-header denial, discovery, page policy
publication, preview authentication, an allowed HA action, rejection of an
unapproved action, clean shutdown/restart, and retained configuration/pages.
It uses synthetic credentials with networking disabled. It does not prove live
LayerV enrollment or actual Supervisor ingress. Options are mounted read-only,
matching the profile instead of widening it for test fixture creation.

CI runs the complete unit suite in the shipped Python image with Node added only
to a disposable test derivative. It builds/runs native amd64 and arm64 packages,
runs existing security/permission/qURL probes, and runs startup/security probes
under the exact AppArmor profile on capable runners. Check the actual logs:
the AppArmor step explicitly reports a skip if a runner lacks enforcement.

Remaining external-beta acceptance requirements include live disposable LayerV
enrollment, external guest access/revocation, SMTP delivery/verification, outbound
TLS handshakes and rejected-certificate tests under confinement, and an actual
upgrade/restore persistence cycle. Supervisor installation, authenticated ingress,
a real HA entity action, restart persistence, and audit-log inspection were
verified in the disposable environment below. Real HAOS execution was amd64;
ARM64 has native container coverage, not a second HAOS VM acceptance run.

### Disposable HAOS verification

A new isolated QEMU/KVM VM was created for this review; no pre-existing Home
Assistant instance was used. Official HAOS 18.3 download checksum:
`fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090`.
It reports Supervisor 2026.10.3, Core 2026.10.4, Docker 29.7.2, supported=true,
and Docker AppArmor support. Access is bound to localhost, with a disposable
32 GiB virtual disk, 2 vCPUs and 4 GiB guest RAM.

The exact reviewed amd64 image was imported, the unchanged `access_pages`
profile loaded in enforce mode, and the full startup, real-service-identity
security, and failure/startup probes passed under that profile. An explicit
attempt to execute `/bin/sh` returned PermissionError.

Supervisor then installed a sandbox-only local App derived from that exact
image. The local installation fixture removes the public `image` setting and
uses a one-line Dockerfile inheriting the reviewed image through a registry
bound to VM loopback, accommodating Supervisor's mandatory base pull. It does
not alter application files, command, environment, profile, privileges or slug.
Supervisor names its loaded profile `local_access_pages`; both the container
inspection and kernel profile list confirmed it was enforced. Nothing was
published to a public registry or deployed to an existing installation.

A disposable HA owner and `input_boolean.access61_probe` entity were created.
The App's normal options explicitly included input_boolean for this test.
Verified through authenticated HA ingress: onboarding, real HA discovery,
page creation, admin preview executing `turn_on`, and the actual entity changing
from off to on. Requests without an ingress session and unapproved actions
were denied. A Supervisor-managed App restart retained the configured page
and resumed authenticated access. The LayerV key was deliberately synthetic;
no enrollment, public guest URL, or external LayerV success is claimed.

Audit logs contain denied reads of `/usr/local/bin/`, `/etc/ssl/openssl.cnf`,
process fd/cgroup metadata, and `/proc/sys/net/core/somaxconn`. These did not
prevent the exercised flows. Do not describe the audit as empty or widen the
profile simply to hide these events. The installed OpenSSL configuration has
an empty initialization section; default SSL contexts inside and outside the
profile have identical CA/cipher digests, CERT_REQUIRED, hostname checking,
minimum TLS 1.2, and security level 2. This checks current effective defaults,
not live handshake behavior or future configuration changes. The denied process
metadata/backlog probes still need observation during live Connector acceptance.

All five jobs passed at `2af7d3f` in
[Security run 40368916751](https://github.com/AZDane/access-pages/actions/runs/40368916751):
static analysis and 428 tests; secret scan; dependency/configuration scan;
amd64 image build, shipped-runtime 428 tests, package/security probes and actual
AppArmor enforcement; native arm64 image build and package/security probes.
Local Ruff/Bandit, the shipped-runtime 428 tests, and `git diff --check` also
passed. Unfiltered reports still contain the findings above.

**Readiness:** keep PR #61 draft pending the patched official Python image and
its repeat validation. The existing package findings have documented exposure
constraints, not a blanket zero-vulnerability claim. External beta remains
blocked on the live-service and upgrade/restore acceptance tests above, even
after the runtime image is updated. No merge or release was performed.
