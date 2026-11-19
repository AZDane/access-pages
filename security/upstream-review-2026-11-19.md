# Assessment review, November 19, 2026 (UTC)

Review of [issue #97](https://github.com/AZDane/access-pages/issues/97), against
main `ac55d0f6d9f84fe3815e78d3c358a6646f5e4d1f` and the existing
[evidence policy](README.md). This is a technical review for owner adoption
through the protected pull-request process, not independent risk approval.

## Stable Debian availability and exposure

Refreshed Trixie and Trixie-security APT indexes in a disposable App container,
including both amd64 and arm64 package indexes. Both architectures offer the
same candidate versions shown below; none supplies a fix for these findings.
The linked Debian advisories were also read on November 19. No sid packages,
local library rebuilds, forced dependency removals or scanner exceptions are
introduced.

| Finding | Stable candidate | Current upstream fix / reassessed exposure |
| --- | --- | --- |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | ncurses `6.5+20250216-2` | infocmp overflow fixed upstream in 6.5-20251213; Debian unstable fix 6.6+20251231-1. Application does not invoke infocmp; its executable is denied by the unchanged AppArmor allowlist. Libraries remain installed and affected. |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | systemd libraries `257.13-1~deb13u1` | Fixed in 261.2-1 in unstable. Requires homed-managed login; systemd-homed is absent from the packaged filesystem. |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | libacl1 `2.3.2-2+b1` | Fixed in 2.4.0-1 in unstable; Debian notes a new ABI. No application pathname ACL operation. Runner repair uses descriptors, refuses symlinks and special files, and preserves private service ownership. |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | util-linux `2.41.5-0+deb13u1` | Fixed in 2.42.3-1 in unstable. No authorized mount-helper or ownership/idmap workflow. Standalone mount/umount absent; no SYS_ADMIN grant or helper execution permission. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | util-linux `2.41.5-0+deb13u1` | Current tracker specifies **2.42.4-1**, correcting the historical review's 2.42.3 claim. Trixie's nsenter join-cgroup feature exists. AppArmor denies execution even as container root; no SYS_ADMIN grant. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | util-linux `2.41.5-0+deb13u1` | Fixed in 2.42.3-1 in unstable. No authorized X-mount.subdir workflow. Retain mount removal and executable/capability restrictions; do not assume an unaffected host kernel. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | util-linux `2.41.5-0+deb13u1` | Fixed in 2.42.3-1 in unstable. No privileged fstab bind-source workflow or ownership hooks. Same confinement and mount removal. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | perl-base `5.40.1-6+deb13u1` | Archive::Tar 3.10 / Debian Perl 5.42.3-1 fix. Archive/Tar.pm absent; application does not invoke Perl. Debian postpones stable remediation pending upstream regressions. |
| [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | libsqlite3-0 `3.46.1-7+deb13u2` | SQLite 3.54.0 / Debian unstable 3.54.1-1 fix. Requires FTS5 detail=none prefix queries with negative rowids. No FTS schema or MATCH operation in the packaged application. |
| [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374) | libsqlite3-0 `3.46.1-7+deb13u2` | Same fixed release. Requires corrupted FTS5 indexes with secure-delete. No FTS consumer, secure-delete operation or database upload endpoint. |
| [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | libsqlite3-0 `3.46.1-7+deb13u2` | Same fixed release. Requires crafted session changesets. Python's packaged binding exposes no session API; no native bridge or changeset import in application source. |

All binary package/version lists remain exact in the baseline, including the
util-linux source-package attribution to login and seven other packages.
SQLite assessments cover remote application inputs and service-owned databases
only. Arbitrary malicious database replacement, untrusted restores, new SQL
consumers, native bridges or confinement changes invalidate them. These are
bounded exposure decisions, not claims that Debian's libraries are patched.

## Official qURL remediation

GitHub's live release API identifies [v4.4.4](https://github.com/layervai/qurl-integrations/releases/tag/v4.4.4),
published November 18 at 21:42:13 UTC. The cached web `releases/latest` response
was stale; release selection uses the live API and exact tag assets.
Downloaded both official Linux archives and unmodified SPDX inventories and
verified their SHA-256 values against GitHub's release asset digests.

Both binaries' `go version -m` build information and both SBOMs embed
go-jose **v4.1.6**, fixing [CVE-2026-116587](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q),
and x/net **v0.62.0**, fixing [CVE-2026-78661](https://pkg.go.dev/vuln/GO-2026-6860).
The prior main scans already contain no go-jose finding: its old v4.1.4 baseline
entry was stale. Remove that entry and the x/net disposition, rather than renew
either. No locally rebuilt qURL is used.

| Artifact SHA-256 | amd64 | arm64 |
| --- | --- | --- |
| Release archive | `c99cdcb3b489ab2d00fa6d835dcd124d50d9ef7b1b1fe901c143af7a07ef1180` | `c37f249bd6e16eea819c1832aa5a9d483e6ff71714665bfb60aa3fa4dee7390b` |
| qURL executable | `209c4ab14600a8bcab0bff3ffdb8db418f210536118e35193e59fa3812c2676b` | `93186094bdc67f627c3a5351696b6b9afa4aacdd5884f1428836177cc50a5368` |
| Upstream SBOM | `2381ef808e8bec60b16eba835569e148e1a80a4540f087b312236a6e566dded9` | `c5526fdddd23d61a29a40e918cdb43315491859d34c2e186ff09d45d98f2cbb6` |

Complete ELF Go inventories contain 48,073 amd64 and 47,507 arm64 functions,
14 JOSE/OIDC initialization/JSON helper symbols each, and no x/net/html symbols.
All 89 effective Go modules match the upstream SBOMs on both architectures,
including the FRP replacement module. The 25 changed dependency archives
match the h1 checksums embedded in the binaries; the main qURL module is
identified by the release commit. The existing reachability probe remains unchanged even though these two module
dispositions are removed. Exact pinned module license/notice files are replaced
from the corresponding upstream module archives. The MPL yamux source is
unchanged. Both upstream SBOMs remain in the image and in the unfiltered scan.

The only application behavior change is the exact IPC version match from
`6/4.2.0` to `6/4.4.4`, retaining the per-share suffix and process-ownership check.
The upstream protocol remains 6. No SQL, schema, import, command operation,
service identity, capability or AppArmor rule changes. The reviewed
`guest_resources.py` source hash advances accordingly. Existing diagnostics
remain allowlisted; unknown error detail is not exposed.

## Architecture evidence and validation

Investigation input: successful native main
[Security run 44184824565](https://github.com/AZDane/access-pages/actions/runs/44184824565)
at `ac55d0f6d9f84fe3815e78d3c358a6646f5e4d1f`.
Downloaded vulnerability artifacts 14374380754 (amd64) and 14373383427 (arm64).
Each complete report passes the unchanged policy with its own image-bound
evidence. Both contain 46 HIGH, zero CRITICAL, 94 MEDIUM, 64 LOW and 17 UNKNOWN
records. The 46 HIGH records comprise 43 Debian records and three x/net targets.

Both probes reproduce the baseline's exact application hashes, SQLite binaries,
187 constant SQL calls and schemas, empty session bindings, and approved linked
function inventories. The source and confinement review confirms that the
existing packaged permission, isolation and component-absence probes still
exercise the controls supporting the Debian decisions. The native jobs passed
their packaged tests; amd64 additionally enforced AppArmor and denied shell,
nsenter and infocmp execution. ARM64 native UID/socket/runtime tests complement
that amd64 enforcement test; ARM64 AppArmor enforcement is not claimed.

Fresh candidate evidence: [Security run 44482861746](https://github.com/AZDane/access-pages/actions/runs/44482861746),
head `7bbac8b704b98d5a204918219c9707bf521b089d`, tested merge
`cd3c5a74c53182c57bb90b10f112a543edf6ac4a`. Both native package jobs passed,
including lifecycle/lock/signal checks, real-UID permission repair, isolation,
startup, TLS, scheduling and component absence. AMD64 additionally passed all
544 Python tests inside the image and enforced AppArmor denial of shell,
nsenter and infocmp. The release dry run separately validates both retained
release images without publication.

| Candidate evidence | amd64 | arm64 |
| --- | --- | --- |
| Artifact ID | 14508044881 | 14509431723 |
| Image ID (SHA-256) | `588f10c83e0a024a5cd8100c29b78d28d7d042bcf737760ff897a95ab0066530` | `5b851d04d60db2e133cf7a82f402c806ff85a78d9ba82df3c1f27153022e2356` |
| Report file SHA-256 | `56165f72a4b1970467d32ea6bfb901f49fb15157b31723ab4d00e424922bde79` | `0c7192327705b5b6da58480f8be7f7e9963b58b1e1a3fa932ea2d44b2d8bdbdf` |
| Evidence file SHA-256 | `f2b9f5e78f0c5d34102afe0ca81c74b9bc03d96a8825108532e7097de01d1cbd` | `fc0c3052e9182553fe646a3d7e3a852955ebde86291a6feb11a4dcfd9aab63e3` |

Each fresh report passes the unchanged policy with its own image-bound evidence.
All 87 Debian package entries and all 43 remaining HIGH advisory fingerprints
are identical to main on both architectures. Both probes differ from main only
in the independently verified qURL executable hash and the reviewed
`guest_resources.py` source hash. SQLite binary hashes, 187 constant SQL calls,
schemas, empty session bindings and linked function inventories are unchanged.

Full candidate counts on each architecture: **43 HIGH, zero CRITICAL,
102 MEDIUM, 66 LOW and 10 UNKNOWN**. These are different database snapshots,
not a same-database before/after benchmark. The x/net HIGH and MEDIUM records
and the x/crypto UNKNOWN record disappear from all three Go/SBOM targets.
Existing Debian records were rescored: CVE-2026-115819, CVE-2026-107493,
CVE-2026-124709 and CVE-2026-35190 to MEDIUM; CVE-2026-100290 to LOW.
New UNKNOWN records are CVE-2026-121757, CVE-2026-121758, CVE-2026-124024
(glibc) and CVE-2026-95690 (OpenSSL). Their installed package versions are
unchanged and no fixed version is reported. All lower-severity findings remain
visible, without implicit approval by this HIGH/CRITICAL assessment.

After this fresh upstream, source, binary, confinement and native-image review,
record November 19 as the technical review date for the eleven remaining
Debian dispositions and **December 19, 2026 at 00:00 UTC** as their exclusive
expiry, exactly 30 days later. Before renewal the candidate reports reject all
43 HIGH records on November 26; after renewal they must reject all 43 at the
new expiry. Changed findings or evidence still block immediately. The owner
adopts these decisions through review and merge of PR #98; the alert remains
open until that baseline is adopted on main.

Scanner versions, thresholds, unfiltered reports, artifact retention,
advisory/property/binary pins, expiry rejection and required checks are unchanged.
Historical evidence is never substituted for a candidate's own evidence. No
application release or App Store publication is performed by this review.
