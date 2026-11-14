# Image vulnerability decisions and beta publication

One unfiltered Trivy vulnerability report per architecture is retained for 90
days. `check_vulnerabilities.py` is the only vulnerability policy decision.
Image secret/configuration checks and repository/history checks remain separate.
No finding is deleted, hidden, or assigned a lower severity by this policy.

## Bounded unreachable dispositions

The existing baseline now also accepts `unreachable`. Each record contains an
exact CVE, package/version, scanner-target/advisory fingerprints, both supported
architectures' binary SHA-256 values, reproducible properties, technical evidence,
an accountable owner, review date, UTC expiry and invalidation conditions.
Expiry is exclusive at midnight UTC and cannot exceed 30 days after review.
`component_absent` and `mitigated` retain their previous behavior: an available
fix blocks them. Only an exact, current, reproduced `unreachable` assessment may
cover an available upstream fix. Unknown or changed HIGH/CRITICAL findings block.

`image_evidence.py` hashes the retained OCI graph, relates its index, architecture
manifest and configuration digests to the original scan, and runs
`verify_unreachable.py` inside that exact local image without networking. The
checker binds the resulting evidence to the complete report and architecture.
Binary, application-source, probe, confinement or advisory changes require
reassessment. Merely copying an old evidence JSON to another build does not work.

AZDane owns the policy. A baseline change is proposed in an ordinary feature PR;
the owner adopts it by reviewing and merging that PR through existing checks.
The technical review date records the investigation, not independent human
approval. This is owner-controlled risk acceptance, not independent security
review. An owner who controls code and workflow settings can change the policy.
There is no second manifest, external reviewer service or approval infrastructure.

The approved *properties* are reused only while their exact inputs remain valid;
every image gets fresh evidence and an artifact identity. This deliberately avoids
manual approval of every rebuilt image digest. Updating a dependency is not an
automatic renewal, and refreshing dates without repeating evidence is prohibited.

### SQLite CVE-2026-119373

Affected library: Debian `libsqlite3-0` `3.46.1-7+deb13u2`, SQLite 3.46.1.
The library includes FTS5; this assessment does not claim the library is fixed.
The upstream reproducer requires an FTS5 virtual table with `detail=none`,
negative rowids and a prefix `MATCH` query:
https://sqlite.org/bugs/info/2026-08-04T08:49:27Z

All 147 SQL calls in `activity.py`, `verification.py`, `guest_resources.py`,
`upstream_cleanup.py`, `layerv_broker.py` and `schedules.py` use constant SQL. Values are bound
as parameters. There is no FTS table, MATCH query, extension loading or database
deserialization. The probe executes the declared CREATE statements with the
packaged SQLite and records every schema. It rejects new/dynamic SQL and changes
to the reviewed schemas. All packaged Python modules and the runner are hashed.

Guest HTTP inputs are values, not SQL or uploaded database files. Session,
activity and cleanup stores are owned by their dedicated services; the runner's
descriptor-based permission repair and packaged permission/isolation tests remain
mandatory. The application does not offer a guest database-import endpoint.
The scope is remote application inputs and databases created by Access Pages.
Arbitrary malicious database replacement, untrusted backups, privileged local
compromise, added SQLite consumers or new search/import features invalidate this
assessment. This is not a claim that an arbitrary restored database is safe.

### qURL / go-jose CVE-2026-116587

Affected module: `github.com/go-jose/go-jose/v4` `v4.1.4`, embedded in official
qURL 3.6.0. The upstream fix is 4.1.6:
https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q

Both official release archives were independently downloaded and verified against
the Dockerfile's SHA-256 pins. The resulting executable hashes are recorded in
the baseline. Both ELF Go function tables contain only go-jose initialization
and JSON helpers and go-oidc initialization. Neither contains JSONWebKey parsing,
RSA JWK construction, ParseSigned/ParseEncrypted, or the OIDC verifier. The probe
requires the exact binaries, a complete recognizable function table and this
exact linked-function inventory; absence of a plain text string is not the test.

Access Pages uses `qurl login`, externally supervised `daemon run`, publication
and deletion (`guest_resources.py`). The integrated FRP client uses admission
tokens; the server-side OIDC verifier is not linked into these shipped binaries.
Module inventory alone cannot establish reachability of an eliminated parser.
The two bundled architecture SBOMs additionally report the same module; they are
retained with explicit target matching, not removed to reduce scan counts.

This assessment cannot transfer to a newer qURL binary, changed CLI operations,
new linked JOSE/OIDC functions or changed vulnerability characteristics. Prefer
a supported official fixed release when available; never rebuild qURL locally.

## Home Assistant compatibility reassessment (2026-11-04, America/Phoenix)

The compatibility change modifies four fingerprinted modules: `ha.py`,
`ha_broker.py`, `actions.py`, and `server.py`. Review of their changes confirms
that they add fixed HA metadata templates, entity-feature validation, narrowed
guest action serialization, and preservation of explicit read-only page grants.
They introduce no SQL consumer, uploaded database, SQLite extension, database
deserialization, or qURL operation. Metadata remains JSON over the existing HA
transport; naming is separate from authorization. New actions require explicit
page policy, and the broker retains its final grant/deadline checks after the
new live-state read.

The unchanged reachability probe reproduces all 115 constant SQL calls and the
five consumer schemas. The container bases, bundled binary pins, confinement,
SQL consumers, runner, and reachability probe are unchanged. Only these four
application hashes and this evidence-document hash are refreshed. Existing
advisory decisions, binary fingerprints, review dates, and expiration dates are
not renewed or relaxed. CI must still produce fresh image-bound evidence and
pass native packaged tests on both architectures before the PR is mergeable.
See [compatibility validation](../docs/home-assistant-compatibility.md) for the
real-Core test scope and outstanding HAOS acceptance limits.

## PR #68 restore repair reassessment (2026-11-04, America/Phoenix)

The guest-session startup repair changes the runner's reviewed source hash.
The retained amd64 and arm64 evidence from
[Security run 41954946349](https://github.com/AZDane/access-pages/actions/runs/41954946349)
was compared with the baseline: only `homeassistant-app/app_runner.py` differs.
Both SQLite and qURL binary hashes, all 115 constant SQL calls and schemas,
the JOSE/OIDC linked-function inventory, advisory fingerprints, and confinement
remain identical to the reviewed inputs.

The runner now uses the existing descriptor-based permission repair for the
broker-private session tree before starting services. It neither changes SQL
nor introduces a database import endpoint or new qURL operation. It preserves
database bytes, refuses symlinks and special files, and restores directory
0700/file 0600 ownership to UID/GID 2102. The packaged permission probe checks
restored SQLite contents, broker read/write access, and denied guest access
using the actual service IDs. Arbitrary malicious database replacement and
untrusted backups remain outside the assessment above.

The runner hash is updated after this reassessment; existing review dates and
the November 26 UTC expiry are unchanged. Fresh image-bound evidence and native
packaged tests are still required for both architectures.

The same CI scan also found the newly available
[APT fix for CVE-2026-109518](https://security-tracker.debian.org/tracker/CVE-2026-109518).
The runtime explicitly upgrades only `apt` and `libapt-pkg7.0` from 3.0.3 to
3.0.4, and the packaged probe enforces that minimum. This is a package fix,
with no new vulnerability disposition or scanner exclusion.

## Dependency remediation reassessment (2026-11-09, America/Phoenix)

The unmodified main scan [42678630300](https://github.com/AZDane/access-pages/actions/runs/42678630300)
reported two new SQLite findings, two zlib findings, and an x/net finding.
The runtime now installs Debian's fixed zlib1g
`1:1.3.dfsg+really1.3.1-1+deb13u1` and both the build and packaged probe enforce
that minimum. This fixes [CVE-2026-76844 and CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-76844)
without a disposition. The runtime base, SQLite and qURL binaries are unchanged.

### SQLite CVE-2026-119374 and CVE-2026-119379

Debian's [FTS5 advisory](https://security-tracker.debian.org/tracker/CVE-2026-119374)
and [session advisory](https://security-tracker.debian.org/tracker/CVE-2026-119379)
list the shipped Trixie package as affected with no stable fix. Mixing in sid's
SQLite would change the supported runtime and is not used as a remediation.

CVE-2026-119374 requires a corrupted FTS5 index and FTS5 secure-delete processing.
The existing packaged probe reproduces all 115 constant SQL calls and schemas:
none creates an FTS virtual table or accepts SQL. CVE-2026-119379 requires calling
`sqlite3changeset_apply()` with an attacker-controlled session changeset. Access
Pages uses Python's stdlib sqlite3 binding, which exposes no session/changeset
API. Review of all packaged Python modules found no ctypes, cffi, APSW, native
session call, changeset import, dynamic native loader or uploaded-database path.
The new probe records the absence of a session/changeset binding and rejects
native bridge imports; exact application hashes bind the remaining source review.
This does not claim the SQLite library lacks the affected native code.

Both decisions retain the existing SQLite binary hashes and schema fingerprint,
add exact scanner-advisory fingerprints, and expire November 26 UTC. They cover
remote application inputs and service-owned databases only. Malicious database
replacement, untrusted backups, a new SQLite consumer, binding, native bridge or
import feature invalidates them. Packaged isolation and permission tests remain
required on both architectures.

### qURL x/net/html CVE-2026-78661

[GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860) identifies the HTML parser's
Parse/ParseFragment entry points and quadratic text-node coalescing before
x/net v0.62.0. This is not a finding in x/net's HTTP transport. The affected module
is in the downloaded qURL binary and its two retained architecture SBOMs, not the
stdlib-only guest-endpoint module compiled by our Go builder.

Both official qURL 3.6.0 archives were downloaded again and matched their
Dockerfile checksums. Their binaries match the existing baseline hashes. Parsing
the ELF Go function tables found 46,060 functions on amd64 and 45,494 on arm64,
with no `golang.org/x/net/html` function, wrapper or type symbol. The probe now
requires that empty inventory in addition to the existing complete-function-table
checks and exact binary hashes. No affected parser is linked into these exact
artifacts; a missing arbitrary string alone is not accepted as evidence.

The latest official release inspected, qURL 3.7.1, still lists x/net v0.61.0 in
its published amd64 SBOM, so it does not supply the upstream fix. Keep the reviewed
official binaries rather than rebuilding qURL. Prefer an official fixed release
when available. Preserve all three scanner targets and their exact advisory
fingerprints. New binary bytes, linked HTML code, changed advisory characteristics
or expiry invalidate the assessment. This new disposition expires November 26 UTC.

The reachability probe and this document were reassessed and their control hashes
updated. Existing application hashes, binary hashes, dispositions and expiry dates
are unchanged. Every candidate must reproduce fresh image-bound evidence; the
previous CI evidence is only the investigation input, never a substitute for it.

## qURL lifetime default reassessment (2026-11-12, America/Phoenix)

The 30-day default changes three fingerprinted modules: `config.py`,
`layerv_broker.py`, and `homeassistant-app/app_runner.py`. Their only changes
replace the omitted-setting fallback of 3 days with 30 days. Explicit limits,
duration validation, grant deadlines, admission-duration bounds, SQL statements,
database schemas, SQLite bindings, qURL operations, and confinement are unchanged.

Both retained native architecture artifacts from
[Security run 43301606782](https://github.com/AZDane/access-pages/actions/runs/43301606782)
reproduce the existing binary, schema, binding, linked-function, and advisory
properties. Their packaged source fingerprints differ only for those three
modules and match the reviewed source bytes. Rechecking both complete reports
with these three updated hashes passes the existing policy. Refresh only those
source hashes and this evidence-document hash; do not renew or relax advisory
decisions, review dates, expiration dates, or binary fingerprints. CI must still
produce fresh image-bound evidence and pass packaged tests for both architectures.

## Release flow

Prepare the next numeric beta version in `homeassistant-app/config.yaml`, the
Dockerfile default and changelog. Pull requests changing the release path run it
without registry login, publication or signing. Native amd64 and ARM64 Security
jobs retain the same packaged regression coverage; release ARM64 execution uses
QEMU on the single release runner.

The release runner retains both final-version images in Docker's containerd image
store with SBOM/provenance attestations. Both scans, reachability evidence and
packaged tests must pass before any registry write. `publish_validated.py`
rechecks policy/expiry and both immutable test identities before pushing. It
pushes the retained indices without rebuilding or `docker push --platform`,
verifies their registry digests, verifies the merged index's exact image and
attestation children, then signs the versioned index. Stable-release `latest`
updates happen last; GitHub prereleases do not update `latest`.

Registry updates are not atomic across tags. A network/signing failure after
validation can leave some validated version tags present, but a failed security
or packaged test cannot publish an image. A published GitHub release is the
existing trigger; its Git tag alone is not proof an installable image exists.
Report a release complete only after image signing and the existing byte-for-byte
App Store repository synchronization in AGENTS.md. No private staging is needed.

Before beta publication, record native CI, the release dry run, failure-path tests
and live acceptance results. Synthetic tests do not replace real LayerV enrollment,
external guest admission/revocation, SMTP verification or Home Assistant restore
acceptance. Do not call an untested live workflow beta-ready.

### Scheduled invitations reassessment — 2026-11-14

App 0.1.152 adds `schedules.py` as a sixth SQLite consumer. Review covers all
147 constant SQL calls and the new schedules, occurrences, schedule_meta and
work-index schema. Guest inputs cannot select SQL or upload databases; all
schedule administration requires the existing admin authentication. The database,
outbox recipient/link material, and authorization permit are in Admin's private
0700 directory with 0600 files. The packaged probe checks guest denial and Admin
write access after permission repair. This is not a safe-import claim for
untrusted backups or malicious database replacement.

Creation journals precede remote calls; unknown outcomes retire broker-owned
resources, and SMTP retries reuse one invitation. Restore recovery removes
scheduled local grants before starting guests. The permit is excluded from HA
cold backups; manual copies must omit it. Timezone support adds read-only access
to `/usr/share/zoneinfo`, not executable access or a new native bridge.

The schema probe, source fingerprints, and AppArmor fingerprint are updated to
this reviewed implementation. No FTS tables, MATCH queries, dynamic SQL, extension
loading, session/changeset binding, ctypes/cffi/APSW bridge, or database-upload
path was added. Existing qURL and SQLite binary fingerprints, advisory evidence,
and the November 26 review deadline remain mandatory. Both architectures still
must reproduce the evidence and pass native packaged checks before publication.
