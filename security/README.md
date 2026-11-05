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

All 115 SQL calls in `activity.py`, `verification.py`, `guest_resources.py`,
`upstream_cleanup.py` and `layerv_broker.py` use constant SQL. Values are bound
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
