# Stable upstream availability, November 9, 2026

This availability check does not renew any vulnerability disposition. The
existing assessments still expire November 26, 2026 and remain tied to the
exact shipped files, binaries, advisory fingerprints, and architecture evidence.

Debian's [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374)
and [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379)
trackers list Trixie sqlite3 3.46.1-7+deb13u2 as vulnerable. The listed fixed
Debian version is 3.54.1-1 in unstable; neither entry lists a patched Trixie
package. The findings concern corrupted FTS5 secure-delete indexes and the
session changeset API respectively. The existing packaged evidence excludes
those application paths; it does not claim that SQLite itself is patched.

The latest official [qURL release is v3.7.1](https://github.com/layervai/qurl-integrations/releases/tag/v3.7.1).
Its published Linux amd64 and arm64 SPDX SBOMs both report
`golang.org/x/net v0.61.0` and `github.com/go-jose/go-jose/v4 v4.1.6`.
The [Go advisory](https://pkg.go.dev/vuln/GO-2026-6860) fixes the affected
`golang.org/x/net/html` parser functions in v0.62.0. Therefore this release is
not a complete patched replacement for the current bounded qURL assessments.
The current official 3.6.0 binaries remain pinned; their complete Go function
inventories exclude the affected HTML parser and JWK parser paths on both
architectures. Any future qURL replacement needs fresh inventories and evidence.

Checked official release assets:

| Asset | SHA-256 of SBOM bytes |
| --- | --- |
| `qurl_3.7.1_linux_amd64.tar.gz.sbom.json` | `becd79a6902a18142655d371decda68872c5e46c0fa2cbbdcb551c4a81e73b33` |
| `qurl_3.7.1_linux_arm64.tar.gz.sbom.json` | `60356e53ba2aeb0981da1c24a0245411f5c6c5326c3db2c40896c7afdc175ede` |

Follow up when stable Trixie fixes or an official qURL binary embedding
x/net v0.62.0 or later become available. Recheck all existing dispositions
invalidated by those changes, retain the full scanner inventory, and validate
the packaged application on amd64 and arm64 before merging.
