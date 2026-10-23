# qURL 3.6.0 upgrade review

Access Pages 0.1.144 restores the official qURL release after LayerV fixed
[issue #1606](https://github.com/layervai/qurl-integrations/issues/1606#issuecomment-6356624274).
The deployed API now accepts explicit resource privacy and returns confirmation.
The temporary source patch, custom binary build, and broker opt-in are removed.

## Provenance

- [Official release v3.6.0](https://github.com/layervai/qurl-integrations/releases/tag/v3.6.0), source commit `dab9399a9297ac80ac9302dd8c9814d5f5ece4f2`.
- Linux amd64 archive SHA-256: `b28e995228d9e3fdc8944b590587d3e9a06b41a43dfe9797d424576ef5c77967`.
- Linux arm64 archive SHA-256: `19521dde36007363281c8c6f36fd7303d46bf9243d1c3ba6ce504193889f7932`.
- Both archives and their upstream SPDX inventories match `checksums.txt`.
- Cosign 3.0.6 verified `checksums.txt.sigstore.json` with certificate identity
  `https://github.com/layervai/qurl-integrations/.github/workflows/release-please.yml@refs/heads/main`
  and OIDC issuer `https://token.actions.githubusercontent.com`.
- qURL embeds Go 1.26.10, Connector 0.14.2, and qurl-go 0.26.3. Updated module
  notices come from the exact pinned Go module archives. The unchanged yamux
  MPL source remains included. Both architecture inventories are retained.

The existing guest endpoint is also rebuilt with Go 1.27.3, pinned to the
builder manifest `sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5`.
The required image scan identified CVE-2026-111943 in its old Go 1.27.2 runtime;
this updates to the fixed version without weakening the scan. The official Go
1.27.3 license was verified byte-identical to the bundled Go license.

## App integration

The broker still explicitly publishes public transport resources. Access Pages
continues to enforce guest authorization, expiration, verification, and revocation
at its own endpoint. Publication now uses the upstream REST privacy request and
requires upstream confirmation, with no compatibility fallback.

The native daemon protocol remains version 5. The broker requires the exact
`5/3.6.0/per-share` or `5/3.6.0` job version, selected session mode, and its own
child PID. Upstream's relaxed native package-upgrade handling does not relax
these broker ownership checks.

Production enrollment still uses a one-time token file, external supervision,
and the sealed `local-key` provider. The manual probe's explicit anonymous login
also remains correct under external supervision; the new automatic standalone
publish enrollment does not replace the App's credential flow. Missing sealed
state still requires explicit administrator recovery.

## Validation

The packaged live probe requires fresh page and guest resources, explicit
`private: false`, `found_existing: false` on first publication, link creation,
exact tunneled content, restart with stable resource identity and confirmed
privacy, content retrieval after restart, and deletion. It uses an isolated
anonymous identity and dummy HTTP content, never account keys or HA data.

The offline packaged probe checks exact binary version, daemon ownership,
contention, shutdown, warm restart, and preservation of identity and registry
files. The application suite covers guest authorization and recovery behavior.
CI additionally builds and exercises both architectures and scans the image.

A separate live migration probe used the released 0.1.143 publisher and binary,
sealed anonymous state, and explicit existing public resource fixtures. It
published and fetched with the old binary, stopped it, then restored the same
state with 3.6.0. Both page/guest CRIDs remained stable, privacy was confirmed,
content retrieval passed, and resources were deleted without re-enrollment.
The public fixtures model resources created before the service correction;
new resources through the legacy native path are now reported as restricted
and are correctly refused by the old compatibility patch.

This migration test covers anonymous sealed state, not a customer's account key.

The release notes identify an upstream Linux diagnostic limitation: an
unauthorized private-access attempt can report unavailable rather than not found.
Access Pages publishes public transport and independently enforces guest access;
this does not justify changing the App's authorization or error recovery rules.
