#!/usr/bin/env bash
set -euo pipefail
destination=${1:?verification output directory required}
mkdir -p "$destination"
issuer=https://token.actions.githubusercontent.com
identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
repository=cgr.dev/chainguard/python
index=sha256:d2711a21a494fa5c2efbfcf4226268395bad5d03406083ed0f3e7bed5199cfb2
amd64=sha256:7b25670efd8a19fe05dcdfca56c418ee0988cd925766e898dd8edf7a061343ed
arm64=sha256:7d37d730037ad599f211eebbae47ebeb8c529b857340678a870cfc1c101bbf85
# A pin update must update the reviewed manifest mapping as well.
grep -Fx "FROM $repository:latest@$index" Dockerfile.ha-minimal
docker buildx imagetools inspect --raw "$repository@$index" > "$destination/index.json"
python3 - "$destination/index.json" "$amd64" "$arm64" <<'PY'
import json, sys
index = json.load(open(sys.argv[1]))
actual = {m['platform']['architecture']: m['digest'] for m in index['manifests']
          if m['platform']['os'] == 'linux'}
assert actual == dict(zip(('amd64', 'arm64'), sys.argv[2:])), actual
PY
for platform in index amd64 arm64; do
  digest=${!platform}
  cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
    --output json "$repository@$digest" > "$destination/$platform-signature.json"
  if [[ "$platform" != index ]]; then
    cosign verify-attestation --type spdxjson --certificate-identity "$identity" \
      --certificate-oidc-issuer "$issuer" "$repository@$digest" > "$destination/$platform-sbom.json"
  fi
done

# Only the original qURL 4.2.0 binary is copied from this signed release.
# Its signature binds the architecture manifests; the Dockerfile checks the
# copied binary against the previously reviewed per-architecture SHA-256.
qurl_repository=ghcr.io/azdane/access-pages-app
qurl_index=sha256:99259c306ff6b918249d5304202e7a64acd0e0c4a9a01eb7dba93cab9a9bd2cd
qurl_amd64=sha256:7f8b51d1f8c534175ced7f1649ce3434c2b1bbb2e99894a05207305f6e33eaf8
qurl_arm64=sha256:b2ad163ea6f8280d35a996475f3a212da16214e5db4cee920f0b1b750c5ed202
grep -Fx "FROM $qurl_repository:0.1.163@$qurl_index AS qurl" Dockerfile.ha-minimal
cosign verify --certificate-identity \
  https://github.com/AZDane/access-pages/.github/workflows/publish-ha-app.yml@refs/tags/v0.1.163 \
  --certificate-oidc-issuer "$issuer" --output json \
  "$qurl_repository@$qurl_index" > "$destination/qurl-source-signature.json"
docker buildx imagetools inspect --raw "$qurl_repository@$qurl_index" > "$destination/qurl-source-index.json"
python3 - "$destination/qurl-source-index.json" "$qurl_amd64" "$qurl_arm64" <<'PY'
import json, sys
index = json.load(open(sys.argv[1]))
actual = {m['platform']['architecture']: m['digest'] for m in index['manifests']
          if m['platform']['os'] == 'linux'}
assert actual == dict(zip(('amd64', 'arm64'), sys.argv[2:])), actual
PY
