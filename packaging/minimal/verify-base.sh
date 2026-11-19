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
