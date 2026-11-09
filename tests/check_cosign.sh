#!/usr/bin/env bash
# Test the real image-signing CLI without images, registry writes, OIDC or Rekor.
set -euo pipefail
fixture=$(mktemp -d)
registry_id=
cleanup() {
  if [[ -n "$registry_id" ]]; then docker rm --force "$registry_id" >/dev/null; fi
  rm -rf "$fixture"
}
trap cleanup EXIT
registry_id=$(docker run --detach --publish 127.0.0.1::5000 \
  registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373)
address=$(docker port "$registry_id" 5000/tcp)
for attempt in {1..30}; do
  if curl --fail --silent "http://$address/v2/" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "http://$address/v2/" >/dev/null
cd "$fixture"
cosign version
# Only this disposable test uses a local key and no transparency services.
# Production retains its default keyless signing and transparency settings.
export COSIGN_PASSWORD=''
cosign generate-key-pair --output-key-prefix ephemeral
cosign signing-config create --out offline-signing.json
printf 'Access Pages signing compatibility fixture\n' > payload.txt
digest=$(sha256sum payload.txt | cut -d' ' -f1)
cosign sign --yes --key ephemeral.key --signing-config offline-signing.json \
  --upload=false --bundle image.sigstore.json --allow-http-registry \
  "$address/signing-fixture@sha256:$digest"
cosign verify-blob-attestation --key ephemeral.pub --bundle image.sigstore.json \
  --insecure-ignore-tlog --type https://sigstore.dev/cosign/sign/v1 payload.txt
printf 'tampered\n' >> payload.txt
if cosign verify-blob-attestation --key ephemeral.pub --bundle image.sigstore.json \
    --insecure-ignore-tlog --type https://sigstore.dev/cosign/sign/v1 payload.txt; then
  echo 'Cosign accepted tampered content' >&2
  exit 1
fi
curl --fail --silent "http://$address/v2/_catalog" | \
  python3 -c 'import json,sys; assert json.load(sys.stdin)["repositories"] == []'
echo 'Image-digest signing, verification, tamper rejection and empty registry: PASS'
