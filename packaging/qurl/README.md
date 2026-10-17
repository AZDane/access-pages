# Temporary LayerV publication compatibility

Access Pages builds **qURL 3.5.0-access-pages.1** from upstream commit
`3da4ba34df029c31e86dc2ed00997d015b1bac8d` plus the files in this directory.
The Dockerfile verifies the source archive SHA-256 before applying the patch
without fuzz. The Go 1.26.9 toolchain, dependency versions, native Connector,
and public hub trust anchor are retained from the official 3.5.0 build.
Upstream MIT licensing and all dependency notices remain in the image.

## Reason and scope

On October 17, 2026, an isolated live probe reproduced this mismatch:
the official CLI pre-creates local resources with a `private` field, while
the deployed API rejects that field with HTTP 400 (`validation_error`).
The published schema at <https://layerv.ai/docs/qurls.json> excludes it from
`CreateResourceRequest`. Removing the field produced HTTP 201, whose resource
row also omitted privacy. Existing Access Pages page resources can keep
working because new guests on those pages do not need a resource create.
These observations do not establish the date or cause of the server change.

The broker explicitly sets `ACCESS_PAGES_LEGACY_PUBLIC_PUBLISH=1`. Only local
`--public` publications with Access Pages' `ha-page-<40 lowercase hex>` or
`ha-guest-<40 lowercase hex>` identities may use the compatibility path.
Private requests, device grants, and access requests fail before resource
creation. With the switch absent, upstream behavior is unchanged.

The patch uses the native signed find-or-create protocol, then reads the
owner-facing REST resource detail before starting service. The requested slug,
CRID, public key, and tunnel type must match. Known private resources, device
grants, passkeys, or access requests are refused. The normal activation,
sharing-state identity checks, daemon supervision, transport encryption, and
cleanup are unchanged. Failures are not retried through an alternate path.

An older response's omitted privacy remains **unknown**, never fabricated as
`false`. Access Pages already requests public LayerV transport and enforces
guest authorization at its own endpoint. This patch cannot support private
LayerV resources and does not replace Access Pages' expiration, revocation,
PIN, or verification controls. A new server default that restricts access
could prevent guest access; it cannot grant broader transport access than
the explicitly requested public mode.

## Validation and removal

The image build runs the patch's Go regression tests and upstream local
publication/private-default tests. Both architectures also run the packaged
daemon lifecycle probe in CI. The live synthetic probe is deliberately
manual because it creates and deletes disposable resources on LayerV:

```sh
docker run --rm --user 2103:2103 --entrypoint python \
  --volume "$PWD/tests/live_qurl_publish_probe.py:/tmp/probe.py:ro" \
  access-pages-app:compatibility-test /tmp/probe.py
```

It uses an anonymous disposable identity and dummy HTTP content, never a
Home Assistant credential. Account enrollment, guest browser protections,
and a connection reset must additionally be checked in the user's HA testbed
with a dedicated API key entered through Access Pages' connection UI.

Remove this directory, the broker opt-in, and the custom build when an official
CLI passes fresh-resource publication, link minting, tunnel retrieval, resource
reuse after restart, and deletion against the deployed API. Restore the
official binary checksum pins and exact daemon version checks together.
