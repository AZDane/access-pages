Temporary CPython backports for the pinned hardened evaluation image

These are exact Lib/ hunks from the official python/cpython commits linked in
manifest.json, under CPython's PSF license (retained by the base Python package).
No application monkeypatch, alternate interpreter, or compiled-library swap is
used. Original package versions, APK inventory, signatures and scanner findings
remain visible. The derivative image includes its own patch manifest; the base
vendor signature is not claimed to cover these local changes.

The installer verifies original module bytes, patch bytes and final module bytes,
then removes affected cached bytecode. A changed base or expired review stops the
build. Review is due before 2026-12-01 16:57 UTC, independently of the unchanged
production vulnerability baseline. Remove these backports when a reviewed vendor
image includes the fixes and passes the same native tests.

CVE-2026-103995: official merged Python 3.15 backport, including the follow-up
Content-Length optional-whitespace compatibility fix:
https://github.com/python/cpython/commit/5b9e3d044764cf59329fb8147177f54a88d1fb49

CVE-2026-115559: official merged STARTTLS fix; identical six-line library change
in the open 3.15 backport. The test-only 3.15 branch supplies compatible regression
fixtures; the application patch comes from the merged upstream commit:
https://github.com/python/cpython/commit/2f0e294d85c905691e360586ebd1d1f7e7a1f5df
https://github.com/python/cpython/pull/161761

security/backport_evidence.py recognizes only these exact publisher advisory IDs
when module hashes, the installed manifest, the passing runtime gate, immutable
image identity, architecture, current probe and fresh review all agree. The raw
publisher records remain in evidence. Any other record remains unresolved.
