# November 24, 2026 release gate review

The November 25, 17:00 Mesa time deadline in [security review #97](https://github.com/AZDane/access-pages/issues/97) is November 26, 00:00 UTC. The proposed December extension in PR #98 was closed without merging. The existing hardened applicability and Python backport reviews, and the separate historical Debian baseline, therefore still expire at that instant. The expiry blocks new builds and releases through the existing checks; it does not stop installed applications.

## Evidence and change since the first failed run

The [November 23 main Security run](https://github.com/AZDane/access-pages/actions/runs/45258799562) failed on amd64 and arm64. Compared with the [preceding passing main run](https://github.com/AZDane/access-pages/actions/runs/45106203483) at the same source commit, six publisher records for CVE-2026-107494 and CVE-2026-121481 changed their OpenSSL event status from `detection` to `pending_upstream_fix` and advanced timestamps. The installed OpenSSL version, affected ranges, severity, and references stayed the same. The packaged runtime and native inventories were byte identical across those runs. That observation justified investigating the status changes; it did not authorize an expiry extension.

The [November 24 feature branch Security run](https://github.com/AZDane/access-pages/actions/runs/45443911789) fetched newer publisher snapshots. Relative to the November 23 run, the production image's record count changed from 56 to 62 on amd64 and from 56 to 61 on arm64. Respectively, 32 and 30 existing records also changed. The minimal image received the same new CVEs and failed its advisory gate. The gates correctly rejected the attempted renewal.

| Change in the fresh publisher records | Impact on the pinned image |
| --- | --- |
| New CVE-2026-121758 and CVE-2026-124024 records for glibc 2.44-r25: six amd64 records and five arm64 records | No reviewed applicability decision or exact record pins exist. Both involve glibc `iconv` conversion paths; reachability for the packaged applications has not been established. |
| CVE-2026-124317 and CVE-2026-128241 Expat records now report `fixed: 2.11.0-r0` | The pinned image has `libexpat1`/`expat` 2.10.0-r1. An affected package with a reported vendor fix needs a new base and native verification or a new, explicit, evidence backed assessment. |
| Further changes to OpenSSL and other existing publisher records | Their old hashes no longer bind the live publisher evidence. Reassess the complete changed records before accepting new fingerprints. |

On November 24, `cgr.dev/chainguard/python:latest` resolved to index `sha256:a76d3a2d5a7ba23ac51e1de1d119796142888aeb7d8276b53c7abbb919e3dc5d`. Its amd64 package inventory still had `libexpat1` 2.10.0-r1 and glibc 2.44-r25. The current pinned index is `sha256:d2711a21a494fa5c2efbfcf4226268395bad5d03406083ed0f3e7bed5199cfb2`. Merely moving to the current `latest` index would not resolve these package versions. This is a point in time check; inspect both architecture inventories again when a candidate base appears.

The glibc CVE descriptions report out of bounds reads in two `iconv` conversions, with attacker control of conversion choice and input among the prerequisites. The native inventory shows an `iconv` reference in libstdc++, but that alone does not prove or exclude a reachable application path. Do not classify either new CVE as unreachable based only on that symbol listing.

## Release decision and next review

Keep the current review dates and advisory pins. Do not merge a date extension, release a new image, or publish a new Home Assistant App version while the native Security jobs are red. Existing installations continue to run.

1. Wait for a signed, architecture complete Chainguard Python base that includes Expat 2.11.0-r0 or later, or document a separately justified resolution for the pinned package. Verify the base signature, package inventory, and both image builds.
2. Review both new glibc CVEs against the actual source, call paths, and exact binaries on amd64 and arm64. Record a bounded applicability decision only if the evidence supports it; otherwise wait for a vendor fix.
3. Compare every changed publisher record against the previous reviewed snapshot. Refresh exact hashes only after reviewing semantic changes, including fixed ranges, not as a bulk timestamp update.
4. Re-run native production and minimal Security jobs, static analysis and tests, secret scanning, dependency and repository checks, and container checks. Extend only the active assessments for which new evidence is complete and all required checks pass. Keep the historical Debian deadline unless that image receives its own reassessment.
5. Have the owner adopt any proposed assessments through a protected pull request with required checks and conversations clear. Confirm the release gate before starting a release; the public App Store repository is a separate release step.

No vulnerability is waived by this note. The existing fail-closed controls remain in force.
