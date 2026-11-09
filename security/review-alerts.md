# Assessment expiry alerts

The Security review alerts workflow checks the baseline daily at 00:23 UTC.
GitHub may delay scheduled runs. It also supports a manual run; the default is
a preview, and `write_issues: true` enables issue updates from `main` only.

Seven calendar days before `review_due`, it creates one issue per deadline,
assigned to AZDane, listing every assessment due on that date. The current
November 26, 2026 deadline first qualifies on November 19 UTC. Expired entries
also qualify, so a missed run does not silently discard an alert. Notification
delivery follows the assignee's GitHub notification settings.

Unchanged issues produce no writes or comments. Changed assessments update the
same issue, and an issue closed while its assessments are still due is reopened.
After remediation or a fresh evidence-backed review changes the baseline, the
maintainer can close the old issue. The automation never changes baseline dates,
approves a disposition, or weakens the existing expired-review failure.

Pull requests exercise a read-only preview and tests for date boundaries,
overdue catch-up, grouping, duplicate suppression, and issue updates. Issue
write permission is confined to the scheduled/manual default-branch job.

When an alert arrives, check stable Debian packages and official qURL releases
first. Inspect the shipped binary's dependencies; changing the Go builder does
not change modules embedded in a downloaded qURL binary. Any image, binary,
source, schema, binding, or confinement change must be assessed against the
existing evidence policy and tested on amd64 and arm64. Keep dependency updates
review driven, including actual image versions and stable-runtime assertions.
