TODO — Access Pages HA - Nova
Online Lessons Learned + Cross-Backend Portability Review

DO NOT START THIS TASK YET.

PREREQUISITES:

1. Complete the current Access Pages HA 0.1.125 owner-only diagnostic test cycle.
2. Preserve/report any useful evidence regarding the unresolved LayerV guest timeout.
3. Complete the required reduction of steady-state diagnostic logging under HA125-OBS-001.
4. Establish the resulting Access Pages HA version/commit as the clean pre-external-beta baseline.
5. Ensure the working tree is clean.

Only after those prerequisites are complete should this review begin.

This task is READ-ONLY.

Do not implement findings during the audit.


==================================================
PURPOSE
==================================================

Access Pages Online - Nova has undergone substantial development, security review, real-browser testing, Home Assistant integration work, revocation testing, crash/recovery work and Gateway alignment.

Access Pages HA - Nova is preparing for external beta users.

Review what we learned while developing:

Access Pages Online - Nova

and determine which lessons should improve:

Access Pages HA - Nova

before external beta.

The objective is NOT to make the two projects 100% identical.

The objectives are:

1. bring worthwhile security/reliability/UX improvements from Online back into HA-Nova;
2. eliminate unnecessary behavioral divergence;
3. preserve legitimate LayerV versus OpenNHP differences;
4. establish a provider-neutral Access Pages configuration/backup model;
5. make a future LayerV ↔ Access Pages Online/OpenNHP migration as seamless as reasonably possible.

Think of:

ACCESS PAGES

as the product,

and:

LayerV
or
Access Pages Online / OpenNHP

as alternative backend/access implementations.


==================================================
CURRENT BASELINES
==================================================

Before analysis, establish exact current source baselines.

HA-NOVA:

Use the final accepted version AFTER:
- 0.1.125 diagnostic testing
- HA125-OBS-001 logging cleanup
- any separately approved fixes resulting from that testing

Do not assume 0.1.125 itself remains the final baseline.

Record:
- repository/worktree
- branch
- commit
- app version
- release/package identity
- working-tree state


ONLINE:

Use the current accepted Access Pages Online baseline.

Expected architectural baseline includes:

Hosted:
- V5

Gateway:
- GA1 / beta.16

Verify actual current state before relying on those labels.

Online is READ-ONLY reference material.


==================================================
CORE PRINCIPLE
==================================================

Do NOT chase 100% source-code commonality.

The desired outcome is:

COMMON CUSTOMER EXPERIENCE
COMMON PAGE/ENTITY MODEL
COMMON SAFETY/UX BEHAVIOR
PORTABLE CONFIGURATION

with deliberately separate:

LayerV authority/tunnel implementation

and

OpenNHP/NHP/AC/FRP authority/tunnel implementation.

Source similarity is useful only where it improves maintainability or prevents duplicated bugs.


==================================================
PART 1 — INVENTORY ONLINE LESSONS
==================================================

Review actual Online source, tests and accepted development evidence.

Pay particular attention to lessons involving:

- browser lifecycle
- stale state
- request timeout
- connection loss
- revocation
- delayed transport withdrawal
- late responses
- action semantics
- action deadlines
- public-state serialization
- entity/page validation
- authorization rechecks
- page/resource binding
- durable page persistence
- crash recovery
- policy recovery
- individual revoke
- bulk revoke
- page deletion cleanup
- retry/idempotence
- normal Home Assistant integration
- Admin UI behavior
- secret isolation
- logging/redaction
- customer-data minimization
- exposure/listener hardening

Review implementation/evidence, not merely old summaries.


==================================================
PART 2 — CLASSIFY EVERY RELEVANT DIFFERENCE
==================================================

Classify each meaningful finding as:

A. ALREADY PRESENT IN HA-NOVA

B. HA-NOVA IS STRONGER / DIFFERENT FOR GOOD REASON

C. SHOULD BACKPORT BEFORE EXTERNAL BETA

D. SHOULD BACKPORT DURING BETA

E. NICE TO HAVE LATER

F. ONLINE-SPECIFIC — DO NOT COPY

G. NEEDS MORE EVIDENCE

Do not treat difference itself as a defect.


==================================================
PART 3 — ACTION SEMANTICS
==================================================

Compare action execution carefully.

Include lessons from the 0.1.125 work.

Compare:

- authorization immediately before action
- queueing
- request lifetime
- deadline enforcement
- HA dispatch
- post-action state verification
- browser timeout
- late action behavior
- automatic retry/replay

Online previously retained stronger fresh-state-before-success behavior.

HA-Nova subsequently added its own request-lifetime protection.

Determine the best combined behavior.

Specifically answer:

- Can either implementation tell the user an action succeeded before fresh HA state supports that conclusion?
- Can an old queued action execute after the browser has abandoned it?
- Can revocation race a queued action?
- Can anything automatically replay a stale action?
- Which implementation is stronger at each stage?

Do not weaken HA-Nova merely for parity.


==================================================
PART 4 — REVOCATION
==================================================

HA-Nova originally introduced the useful pattern:

immediate application authorization revoke
→ brief transport grace
→ browser learns revoked state
→ LayerV cleanup

Online V5 subsequently hardened/adapted that model.

Compare:

- immediate authorization denial
- guest-session invalidation
- transport grace
- persistent deferred cleanup
- restart recovery
- retry
- browser revoked state
- stale control clearing
- timeout fallback
- late-response suppression
- fail-safe eventual transport closure

Identify improvements worth bringing back to HA-Nova.

Do NOT copy NHP/AC lease mechanics merely because Online uses them.


==================================================
PART 5 — CONNECTION LOSS / BROWSER SAFETY
==================================================

Compare:

- normal polling
- hidden/background behavior
- request timeout
- network loss
- stale controls
- stale values
- unavailable presentation
- late responses
- reconnect behavior
- page-ended state
- camera Blob cleanup
- mobile behavior

Incorporate lessons from the real LayerV timeout investigation.

A guest UI must not continue appearing operational when current authority/state cannot be established.


==================================================
PART 6 — PUBLIC STATE MINIMIZATION
==================================================

Compare what each Gateway sends to guest browsers.

Review:

- raw HA attributes
- internal IDs
- recipient information
- backend identifiers
- installation identity
- authority state
- provider information
- entity metadata
- action capability data

Prefer minimal explicit public serializers.

Determine whether HA-Nova exposes anything unnecessary compared with Online.


==================================================
PART 7 — PAGE / ENTITY AUTHORIZATION
==================================================

Compare:

- page/resource binding
- entity membership
- allowed actions
- service restrictions
- out-of-page access
- unsupported domains
- validation
- authorization rechecks
- path handling
- page deletion
- entity removal

Identify whichever implementation is stronger for each common behavior.


==================================================
PART 8 — DURABILITY / RECOVERY
==================================================

Compare:

- atomic writes
- fsync
- page persistence
- delete persistence
- policy pending markers
- restart recovery
- revoke ordering
- cleanup queues
- retry
- idempotence
- bulk revoke
- page deletion cleanup
- expiration cleanup
- reset cleanup

Look specifically for:

local identifier/state disappears
BEFORE
the information necessary to revoke backend authority is durably captured.

That is a pre-beta concern.


==================================================
PART 9 — HOME ASSISTANT INTEGRATION
==================================================

Compare the current normal HA clients.

Review:

- discovery
- metadata
- state reads
- service calls
- timeout
- reconnect
- unavailable entities
- entity capabilities
- action result handling
- HA errors
- restart behavior

Online GA1 incorporated HA-Nova patterns and retained some stronger Online behavior.

Identify improvements that should now flow back.


==================================================
PART 10 — ADMIN UI
==================================================

Compare:

- page builder
- entity picker
- ordering
- validation
- invitation creation
- invitation state
- revoke UX
- delivery status
- SMTP failure/fallback
- manual link sharing
- connection status
- reset/reconnect
- interrupted reset
- preview isolation
- errors
- mobile/responsive behavior

Prioritize beta-user confusion and recovery over cosmetic similarity.


==================================================
PART 11 — LOGGING / OBSERVABILITY
==================================================

Review lessons from the 0.1.125 diagnostic cycle and Online.

Desired long-term principle:

QUIET WHEN HEALTHY
DETAILED WHEN ABNORMAL
BOUNDED UNDER SUSTAINED USE

Compare:

- request correlation
- timing
- slow-request diagnostics
- error diagnostics
- secret redaction
- storage footprint
- log retention assumptions
- action/revocation audit events

Do NOT reintroduce high-volume healthy polling logs.

Do not create diagnostic network traffic.

Do not create a telemetry database merely for parity.


==================================================
PART 12 — LISTENER / EXPOSURE REVIEW
==================================================

Perform a focused HA-Nova exposure review.

Identify every listener/interface associated with the app.

Classify:

HA/OWNER AUTHENTICATED
LAYERV PROTECTED
LOCAL/PRIVATE
INTENTIONALLY PUBLIC
UNJUSTIFIED

Determine whether any route/listener is reachable more broadly than necessary.

Do not change networking during this review.


==================================================
PART 13 — SECRETS / CREDENTIALS
==================================================

Compare handling of:

- LayerV API keys
- qURL credentials
- HA tokens
- guest session credentials
- email/provider credentials
- logs
- backups
- Admin responses
- browser storage

Identify improvements learned from Online that reduce credential exposure.


==================================================
PART 14 — PORTABLE ACCESS PAGES CONFIGURATION
==================================================

This is a strategic priority.

Design:

ACCESS PAGES PORTABLE CONFIGURATION v1

The customer's Access Pages configuration should belong to Access Pages, not to LayerV or OpenNHP.

Determine how much of the current HA-Nova and Online data models can use one portable format.


Potential portable content:

- format version
- page IDs
- page names
- page ordering
- entity/resource membership
- entity presentation
- allowed actions
- page UI settings
- common notification preferences
- other backend-neutral Access Pages settings


Must NOT blindly export:

- LayerV API credentials
- qURL capability/token
- Online AccessLinks
- NHP Agent keys
- Gateway private identity
- active sessions
- backend authority state
- HA credentials
- provider secrets


==================================================
PART 15 — PAGE BACKUP COMPATIBILITY
==================================================

Determine whether an export from HA-Nova could be imported directly into Online and vice versa.

Answer:

- Can page IDs remain identical?
- Are entity/resource IDs compatible?
- Are action definitions compatible?
- Is ordering compatible?
- Are presentation settings compatible?
- Which fields require translation?
- Which fields should be ignored safely?
- How are unsupported future fields handled?
- How are unsupported entity domains handled?
- How are conflicts handled?
- How is schema versioning handled?
- Can import be idempotent?

The desired customer experience is:

export Access Pages
→ change backend/product
→ import
→ pages look and behave essentially the same


==================================================
PART 16 — INVITATION INTENT PORTABILITY
==================================================

Actual guest capabilities are NOT portable.

A LayerV qURL must not be converted cryptographically into an Online AccessLink.

An Online AccessLink must not be converted into a LayerV qURL.

But invitation INTENT may be portable.

Evaluate fields such as:

- friendly guest label
- recipient
- page
- reusable vs single-use preference
- expiration duration/policy
- verification preference where compatible

Do not include backend capability secrets.


==================================================
PART 17 — CROSS-BACKEND MIGRATION
==================================================

Design migration:

HA-Nova / LayerV
→ portable Access Pages backup
→ Access Pages Online / OpenNHP

and the reverse.

Desired behavior:

1. preserve pages/settings
2. establish new backend installation identity
3. import configuration
4. identify old invitations
5. revoke old backend authority
6. mint NEW backend-native invitations
7. preserve invitation intent where possible
8. tell owner which guest links changed


==================================================
PART 18 — GUEST LINK REVOCATION DURING MIGRATION
==================================================

This is the major migration security problem.

Analyze:

- Can all existing LayerV qURLs be enumerated?
- Can all be revoked reliably?
- What happens if LayerV is unavailable?
- Should new Online invitations remain disabled until old LayerV revocation succeeds?
- How are pending old-backend revocations persisted?
- How does retry work?
- How does restart work?
- How do we prevent rollback from resurrecting old links?
- What if migration is reversed?
- What if only some old links revoke successfully?

Prefer fail closed.

Do not sacrifice old-link revocation merely to make migration appear seamless.


==================================================
PART 19 — MIGRATION UX
==================================================

Design the owner experience conceptually.

Example:

"Your pages and settings were imported successfully.

4 existing guest invitations cannot retain their old URLs because the access backend changed.

3 old links were revoked successfully.
1 is awaiting revocation.

New guest links will not be activated until the remaining old authority is safely resolved."

Determine whether that level of fail-closed behavior is appropriate.

Do not implement UI yet.


==================================================
PART 20 — SHARED CODE IS OPTIONAL
==================================================

Do not assume portable data requires a shared code package.

Evaluate separately:

A. behavioral compatibility
B. portable schema compatibility
C. source-code sharing

We may achieve seamless migration without tightly coupling release cycles.

Recommend shared code only if evidence shows it materially reduces maintenance.


==================================================
PART 21 — PRE-EXTERNAL-BETA PRIORITY
==================================================

For every proposed HA-Nova improvement assign:

BLOCKER BEFORE EXTERNAL BETA

SHOULD DO BEFORE EXTERNAL BETA

SAFE DURING BETA

LATER

DO NOT COPY


BLOCKER:
credible security, authority, data-loss or dangerous-action issue

SHOULD:
meaningful reliability/recovery/user-experience issue likely to affect beta users

Do not inflate priority simply because Online differs.


==================================================
PART 22 — PORTABLE BACKUP TIMING
==================================================

Separately recommend whether portable configuration should be implemented:

A. BEFORE external HA-Nova beta

B. DURING beta before general release

C. AFTER beta

Consider:

- schema stability
- migration value
- backup value
- implementation risk
- whether early beta users could otherwise create configuration that becomes difficult to migrate later

Even if implementation is deferred, determine whether we should freeze/design the portable schema BEFORE external beta so current data remains forward-migratable.


==================================================
PART 23 — IMPLEMENTATION ESTIMATES
==================================================

For every BLOCKER/SHOULD improvement report:

- files affected
- approximate production LOC
- tests required
- implementation risk
- whether Online already has proven code/pattern
- whether LayerV-specific live testing is needed

Estimate portable-backup work separately.


==================================================
PART 24 — DO NOT MODIFY
==================================================

READ-ONLY AUDIT.

Do NOT:

- modify HA-Nova source
- modify Online source
- deploy
- publish
- change LayerV
- create/revoke live qURLs
- change HA configuration
- create shared package
- implement portable backup
- implement migration
- resume high-volume diagnostic logging

Safe local read-only comparison/testing is allowed.


==================================================
DELIVERABLES
==================================================

Create:

- ONLINE-LESSONS-FOR-HA-NOVA.md
- PRE-BETA-BACKPORT-MATRIX.md
- ACTION-SEMANTICS-COMPARISON.md
- REVOCATION-COMPARISON.md
- BROWSER-LIFECYCLE-COMPARISON.md
- PUBLIC-STATE-COMPARISON.md
- AUTHORIZATION-COMPARISON.md
- DURABILITY-RECOVERY-COMPARISON.md
- HA-INTEGRATION-COMPARISON.md
- ADMIN-UX-COMPARISON.md
- OBSERVABILITY-COMPARISON.md
- HA-NOVA-EXPOSURE-REVIEW.md
- PORTABLE-CONFIGURATION-V1-DRAFT.md
- CROSS-BACKEND-MIGRATION-DESIGN.md
- GUEST-LINK-REVOCATION-MIGRATION.md
- PRE-BETA-IMPLEMENTATION-PLAN.md


==================================================
FINAL QUESTIONS
==================================================

Answer:

1. What did Online teach us that current HA-Nova does not already do?
2. What should HA-Nova adopt before external beta?
3. Are there any blockers?
4. Which HA-Nova behaviors are stronger and should remain?
5. Which Online behaviors are stronger?
6. Are action semantics equally safe?
7. Are revocation semantics equally safe?
8. Is connection-loss behavior equally safe?
9. Is browser stale-state handling equally strong?
10. Is public browser data equally minimized?
11. Are page/entity authorization boundaries equivalent?
12. Are durable cleanup/recovery semantics equivalent?
13. Are there unnecessary HA-Nova listeners/routes?
14. Are credentials/secrets equally well isolated?
15. What Online-specific behavior should NOT be copied?
16. How much implementation is actually warranted before beta?
17. Can both products use Access Pages Portable Configuration v1?
18. What percentage of current page/entity configuration is directly portable?
19. What requires translation?
20. What must never be portable?
21. Can invitation intent migrate safely?
22. How should old LayerV qURLs be revoked during migration?
23. What happens if old-backend revocation cannot complete?
24. Can migration work in both directions?
25. Should the portable schema be defined before external beta?
26. Should portable import/export itself be implemented before external beta?
27. Is a shared code package necessary?
28. What is the shortest safe path from the post-diagnostic HA-Nova baseline to external beta?
29. What work can safely wait until beta is underway?
30. Is HA-Nova ready for the resulting implementation plan?

READ-ONLY REVIEW ONLY.
NO IMPLEMENTATION.
NO DEPLOYMENT.