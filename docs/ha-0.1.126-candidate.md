# Access Pages HA 0.1.126 implementation candidate

Candidate only; owner approval is required before merge, release, App Store
synchronization, or live deployment. The historical timeout remains UNKNOWN.
Normal development does not depend on resolving that incident.

## 1–4. Branch, source, and exact production changes

Branch: `codex/ha-0.1.126-minimum-observability`.
Pull request: https://github.com/AZDane/access-pages/pull/14 (draft).
Runtime source commit: `a1152b918ee0cc740b581bccd06ee4ddb7e046ee`.
Later evidence and whitespace-only commits do not change runtime behavior.

The feature branch was created from fetched protected main
`0ef568e7ac9d03e8408938b71c67bf86a48920ec`. The unrelated Online lessons branch
was not included. The 0.1.125 frozen build remains available as a reference.

“Production” below means executable Python/Go/browser JavaScript, excluding
unit tests, documentation, workflow configuration, and packaging metadata.

| Baseline | Added | Removed | Net |
|---|---:|---:|---:|
| 0.1.125 main `0ef568e` | 578 | 416 | +162 |
| 0.1.124 `d4ff4eb` | 868 | 22 | +846 |

Image/App configuration adds +7/-3 versus 0.1.125 and +8/-3 versus
0.1.124 across the two Dockerfiles, `config.yaml`, and `apparmor.txt`. Including
those production packaging files gives **+585/-419 (net +166)** versus 0.1.125
and **+876/-25 (net +851)** versus 0.1.124. CI adds one native ARM64 job; it does
not weaken the four existing required checks.

This is a structural simplification, **not a line-count reduction**. The hard
emission bounds in two runtimes, restart-safe activation, and closed-output
handling cost more code than the unthrottled 0.1.125 sinks. The earlier estimate
of 350–550 net production lines above 0.1.124 was too low. No collector, history,
export service, or diagnostic storage was added to justify that difference.

## 5–7. Removed machinery, retained evidence, independent safety

Removed `StateTrace`, per-request lists of events, interesting-event propagation,
helper decorators, helper timing taxonomy, buffered healthy-event construction,
and duplicate detailed event/stage histories. The Python diagnostic module is
210 lines; its request lifetime logic
moved to `guest_request.py`, which imports no logging module.

Retained: a random opaque request ID; trusted Gateway CLOCK_BOOTTIME origin;
fixed numeric timing transport on existing internal request/response paths;
the dynamic browser response ID; one fixed 12-slot timing vector per in-flight
request. Internal timing headers are stripped at the Gateway. Browser body-read
errors retain a validated returned ID without sending it elsewhere.

The route classifier remains because it distinguishes real assets, correlated
operations, and unambiguous actions while preserving opaque saved identifiers.
Ambiguous verification/action paths are refined only after payload validation.
The actual broker route owns action semantics, independently of diagnostic labels.

The vector is milliseconds from Gateway receipt (clamped at 600,000), with `-1`
for an unobserved boundary:

| Slot | Meaning |
|---:|---|
| 0 | Guest Service receipt |
| 1 | First broker RPC initiation, before connection |
| 2 | First broker handling start |
| 3 | First HA request invocation |
| 4 | Latest HA invocation/body-processing end, including failed completion |
| 5 | Latest broker response readiness |
| 6 | Guest Service response readiness |
| 7 | HA call count, capped at 600,000 |
| 8 | Total HA call duration, milliseconds, capped at 600,000 |
| 9 | Broker RPC count, capped at 600,000 |
| 10 | Service dispatch: 0 unknown, 1 not attempted, 2 attempted/unconfirmed, 3 confirmed |
| 11 | Fixed failure code: 0 none, 1 error, 2 timeout, 3 deadline, 4 disconnect, 6 RPC, 7 activity delivery |

Gateway receipt/completion are observations in their own right; `ms` is the
current elapsed time. Multiple calls use counts/totals and first/latest offsets,
not span lists. RPC-to-broker delay combines connection, IPC, and waiting; it is
not a kernel-queue measurement. A failed HA end observation is not proof of a
successful response. A loss-only record carries no request evidence.

`guest_request.py` owns the original nonrenewable eight-second budget, trusted
header validation, and remaining-budget calculation. `ha.py` and both services
call that module directly. Go lifetime/clock/ID primitives are separate from its
sink. Logging mode, output success, and diagnostic categories do not authorize
or renew an action. Existing final authorization/expiry/revocation checks remain.

A deadline summary claims non-dispatch only with positive evidence. A service
invocation without confirmation is uncertain. No action is replayed. Remaining
socket timeouts are not a hard total-I/O deadline, a pre-Gateway delay is outside
this lifetime, and an already-dispatched command cannot be recalled.

## 8–12. Exact logging, configuration, expiry, and resource bounds

Normal mode emits no per-request records for healthy requests below five seconds,
including successful three-second polling. A Gateway summary is eligible for an
unexpected error, transport/HA failure, disconnect, stale-action rejection,
uncertainty, or elapsed time >=5 seconds. Routine security denials are not logged
again. Generic Admin access logging for `/api/internal/guest-event` is suppressed
for all response statuses; the existing business/security processing remains.
The broker observes callback delivery errors. Backend fallback records cover exceptions/disconnects whose evidence
cannot reach the Gateway. A small number of duplicate fallback records can
therefore occur; no deduplication table is maintained. Failed delivery of an
existing business activity callback is marked in the summary, replacing its
previous repeated diagnostic prints; the callback itself is unchanged.

The native App option is:

```yaml
diagnostic_logging: "off"  # off | 30 minutes | 1 hour | 4 hours
```

Save and restart to enable. One root-owned byte in `/data/diagnostics-consumed`
is a consumed-configuration latch, not a diagnostic log or quota ledger. It is
fsynced before enabling; activation failure leaves logging off. A non-Off
selection cannot reactivate on restart or by choosing a different duration.
To rearm: Off → save/restart → duration → save/restart. Startup prints one ordinary
lifecycle line showing whether a temporary capture was enabled or remains off.
The selector is a request for activation, not a live status indicator.

The supervisor passes one absolute CLOCK_BOOTTIME deadline to the existing
Gateway, Guest Service, and HA Broker processes. Traffic and later child starts
cannot renew it. The deadline includes suspend time and ignores wall-clock
changes. Detailed observations stop at expiry; queued detailed records are
discarded. One write already blocked inside the output API may arrive later;
there is no continuing capture or indefinite shutdown drain.

Each process has a 16-entry queue and at most one output worker with one record
in hand. Snapshot fields and counters have fixed sizes; no completed history,
active registry, overdue scanner, per-request diagnostic thread, or diagnostic
timer exists. JSON encoding and output I/O run in the worker. The request path
drops on a full queue. Output failure has no fallback storm. Go ignores SIGPIPE
so a closed stderr pipe cannot terminate the Gateway; the regression first
reproduced termination before this fix.

Each encoded record is <=512 bytes, including newline. A packaged Python fixture
with maximum-valued fields encoded to 255 bytes and occupied 1,555 bytes including
referenced objects in that fixture. This is a measurement, not a universal heap
byte cap: interpreter objects, shared strings, queues, and thread stacks add
runtime overhead. The enforceable memory bound is fixed record count and schema.

Both admission and output use a token bucket:

| Mode | Burst capacity | Refill | Bound over T seconds in a stable mode |
|---|---:|---:|---|
| Normal | 1 | 1 / 60 seconds | <=1 + floor(T/60) records/process |
| Detailed | 12 | 1 / 2 seconds | <=12 + floor(T/2) records/process |

Loss reports share the output allowance. Output blocked time earns no new burst.
Mode transition resets the allowance once; process restart resets volatile
counters/budgets. With P Gateway processes, aggregate allowances scale with P+2.
This is explicitly a **per-process bound**, not a fixed App-wide quota. For one
page, normal sustained output is at most three records/minute after initial
allowances; detailed output is at most 90/minute after initial allowances.
Large page counts multiply those limits. No restart-resistant rate ledger or
central allocation protocol is introduced.

`lost` combines suppression, full-queue, output, and stale-detail losses and is
saturated at 2,147,483,647. It includes failed attempts to report loss. Subsequent
records carry it; an idle worker attempts an unreported-loss summary once per
minute, still within its output budget. No losses means no idle output.

## 13–17. Measured output, requests, and resources

The [companion JSON](ha-0.1.126-measurements.json) contains raw numerical summaries and timestamps. Workloads
use disposable images, one Chrome device/page with a real three-second browser
poll loop, actual Gateway/Guest Service/broker processes and Unix sockets,
synthetic HA, and a synthetic existing connector-health endpoint. No real LayerV
route or HA-Nova production workload is used. CPU and RSS sum the three guest production
processes, excluding the browser, Admin/test-host process, synthetic services,
and unrelated host work.
Latency is measured by the local TLS test proxy, not across LayerV.

A ten-minute development-build comparison produced:

| Metric | 0.1.125 | 0.1.126 normal | 0.1.126 detailed |
|---|---:|---:|---:|
| Browser polls / HA reads / existing connector probes | 199 / 199 / 199 | 199 / 199 / 199 | 199 / 199 / 199 |
| Existing activity callbacks | 199 | 199 | 199 |
| Diagnostic records | 199 | 0 | 908 |
| Diagnostic bytes | 77,369 | 0 | 158,268 |
| Production CPU seconds | 1.08 | 1.04 | 1.13 |
| Final production RSS, bytes | 79,355,904 | 80,535,552 | 79,536,128 |
| Median request latency, ms | 6.365 | 6.180 | 6.399 |
| P95 request latency, ms | 6.981 | 6.867 | 7.319 |

That development image predates the final closed-output, loss-accounting and
summary refinements. It is supporting evidence, not an exact-final-image claim.
Separate confirmation with the final boundary/sink code and the final real
Admin callback logger is recorded below and in JSON.
Do not infer a statistically established CPU/RSS improvement from these small,
shared-host samples. They show no material latency regression in this fixture.


The final source (`a1152b9`) also ran a two-minute equivalent workload through
**the real Admin HTTP handler and activity store**, rather than the quiet stub.
Admin runs inside the disposable test-host process for this comparison; the
separate packaged security probe verifies its production UID/permissions.

| Metric | 0.1.125 real Admin | 0.1.126 final real Admin |
|---|---:|---:|
| Polls / HA reads / connector probes / activity callbacks | 40 / 40 / 40 / 40 | 40 / 40 / 40 / 40 |
| Request diagnostic records / bytes | 40 / 15,550 | **0 / 0** |
| Redundant Admin callback access lines / bytes | 40 / 3,400 | **0 / 0** |
| Guest process CPU seconds | 0.22 | 0.21 |
| Guest process RSS before → after, bytes | 75,845,632 → 77,680,640 | 77,967,360 → 80,314,368 |
| Median / P95 latency, ms | 6.888 / 8.178 | 6.724 / 7.599 |

The separate reviewed-boundary runtime (`138f874`, before the Admin-only logging
correction) ran 40 polls in each of normal and expiring detailed mode over two
minutes. Both modes made 40 HA reads, probes and existing activity callbacks.
Normal emitted zero records/bytes; detailed emitted 137 records / 24,021 bytes
before reverting to normal. A test-only absolute deadline 90 seconds after
fixture startup expired at 20:26:57.003 UTC. No request observations appeared in
the remaining measured window through 20:27:31.894 UTC while 12 further HA reads completed.
The product configuration still offers only 30 minutes, one hour and four hours.
CPU seconds were 0.21 normal / 0.22 expiring detailed; final RSS was 80,228,352 /
78,614,528 bytes; P95 latency was 6.514 / 7.172 ms. The final Admin correction does
not change the sinks, timing boundaries, deadline, or emission budgets.

Healthy normal-mode observed emission rates are **0 records/hour/device and
0 diagnostic bytes/hour/device** (zero observed over the measured windows,
normalized to an hour; not a claimed hour-long live test). The old ten-minute
result projects to 1,194 records / 464,214 bytes per hour. No ordinary lifecycle
lines occurred inside the measured healthy windows. The initial fixture used a
synthetic Admin responder and therefore did not measure its access logs; the
final real-Admin comparison above explicitly covers that additional source. Startup messages are outside
those windows.

Sustained failure: 1,298 real failed state requests in 65 seconds emitted two
Gateway summaries totaling 370 bytes; maximum record length was 186 bytes. The
first showed HA start/end and status 502; the second carried `lost:1198`.
The later idle loss summary carried `lost:1298`: 1,296 suppressed request summaries
plus two suppressed loss-report attempts. Counters include loss-report attempts,
not just failed guest requests. This workload predates the final post-write
budget correction; the final regression additionally proves blocked time cannot
refill the output budget. Unit stress tests offer 1,000 events/second for one
simulated hour: 60 admissions normal, 1,811 detailed, excluding the endpoint.

The ten-minute detailed run's last observed counters were Gateway 98, Service
293, Broker 490. They are cumulative observations including startup requests;
unreported tail losses may follow. Missing observations never prove absence of
traffic. Normal healthy tests assert no emission and no Gateway loss increments.

Equivalent workloads produced zero extra HA reads, connector probes, activity
callbacks, or browser polls in either mode. Real LayerV request/connection counts
remain unmeasured here. Source changes contain no new network call or probe;
LayerV implementation and broker concurrency are unchanged. The accepted 61-byte
browser correlation header remains; bandwidth and connection/resource occupancy
are distinct from diagnostic log volume.

## 18. Home Assistant Logs and Download logs

Source verification, not a live HA-Nova UI claim:

- The [App log tab](https://github.com/home-assistant/frontend/blob/e5f1cb0b1fd8459202b2ed53de48f4afe05f0bb4/src/panels/config/apps/app-view/log/supervisor-app-log-tab.ts)
  uses the existing log card with the App slug as provider.
- The [download dialog](https://github.com/home-assistant/frontend/blob/e5f1cb0b1fd8459202b2ed53de48f4afe05f0bb4/src/panels/config/logs/dialog-download-logs.ts)
  requests a chosen number of lines and boot selection. Its request does not
  include the displayed text search filter. This is retained App output, not
  an Access Pages export or necessarily every historical line.
- [Supervisor routes](https://github.com/home-assistant/supervisor/blob/d0d259cf73e9191185b00a2a14c8f8f04b42f9c2/supervisor/api/__init__.py)
  select the App's journal identifiers. [Log handling](https://github.com/home-assistant/supervisor/blob/d0d259cf73e9191185b00a2a14c8f8f04b42f9c2/supervisor/api/host.py)
  applies boot/line filters; restricting output to the latest container epoch is
  a separate endpoint behavior. App restart does not itself delete retained
  journal history. Actual availability depends on HA retention/version.
- No supported persistent clear-log action was found in the App log UI source.
  Its display-clear operation resets rendered text, not journal storage.
  No clearing mechanism has been added.

The log includes stderr diagnostics and ordinary stdout/stderr App lifecycle
messages. It is not guaranteed to include arbitrary Connector-owned files. Only
this fixed request diagnostic schema is asserted free of paths, credentials,
cookies, email, bodies, entity state, and raw exceptions; other product/native
logs retain their existing behavior.

## 19. Validation

- Full Python regression/security suite: 372 tests passed in final runtime CI,
  including blocked-time accounting and real Admin callback access-log silence.
- Go race suite passed, including real Unix disconnects, healthy silence, a real
  five-second slow response, forged timing, ambiguous route IDs, throttles,
  blocked output, closed stderr, and conservative non-dispatch evidence.
- Frontend runtime suite passed, including verification recovery, no replay,
  visibility behavior, and request-ID preservation after body timeout.
- Ruff, Bandit, JavaScript syntax, and diff whitespace checks passed.
- Final amd64 packaged real-UID security and permission-repair probes passed.
  They cover sessions, verification, policy, actions, revocation, corrupt data,
  service restarts/outages, and file/socket identity boundaries.
- Native ARM64 CI builds and runs the same packaged real-UID security probe.
  The local cross-build failed only at ARM execution because this workstation
  lacks ARM emulation; native CI passes and supplies runtime evidence.
- Packaged duration latch: initial activation, same-selection restart off,
  Off rearm, and fresh activation passed using disposable data.
- Chrome packaged faults: 11 scenario groups passed across verification recovery,
  reusable/single-use behavior, per-device verification, revoked/expired queued
  actions, no replay, state timeouts, and delayed HA / serial broker waiting.
- Required GitHub checks and the additional ARM64 package check run on the draft
  PR; the completion report identifies their final-head result.

## 20–21. Deviations, limits, and UNKNOWN items

No prohibited architecture was added. A per-process throttle is the explicitly
allowed simple policy; it scales with process count and is not a global or
restart-resistant emission guarantee. The activation latch is the one permitted
piece of persistent activation state. The native selector requires two restarts
to rearm, deliberately avoiding a command interface or session subsystem.

Production code is larger than the early estimate, for the safety/resource
reasons above. Detailed mode is sampled by a shared per-process allowance; it
cannot promise every boundary for every request. There is no retrospective
history, first-failure completeness guarantee, or proof of downstream browser
receipt. A recurrence may need a new owner-enabled reproduction.

UNKNOWN: historical timeout cause; real LayerV timing/occupancy under this build;
HA-Nova CPU/RSS/latency; actual installed-version App UI/download/retention;
new marker rule under HA-Nova's enforced AppArmor; long-term beta failure mix.
None is represented as already verified by local Docker acceptance.

## 22. Proposed HA-Nova owner acceptance (not executed)

After approval of a specific candidate and its deployment route:

1. Record the existing App version, host resource readings, and baseline logs;
   keep 0.1.125 available as the forensic reference. Do not clear the journal.
2. Install the approved candidate with diagnostic logging Off. Verify retained
   invitations/sessions, two independently verified devices, expiry, revocation,
   single-use denial, and explicit actions without replay.
3. With one, then two visible devices, run ten-minute healthy polling windows.
   Count polls and existing HA/Connector activity where available; verify zero
   healthy `ap_diag` records and record CPU/RSS, latency, and HA log growth.
4. Enable 30 minutes through native Configuration. Verify boundary observations
   and the Logs tab / Download logs output, recording the installed HA versions,
   line selection, restart visibility, and any supported UI clearing behavior.
5. Verify automatic expiration while polling continues. Restart with the
   selection unchanged and verify capture remains off; then exercise Off rearm.
6. Reproduce a safe state-read delay or natural timeout if available. Inspect
   correlation and the last observed boundaries. Do not issue physical control
   faults or induce LayerV outages merely to test diagnostics.
7. Return to Off and retain the native downloaded log for owner review. Compare
   requests as well as bytes; report anything unobservable as UNKNOWN.

Normal Access Pages work can resume after acceptance. Resolving the historical
incident is not a prerequisite for every later product change.
