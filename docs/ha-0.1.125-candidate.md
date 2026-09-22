# Access Pages HA 0.1.125 candidate

This is a review candidate, not a published release. The comparison baseline is
0.1.124, commit `d4ff4eb55ff47d34b7c759efbb026804cfb4fe9e`. The PR head identifies
the candidate. Merge, release, App Store synchronization, LayerV changes and the
Online lessons audit are outside this candidate's authorization.

The cleanup candidate supersedes `cca408d4e72ed5469aed939d5c70a835822d4ee8`.
Its only additional changes correct opaque identifier classification, include
the diagnostic dependency in the root image, and reduce normal polling logs
while preserving slow/error stage evidence. Existing routing/policy validation
and session persistence are unchanged; there are no new reserved identifiers.

## Source scope

- **A:** Guest Service skips zero-length body writes, preserves 303/Location and
  Secure/HttpOnly/SameSite cookies, and treats BrokenPipe/ConnectionReset as the
  end of a response. It never sends a second 503 to that disconnected peer.
- **B:** After successful email verification, a failed state read goes through
  the page's unavailable/retry handling. Failed verification remains in the
  verification dialog; revocation still ends access. No verification policy or
  session storage changes.
- **C:** Correlated, bounded diagnostics in the existing Go Gateway, Python
  Guest Service, HA broker and HA client. No public diagnostic endpoint.
- **D:** A separate eight-second action-request lifetime from Gateway receipt.
  Existing authorization-expiry checks remain separate and mandatory.
- Packaging changes add the diagnostic module and set candidate version 0.1.125.
  Tests and this document accompany these four changes.

No broker concurrency, caching, LayerV protocol/admission changes, browser timeout
increase, automatic action retry, session migration, Online changes or unrelated
UI/refactoring are included. The ten-second browser timeout remains unchanged.

## Production source delta

Git text-line counts against 0.1.124, including comments and blank lines,
excluding tests, documentation, Docker packaging and version metadata:

| Production file | Added | Removed |
| --- | ---: | ---: |
| `cmd/guest-endpoint/main.go` | 105 | 3 |
| `cmd/guest-endpoint/timing_linux.go` (new) | 136 | 0 |
| `guest_diagnostics.py` (new) | 293 | 0 |
| `guest_service.py` | 89 | 9 |
| `ha.py` | 13 | 2 |
| `ha_broker.py` | 54 | 0 |
| `static/access.js` | 11 | 3 |
| **Total** | **701** | **17** |

Net production change: **+684 lines**. Relative to superseded `cca408d4`, the
production cleanup is **+169/-19**, net **+150** lines. Packaging/version metadata
adds four lines and removes three across both Dockerfiles and `config.yaml`. The other
changed files are the changelog, this review/acceptance document, Go tests and
Python/frontend regression tests. `static/admin.js`, `verification.py`,
`layerv.py` and `layerv_broker.py` have no source delta.

## Deadline contract and limits

The Gateway creates a random 128-bit request ID and captures Linux
`CLOCK_BOOTTIME` on HTTP handler entry, before forwarding or local queueing.
Python uses the same host clock, including suspend time. Internal headers carry
that original start unchanged through Guest Service and every broker RPC. The
Gateway strips client-supplied internal headers first. Unix socket permissions,
page capability and peer identity checks remain in place; the timing ID grants
no authority. Missing, duplicate, malformed or future timing is rejected for
public actions and the broker action route.

The absolute action deadline is always `original_start + 8 seconds`. It is
checked on Guest Service entry, at broker dequeue, after policy/session
revalidation and again at the HA HTTP boundary. Broker connection/read and HA
HTTP timeouts are capped by the remaining budget; a new RPC never renews it.
The Gateway also stops unambiguous action proxy requests at eight seconds.
`verification/send` and `verification/verify` are ambiguous until existing payload
validation selects either verification or a saved action. Guest Service refines
the operation from that actual RPC route, preserving the original Gateway clock.
The broker's actual action route enables the deadline independently of diagnostic
labels; unknown labels cannot reject a valid action or remove its deadline.
Expired queued work cannot initiate an HA service POST. Recovery only polls
state; another action requires another deliberate command.

**The clock starts at Gateway receipt, not the browser's click.** LayerV or any
upstream proxy can delay a request before the Gateway sees it. If that proxy
also hides browser cancellation, the request can arrive after the browser's
ten-second timeout and still have a fresh server receipt budget. This candidate
cannot securely measure that unseen interval. It does not trust browser
wall-clock timestamps or claim to prevent all execution after browser timeout.
Within Access Pages, subsequent transport/queue stages cannot extend the
original Gateway budget.

Once the HA HTTP request has been dispatched, expiration, a response timeout or
revocation cannot recall it. A missing response means the outcome may be
unknown; refresh state before explicitly deciding whether to issue a new action.
HA may complete an already-dispatched operation after either timeout.

## Diagnostic events and fields

All request diagnostics are JSON lines. Gateway and Python processes each use a
bounded 256-record queue and a background output worker. Request handling never
waits for log output; saturation drops records and increments `dropped_events`.
There is no sampling. Asset and health noise is omitted. Logging windows can be
incomplete because of drops, process exit/restart, or external log truncation.

Ordinary successful state polls emit **one Gateway completion record**. Python
holds at most 32 sanitized records per request, flushing detailed history for
elapsed time >=250 ms, broker wait >=100 ms, failures/denials/disconnects, or a
change in the process's drop counter. Actions, verification and session transitions
retain detailed logging. No output I/O occurs on request threads.

A fixed, bounded numeric internal response header carries five stage offsets and
broker wait through the existing verified Unix peers. The Gateway consumes and
removes it; malformed telemetry is ignored and cannot reject a response. The
completion's `stages_us` array contains, in order: Guest Service receipt, RPC sent,
broker handling start, HA request start, HA completion (microseconds since original
Gateway receipt), and broker wait duration in microseconds. `-1` means unavailable.
The last element is queue/connect/IPC time, **not HA latency**. This compact trace
preserves upstream stage evidence even if a fast successful backend is followed
by a slow or disconnected downstream Gateway write. Gateway receipt is represented
by elapsed time zero; its separate receipt record is retained for interesting
state requests with its original timestamp. Buffered records can arrive out of
order: reconstruct using request ID and monotonic elapsed time, not log line order.

Measured across 116 ordinary polls: **1 record, median 389 bytes** (387–395), versus
14 records / 4,453 bytes before cleanup: **91.3% less**, about **0.445 MiB/hour**
or **10.68 MiB/day** per continuously visible device at three-second polling.
A deliberately slow request retained 14 records / 4,548 bytes; a 10-second HA
timeout retained 13 / 4,165, including all required stage markers. A blocked output
worker test accepted 10,000 nonblocking enqueue attempts in approximately 10 ms,
dropped 9,999 with a one-slot test queue, and reported the cumulative drop count
after recovery. Production queue capacity remains 256; detailed logs remain
best-effort under output failure/backpressure.

Common fields: `event`, `component`, `instance_id`, `process_id`, `request_id`,
`operation`, UTC `timestamp`, monotonic `elapsed_ms`, `outcome`, `dropped_events`.
`status` and `status_class` appear when an HTTP status is known. A new opaque
`instance_id` identifies each process start. The Gateway returns
`X-Access-Pages-Request-ID` when it can return response headers.

| Event | Meaning / additional fields |
| --- | --- |
| `guest_request_received` | Gateway handler entered. |
| `guest_service_received` | Guest Service entered with the Gateway context. |
| `broker_rpc_sent` | Guest Service finished sending its RPC; `duration_ms` covers connect/peer-check/send. |
| `broker_request_started` | Broker began handling; `broker_wait_ms` covers time since the sender began that RPC, including connect, queue, IPC, accept and HTTP header handling. **It is not HA latency.** |
| `ha_request_started` | Entry to the HA dispatch boundary; `ha_operation` is `state_read`, `service_call`, `camera_read` or `other`. |
| `ha_response_completed` | HA response body processing completed or failed; `duration_ms`, sanitized outcome and known HTTP status. |
| `guest_work_completed` | Local operation completed; `work` is `connector_health`, `session_validation`, `policy_preparation` or `guest_event`, with `duration_ms`. Successful function completion does not itself mean authorization was granted or event delivery acknowledged. Policy preparation may include an HA read; do not sum nested spans. |
| `broker_response_written` | Broker response handling ended, including peer disconnect outcome. |
| `broker_rpc_failed` | Guest Service observed RPC timeout/disconnect. |
| `guest_request_failed` | Guest request handling ended with timeout/disconnect; use the last completed stage and any `broker_rpc_failed` event to locate the failure. |
| `guest_response_written` | Guest Service response write completed or encountered disconnect. |
| `gateway_response_completed` | Gateway proxy handling ended; `bytes` when nonzero, status and disconnect/timeout outcome. A successful completion means handed downstream, **not proven browser receipt**. |
| `action_not_dispatched` | A request-deadline guard rejected work before service dispatch, outcome `deadline_exceeded`. Other authorization denials retain their existing HTTP status and are not relabeled as deadlines. |

Operation categories are bootstrap, document, asset, state, camera, verification,
action and other. Outcomes are fixed categories, including success, denied,
unavailable, disconnected, timeout and deadline_exceeded. No raw URLs, query
strings, cookies, page/bootstrap/API capabilities, tokens, email addresses,
OTPs, entity IDs, states, action parameters, HA payloads or exception text enter
this diagnostic schema. The request ID is independently generated and is not a
session hash or credential. Internal clock headers are not browser credentials.

Interpretation requires a complete timeline, not an isolated missing line:

- Browser request with no Gateway record in a complete, continuously observed
  logging window: investigate the pre-Gateway path with LayerV. Ordinary polls
  have a completion summary instead of a separate receipt line. Wait for pending
  request handling to finish; exclude log loss and process termination before
  inferring non-arrival. This alone does not identify an access controller.
- Gateway receipt followed by late Guest Service receipt: local proxy/service
  delay. Use Connector-health duration and RPC markers for the following gap.
- Long `broker_wait_ms`: local queue/IPC delay; HA spans identify the work
  occupying the broker, if any.
- Long HA span: HA HTTP latency; session/policy/event timings distinguish other
  local work from HA time.
- Fast Gateway completion but browser timeout: investigate downstream transport
  and browser behavior; completion does not prove delivery.

## Local candidate validation

- All **366 Python tests** pass (the existing 361 plus five focused regressions), including real Unix disconnect tests for 303,
  normal state and error responses; deadline-at-dequeue/final-boundary tests;
  metadata validation, RPC lifetime preservation, redaction, bounded logging,
  per-device authorization and frontend verification recovery.
- Gateway tests pass with the Go race detector; the Gateway compiles for ARM64.
  Ruff, Bandit and JavaScript syntax checks pass.
- Both supported images build, import the required production modules in isolation,
  and serve a real local health request with the app's broker configuration.
  Their 21 shared Python modules match byte-for-byte; only the HA image additionally
  needs `guest_service.py`. Import-dependency closure is checked, with no test-only
  modules packaged. The existing packaged real-UID security probe
  passes, including permission/socket boundaries, verification, revocation,
  corrupt data, service restart and outage handling.
- **20 Chrome runtime scenario groups** pass through the packaged Gateway,
  Guest Service and HA broker with a synthetic HA HTTP server. They cover 20
  repeated pairs of fresh devices, legacy consumed reusable grants and original
  sessions, single-use links, expiry, verification isolation, revocation,
  delayed initial/polled state, automatic recovery and action timing.
- A further six repeated device pairs run with delayed 303 headers. In the redirect
  acceptance run, real 303 responses pause 250 ms after header flush;
  redirects/cookies continue working with no BrokenPipe traceback or secondary
  503. Entirely withheld redirects are tested separately: reusable manual retry
  works and single-use consumption remains enforced.
- A timely queued action dispatches once after about two seconds. An action
  behind about 11.8 seconds of broker work produces **zero new HA service
  POSTs**. Revocation and authorization expiry while queued also produce zero.
  Recovery never replays actions; a fresh deliberate command succeeds.
- All **2,338 diagnostic records / 369 request IDs** pass strict field/schema
  and private-sentinel checks, with no dropped events. Full cross-process stages
  are correlated for state and action requests. Controlled broker wait reaches
  11.810 seconds while a separate HA span reaches 10.008 seconds, demonstrating
  that those measurements are distinct.
- A buffering proxy deliberately holds an action before Gateway receipt and
  hides browser cancellation. The Gateway receives it 11.529 seconds after the
  click, then dispatches within 0.007 seconds. This is a passing **limitation
  test**, not a claim of universal cancellation after browser timeout.
- A packaged identifier matrix executes **72 authorized HA actions** across page
  IDs `static`, `camera`, `api`, `health`; resource/action names `static`, `camera`,
  `state`, `action`; and the ambiguous `verification/send` and `verification/verify`
  saved actions. Actual camera and static routes pass. Unit coverage also searches
  `verification`, `g`, `access`, `api`, and `health` identifier positions. Existing
  route validation remains unchanged.

These are local packaged-runtime results, not live LayerV acceptance and not
proof of the historical incident's cause. Runtime fixtures, results, source
hashes and logs are retained in the task's candidate evidence bundle. GitHub
required-check results belong to the frozen PR head and are reported with it.

## Real LayerV acceptance procedure

Local acceptance uses the packaged processes and their real Unix identities,
with a synthetic HA HTTP server and Chrome over local HTTPS. It cannot exercise
LayerV's access controllers. The owner previously elected to install/test the
GitHub beta themselves; no live test installation or qURL was supplied here.
Real LayerV acceptance remains pending and must not be reported as passed.

After candidate review and separate authorization for a beta installation:

1. On an owner-controlled HA test installation, record the installed source/image
   identity and UTC time. Retain a reusable invitation created before upgrading,
   with its original device session. Use only harmless test entities, such as a
   dedicated input_boolean. Capture the App log continuously, including process
   starts and dropped-event counters. Leave LayerV configuration unchanged.
2. Open that existing qURL on its original device, then on an independent device
   or fresh browser profile through the real external LayerV route. Confirm both
   can read approved state and execute a deliberate harmless action. Inspect
   cookies locally to confirm separate sessions; do not copy cookie values into
   logs or reports. Confirm the original device also retains access.
3. Repeat with a newly created reusable invitation and several first-open runs,
   both sequentially and concurrently. Repeat with email verification enabled:
   each device must verify separately, device A's code must not verify device B,
   and the unverified device must receive neither state nor action access.
4. Revoke each reusable invitation and verify both devices lose state and action
   access. Verify a single-use invitation admits one device only, and an expired
   invitation denies access. Confirm the Admin save message is `Page saved.` and
   no obsolete ten-minute warm/sleep message appears.
5. In a controlled test network, delay a state response beyond ten seconds. Verify
   controls clear, a retained old control cannot act, and polling recovers with
   the same device session. Repeat immediately after successful verification;
   the error must be visible on the page and recover without another code.
6. Using a controlled HA test responder/fault fixture, hold the serial broker
   behind state work and issue a harmless action. Below eight seconds it may
   dispatch once; beyond eight seconds from **Gateway receipt** it must produce
   zero HA service POSTs. Revoke or expire authority while queued and repeat.
   After recovery, verify no automatic action occurs; a fresh deliberate action
   must still work. Count HA calls directly, not just browser responses.
7. Test downstream loss of a 303 and loss of an already-dispatched action's
   response separately. Successful 303 headers retain cookie/Location behavior;
   a wholly lost redirect may require reopening the invitation. Single-use
   consumption must not be relaxed to recover lost headers. An already-sent
   action may execute once, but must never be automatically replayed.
8. If the unexplained timeout recurs, record device/browser, verification state,
   exact UTC interval, browser Network method/status/duration and returned
   request ID when available. Share sanitized stage records. Do not export an
   unsanitized HAR (it contains credentials and private URLs).
9. Ask LayerV to correlate that exact interval with admission creation/refresh,
   admission generation and propagation/acknowledgement at **every** access
   controller, controller selection/route changes, allow/deny decisions, ingress
   and connector stream open/forward/close times, reset/timeout reasons, and the
   partial-AC fix's actual deployment time/version. Compare with Access Pages
   receipt, broker wait, HA duration and downstream completion.

A failure in source acceptance stops publication and requires a reviewed source
change; it is not permission to hot-fix a released image. The original 0.1.124
live timeout remains **unresolved**. Partial access-controller admission is a
technically consistent external hypothesis, not a proven root cause. Correcting
the independently reproducible 303 write issue does not establish that the live
state timeout is fixed.
