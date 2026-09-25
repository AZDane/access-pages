# Gateway architecture

Access Pages enforces guest grants, saved page policy, and Home Assistant action
authorization. LayerV supplies qURL admission and the Connector. See
[SECURITY.md](SECURITY.md) for the implemented trust boundaries and remaining
limitations.

## Purpose

Access Pages for Home Assistant gives a guest narrowly scoped access to Home
Assistant resources selected by an administrator. The browser is not trusted
to choose a Home Assistant entity, domain, service, or unrestricted parameter.
The server resolves those values from the saved page policy.

The current private-development Gateway is dependency-free Python 3.12 and uses
`ThreadingHTTPServer`. Small static Go processes provide the page-facing
endpoints. The Home Assistant App runs these components with supporting
brokers and stores under separate process identities inside one App container.
The pinned Connector's `/var/log/layerv` path links to the App's persistent
`/data/logs/layer-v-connector` directory. Page audit files under that directory
are supplied to the Connector through `QURL_AUDIT_FILE`.

The packaged App routes per-page Go endpoints to one shared unprivileged Guest
Service over a Unix socket. The Guest Service has no HA admin, policy
publication, LayerV management, or SMTP credential. It sends scoped guest
requests to the HA broker's restricted guest Unix interface, where the broker
checks current grants, individual sessions, verification, published policy,
proximity, and action parameters. The administrative Python Gateway remains
available for owner operations and narrow verification-email delivery; it is
outside ordinary guest HTTP traffic. Fresh installations use broker-owned
individual guest sessions.

## LayerV enrollment and resources

The App packages qURL 2.6.0 with embedded Connector module v0.14.0. One
externally supervised Connector runtime serves the installation. A dedicated,
retained management API key has qURL read/write and enrollment-token minting
authority. On the first required publication of a genuinely fresh
installation, Access Pages mints a one-shot enrollment token and passes it to
`qurl login` through a protected temporary file. The persistent API key is not
the login credential. Sealed Agent/device state and its local wrapping key are
retained for later publications and restarts. Loss or rejection of established
Agent state fails closed and requires explicit administrator recovery; it never
triggers automatic re-enrollment.

`resource_isolation: guest` is the default: each grant has its own LayerV
resource/CRID and qURL. This gives stronger upstream separation for guests who
may share a public IP. Optional `resource_isolation: page` shares one
resource/CRID for an Access Page while keeping one qURL, grant, and session per
guest. Both modes use the same Connector runtime. The Gateway generates a
grant-specific `target_path`, and the LayerV broker requires confirmation that
the qURL uses it before granting access.

## Primary modules

| Module | Responsibility |
| --- | --- |
| `server.py` | Administrative Gateway, owner UI/API, preview, and email delivery |
| `guest_service.py` | Isolated scoped guest shell, assets, cookies, and broker-backed guest API |
| `admin.py` | Administrative page, grant, email, preview, qURL, reset, activity, update, and deletion routes |
| `access.py` | Administrative preview data and action routes |
| `internal.py` | Narrow internal verification-email broker endpoint |
| `actions.py` | Administrative preview action validation and Home Assistant dispatch |
| `pages.py` | Page and grant validation plus atomic JSON persistence |
| `ha.py` | Direct and brokered Home Assistant clients, discovery, state reads, capabilities, and service calls |
| `ha_broker.py` | Broker-owned guest authorization and published-policy resolution, plus separate admin broker operations |
| `layerv.py` / `layerv_broker.py` | LayerV qURL creation and deletion clients and broker policy |
| `policy.py` / `policy_store.py` | Publication and storage of grant-free authoritative page policy |
| `activity.py` | Bounded, privacy-conscious guest activity and security-event storage |
| `verification.py` | Email challenge and verified-session lifecycle |
| `email_delivery.py` | TLS-only SMTP configuration, validation, and message delivery |
| `rate_limit.py` | Thread-safe sliding-window rate limiting |
| `config.py` | Environment and secret-file configuration validation |

The browser clients use dependency-free native ES modules:

- `static/admin.js` owns admin UI state, rendering, and feature workflows;
  `static/admin-api.js` is the only admin HTTP transport and attaches the admin
  credential to requests.
- `static/access.js` owns guest UI state, rendering, polling, and access-ended
  behavior; `static/access-api.js` constructs authorized guest URLs and is the
  only guest HTTP transport.

The browser modules improve usability but do not make authorization decisions.
Keeping transport separate makes request construction and credential handling
reviewable without introducing a framework or bundler.

## HTTP trust-boundary dispatch

The administrative `server.py` handlers validate the request envelope and
dispatch by URL namespace. Ordinary guest traffic does not enter this server:

```text
GET/POST/PUT/DELETE request
            |
            v
  shared request validation
            |
     +------+------+----------------+
     |             |                |
/api/admin/*  /api/admin/preview/*  /api/internal/email/guest-verification
     |             |                |
  admin.py      access.py       internal.py
     |             |                |
 admin token   admin preview    HA broker token
                token
```

The modules expose ordinary functions and receive the existing handler plus
the gateway's shared runtime namespace. They do not construct duplicate
clients, stores, locks, or rate limiters. There is no routing framework or
route-class hierarchy.

The Gateway has no endpoint capability authority or ordinary guest route.

## Packaged guest read flow

```text
Guest request
    -> dedicated compiled page endpoint process
    -> allow only scoped guest routes and inject its page capability
    -> verify Guest Service Unix peer UID/GID 2101
    -> isolated Guest Service handles shell, cookies, and guest HTTP
    -> HA broker guest socket verifies Guest Service UID 2101
    -> broker binds capability to page and validates current grant/session
    -> broker enforces verification and published resource policy
    -> broker filters Home Assistant state and camera responses
    -> return a sanitized page response
```

The page capability identifies the endpoint to the guest broker; it is not a
guest session or an HA admin credential. The shell contains no live Home
Assistant data. Metadata, state, camera images, and actions require the
individual guest session and current grant. The Guest Service cannot load the
admin Gateway's private page or email stores.

The broker emits only typed, authenticated guest activity and notification
events derived from identities and outcomes it has validated. The Admin side
persists activity, selects recipients, and delivers configured alerts. Guest
Service has neither Admin activity-write nor notification authority.

## Guest action flow

All guest Home Assistant mutations follow one path:

```text
POST /g/<page>/<grant>/api/access/<page>/<resource>/<action>
    -> page-bound Go endpoint -> isolated Guest Service
    -> HA broker guest Unix interface
    -> bind page capability and individual session to current grant
    -> enforce verification and guest action rate limit
    -> resolve resource/action from current published policy
    -> validate proximity and action parameters
    -> recheck current grant and policy immediately before HA dispatch
    -> return a sanitized action result
```

An action already dispatched to Home Assistant cannot be recalled by a later
revocation. Broker rechecks prevent a revoked grant or changed policy from
authorizing a later dispatch. Gateway `access.py` and `actions.py` serve only
administrative preview.

The App runs one compiled endpoint per page under a distinct Linux UID. Each
receives one page capability and access to the Guest Service socket through
group 2004; it receives no page data, alert recipients, or HA credential. The
broker derives the page from the capability and enforces guest authorization.
The App still shares a loopback namespace, so separate UIDs alone do not
establish cross-page network isolation.

## Administration and revocation

Administrative operations require the admin token even when the administrative
namespace is enabled. Home Assistant Ingress is the intended UI entry point and
adds the internal credential when forwarding requests.

Grant revocation, revoke-all, page deletion, and LayerV connection reset remove
local grant records before attempting remote qURL cleanup. Invitations
require a grant-bound session on every protected request, with no page-wide
fallback. Pending cleanup is persisted and retried after restart. Per-guest
cleanup deletes only the privately bound resource, covering its qURL; per-page
cleanup preserves the shared resource. The guest session path denies removed
grants even when another grant remains active on the page. A remote LayerV
failure is reported but never restores the local grant. Page deletion and
revocation also clean up verification state according to the operation.
The durable Admin and LayerV broker queues retry failed upstream cleanup after
temporary errors and process restarts. In page mode, revoking one guest does
not retire the shared resource while another guest still needs it.

## Persistence

- Page JSON is stored atomically under `$GATEWAY_DATA_DIR/pages`.
- New guest bearer tokens are persisted only as SHA-256 hashes.
- Complete invitation links are also retained for owner sharing until the owner
  confirms **Finished Sharing**. This clears the saved link while preserving
  grant authority and cleanup identifiers; it does not revoke the invitation.
  Earlier backups and distributed copies may still contain the link. No secure
  erasure is attempted.
- Guest activity and verification state use separate SQLite stores.
- SMTP, connector, broker, and policy data use separately permissioned App
  directories and process identities.
- Runtime data, connector state, credentials, backups, and logs are not source
  artifacts and must not enter the repository.

## Concurrency and availability controls

- `GatewayHTTPServer` caps active request threads and applies connection
  timeouts.
- Page locks linearize mutations against local revocation and deletion.
- Rate limiters use internal locks and bound guest action and invalid-access
  traffic.
- Request body, header count, aggregate header size, and camera response size
  are bounded.
- The Go endpoint supplies the public guest CSP, Referrer-Policy, nosniff, and
  no-store headers once; Guest Service does not disclose a Python Server value.

## Further reading

- `SECURITY.md` defines the concise credential and authorization contract.
- `REVIEW_GUIDE.md` maps critical invariants to code and tests.
