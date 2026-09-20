# Gateway review guide

## Review objective

Confirm that an untrusted browser or guest process cannot use one valid grant
to read or operate resources outside its saved page policy, cross into an
administrative or internal boundary, bypass revocation, or obtain upstream
credentials and sensitive response details.

This guide covers the production gateway and packaged Home Assistant App. Demo
infrastructure, attacker-lab material, generated presentations, and historical
reports are supporting research rather than the primary code-review path.

## Suggested reading order

1. `ARCHITECTURE.md` — modules, process boundaries, and request flows.
2. `SECURITY.md` — supported security claims and credential boundaries.
3. `config.py` and the initialization section of `server.py` — startup
   validation and shared services.
4. `Handler` helpers in `server.py` — request bounds, headers, authentication,
   logging, and page locking.
5. `admin.py`, `access.py`, and `internal.py` — administration, preview, and configured email delivery.
6. `ha_broker.py` — authoritative guest action policy and mutation path.
7. `pages.py` — stored policy validation and atomic persistence.
8. `ha.py` and `actions.py` — admin preview action handling and Home Assistant client.
9. `layerv.py`, `layerv_broker.py`, `policy.py`, and `policy_store.py` — qURL
   lifecycle and authoritative policy publication.
10. The tests mapped below, followed by the complete suite.

For the browser boundary, review `static/admin-api.js` and
`static/access-api.js` before their corresponding UI modules. Confirm that UI
modules do not call `window.fetch` directly and that the API modules remain
small transport adapters rather than sources of authorization policy.

## Critical invariants and evidence

| Invariant | Primary implementation | Regression evidence |
| --- | --- | --- |
| Admin Gateway rejects ordinary guest routes and endpoint capability | `server.py`, `access.py`, `internal.py` | `tests/test_gateway_roles.py` |
| Guest session is bound to one page and current grant | `guest_service.py`, `ha_broker.py` | `tests/test_guest_cutover.py`, `tests/test_broker_guest_sessions.py` |
| Broker resolves actions from saved policy and bounds parameters | `ha_broker.py` | `tests/test_broker_guest_sessions.py`, `tests/test_ha_broker.py` |
| Guest Service cannot mutate HA directly | `guest_service.py`, `ha_broker.py` | `tests/test_guest_service.py`, `tests/test_action_boundary.py` |
| Revocation and policy changes deny subsequent guest operations | `ha_broker.py`, `pages.py` | `tests/test_broker_guest_sessions.py`, `tests/test_server.py::IndividualRevokeTests` |
| LayerV cleanup failure cannot restore grants or retire another guest's resource | `server.py`, `layerv_broker.py`, `guest_resources.py` | `tests/test_cleanup_reconciliation.py` |
| Public guest headers are single-valued and disclose no Python Server version | `cmd/guest-endpoint/main.go`, `guest_service.py` | `cmd/guest-endpoint/main_test.go`, `tests/packaged_security_probe.py` |
| Internal listeners require their exact credentials | Broker handlers and `internal.py` | `tests/test_internal_listener_auth.py` |
| Published HA policy contains no guest grants | `policy.py`, `policy_store.py` | `tests/test_policy.py`, `tests/test_policy_store.py` |
| Logs and activity omit bearer credentials | `server.py`, `activity.py`, `audit.py` | `tests/test_activity.py` |
| Images contain every required runtime module | `Dockerfile`, `Dockerfile.ha-app` | `tests/test_packaging.py` |

## Boundary-specific questions

### Administration

- Does every administrative operation call `_require_admin()` before reading
  or changing protected state?
- Can malformed page, preview, activity, or qURL paths fall through to a more
  permissive handler?
- Do page updates validate server-curated entity and action policy before
  persistence and policy publication?
- On remote cleanup failure, does local revocation remain authoritative?

### Guest access

- Does the HA broker recheck the current grant and published policy immediately
  before Home Assistant dispatch?
- Can a token for page A select a resource from page B?
- Can the browser influence an upstream entity, domain, service, or an
  unrecognized parameter?
- Do verification, expiry, proximity, and rate-limit failures stop before
  Home Assistant dispatch?
- Are upstream errors and response bodies sanitized before returning to the
  browser?

### Internal and broker services

- Does each listener use a distinct credential and constant-time comparison?
- Does the HA broker resolve operations from authoritative policy rather than
  caller-supplied Home Assistant identifiers?
- Are the policy store, verification-email path, and qURL lifecycle broker
  limited to their explicit operations?
- Do process environments and filesystem permissions expose only the secrets
  needed by that process?

## Verification commands

Run the complete unit and adversarial suite:

```sh
python -m unittest discover -s tests -v
```

Check Python syntax for the routing and action boundary:

```sh
python -m py_compile server.py admin.py access.py internal.py actions.py
```

Build both production artifacts:

```sh
docker build -t access-pages:review .
docker build -f Dockerfile.ha-app -t access-pages-app:review .
```

Review whitespace and the exact proposed change:

```sh
git diff --check
git status --short
```

External Home Assistant and LayerV calls must remain mocked or locally fault
injected in unit and integration tests. Local tests may exercise the actual
Admin-to-broker transport and durable reconciliation without contacting
LayerV. End-to-end acceptance testing requires an explicitly authorized,
isolated environment with synthetic or disposable test data.

## Review completion record

A review report should state:

- exact commit and version reviewed;
- tests, builds, scanners, and manual scenarios performed;
- configuration and persistence implications;
- security findings and accepted residual risks;
- whether any credentials or live runtime artifacts were encountered; and
- screenshots for user-interface findings or changes.
