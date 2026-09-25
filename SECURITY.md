# Security policy

## Reporting a vulnerability

Do not report suspected vulnerabilities in a public GitHub issue or include
live API keys, qURLs, Home Assistant tokens, page data, connector state, or
logs in a public report.

Access Pages is responsible for security reports about this application.
Report them through [GitHub private vulnerability reporting for
AZDane/access-pages](https://github.com/AZDane/access-pages/security/advisories/new).
Include the affected App version, impact, reproduction steps using synthetic
credentials, and relevant sanitized logs in the private report.

## Security model

Invitations establish scoped, grant-bound Secure, HttpOnly sessions. Single-use
invitations consume their bootstrap once; renewable invitations can establish
independent sessions on multiple browsers until the grant expires or is revoked.
Email verification, when required, is bound to each session. Protected operations
check the current grant, and final HA dispatch checks expiry.
Local revocation precedes durable upstream cleanup. Default per-guest isolation
deletes the guest's LayerV resource, which also revokes its qURL; optional
per-page isolation deletes only the individual qURL and cannot promise
termination of established upstream connections. LayerV admission can be
shared by browsers behind the same public IP, so the individual broker-owned
guest session remains mandatory in both modes. See the
[configuration documentation](homeassistant-app/DOCS.md).

- Home Assistant authenticates administrators through Ingress.
- The administrative Gateway stores independent, expiring grants for each named
  guest; the HA broker requires that guest's current session on protected
  packaged routes.
- Every page, entity, action, and action parameter is enforced server-side.
- Invitation bootstrap secrets are stored as SHA-256 hashes. Remote qURL links
  are separately persisted and remain secret-bearing.
- Local revocation takes effect before remote qURL cleanup is attempted.
- The LayerV API key and connector identity are installation-specific secrets.

The App packages qURL 2.6.0 with embedded Connector v0.14.0 and supervises one
Connector runtime per installation. The retained management API key can read
and write qURLs and mint a one-shot Agent enrollment token; CRID/headless
resolve scope is not required. On the first publication of a genuinely fresh
installation, only that one-shot token is passed to `qurl login` through a
protected temporary file. The key, token, and persisted sealed Agent/device
credential have different roles. Later guests and restarts reuse the Agent
identity. Missing or rejected established state fails closed and requires
explicit administrator recovery, never automatic re-enrollment.

Default `resource_isolation: guest` gives each guest a distinct LayerV
resource/CRID and qURL for stronger upstream separation, including guests
behind one public IP. Optional `resource_isolation: page` shares one resource
among a page's guests while keeping independent qURLs, grants, and sessions.
Neither mode makes IP address a guest identity. Optional email verification
gates protected state and actions; a wrong or expired code grants no access.

The implemented request and credential boundaries are:

| Boundary | Accepted credential | Permitted scope | Implementation |
| --- | --- | --- | --- |
| Admin | Admin token in `X-Admin-Token`; short-lived signed token for page preview | Page, grant, email, preview, qURL, activity, and connection administration | `admin.py` and `access.py` |
| Guest | Individual grant-bound session and page capability | Saved page metadata, state, camera resources, and saved actions | Packaged `guest_service.py` and HA broker guest interface |
| Internal | Exact HA broker token | Configured guest-verification email delivery | `internal.py` |
| Home Assistant | Direct gateway credential or isolated HA broker credential | Server-resolved discovery, reads, proximity checks, and operations | `ha.py` and `ha_broker.py` |

Credentials are deliberately non-interchangeable. An admin token is not guest
authorization; a guest grant is not an admin or internal credential; and one
broker credential is not accepted by a different internal listener. The Admin
Gateway has no ordinary guest route or endpoint capability authority.
The Home Assistant broker supports per-page guest capabilities separately
from its admin credential. In the packaged App, each endpoint sends its page
capability through the isolated Guest Service to the restricted broker guest
interface. The broker binds it to one page but requires an individual guest
session and current grant for protected operations. Neither the endpoint nor
Guest Service receives an HA admin credential.

### Action authorization choke point

Guest route code accepts stable page, resource, and action identifiers. It does
not accept a client-selected Home Assistant entity, domain, or service as
authority. In the packaged App, the HA broker resolves the current published
resource and action, validates parameters and proximity, and rechecks grant
and policy before dispatch. Gateway `actions.py` serves administrative preview.
Browser-reported proximity is checked against the configured Home location and
page policy, but browser coordinates are not physical attestation and may be
spoofed.

In the brokered App topology, every page has a separately credentialed,
compiled endpoint process. The endpoint holds no page data or recipient list
and forwards only scoped guest routes to the isolated Guest Service. The HA
broker validates the endpoint capability, individual session, current grant,
and published page policy before using Home Assistant authority. The browser
cannot widen an operation by substituting an entity, domain, service, or
unknown parameter. A capability cannot select a sibling page. Separate UIDs
do not isolate shared loopback access, but a sibling endpoint capability
cannot replace the other page's individual guest session.

### Revocation locking

The Gateway preview action path uses a page action lock through Home Assistant
dispatch. In the packaged guest path, the broker independently rechecks the
current grant, session, and published policy immediately before dispatch. An
already-dispatched action may finish after revocation; a later action cannot
use the revoked grant. Grant creation reloads current page state before
committing so it cannot restore a concurrently revoked grant.

Local access is removed before LayerV qURL cleanup. Remote cleanup failure is
reported and never restores the local grant. Durable Admin and LayerV broker
records retry qURL or resource retirement after temporary failures. A local
fault-injection test exercised LayerV 503 and recovery in both isolation modes;
no destructive LayerV network outage was induced on HA Green.

The authoritative review package is:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — implemented module responsibilities
  and request flows;
- [`REVIEW_GUIDE.md`](REVIEW_GUIDE.md) — review order, invariants, and direct
  test evidence.

## Credential response

If a LayerV API key, activation qURL, access link, preview token, Home Assistant
token, or connector state is exposed, revoke or rotate it immediately. Revoke
affected guest grants in the Gateway UI. Do not rely on deleting a message,
browser history entry, screenshot, backup, or log as revocation.

## Automated security checks

Every pull request and push to `main`, plus a weekly scheduled run, performs:

- Ruff static correctness checks and Bandit Python security analysis
- Gitleaks scanning across the complete Git history
- Trivy dependency, secret, and configuration scanning of the repository
- A clean Home Assistant App image build followed by a Trivy image scan
- JavaScript syntax checks and the complete unit-test suite

Scanner actions and Python tools are pinned to reviewed versions. Dependabot
checks the pinned GitHub Actions and Docker base images weekly. This project
currently has no third-party production Python or JavaScript packages; Trivy
will detect supported dependency manifests if any are introduced later.

The standalone gateway image runs as an unprivileged user. The Home Assistant
App follows Home Assistant's root-based App container model so existing
Supervisor-owned `/data` volumes remain readable. Home Assistant protection
mode remains active. The explicit AppArmor allowlist was exercised under real
Home Assistant acceptance. The documented Trivy exception expires automatically
and must be reviewed again before 2027.

The AppArmor profile limits host and filesystem access. The App supervisor and
its child processes share one App container. Guest endpoints and the main
application roles use distinct identities. The LayerV broker and its supervised
qURL runtime currently share an identity and trust boundary. Processes use
minimal environments and explicitly permissioned persistent directories.
Artifact-level permission testing confirms that page endpoint processes cannot
read the LayerV API key,
Connector identity, administrator runtime data, broker registry, or
authoritative policy store. The root supervisor and the host kernel/container
runtime remain part of the trusted computing base. `ARCHITECTURE.md` documents
the complete trust boundary and `REVIEW_GUIDE.md` maps it to test evidence.

First-run onboarding HTTP parsing runs under a dedicated unprivileged identity.
It submits the API key once through an inherited anonymous pipe to the root
supervisor, which revalidates and atomically stores the credential for the
Connector. The onboarding process cannot open the protected key path, and
initial Connector registration runs under the Connector identity.

The App pins architecture-specific qURL 2.6.0 release archives by SHA-256.
Repository, static-analysis, test, Git-history secret, and built-image scans
remain release gates. Findings must be reviewed against the actual current
binary and its embedded Connector module; historical findings for an older
standalone Connector image are not evidence of the current image's status.
