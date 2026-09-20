# Home Assistant App onboarding

## First installation

Install Access Pages on Home Assistant OS or Supervised, start the App, and
open its Web UI through Home Assistant Ingress. The **Connect to LayerV** screen
accepts one dedicated installation API key. The key needs permission to read
qURLs (`qurl:read`), create, update, and delete qURLs (`qurl:write`), and mint
qURL Connector enrollment tokens (`qurl:agent`). CRID/headless resolve scope
is not required.

Access Pages validates the key's local format and stores it in protected App
data. This setup step does not enroll an Agent or publish a guest resource.
The Admin page then opens through Ingress, where the owner can configure an
Access Page and create the first guest invitation.

## First publication and later starts

The first publication on a genuinely fresh installation follows this sequence:

1. Access Pages uses the retained management API key to mint a one-shot
   Connector/Agent enrollment token.
2. The LayerV broker passes that token to qURL 2.6.0 login through a protected
   temporary token file. It does not pass the retained API key to `qurl login`.
3. qURL establishes sealed, persistent Agent/device state. One supervised
   Connector runtime serves the installation's resources.
4. Access Pages publishes the resource and creates the grant-specific qURL.

Subsequent invitations and normal App or Home Assistant restarts reuse that
Agent identity. The retained API key remains necessary for ongoing qURL read
and write management; it is distinct from the one-shot enrollment token and
the persisted Agent/device credential.

After enrollment has succeeded, missing, damaged, or rejected Agent state
fails closed. Access Pages never automatically enrolls a replacement Agent.
The administrator must investigate and use **Reset LayerV connection** for
explicit recovery. Reset removes local guest authorization and the old
connection state while preserving Access Page definitions; old invitations
cannot be restored. Backups can contain credentials and need protection.

## Guest and administrator boundaries

Home Assistant Ingress carries the separate Admin Web UI. Guests follow their
LayerV qURL through a page-bound Go endpoint, isolated Guest Service, and
restricted HA Broker guest interface. Guest sessions and current grants are
checked independently of LayerV admission. The browser receives no Home
Assistant or Admin credential.

The default `resource_isolation: guest` allocates one LayerV resource/CRID per
guest. Optional `resource_isolation: page` shares one resource/CRID among a
page's guests while preserving independent grants, sessions, and revocation.
Both modes use the same supervised Connector runtime.

## Safe diagnostics

- Local setup validation cannot prove that LayerV will accept the key's scopes;
  a permission or plan error may appear on the first publication.
- Preserve App data when investigating startup or enrollment failures. Do not
  delete Agent state to provoke another automatic login.
- Never include the management key, enrollment token, Agent state, invitation
  URL, guest cookie, or Home Assistant credential in public logs or reports.
