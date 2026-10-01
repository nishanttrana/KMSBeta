# Connections: the one store of outbound credentials

Owner decision, 2026-09-28: webhooks and SIEM are part of Playbooks, not a
separate tab. Every outbound integration is a **connection**. Playbook
actions, audit event streams and governance approval notices all name one.
Nothing else in the platform stores an outbound URL or credential
(2.10.0-beta).

## What a connection is

A row in compliance (`compliance_playbook_connections`, replicated) with a
name, a type, the endpoint host, and the names of the fields set. Every field
value is sealed as one envelope under the compliance master key from keycore
(`pkg/mek`, [SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md)). The envelope
names its tenant and connection, so a blob copied to another row doesn't
open there. The API never returns a value, and an update sends `********` to
keep one.

| Category | Types | Used by |
|---|---|---|
| notify | `slack`, `teams`, `webhook` (optional `signing_secret`, HMAC-SHA256 from `pkg/crypto`) | playbook actions, event streams; Slack/Teams also approval notices |
| ticketing | `jira`, `servicenow` | playbook actions |
| siem | `splunk_hec`, `datadog`, `elastic`, `sentinel`, `syslog` (`pkg/siem`) | `send_siem_alert`, event streams |
| source | `git`: the hosting site (`git_url`), an access `token`, optional `username` for Basic authentication (7.20.0-beta) | discovery's git repository scans |

## Who can open one

- **Compliance** opens connections for playbook actions and connection tests.
- **The audit service** (event streams) and **governance** (approval
  notices) hold only a connection ID. They get the fields from
  `POST /compliance/connections/{id}/resolve` over internal mTLS. The kernel
  admits only the `kms-audit` and `kms-governance` service identities
  (`tenantcheck.IsServicePrincipal` plus the client ID). Users,
  administrators and other services are refused, and each refusal is
  audited. Each caller gets only the types it uses: streams take stream
  types, notices take Slack or Teams. Every release is audited as
  `audit.compliance.connection_resolved`, naming the caller and never a
  field.
- **Discovery** (git repository scans, 7.20.0-beta) holds a connection ID
  per private repository and is admitted as `kms-discovery` for `git`
  connections only; the audit service and governance can't open one. It
  opens the connection for each scan, checks that the connection's host is
  the repository's host, sends the token only there and removes it on a
  redirect to another host. It keeps nothing after the scan. A git
  connection is tested on a repository that uses it
  (`POST /discovery/repositories/{id}/test`); the Connections test refuses
  with `connection_test_elsewhere`.
- The audit service keeps an opened connection in memory for 60 seconds and
  governance for one notice. Neither writes one to disk, a log or an error:
  delivery errors name the host, never the URL (a Slack or Teams URL is
  itself a credential).

## Every call is TLS

- HTTP types go through `ssrfguard.NewHTTPSClient`: HTTPS only, TLS 1.3, no
  redirects, no proxy, and the dialer refuses private, loopback, link-local
  and metadata addresses after resolving (no DNS rebinding). Platform hosts
  are refused when the connection is saved.
- `syslog` is RFC 5425 over TLS 1.3 through `ssrfguard.DialContext`,
  verified against the system roots or the connection's `ca_pem`. There is no
  plain UDP or TCP syslog. (The earlier `pkg/siem` QRadar exporter dialled
  plain UDP. It was never wired to anything and has been rewritten.)
- Microsoft Sentinel uses the Logs Ingestion API with an Entra
  client-credentials token. The HTTP Data Collector API (shared key) was
  retired by Microsoft on 14 September 2026 and is not used.

## Deleting

A git connection in use by a discovery repository can't be deleted either:
compliance asks discovery, and only for that type, so a deployment without
discovery can still delete every other connection.

A connection in use can't be deleted. Compliance checks its playbooks, asks
the audit service for its event streams and, for the root tenant, asks
governance for its notice settings, as `kms-compliance`. If either service
can't answer, the delete is refused (`connection_usage_unverified`): a
silently broken SIEM feed is worse than a delayed delete.

## Migration (2.10.0-beta)

Two stores held their own credentials before this release. The primary
moves both into connections, retries every 15 minutes until done, and runs
again after a restore:

- **Audit event streams** kept a URL, format, signing secret and header
  values (sealed under the audit master key). Each maps to the type its
  format spoke (`json` → `webhook`, `slack` → `slack`, `splunk_hec` →
  `splunk_hec` with the token from `Authorization: Splunk …`, `datadog` →
  `datadog` with `DD-API-KEY`). Compliance creates
  `pbconn_audit_<stream id>` (the same ID on a retry, so a crash can't
  duplicate). The stream then names it and its own copy is cleared. An open
  exposure-register entry, or a row still in plaintext, is recorded against
  the new connection. A stream whose headers don't map keeps delivering as
  before and is reported once as `webhook_migration_refused`, for an
  operator to point at a connection.
- **Governance** kept the Slack and Teams incoming-webhook URLs in
  plaintext (`governance_settings`) and returned them from
  `GET /governance/settings`. They become `pbconn_governance_slack` /
  `_teams`, recorded as **exposed**: database copies and backups made before
  still hold them. Rotate those webhooks in Slack/Teams, then enter the new
  URL on the connection. The warning clears when every field is replaced.

## What is still open

- A SIEM on a private network (an on-premises QRadar or Splunk) can't be a
  destination: the outbound guard refuses private addresses for every
  connection. Allowing it needs an administrator-approved allowlist of
  private ranges, not an exception.
- Streams deliver one event per request. Batching (every `pkg/siem`
  destination accepts a batch) would cut request volume for busy tenants.
- Sentinel supports the public Azure cloud only (the Entra host is fixed).
- A git server on a private network can't have a connection, for the same
  reason as a private SIEM. Discovery can still scan its repositories that
  need no token.
