# Credentials: the one store of external credentials

Owner decisions. 2026-09-28: webhooks and SIEM are part of Playbooks, not a
separate tab; every outbound integration is a **connection** (2.10.0-beta).
2026-10-10: every credential the KMS uses to reach an external system is
added in one place, **Playbooks → Credentials**, before a feature can use
it (8.0.0-beta). A connection and a credential are the same thing: the API
and tables keep the name connection.

Nothing else in the platform stores an external URL, account, PIN, key or
token. A feature holds a credential's ID, never a secret. Two things are
deliberately outside the store:

- **The tenant's HSM profile** (HSM tab), the KMS's root of trust. Its PIN
  stays in the connector's environment or a file on that host: sealing it
  under a keycore key would make the root of trust depend on what it
  protects ([HSM_INTEGRATION.md](HSM_INTEGRATION.md)).
- **Identity provider secrets** (LDAP bind password, OIDC client secret),
  which the auth service still stores itself. See "What is still open".

BitLocker and HYOK/DKE hold no outbound credential: the BitLocker agent
signs in to the KMS with its own token, and HYOK verifies Entra tokens
against published keys.

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
| cloud | `aws` (`access_key_id`, `secret_access_key`; optional `role_arn`, `external_id`, `region`, `endpoint_url`), `azure` (Entra app registration: `tenant_id`, `client_id`, `client_secret`), `gcp` (`service_account_json`), `oci`, `alibaba`, `salesforce`; `servicenow` with `username` and `password` (8.0.0-beta) | Cloud BYOK accounts; `azure` also Azure EKM vaults, `aws_xks` (`access_key_id` 20 to 30 of A-Z and 2-7, `secret_access_key` 43 to 64 characters; the credential AWS KMS signs XKS calls with), `oci_identity_domain` (`client_id`, `client_secret` of the OCI External KMS resource app, to read a protected JWKS) |
| database | `database` (`host`, `database`, `username`, `password`; optional `port`, `ca_pem`): a PostgreSQL administrator the secret vault issues short-lived logins with (13.34.0-beta) |
| timestamp | `tsa`: `url` (https), optional `username` with `password`, `trust_pem` (the authority's root) (13.47.0-beta) | audit checkpoint anchoring ([AUDIT_INTEGRITY.md](AUDIT_INTEGRITY.md)); tested there, not here |
| mail | `smtp`: `host`, `port`, `from`, optional `username`, `password`, `ca_pem` (8.0.0-beta) | governance approval and playbook mail |
| hsm | `pkcs11_hsm`: `library_path`, `pin`, `slot_id` or `token_label`, optional `topology` (`single` or `ha_group`) and `vendor` (8.0.0-beta) | keys and CA keys created, formed or imported in an HSM |
| source | `git`: the hosting site (`git_url`), an access `token`, optional `username` for Basic authentication (7.20.0-beta) | discovery's git repository scans |
| source | `s3`: the storage service (`endpoint_url`), `access_key_id`, `secret_access_key` (at least 10 characters), optional `role_arn` and `external_id` (Amazon only). `azure_blob`: the storage account (`account_url`) and exactly one credential: a `sas_token` with read and list, an Entra ID application (`azure_tenant_id`, `client_id`, `client_secret`), or the `account_key` (with `account_name` if the address does not name the account). `gcs`: `gcs_url` and a `service_account_json` key file (7.34.0-beta; roles, Entra ID, account key and `gcs` 7.39.0-beta) | discovery's object storage scans |

## What a credential records (8.0.0-beta)

- **Attributes.** The values of the fields a type marks public (an HSM's
  slot, token label and declared topology, a region, an app registration's
  client ID) are returned, so a picker can show which is which. No other
  field value is ever returned.
- **Health.** The result of the last real test of the current secret:
  passed, failed (with the error) or not tested. Saving in the dashboard
  runs the test. A changed secret clears it.
- **Age, expiry and rotation.** When a secret field last changed, an
  optional expiry the operator records, and an optional rotation interval.
  The primary's hourly sweep raises `audit.compliance.credential_expiring`
  (30 and 7 days before), `credential_expired` and
  `credential_rotation_due`, each once per secret; a failed test raises
  `credential_test_failed`. All four are playbook triggers.
- **Where it is used.** `GET /compliance/connections/{id}/usage` asks
  playbooks, event streams, governance, discovery, cloud, ekm and keycore.
  A service the deployment leaves out is not asked; one that can't answer
  makes the answer "unavailable", never "unused".

## Who can attach one (8.0.0-beta)

Managing credentials (list, create, change, delete, test) needs the
playbook permissions. **Attaching** one to a feature needs
`compliance.connection.use`, and that permission alone neither lists the
store nor changes it. The service that owns the feature checks it on the
caller's own verified token when the credential is chosen (registering a
cloud account, saving a vault or the mail relay, creating a key or CA on an
HSM credential), refuses and audits when it is missing, and reads pickers
from `GET /compliance/connections?type=`.

## Who can open one

- **Compliance** opens connections for playbook actions and connection tests.
- **The audit service** (event streams) and **governance** (approval
  notices) hold only a connection ID. They get the fields from
  `POST /compliance/connections/{id}/resolve` over internal mTLS. The kernel
  admits only the `kms-audit` and `kms-governance` service identities
  (`tenantcheck.IsServicePrincipal` plus the client ID). Users,
  administrators and other services are refused, and each refusal is
  audited. Each caller gets only the types it uses: streams take stream
  types and `tsa` (checkpoint anchoring, 13.47.0-beta), notices take Slack
  or Teams. Every release is audited as
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
- **Discovery, object storage** (7.34.0-beta): the same rules for `s3` and
  `azure_blob` connections, one per private bucket. The S3 key signs each
  request (Signature V4, HMAC-SHA256 from `pkg/crypto`) to the connection's
  host only; the secret itself is never sent. The SAS token is sent as the
  request's query to the connection's host only. No redirect is followed,
  and no error or audit event carries the URL. Tested on a bucket that uses
  it (`POST /discovery/buckets/{id}/test`).
- **Where each storage secret goes** (7.39.0-beta): an AWS key signs
  requests to the bucket's host and, with a role, one `AssumeRole` call to
  AWS STS; the key is never sent. An Azure account key signs requests and
  is never sent. An Entra ID client secret is sent only to
  `login.microsoftonline.com`, and a Google assertion only to
  `oauth2.googleapis.com`; the tokens they return go only to the bucket's
  host. Temporary credentials and tokens are held for one scan and never
  stored. The preferred choices are the narrow ones: a role, a SAS token,
  an Entra ID application or a service account with read access to the
  bucket. An account key grants the whole storage account.
- The audit service keeps an opened connection in memory for 60 seconds and
  governance for one notice. Neither writes one to disk, a log or an error:
  delivery errors name the host, never the URL (a Slack or Teams URL is
  itself a credential).

- **Cloud BYOK** (8.0.0-beta) is admitted as `kms-cloud` for the cloud
  types. An account holds a credential ID; every provider call opens it and
  keeps the fields in memory for that call. With an AWS `role_arn` the
  access key only calls `sts:AssumeRole`.
- **Azure EKM** vaults (8.0.0-beta) were admitted as `kms-ekm` for
  `azure`; the feature was removed in 13.30.0-beta and `kms-ekm` opens no
  credential. Azure EKM is now a HYOK protocol that needs none: Managed HSM
  authenticates to the KMS with its client certificate.
- **Database credentials** (13.34.0-beta) are admitted as `kms-secrets`
  for `database` only.
- **AWS XKS** (13.32.0-beta) is admitted as `kms-hyok-proxy` for
  `aws_xks` and, since 13.36.0-beta, `oci_identity_domain`. The hyok
  service opens an `aws_xks` credential to verify AWS's SigV4 signature,
  never to call out, and caches it for 15 seconds. It uses an
  `oci_identity_domain` credential only to get a token from that domain's
  `/oauth2/v1/token` (on the JWKS URL's host, through the SSRF guard) and
  read its JWKS.
- **The HSM connector** (8.0.0-beta) is admitted as `kms-hsm` for
  `pkcs11_hsm` only, and caches an opened credential for 15 seconds, as it
  does a profile. The library path is confined to the provider workspace
  exactly as a profile's is.
- **Governance** additionally opens `smtp` for mail.
- Each service that tests a credential where it is used reports the result
  with `POST /compliance/connections/{id}/tested`, for its own types only.

## Private endpoints (7.40.0-beta)

The outbound guard refuses private addresses for every connection. Source
connections (`git`, `s3`, `azure_blob`, `gcs`) are the exception a root
administrator can grant, because what they reach is often on the
customer's own network:

- A root administrator approves a private range for one tenant
  (`POST /compliance/private-endpoints`, Playbooks → Connections → Private
  endpoints). The caller must be a person in the root tenant holding
  `compliance.private_endpoint.approve`; a tenant's administrator and a
  service are refused (`platform_tenant_required`).
- A range lies wholly inside private address space (10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7) and is at most a
  /16 (IPv4) or /48 (IPv6). Loopback, link-local, metadata and public
  addresses can't be approved.
- When a source connection is saved, a private host is accepted only if
  every address it has is public or inside a range approved for the
  tenant.
- Compliance hands the tenant's approved ranges to discovery with each
  opened connection. Discovery refuses to dial a private address outside
  them for any request that carries the credential, checking the address
  actually dialled. Its own guard still refuses reserved addresses and the
  KMS platform's services, whatever is approved.
- Withdrawing a range leaves the connections in place; from the next scan
  their credential is no longer sent there.

**Mail relays (8.0.0-beta).** An `smtp` credential may name a host inside
a range approved for its tenant, checked when it is saved; governance is
given the ranges with the credential and its dial guard refuses any other
private address.

**Notification, ticketing and SIEM (8.1.0-beta).** The same approval covers
`webhook`, `slack`, `teams`, `jira`, `servicenow` and every SIEM type (an
on-premises Splunk, Elastic or TLS syslog collector).
- Saving one on a private address is accepted only inside a range approved
  for the tenant; the audit event carries `private_endpoint: true`.
- Each service that dials it builds its client from that tenant's ranges
  (`ssrfguard.Allow`): compliance per delivery, audit per stream
  connection, governance per notice. That client is never used for another
  tenant, because a kept-alive connection is reused without a new dial.
- The check is on the address dialled. Under any approval the dial still
  refuses loopback, link-local and metadata addresses, and every address a
  platform hostname resolves to (`pkg/ssrfguard/platform.go`).
- A tenant with no approved range uses the shared public-only client, as
  before. Withdrawing a range takes effect on the next delivery (within
  60 seconds for an audit stream, whose opened connection is cached).
- Cloud account credentials are not covered: they reach the provider's
  public endpoints.

## Every call is TLS

- Every host name is resolved in one place, `pkg/ssrfguard` (the guard,
  and `ssrfguard.LookupNetIP` for a service's own address checks), so the
  address checked is the address used and a test can answer every lookup
  (conformance `name-resolution`, 13.8.0-beta).
- HTTP types go through `ssrfguard.NewHTTPSClient`: HTTPS only, TLS 1.3, no
  redirects, no proxy, and the dialer refuses private, loopback, link-local
  and metadata addresses after resolving (no DNS rebinding). Platform hosts
  are refused when the connection is saved.
- `smtp` (8.0.0-beta) always uses TLS: implicit on port 465, STARTTLS on
  any other, refused if the relay offers neither (`pkg/smtpmail`). TLS 1.2
  is the minimum (FIPS exception: external protocol mandate); a relay with
  a private CA takes `ca_pem`.
- `syslog` is RFC 5425 over TLS 1.3 through `ssrfguard.DialContext`,
  verified against the system roots or the connection's `ca_pem`. There is no
  plain UDP or TCP syslog. (The earlier `pkg/siem` QRadar exporter dialled
  plain UDP. It was never wired to anything and has been rewritten.)
- Microsoft Sentinel uses the Logs Ingestion API with an Entra
  client-credentials token. The HTTP Data Collector API (shared key) was
  retired by Microsoft on 14 September 2026 and is not used.

## Deleting

A source connection (`git`, `s3`, `azure_blob`) in use by a discovery
repository or bucket can't be deleted either: compliance asks discovery, and
only for those types, so a deployment without discovery can still delete
every other connection.

A connection in use can't be deleted. Compliance checks its playbooks, asks
the audit service for its event streams and checkpoint anchoring and, for
the root tenant, asks
governance for its notice settings, as `kms-compliance`. If either service
can't answer, the delete is refused (`connection_usage_unverified`): a
silently broken SIEM feed is worse than a delayed delete.

Since 8.0.0-beta the same guard covers cloud accounts (asked of the cloud
service; Azure EKM vaults until 13.30.0-beta), the governance mail relay, and HSM
keys (asked of keycore, which counts live keys only: a destroyed key's
objects are gone from the HSM).

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

## Migration (8.0.0-beta)

Three more stores held their own credentials. The primary moves each into
the store, retries every 15 minutes, and runs again after a restore. A row
the store won't take keeps working from its own copy and is reported once.

- **Cloud accounts** kept a sealed credentials document. Its keys map onto
  the provider type's fields; any other key goes into `options_json`
  unchanged. `pbconn_cloud_<account id>`; carried over as exposed if the
  cloud exposure register listed it.
- **Azure EKM vaults** kept the client secret in **plaintext**.
  `pbconn_ekm_<config id>`, recorded as exposed: rotate the secret in Entra.
  (Feature removed in 13.30.0-beta; migration `011_drop_azure_ekm.sql`
  drops its tables. Database backups made before still hold old rows.)
- **Governance** kept the SMTP host, account and password in
  **plaintext**. `pbconn_governance_governance_smtp`, recorded as exposed
  when a password was stored: change it on the relay.

The Google CSE service account key was stored in plaintext and never used.
It is deleted, not migrated.

## What is still open

- Streams deliver one event per request. Batching (every `pkg/siem`
  destination accepts a batch) would cut request volume for busy tenants.
- Sentinel supports the public Azure cloud only (the Entra host is fixed).
- Approving a private endpoint is a root administrator's decision alone,
  audited, with no second approver (7.40.0-beta). A governance approval
  step can be added if the owner wants one.
- Which storage credentials have been run against a real service, and how
  to run the rest with your own accounts, is in
  [STORAGE_LIVE_VERIFICATION.md](STORAGE_LIVE_VERIFICATION.md). Role
  assumption is verified against MinIO (9.1.0-beta); Amazon STS itself,
  Entra ID and the Google service-account exchange still need an account.
  Entra ID supports the public Azure cloud only (the login host is fixed),
  and role assumption the standard AWS partition's regional STS endpoints.
- Identity provider secrets (LDAP and AD bind passwords, OIDC and Entra
  client secrets) are not in this store, by decision: auth can't depend on
  compliance to sign users in. They are sealed inside auth under its own
  master key (9.0.0-beta, [SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md)).
- The tokenization "external vault" and its `password_ref` are gone
  (9.0.0-beta): nothing ever connected to the database it named
  ([REAL_CAPABILITY.md](REAL_CAPABILITY.md)).
- Cloud credentials name public provider endpoints only: a custom endpoint
  on a private address is refused, and the cloud service's own HTTP clients
  don't go through the outbound guard.
- The cloud and ekm services are still on the raw mux: they verify the
  caller's token and tenant (8.0.0-beta) but have no per-route permission
  except the credential routes.
