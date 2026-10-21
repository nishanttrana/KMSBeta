# Dynamic database credentials

The Secret Vault issues short-lived PostgreSQL logins (13.34.0-beta,
`services/secrets/dbengine.go`). An application asks for credentials, gets a
new login and password valid for its lease, and the vault drops the login
when the lease is revoked or expires. No password is stored; it is returned
once.

## Pieces

- **Database credential** (Playbooks → Credentials, type `database`): the
  PostgreSQL administrator the vault acts as: `host`, `database`,
  `username`, `password`, optional `port` (5432) and `ca_pem`. The host is
  checked like any outbound address; a private address must be an approved
  private range on the credential.
- **Role** (Secret Vault → Database credentials): the credential, the
  default and maximum TTL (60 seconds to 30 days), and two SQL templates.
  Saving a role connects to the database first; a role that can't reach it
  is refused.
- **Lease**: one issued login, `active` until revoked (`revoked`) or past
  its end (`expired`); a revocation that fails is `revoke_failed` and retried
  every minute.

## Templates

Statements are one per line. Placeholders are filled only with values the
vault generates, each quoted for where it appears:

| Placeholder | Value |
|---|---|
| `{{name}}` | the login as a quoted identifier, `v_<role>_<10 random>` (at most 63 bytes) |
| `{{username}}` | the same as a string literal |
| `{{password}}` | 32 random base-62 characters, as a string literal |
| `{{expiration}}` | the lease end as a timestamp literal |

Creation must use `{{name}}` and `{{password}}`; any other placeholder, or an
unclosed one, is refused. Defaults: create a login valid until the lease
end with `SELECT` on the `public` schema; revoke by ending its sessions,
revoking its grants and dropping it. Creation runs in one transaction; a
login whose lease can't be recorded is dropped at once.

## Lifecycle

- **Issue** `POST /secrets/database/roles/{name}/creds` (`ttl_seconds`
  optional) → `username`, `password` (once), `lease`.
- **Renew** `POST /secrets/database/leases/{id}/renew` (`increment_seconds`
  optional) moves the login's `VALID UNTIL`, never past the role's maximum.
- **Revoke** `POST /secrets/database/leases/{id}/revoke` drops the login.
- **Expiry**: a sweep on the primary every minute drops logins past their
  lease end and retries failed revocations.

Vault / OpenBao clients: `GET /v1/database/creds/{role}` (lease ID
`database/creds/<role>/<id>`), `PUT|POST /v1/sys/leases/renew` and
`/v1/sys/leases/revoke`, authenticated like the vault's other Vault routes
(`Authorization: Bearer`).

## Security

- Every connection is TLS 1.3 with the server certificate and host
  verified (`ca_pem` or the system roots); there is no plaintext fallback.
- Defining a role runs SQL as the database administrator, so it needs
  `secrets.database.admin` and, to attach the credential,
  `compliance.connection.use`; issuing, renewing and revoking need
  `secrets.database.creds`; reading `secrets.database.read`.
- Errors name a statement's position, never its text (which holds the
  password). Audit events carry the username, never the password.

## Tested by

`TestDynamicDatabaseCredentialsPostgres` against a PostgreSQL that checks
passwords: each issued login is used (and a wrong password refused),
renewal moves `rolvaliduntil`, revocation and the sweep drop the role, a
failed revocation is recorded and retried, and another tenant sees none of
it. The test server has no TLS, so the test connects in plaintext with the
credential's own fields; the TLS and address checks are proven in
`TestDatabaseConnectionsVerifyTLSAndRefuseBlockedAddresses`. PostgreSQL only
for now.
