# Secret Rotation

The bootstrap/shared secrets live only in the (git-ignored) `.env`; rotate them
with [`scripts/rotate-secrets.sh`](../../scripts/rotate-secrets.sh):

```bash
./scripts/rotate-secrets.sh          # rotates ./.env, keeps a .env.bak.<ts> backup
```

It generates fresh values for `POSTGRES_PASSWORD`, `NATS_AUTH_TOKEN`,
`WORKLOAD_IDENTITY_SHARED_SECRET`, `SOFTWARE_VAULT_PASSPHRASE`,
`INTERNAL_API_TOKEN`, `INTERNAL_SERVICE_BOOTSTRAP_SECRET`,
`AUTH_BOOTSTRAP_ADMIN_PASSWORD`, and
`AUTH_BOOTSTRAP_CLI_PASSWORD`. Hex for connection-string/header-safe values;
policy-compliant strings (≥12 chars, mixed classes) for the bootstrap passwords.
It also rotates `SECRETS_MEK_B64` (base64, 32 bytes) by moving the old key to
`SECRETS_MEK_PREVIOUS_B64`; see
[Rotating the secrets master key](#rotating-the-secrets-master-key).

> The script only rewrites the **configured** values. It does **not** touch
> running containers or data volumes — some secrets are baked into persistent
> volumes on first start, so a plain restart after rotation will break auth.
> Apply to a live stack with the steps below.

## Applying to a running stack (non-destructive)

| Secret | Why a restart isn't enough | Apply |
|---|---|---|
| `POSTGRES_PASSWORD` | The `postgres-data` volume keeps the password it was first initialized with. | `docker compose exec postgres psql -U "$POSTGRES_USER" -c "ALTER USER \"$POSTGRES_USER\" PASSWORD '<new>';"` then recreate dependents. |
| `NATS_AUTH_TOKEN`, `INTERNAL_API_TOKEN`, `WORKLOAD_IDENTITY_SHARED_SECRET` | Shared between services; all must use the same value at once. | `docker compose up -d --force-recreate` (recreates every service with the new env together). |
| `INTERNAL_SERVICE_BOOTSTRAP_SECRET` | Every service derives its API key from it; auth holds the key hashes. | `docker compose up -d --force-recreate`. On start, auth provisions keys for the new secret and **retires every service key derived from the previous one** (logged as `SECURITY retired … stale … service key(s)`). Service JWTs already minted stay valid until they expire (≤ 1 h). |
| `AUTH_BOOTSTRAP_ADMIN_PASSWORD`, `AUTH_BOOTSTRAP_CLI_PASSWORD` | Only seed a **fresh** auth volume; the existing admin keeps its current password. | Rotate the live admin/CLI password via the dashboard or auth API. |
| `SOFTWARE_VAULT_PASSPHRASE` | Vault data already sealed under the old passphrase won't unseal under the new one. | Run the vault rekey/re-seal flow **before** restarting the vault service. |
| `SECRETS_MEK_B64` | It wraps the DEK of every stored secret; a new key alone opens nothing. | See [Rotating the secrets master key](#rotating-the-secrets-master-key). |

## Rotating the secrets master key

`SECRETS_MEK_B64` wraps the per-value data key (DEK) of every secret the
secrets service stores. It has no fallback: the service refuses to start
without a valid one. It records a keyed fingerprint of the key the data is
under (`secrets_mek_state`), so a wrong key stops the start instead of
failing every read.

1. `./scripts/rotate-secrets.sh` moves the current key to
   `SECRETS_MEK_PREVIOUS_B64` and writes a new `SECRETS_MEK_B64`. It refuses
   to rotate again while `SECRETS_MEK_PREVIOUS_B64` is set, because a second
   rotation would drop the key the data is still under. To do it by hand, set
   both variables the same way.
2. `docker compose up -d --force-recreate secrets`. On start the service
   re-wraps every DEK found under the previous key, then records the new key's
   fingerprint. Each tenant gets `audit.secrets.mek_rewrapped` with the count
   and the secret IDs, and the log says `every value is under the configured
   MEK; remove SECRETS_MEK_PREVIOUS_B64`. If a row can't be rewritten, the
   start is refused (`audit.secrets.mek_rewrap_refused`) and nothing is
   recorded. Fix the cause and restart; rows already moved are skipped.
3. Clear `SECRETS_MEK_PREVIOUS_B64` in `.env` and recreate the service again.
4. **Cluster:** members must use the primary's key. Copy the new
   `SECRETS_MEK_B64` to every member and recreate their secrets service. A
   member with a different key refuses to start
   (`audit.secrets.mek_check_refused`, reason `mek_mismatch`). Members never
   re-wrap; they receive the primary's re-wrapped rows by replication.

**What rotation does and doesn't do:** it re-wraps DEKs; it doesn't
re-encrypt the values. After step 2 the old key opens nothing in the live
database. A database backup taken before the rotation, together with the old
key, still decrypts the values it holds. If the old key may have leaked,
rotate the stored secret values themselves at their source.

**Upgrading from a release before 1.2.0-beta:** values were stored under a
public development key. `deploy-local.sh` generates `SECRETS_MEK_B64`, and on
the first start the service re-wraps them (`audit.secrets.dev_mek_rewrapped`).
See the 2026-09-26 entry in [SECURE_DEFAULTS.md](SECURE_DEFAULTS.md#history)
for what that means for older backups.

## Full clean reset (destructive — local/dev only)

If there is no data worth keeping, recreate the volumes so the new bootstrap
values seed cleanly:

```bash
docker compose down -v && docker compose up -d   # DELETES all volume data
```

## Note on history

The previously-tracked `.env` exposed earlier dev secrets in git history. These
have now been rotated, so the historical values are stale. Per the maintainer's
decision the history was not rewritten; rotation supersedes those values.
