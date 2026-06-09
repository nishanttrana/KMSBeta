# Secret Rotation

The bootstrap/shared secrets live only in the (git-ignored) `.env`; rotate them
with [`scripts/rotate-secrets.sh`](../../scripts/rotate-secrets.sh):

```bash
./scripts/rotate-secrets.sh          # rotates ./.env, keeps a .env.bak.<ts> backup
```

It generates fresh values for `POSTGRES_PASSWORD`, `NATS_AUTH_TOKEN`,
`WORKLOAD_IDENTITY_SHARED_SECRET`, `SOFTWARE_VAULT_PASSPHRASE`,
`INTERNAL_API_TOKEN`, `AUTH_BOOTSTRAP_ADMIN_PASSWORD`, and
`AUTH_BOOTSTRAP_CLI_PASSWORD`. Hex for connection-string/header-safe values;
policy-compliant strings (≥12 chars, mixed classes) for the bootstrap passwords.

> The script only rewrites the **configured** values. It does **not** touch
> running containers or data volumes — some secrets are baked into persistent
> volumes on first start, so a plain restart after rotation will break auth.
> Apply to a live stack with the steps below.

## Applying to a running stack (non-destructive)

| Secret | Why a restart isn't enough | Apply |
|---|---|---|
| `POSTGRES_PASSWORD` | The `postgres-data` volume keeps the password it was first initialized with. | `docker compose exec postgres psql -U "$POSTGRES_USER" -c "ALTER USER \"$POSTGRES_USER\" PASSWORD '<new>';"` then recreate dependents. |
| `NATS_AUTH_TOKEN`, `INTERNAL_API_TOKEN`, `WORKLOAD_IDENTITY_SHARED_SECRET` | Shared between services; all must use the same value at once. | `docker compose up -d --force-recreate` (recreates every service with the new env together). |
| `AUTH_BOOTSTRAP_ADMIN_PASSWORD`, `AUTH_BOOTSTRAP_CLI_PASSWORD` | Only seed a **fresh** auth volume; the existing admin keeps its current password. | Rotate the live admin/CLI password via the dashboard or auth API. |
| `SOFTWARE_VAULT_PASSPHRASE` | Vault data already sealed under the old passphrase won't unseal under the new one. | Run the vault rekey/re-seal flow **before** restarting the vault service. |

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
