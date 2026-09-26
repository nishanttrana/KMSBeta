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
| Service master keys (secrets, certs, cloud, ekm) | Not in `.env`: they come from keycore. | See [Service master keys](#service-master-keys). |
| Certs CRWK passphrase | Lives in the certs key volume, not `.env`; the sealed root wrapping key only opens under the passphrase it was sealed with. | `./scripts/rotate-crwk-passphrase.sh`. See [Certs root wrapping key passphrase](#certs-root-wrapping-key-crwk-passphrase). |

## Service master keys

The master keys of the secrets, certs, cloud and ekm services aren't
configured anywhere, so `rotate-secrets.sh` doesn't touch them. Each is
derived from a protected keycore system key (`vecta.system` label). To
rotate one, rotate that key in keycore, then restart the service. It re-wraps
every stored value onto the new version and emits `mek_rewrapped`
(`from: previous_version`). Keycore refuses to destroy, disable or export a
system key. See [SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md).

## Certs root wrapping key (CRWK) passphrase

Every CA signing key is wrapped by the certs root wrapping key (CRWK). The
CRWK is sealed in `crwk.sealed` on the certs key volume under a key derived
(Argon2id) from a passphrase. That passphrase is generated inside the same
volume as `bootstrap.passphrase` (64 hex characters) by
`infra/scripts/crwk-passphrase.sh`. `CERTS_CRWK_BOOTSTRAP_PASSPHRASE` in
`.env` overrides it, but leave that empty.

**Rotate it:**

```bash
./scripts/rotate-crwk-passphrase.sh
```

The script:
1. stops certs;
2. moves the current passphrase aside as `bootstrap.passphrase.previous`
   (an inline `.env` value is written there and cleared in `.env`, with a
   backup);
3. generates a new one in the volume;
4. recreates certs.

No passphrase is printed or put on a command line.

**What certs does on start:**
1. The sealed CRWK doesn't open under the new passphrase, so it opens it
   with the previous one.
2. It generates a **new random CRWK**, sealed under the new passphrase in
   `crwk.sealed.next`, and wraps everything new with it.
3. It rewraps every CA signer's DEK (all tenants) and the internal PKI cache
   (`internal-pki.json`) under the new CRWK.
4. Only then does `crwk.sealed.next` replace `crwk.sealed`. The retired
   CRWK and the previous passphrase file are deleted.
5. It emits `audit.certs.crwk_rotated` with `from_version`, `to_version`,
   `reason` and `ca_signers_rewrapped`.

**If it fails part-way:**
- A failed rewrap emits the same event with `result: failure` and
  `reason: rewrap_failed`. It keeps both keys and the previous passphrase,
  and it is retried on the next start.
- A crash resumes with the same `crwk.sealed.next`.
- Only the cluster primary rewraps.

**Check it:**
- Status: `GET /certs/security/status` shows `rotation_pending` until the
  rewrap is done.
- Logs: `CRWK rotation incomplete` means it will retry on the next start.

**Retired public default.** Before 1.10.0-beta, `start-kms.sh` and
`start-kms.ps1` wrote a public passphrase that shipped in the repository
when none was set.
- The next `start-kms` recognises it by its SHA-256, moves it aside as
  `.previous` and generates a new one. Certs then re-keys as above, with
  `reason: public_default_passphrase`.
- Certs refuses to start on the public value, or on any passphrase shorter
  than 32 characters or with fewer than 8 distinct characters.
- **What re-keying can't fix:** a copy of the old `crwk.sealed` together
  with a database dump from the same period still opens the CA keys, since
  the public passphrase unseals it. If such copies (volume backups,
  snapshots) may exist outside your control, rotate the CAs themselves:
  issue new CAs and re-issue under them.

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
