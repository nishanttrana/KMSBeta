# Secure Defaults

**Standing rule for all Vecta KMS development.** A KMS is only as strong as its
weakest default: a secret that ships in this repo is a secret every attacker
already has. These rules apply to every new service, feature, installer,
compose file and customer-side agent. `make conformance` enforces what can be
checked mechanically. Reviewers enforce the rest.

## The rules

1. **No secret falls back to a value in the repo.** A missing secret must
   either fail fast or be generated at random. Never `${SECRET:-some-value}` in
   compose, and never `envOr("X_SECRET", "some-value")` in Go.
   - Compose: `${X_SECRET:?X_SECRET is required (openssl rand -hex 32)}`.
   - Go: validate at startup and `logger.Fatalf` when the value is bad. Or, if
     the value is never needed by a human, generate it with
     `pkgcrypto.RandomBytes`.
   - Installers (`install.sh`, `deploy-local.sh`, `run-local.sh`) must generate
     every required secret with `openssl rand -hex 32`. A variable that compose
     requires but an installer doesn't write will stop fresh installs.
2. **Validate strength, not just presence.** Reject empty values, known
   placeholders and short values (< 32 characters for shared secrets). The
   reference implementation is `servicetoken.ValidateBootstrapSecret`
   ([pkg/servicetoken/servicetoken.go](../../pkg/servicetoken/servicetoken.go)).
3. **Fail closed.** If a secret is set but weak, the service refuses to start.
   Starting in a degraded or "tokenless" mode is not acceptable for anything
   that grants identity or decrypts data.
4. **Revoke what the old default produced.** When you remove a leaked or
   default secret, don't just stop using it: find and delete every credential
   derived from it, on startup, idempotently. Otherwise upgraded deployments
   stay exploitable. See `revokeInsecureServiceKeys` in
   [services/auth/main.go](../../services/auth/main.go).
5. **Human bootstrap passwords are a documented exception.** The only
   repo-visible default is the bootstrap admin password `changeit`. It is
   allowed only because the account is always seeded with
   `MustChangePassword=true`, so its first login can do nothing except change
   the password. Any other seeded account without an operator-supplied password
   gets a random, unknowable password (for example the CLI user).
6. **Placeholders are rejected at runtime.** A value like `your-...`,
   `change-me` or `replace-me` only ever comes from docs or an example file.
   Every service refuses to start with one (`config.RejectPlaceholderSecrets`,
   run by `config.Load` and `config.NewHTTPServer`, so every service built on
   `pkg/platform` gets it by construction). `deploy-local.sh` refuses too, and
   `.env.example` ships every secret empty.
7. **Credentials inside connection strings count.** A URL like
   `postgres://postgres:postgres@...` is a hardcoded secret even though the
   variable is named `*_DSN`. There is no built-in DSN; `pkg/db` fails without
   `POSTGRES_DSN`. At startup, `*_DSN` / `*DATABASE_URL` values whose password
   is empty, equals the username, is a vendor default (`postgres`,
   `password`, `admin`, `root`, `secret`) or is a placeholder are rejected.
8. **Config knobs are not secrets.** Paths (`*_FILE`, `*_PATH`), modes, flags
   and URLs may have defaults. The secret they point at may not.
9. **Key material never comes from a string in the repo.** Hashing a literal
   (`Hash("SHA-256", []byte("…-dev-mek"))`), keying an HMAC or KDF with a
   literal, or assigning a key from a literal all produce a key anyone with
   the source can compute. That's a public key, however it's spelled. A
   service's master key comes from keycore through `pkg/mek`
   ([SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md)); other secrets come from
   the environment, validated and fail-closed. The public keys earlier releases
   used are named once, in `pkg/mek/catalog.go`, each on a line marked
   `conformance:legacy-public-key`, only so data can be migrated off them.

## How it's enforced

| Check | Where | Catches |
|---|---|---|
| `no-secret-fallback-compose` | `scripts/conformance.sh` | `${NAME:-value}` in `docker-compose*.yml`, where NAME contains SECRET, TOKEN, PASSWORD, PASSPHRASE, API_KEY, PRIVATE_KEY, `_KEY_B64`, `_KEY_PEM`, MEK or KEK |
| `no-secret-fallback-go` | `scripts/conformance.sh` | `("NAME", "literal")` env fallbacks in `services/` and `pkg/` for the same names |
| `no-credential-in-url-go` / `-compose` | `scripts/conformance.sh` | `scheme://user:pass@` literals; URLs must be built from `${VAR}` or `%s` |
| `env-example-no-secret-values` | `scripts/conformance.sh` | any non-empty secret value in `.env.example` |
| `no-literal-key-material` | `scripts/conformance.sh` | in `services/` and `pkg/mek`, a hash of a string literal, an HMAC/KDF keyed by a literal, or a MEK/KEK/master key assigned from a literal. The only exception is a marked line in `pkg/mek/catalog.go` |
| Placeholder rejection | `pkg/config/secrets.go`, run from `Load` and `NewHTTPServer` | a service starting with `your-...` / `change-me` secrets, or a DSN with a default password |
| `deploy-local.sh` preflight | the deploy script | placeholders in `.env`; generates every missing secret, including the JWT signing key |
| Startup validation | per service (for example `bootstrapInternalServiceClients`) | weak values at runtime |
| Unit tests | `pkg/servicetoken/servicetoken_test.go`, `services/auth/bootstrap_admin_test.go`, `pkg/config/secrets_test.go`, `pkg/mek/mek_test.go`, `services/keycore/system_keys_test.go` | validation rules, default-key revocation, rotated-key retirement, placeholder detection, dev-key re-wrap and exposure register (SQLite and Postgres), system-key protection |

The only exemption is `AUTH_BOOTSTRAP_ADMIN_PASSWORD` (rule 5). Don't add
another exemption without the same forced-change guarantee.

## Checklist for a new secret

- [ ] Compose uses `${NAME:?...}`, or `${NAME:-}` only when the feature is
      optional and disabled when the value is empty.
- [ ] `install.sh` writes it to `.env` (random); `deploy-local.sh` uses
      `ensure_secret NAME`.
- [ ] The consuming code validates it and fails closed.
- [ ] `scripts/rotate-secrets.sh` rotates it, and rotation really invalidates
      the old value (see "Rotation must invalidate the old value"). Otherwise
      it's documented as not rotatable in [SECRET_ROTATION.md](SECRET_ROTATION.md).
- [ ] `.env.example` shows a placeholder that validation rejects, never a
      working value.
- [ ] `make conformance` passes.

## History

- **2026-09-25:** `INTERNAL_SERVICE_BOOTSTRAP_SECRET` fell back to the public
  string `vecta-internal-svc-dev-secret-change-me`, and `install.sh` never
  generated it, so every installer-based deployment used it. Anyone could
  derive every internal service's API key and mint service JWTs. Fixed: compose
  requires the secret, validation rejects the placeholder and short values, auth
  refuses to start on a weak value and revokes keys derived from the
  placeholder, and the installers generate it. At the same time the admin
  default became `changeit` (forced change), the CLI user's hardcoded
  `VectaCLI@2026` fallback became a random password, and rule 3 of
  `make conformance` was added.
- **2026-09-25 (follow-up):** rotating the bootstrap secret now retires service
  keys from the previous value, so `rotate-secrets.sh` rotates it. `.env.example`
  placeholders such as `your-workload-identity-secret` had been accepted as
  real secrets, and `deploy-local.sh` copied them into `.env` on fresh
  installs. The example now ships empty, services and `deploy-local.sh` reject
  placeholders, and `POSTGRES_PASSWORD` became required in compose.
- **2026-09-25 (follow-up 2):** `pkg/config` fell back to
  `postgres://postgres:postgres@localhost…` when `POSTGRES_DSN` was unset, and
  `run-local.sh` exported the same string. The naming-based rules missed it
  because the variable is `*_DSN`. Removed: no built-in DSN, weak DSN
  passwords are rejected at startup, `run-local.sh` builds the DSN from `.env`,
  and conformance bans credentials in URL literals.
- **2026-09-26:** secrets, certs, cloud and ekm wrapped their stored data
  (secret values, CA signing keys, cloud credentials, BitLocker recovery keys)
  under `SHA-256("vecta-<service>-dev-mek")` whenever `<SERVICE>_MEK_B64` was
  unset. cloud could also fall back to the literal `0123456789ABCDEF…`. No
  installer or compose file ever set these variables, so this covered **every
  deployment**. Rule 3's checks missed it because the fallback was a hash of
  a literal, not a `("VAR", "default")` pair. Fixed
  ([SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md)):
  - The master key now comes from keycore (a protected system key per
    service, plus service-bound derivation). There is no variable and no
    fallback, and keycore refuses to destroy, disable or export a system key.
  - **Revoking what the default produced (rule 4):** every row under a public
    key is re-wrapped at startup and by a periodic rescan. Backups stored in
    governance are re-protected and re-sealed under a new backup key, and
    restores are re-wrapped before any row lands.
  - What re-wrapping can't reach (copies made before: dumps, snapshots,
    downloaded backups) is tracked in each service's **exposure register**
    until the material is replaced, which is the only thing that makes such a
    copy worthless.
  - Rule 9 and the `no-literal-key-material` check were added.

## Rotation must invalidate the old value

Rotating a secret must actually lock out the old value, not just add the new
one. Auth bootstrap retires every service API key that doesn't match the current
`INTERNAL_SERVICE_BOOTSTRAP_SECRET` (`DeleteClientAPIKeysExcept`), so
`rotate-secrets.sh` rotates it. Any new derived-credential scheme must do the
same before it is added to the rotation script.
