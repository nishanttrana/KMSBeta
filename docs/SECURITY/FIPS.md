# FIPS 140-3

**Standing rule.** Every Vecta KMS binary links the CMVP-certified Go
Cryptographic Module. Whether it runs in FIPS mode is **the customer's choice**,
made **in the KMS UI** and changeable at any time. Each service applies a
change with a graceful, staggered restart. The platform must behave correctly,
and be tested, in every mode the customer can choose.

## The three modes

| Mode | Go runtime | What the customer gets |
|---|---|---|
| `on` (default) | `GODEBUG=fips140=on` | Certified module in FIPS mode: power-on self-tests, approved DRBG, FIPS-restricted TLS. `pkg/crypto` offers only approved algorithms. Integrations that need non-approved algorithms (payment TDES, X25519/age secrets, ChaCha20 field encryption) stay available; the per-tenant FIPS Policy (governance) can block them for keys. |
| `only` | `GODEBUG=fips140=only` | Strict. The Go runtime refuses every non-approved algorithm, and the platform refuses the non-approved code it runs outside the module (see the table below). Refused features return a clear error; nothing panics. FIPS policy applies to every tenant. |
| `off` | `GODEBUG=fips140=off` | FIPS mode disabled; everything available. The platform reports "not running a validated module". |

## Changing the mode (System Administration → Runtime Crypto)

1. **Pick a target mode.** A root-tenant administrator does this (enforced by
   governance `requireSystemAdminTenant`).
2. **Review the impact.** The UI calls
   `GET /governance/system/fips-mode/impact?target=…` and shows:
   - **Stops working / Starts working:** from the catalogue in
     `pkg/fips/impact.go`. Every strict-mode entry is backed by a
     `fipstest.StrictOnly` refusal test.
   - **Notes:** for example, TLS restrictions when leaving `off`, and a
     **security downgrade** warning when lowering assurance.
   - **Restarts:** every service that reports a mode, with an estimated time.
3. **Confirm.** Type the target mode and give a reason; both go into the audit
   log. `PUT /governance/system/fips-mode` stores it in `platform_fips_mode`
   and emits `audit.governance.fips_mode_changed`, with severity `critical`
   for a downgrade.
4. **Services apply it by construction** (`pkg/config.RequireFIPSRuntime`,
   called from `Load` and `NewHTTPServer`):
   - Each service polls the setting every 15 s.
   - On a change it waits its restart tier (`fips.RestartDelay`): edge
     services 0–20 s, then auth / keycore / audit / policy at 40–45 s, then
     governance at 60 s. The platform is never fully down.
   - It then sends itself SIGTERM, so its normal graceful shutdown drains
     requests in flight.
   - Docker (`restart: unless-stopped`, enforced by conformance for every Go
     service) starts it again.
   - At startup it reads the setting and **re-executes itself** with the
     matching `GODEBUG=fips140` before any cryptography runs, then verifies
     the module.
5. **Watch the rollout.** Each instance records the mode it actually runs in
   `platform_fips_observed`. The UI shows each service's observed mode and
   stays "applying" until every service matches, polling every 5 s. A full
   rollout takes about 1–2 minutes.

**How the initial mode is chosen:**
- `VECTA_FIPS_MODE` (compose default `on`) only **seeds** the mode until an
  administrator sets one in the UI.
- Once set, the UI setting always wins, whatever the container environment
  says.
- The installer no longer asks.

**What stops a service from starting:** an invalid mode; a re-exec that didn't
reach the target mode (it never loops); or a FIPS mode chosen on a binary
without the certified module. Each service logs
`fips: mode=… module=… validated=…`.

**Verified end to end** (2026-09-25, real containers):
- A keycore container started with `GODEBUG=fips140=on` while the platform
  setting was `off`. It re-executed into `off` and reported `validated=false`.
- The setting was then changed to `only`. keycore logged
  `platform mode changed off -> only; kms-keycore restarts in 40s`, shut down
  gracefully, and was restarted by Docker (restart count 1).
- It re-executed into `only` and reported `validated=true`. Total time: about
  55 s.

**Outside Docker:** with `run-local.sh` there is no supervisor, so a service
that stops for a mode change stays stopped. Restart it by hand.

## The build: always the certified module

- Every Go Dockerfile sets `ENV GOFIPS140=v1.0.0`. So do the `Makefile` and `run-local.sh`.
- `v1.0.0` is the snapshot listed in `$(go env GOROOT)/lib/fips140/certified.txt` for the Go 1.27.1 toolchain (`v1.0.0-c2097c7c`). The binary records it (`go version -m <binary>` shows `GOFIPS140=v1.0.0-c2097c7c` and `DefaultGODEBUG=fips140=on`).
- The pinned value lives in one place, `pkg/fips.CertifiedModuleVersion`, and conformance checks every Dockerfile against it.
- Look up the module's certificate on the NIST CMVP site ("Go Cryptographic Module"). Don't write a certificate number into this repo without the certificate in hand.
- **Upgrading the module:** when a newer snapshot moves from `inprocess.txt` to `certified.txt` (at the time of writing, `v1.26.0` is in process), change `CertifiedModuleVersion` and the Dockerfiles together, then run `make test-fips-modes`.

## What's inside the validated boundary, and what isn't

| Inside the certified module (Go stdlib `crypto/*`) | Outside it (not validated even where the algorithm is approved) |
|---|---|
| AES (GCM with module-generated IV, CBC, CTR), SHA-2/SHA-3, HMAC, HKDF, PBKDF2, RSA, ECDSA, Ed25519, ECDH P-curves, ML-KEM, DRBG | **ML-DSA, SLH-DSA** (`cloudflare/circl`): refused in `only` mode |
| | **X25519** via `filippo.io/age`: refused in `only` mode by an explicit guard, because the runtime can't see it |
| | **OpenPGP** (`ProtonMail/go-crypto`, SHA-1 fingerprints): refused in `only` mode |
| | **DES/TDES** payment crypto (`pkg/payment`, `moov-io/tr31`), **ChaCha20** (`x/crypto`): refused by the runtime in `only` mode |

**Shamir secret sharing** (`pkg/crypto/shamir.go`, backup key split): a
split-knowledge procedure over GF(2^8), not an encryption algorithm, and not
covered by a FIPS standard. It draws its randomness from the module DRBG
and only splits a key that software-mode backups already hand out whole, so
it runs in every mode without a guard. It is not claimed as validated
([BACKUP_KEYS.md](BACKUP_KEYS.md)).

**Customer HSMs** ([HSM_INTEGRATION.md](HSM_INTEGRATION.md)): operations on
HSM-resident keys and the tenant key run in the HSM's own module, with
approved mechanisms only (AES-GCM, RSA-PSS, ECDSA P-256/P-384), the same in
every mode. The KMS never claims that module is validated; the customer
checks its certificate.

Third-party crypto doesn't go through the module, so `GODEBUG=fips140=only`
**can't block it**. Every such call needs an explicit `fips140.Enforced()`
guard (see `generateAgeX25519KeyPair`, `generateOpenPGPKeyPair`,
`implementedOutsideValidatedModule`).

## Rules for development

1. **All primitives come from `pkg/crypto`.** That rule is conformance-enforced, and it's what keeps the boundary auditable.
2. **AES-GCM encryption uses a module-generated IV:** `Seal`, `SealDetached`, or `EncryptEnvelope`. FIPS 140-3 IG C.H requires this, and `cipher.NewGCM` with a caller-supplied nonce is refused in `only` mode. A caller-chosen IV (external or deterministic IV features) must go through `SealGCMWithNonce`, which returns `ErrCallerNonceStrict` in strict mode.
3. **Non-approved or non-module crypto gets a strict-mode guard that returns an error.** Go panics on SHA-1 and on HMAC keys under 112 bits in strict mode, so the guard must run before the call.
4. **Every feature is tested in every mode:**
   - A test that exercises a non-approved feature calls `fipstest.SkipIfStrict(t, "<feature>")`.
   - It is paired with a `fipstest.StrictOnly` test proving the strict-mode refusal is a clean error.
   - `make test-fips-modes` runs the suite in `off`, `on` and `only`. CI does the same (the `fips-modes` matrix) with `VECTA_REQUIRE_CERTIFIED_MODULE=1`.
5. **Never claim "validated" unless `fips.ModuleValidated()` is true.** `fips140.Enabled()` alone can be the unvalidated `latest` module.
6. **Keep stored formats stable.** Envelope IVs are persisted as 16 bytes (12-byte module nonce + 4 zero bytes); envelopes written before 2026-09-25 (16 random bytes, first 12 used) still decrypt. `TestLegacyEnvelopeStillDecrypts` guards this.

## How it's enforced

| Check | Where |
|---|---|
| `fips-module` | `scripts/conformance.sh`: every Go Dockerfile pins `GOFIPS140 = CertifiedModuleVersion`; compose passes `VECTA_FIPS_MODE` and `GODEBUG=fips140` to every Go service |
| Startup verification | `pkg/config.RequireFIPSRuntime` (from `Load` / `NewHTTPServer`, so every `pkg/platform` service gets it by construction) |
| Mode matrix | `make test-fips-modes`; CI job `fips-modes` (`off` / `on` / `only`) |
| Certified build | `TestBuiltWithCertifiedModule` (`VECTA_REQUIRE_CERTIFIED_MODULE=1`) |
| Strict refusals | `StrictOnly` tests in `pkg/crypto`, `pkg/payment`, `services/keycore`, `certs`, `dataprotect`, `secrets` |

## Known gaps

- **dataprotect legacy keys:** keys that predate 2026-09-25 still use
  identifier-derived (v1) working keys until an operator migrates them. Strict
  mode refuses v1; new keys are keycore-derived from birth. See
  [DATAPROTECT_KEY_DERIVATION.md](DATAPROTECT_KEY_DERIVATION.md).
- **ML-DSA / SLH-DSA:** not available in `only` mode until they come from a certified module snapshot.
