# Real capability only

**Standing rule** (owner directive, 2026-09-26; CLAUDE.md rule 8): every
feature in the KMS is 100% real capability. It does what its UI and API say,
end to end. Nothing is mimicked, simulated or faked, and a screen with no
working backend behind it doesn't count as a feature.

## What counts as fake

- Results the code invents: synthetic certificates, "passed" steps that
  never ran, made-up RTO/RPO, fixed "10/10 keys restored".
- A workflow that stores records but never touches the thing it claims to
  protect, such as "escrowing" a key without the key material.
- Demo or sample data shown as if it came from the customer's system.
- UI controls that change nothing in the backend.
- Security values from non-cryptographic randomness (`Math.random` nonces,
  timestamp fallbacks).

## What to do instead

1. Build it for real. Test it against its real dependency (Postgres, the
   real protocol client, SoftHSM2 for PKCS#11), audit every action and
   refusal, and take the tenant and actor from verified claims.
2. If that isn't possible yet, remove it (preferred). Otherwise label it a
   preview: list it in `pkg/features.Preview`, label its responses, and have
   operations it can't perform return `409 feature_preview`. A preview
   stores settings; it never produces results.

## How it's enforced

- `make conformance`, rule `real-capability`, fails on:
  - `simulate*`, `synthetic*`, `fabricate*`, `fake*` and `mock*` functions
    outside tests (Go and dashboard TypeScript);
  - `Math.random()*256` byte generation and `nonce-${Date.now…}` fallbacks
    in the dashboard.
- Review: follow the data. If no code path touches the secret, calls the
  network or runs the check, the feature is a record-keeper, whatever the
  UI shows.

## Removed for faking (2026-09-26)

| Feature | What it faked | Replaced by |
|---|---|---|
| Key escrow workflow (keycore) | Stored key names only; approvals released nothing; votes forgeable | M-of-N guardian shares for the backup key ([BACKUP_KEYS.md](BACKUP_KEYS.md)) |
| CT log monitor (certs) | `simulateCTFetch` invented certificates and "unknown CA" alerts | Nothing yet; certificate discovery and scanning may come later |
| DR drill (keycore) | Every step "passed", synthetic RTO/RPO | Verify Backup (`POST /governance/backups/verify`) |
| mTLS Mesh (certs) | "Renew" discarded the cert and key; topology claimed mTLS on plain-HTTP links | Internal mTLS from the internal-services Sub CA ([INTERNAL_TLS.md](INTERNAL_TLS.md)) |
| Tokenize nonce fallback (dashboard) | `Math.random` / timestamp nonces | The browser CSPRNG only; fails closed |
