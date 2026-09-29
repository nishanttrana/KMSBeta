# Algorithm facts and the customer's migration policy (5.1.0-beta)

**Rule** (owner, 2026-09-29: "avoid quoting direct sources, drafts,
references; let customer decide when and what he wants to migrate as per his
policy"):

- The product states only **technical facts** about algorithms, from one
  place, [`pkg/cryptocatalog`](../../pkg/cryptocatalog/catalog.go):
  - security strength in bits;
  - post-quantum category;
  - whether a quantum computer breaks it;
  - whether it is weak today (broken, under 112 bits, or an unsafe mode such
    as ECB or FF3).
- **When and what to migrate is the customer's policy.** The product ships no
  migration dates, approval statuses, standards citations or draft
  references.
- A name without a parameter set (`RSA`, `AES`, `Dilithium3`) is **not
  assessed**, never guessed.

## The customer's migration policy

Each tenant writes rules (keycore `/agility/policy/rules`, Crypto Agility tab
→ Your migration policy). A rule has:

| Field | Meaning |
|---|---|
| `match_kind` / `match_value` | `algorithm` (one algorithm), `family` (RSA, ECDSA, AES…), `quantum_vulnerable`, `weak`, or `below_strength` (bits) |
| `action` | `deprecated`: keys keep working, flagged for migration. `decrypt_only`: new protection refused, existing data still readable. `disallowed`: every cryptographic operation refused |
| `effective_date` | the customer's date; required |
| `target_algorithm` | optional; known and not weak |

The strictest rule in force applies to a key's algorithm. Keycore enforces it
in `checkPolicy`, which every key operation passes through
(`services/keycore/agility_enforce.go`):

- **New protection:** create, import, rotate, encrypt, sign, wrap, MAC,
  derive, service-derive, KEM encapsulate and data-key generation.
  - Refused under `decrypt_only` and `disallowed`.
- **Processing existing data:** decrypt, verify, unwrap, KEM decapsulate
  and attested release.
  - Refused only under `disallowed`.
- **Lifecycle:** export, destroy, approval and export-policy changes.
  - Never refused by the migration policy, so a key can always be retired.

Keycore enforces a **minimum algorithm tier** from governance posture
(`posture_min_algorithm_tier`) on the same new-protection operations, and a
value that is not a tier refuses new protection until it is fixed (fail
closed). **Governance does not store or return that field**, so in a
deployment the floor is never set and this check never fires (see Open);
`TestTenantMinAlgorithmTierEnforced` injects it directly. Until 5.1.0-beta
this page said the tier was "stored and never enforced"; it was never stored.

Every refusal answers `403 policy_denied`. It emits
`audit.key.crypto_policy_refused` with its reason and rule, and the
operation's own event carries the same reason. Both refusals and rule changes
are Playbooks triggers (`crypto_policy_refused`, `crypto_policy_changed`).
Rules are cached per tenant for up to 10 seconds, and local writes
invalidate the cache.

## Where the facts are used

- The Crypto Agility tab and keycore `/agility/*`.
- `pkg/cbom` tiers: classical tiers follow security strength, a weak
  algorithm is `deprecated`, and an unparsed name is `not-assessed`. Neither
  meets a floor.
- The policy service's `minAlgorithmTier` floor.
- pqc and discovery classification, `strength_bits`, PQC readiness and
  migration targets.

The pqc timeline is the customer's own plan deadlines. A plan without a
deadline has none.

## How it is enforced

- `TestCatalogFacts`, `TestNamesWithoutAParameterSetAreNotAssessed`,
  `TestHybridKeyEstablishment` (catalogue).
- `TestCryptoPolicyEnforcedOnKeyOperations`: `decrypt_only` refuses encrypt
  and key creation but allows decrypt; `disallowed` refuses decrypt; a
  future rule changes nothing; every refusal is audited.
- `TestTenantMinAlgorithmTierEnforced`.
- `TestAgilityPostureAgainstCustomerPolicy`,
  `TestAgilityPolicyRulesValidatedAndAudited`.
- `TestTimelineIsTheCustomersPlanDeadlines` (pqc).
- `web/dashboard/tests/crypto-agility.spec.ts` asserts that the tab shows no
  standards document, draft or reference.

## Open

- A rule applies to keycore keys. Certificates, TLS endpoints and
  discovered assets are measured and planned (pqc, discovery), but the KMS
  cannot refuse their use.
- CARAF assessment (threats, asset profiles, timeline and cost ratings,
  decisions) is the next crypto-agility slice.
- The minimum algorithm tier has no setting: governance has no
  `posture_min_algorithm_tier` (column, API or UI), so keycore always reads
  it empty. Either governance gains the setting, with its UI and audit, or
  keycore's check is removed. Until then a floor is a policy's
  `spec.minAlgorithmTier` or a migration policy rule.
