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

A floor is a rule: `quantum_vulnerable → decrypt_only` requires post-quantum
algorithms for all new protection, and `below_strength 128 → decrypt_only`
sets a strength floor. (5.1.0-beta also read a tenant "minimum algorithm
tier" from governance posture, but governance has no such setting, so it
could never be set; 5.4.0-beta removed the check.)

Every refusal answers `403 policy_denied`. It emits
`audit.key.crypto_policy_refused` with its reason and rule, and the
operation's own event carries the same reason. Both refusals and rule changes
are Playbooks triggers (`crypto_policy_refused`, `crypto_policy_changed`).
Rules are cached per tenant for up to 10 seconds, and local writes
invalidate the cache.

## Risk assessment (CARAF, 5.4.0-beta)

Crypto Agility → Risk assessment (keycore `/agility/caraf/*`, tables
`caraf_threats`, `caraf_assets`). The customer records:

- **Threats**, each with the algorithms it breaks (the same match kinds as
  rules) and **Z**, the years until they expect it (0 = now).
- **Assets** (an application, a device fleet, a database) with their
  ownership, implementation, post-quantum support, location, jurisdiction,
  sensitivity, **X** (years the data or device must stay protected), **Y**
  (years a migration would take), migration cost, and the keycore keys they
  use (whose live algorithms are read from keycore) or other algorithms.

Keycore computes, per asset, the soonest threat that reaches its
algorithms. The asset is **exposed** when X + Y > Z, **at the limit** when
equal, and has **time to spare** when less. It is **not assessed** until X
and Y are recorded.

The suggested mitigation follows the CARAF matrix:

| | Low cost | High cost |
|---|---|---|
| Time to spare | Phase out | Accept |
| Exposed | Secure | Phase out |

Medium or unknown cost makes no suggestion.

The customer records the decision (secure, accept, phase out or
compensating control) with an owner and a due date. An acceptance needs a
future review date and shows as expired after it. The roadmap lists
decisions by date; overdue and lapsed ones are counted. Every write is a
kernel event (`audit.key.caraf_*`). A recorded decision is the Playbooks
trigger `crypto_risk_decision_recorded`. The product supplies no threat
dates, bands or defaults.

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
- `TestQuantumVulnerableRuleActsAsPQCFloor`.
- `TestAgilityPostureAgainstCustomerPolicy`,
  `TestAgilityPolicyRulesValidatedAndAudited`.
- `TestTimelineIsTheCustomersPlanDeadlines` (pqc).
- `web/dashboard/tests/crypto-agility.spec.ts` asserts that the tab shows no
  standards document, draft or reference.

## Open

- A rule applies to keycore keys. Certificates, TLS endpoints and
  discovered assets are measured and planned (pqc, discovery), but the KMS
  cannot refuse their use.
- CARAF decisions are recorded, not gated: accepting a risk needs a review
  date, not a governance approval.
