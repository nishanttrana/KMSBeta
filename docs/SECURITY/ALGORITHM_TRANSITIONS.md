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

The assessment also counts assets by sensitivity and timeline (`heatmap`)
and how many carry each value it rests on (`profile`: owner, X, Y, cost,
sensitivity, a live key). Unknown values count as gaps, never as a score.

## Swap drill (6.1.0-beta)

`POST /agility/drills` rehearses a swap on a keycore node. Throwaway keys
come from keycore's own key generation, round trips run through the key
engine and are checked, and medians and real sizes are recorded. Nothing
enters the key inventory. Both algorithms must pass the tenant's FIPS mode
and the target must pass the tenant's own migration policy, through the same
`policyRefusal` decision as key operations. A name without a parameter set
is refused so no measurement is mislabelled. Events:
`audit.key.agility_drill_run` (refusals `fips_mode_violation`,
`crypto_policy_disallowed`, `crypto_policy_decrypt_only`) and
`audit.key.agility_drills_listed`.

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

## Requiring post-quantum, and what pqc reports (6.3.0-beta)

A tenant requires post-quantum for new protection with a migration rule
(`match_kind: quantum_vulnerable`, `action: decrypt_only`). Keycore refuses
create, import, rotate, encrypt, sign, wrap, MAC and derive with a
quantum-vulnerable key from the rule's effective date, and audits each
refusal. This is the only switch that requires PQC.

The pqc service's tenant "PQC policy" (`/pqc/policy`: profile, default KEM
and signature, interface and certificate default modes, HQC backup, three
`flag_*` switches, `require_pqc_for_new_keys`) was removed. Nothing outside
pqc read it, so `require_pqc_for_new_keys` enforced nothing, and the flags
only hid findings. Migration 003 drops `pqc_policies`.

pqc reports measured counts only:

- Inventory and scans count keys, certificates and discovered assets as
  classical, hybrid or PQC-only by the algorithm each has. The
  hand-weighted `readiness_score` (scan 55/30/15, inventory 85/15 with
  hybrid counted as 0.7), `quantum_readiness_percent` and a plan's
  `estimated_risk_reduced` were removed.
- Interfaces are `not_assessed`. The inventory used to report an
  interface with `pqc_mode: inherit` as having the policy's default mode,
  so a TLS mode that was never measured appeared as measured. The
  interface `pqc_mode` in keycore is recorded but not enforced.

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
- `TestDrillMeasuresRealRoundTrips`, `TestAgilityDrillRouteValidatedAndAudited`,
  `TestAgilityDrillStrictRefusesNonModuleAlgorithm` (swap drill).
- `TestPQCPolicyRemovedAndNoInventedScores` (pqc): `/pqc/policy` is gone,
  and inventory, readiness and report carry no score, policy or interface
  mode. `TestPQCServiceReadinessPlanExecuteRollback` checks the inventory
  counts against each asset's algorithm and that interfaces are
  `not_assessed`. `TestPolicyAndScoreDroppedPostgres` runs the migrations on
  Postgres.
- `web/dashboard/tests/crypto-agility.spec.ts` asserts that the tab shows no
  standards document, draft or reference.

## Open

- A rule applies to keycore keys. Certificates, TLS endpoints and
  discovered assets are measured and planned (pqc, discovery), but the KMS
  cannot refuse their use.
- The key exchange a KMS listener negotiates is not measured, and keycore's
  per-interface `pqc_mode` is recorded only. It should be removed, or made a
  preview (`409 feature_preview`), or enforced at the listener.
- CARAF decisions are recorded, not gated: accepting a risk needs a review
  date, not a governance approval.
