# Command Center & Recommendations

The dashboard home page (**Overview → Command Center**) answers one question for
a key-management operator: *what should I fix next, and why?*

It evaluates live tenant state every time it loads (or on **Re-evaluate**),
produces a posture score, and lists prioritised recommendations. Each
recommendation says what was found, why it matters, how to fix it and which
objects are affected, and links straight to the module where it is fixed.
**Overview → Recommendations** shows the full list with severity and
category filters.

Source: `web/dashboard/src/lib/recommendations.ts` (rules, pure and unit-tested
in `tests/unit/recommendations.test.ts`) and `src/lib/platformSnapshot.ts`
(data collection).

## Honesty contract

- Every data source is loaded independently. A service that is down, not
  licensed, or not permitted for the current user yields **not assessed** — its
  checks are shown with a dashed icon and **never** pass, fail or change the
  score. Nothing is estimated or fabricated.
- A Go zero time (`0001-01-01T00:00:00Z`) is no time. Services answer a
  tenant that was never scanned with it, so every response the dashboard
  reads goes through `parseServiceJSON` (`src/lib/wire.ts`), which turns it
  into an empty value. `posture-open` therefore reads **not assessed** until
  a posture scan is on record, instead of passing (11.4.0-beta,
  `tests/unit/zeroTime.test.ts`).
- **Algorithm facts come from the catalogue; dates and deprecations come from
  you** (13.19.0-beta). Whether an algorithm is weak or quantum-vulnerable,
  and its strength, comes only from `pkg/cryptocatalog`: for keys through
  keycore's `GET /agility/posture` (which needs `key.agility.read`), for
  certificates through the `algorithm_facts` the certs service returns with
  each certificate. Whether an algorithm is deprecated, decrypt-only or
  disallowed, and from when, comes only from the tenant's own migration
  rules (Crypto Agility). No rule cites a standard, and no rule sets a
  date. Without the agility posture the algorithm rules read **not
  assessed**; an algorithm name without a parameter set (`RSA`) is never
  judged. `tests/unit/recommendations.test.ts` fails if a citation, a
  deadline year or an algorithm list returns to the engine or the
  Command Center.
- Snoozing a recommendation (30 days) is a per-browser convenience only; it does
  not change platform state or any audit record.

## Score

`100 − Σ severity weight` over open recommendations (critical 18, high 9,
medium 4, low 1.5), floored at 0. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F.
The score is shown only when at least one control could be assessed.

## Rule catalogue

| ID | Severity | Triggers when | Fix in |
|---|---|---|---|
| `algo-weak` | critical | An active key's algorithm is weak in the catalogue | Key Management |
| `algo-policy-stopped` | high | An active key's algorithm is decrypt-only or disallowed by one of your migration rules | Crypto Agility |
| `algo-policy-deprecated` | medium | An active key's algorithm is deprecated by one of your migration rules | Crypto Agility |
| `pqc-migrate` | medium | Active keys whose algorithm the catalogue marks quantum-vulnerable; says how many no migration rule of yours covers | Crypto Agility |
| `no-cryptoperiod` | high / medium | Active keys without an expiry (high if > 50 % of keys) | Key Management |
| `expired-active` | high | Key past `expires_at` still active | Key Management |
| `never-rotated` | medium | Symmetric key (by the catalogue) still at version 1 after 365 days | Rotation & Scheduling |
| `exportable` | medium / low | Keys with export allowed | Key Management |
| `unowned` | low | Keys without an `owner` / `app` / `team` label | Key Management |
| `no-rotation-policy` | high | No enabled automatic rotation policy for keys | Rotation & Scheduling |
| `deny-default` | high | Key access not deny-by-default | Key Management → access settings |
| `dual-control` | medium | Key access policy changes need no approval | Approvals |
| `signed-requests` | low | Signed requests / replay protection not enforced | Key Management → access settings |
| `grant-ttl` | low | Access grants can exceed 24 h | Key Management → access settings |
| `no-quorum` | high | No governance (M-of-N) policy | Approvals |
| `default-admin` | critical | Bootstrap `admin` still has its initial password | Administration |
| `too-many-admins` | medium | More than 5 active administrators | Administration |
| `cert-expired` | high | Non-revoked certificate past `not_after` | Certificates / PKI |
| `cert-expiring` | high / medium | Certificates expiring within 30 days (high if any within 7) | Certificates / PKI |
| `cert-weak` | high | A certificate's algorithm is weak in the catalogue | Certificates / PKI |
| `no-backup` | critical | No completed encrypted backup on record | System Administration → Backups |
| `backup-stale` | high | No completed encrypted backup in 7 days | System Administration → Backups |
| `single-node` | medium | Cluster has one node | Cluster |
| `nodes-down` | high | Degraded or down cluster nodes | Cluster |
| `posture-open` | high | Open critical/high posture findings | Posture |
| `pqc-scan` | medium | No PQC readiness scan on record | SBOM / CBOM |
| `fips-off` | low | FIPS strict mode disabled | Administration |

Removed in 13.19.0-beta, because each restated a standard's threshold or
deadline instead of a fact or the tenant's own rule: `algo-legacy`
(RSA-2048 retirement dates), `algo-aes128` (AES-128 below a national
profile) and `cert-lifetime` (a public-CA TLS lifetime limit). A tenant
that wants any of them adds a migration rule (for example "below strength
128") or a certificate profile, and the recommendation follows that.

## Adding a rule

1. Add the check to `evaluate()` in `src/lib/recommendations.ts`. Call
   `check(id, label, category, known, failed)` so the coverage panel shows it,
   and push a `Recommendation` only when it fails. A rule about an algorithm
   reads the catalogue's facts (`keyFacts`, `algorithm_facts`), never the
   name, and a date comes from the tenant's rules, never from the rule.
2. If it needs new data, add an independent loader to `platformSnapshot.ts`
   (wrapped in `opt()` so a failure means "not assessed").
3. Add a unit test in `tests/unit/recommendations.test.ts`, then
   `npm run test:unit && npm run typecheck && npm run lint`.
