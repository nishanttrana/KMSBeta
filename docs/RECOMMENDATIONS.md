# Command Center & Recommendations

The dashboard home page (**Overview → Command Center**) answers one question for
a key-management operator: *what should I fix next, and why?*

It evaluates live tenant state every time it loads (or on **Re-evaluate**),
produces a posture score, and lists prioritised recommendations. Each
recommendation says why it matters, how to fix it, which controls it maps to,
which objects are affected, and links straight to the module where it is fixed.
**Overview → Recommendations** shows the full list with severity, category and
framework filters.

Source: `web/dashboard/src/lib/recommendations.ts` (rules, pure and unit-tested
in `tests/unit/recommendations.test.ts`) and `src/lib/platformSnapshot.ts`
(data collection).

## Honesty contract

- Every data source is loaded independently. A service that is down, not
  licensed, or not permitted for the current user yields **not assessed** — its
  checks are shown with a dashed icon and **never** pass, fail or change the
  score. Nothing is estimated or fabricated.
- Snoozing a recommendation (30 days) is a per-browser convenience only; it does
  not change platform state or any audit record.

## Score

`100 − Σ severity weight` over open recommendations (critical 18, high 9,
medium 4, low 1.5), floored at 0. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F.
The score is shown only when at least one control could be assessed.

## Rule catalogue

| ID | Severity | Triggers when | Maps to | Fix in |
|---|---|---|---|---|
| `algo-broken` | critical | Active key uses DES/3DES, RC4, MD5, SHA-1, RSA < 2048 or P-192/P-224 | NIST SP 800-131A r3, PCI DSS 4.0 §3.6.1, CNSA 2.0 | Key Management |
| `algo-legacy` | medium | Active RSA-2048 key (112-bit security) | NIST IR 8547, SP 800-131A r3 | Crypto Agility |
| `algo-aes128` | low | Active AES-128 key | CNSA 2.0 | Key Management |
| `pqc-migrate` | high / medium | Quantum-vulnerable asymmetric keys (RSA/ECC/EdDSA/DH); **high** if any have no expiry or live past 2030 | NIST IR 8547, FIPS 203/204/205, CNSA 2.0 | Crypto Agility |
| `no-cryptoperiod` | high / medium | Active keys without an expiry (high if > 50 % of keys) | NIST SP 800-57 Pt1 §5.3, PCI DSS 4.0 §3.6.4 | Key Management |
| `expired-active` | high | Key past `expires_at` still active | NIST SP 800-57 Pt1 §5.3, PCI DSS 4.0 §3.6.4 | Key Management |
| `never-rotated` | medium | Symmetric key still at version 1 after 365 days | NIST SP 800-57 Pt1, PCI DSS 4.0 §3.7.4 | Rotation & Scheduling |
| `exportable` | medium / low | Keys with export allowed | PCI DSS 4.0 §3.6.1, FIPS 140-3 | Key Management |
| `unowned` | low | Keys without an `owner` / `app` / `team` label | PCI DSS 4.0 §12.3.3, DORA Art. 9 | Key Management |
| `no-rotation-policy` | high | No enabled automatic rotation policy for keys | NIST SP 800-57 Pt1, PCI DSS 4.0 §3.6.4 | Rotation & Scheduling |
| `deny-default` | high | Key access not deny-by-default | NIST SP 800-207, PCI DSS 4.0 §7.2, DORA Art. 9 | Key Management → access settings |
| `dual-control` | medium | Key access policy changes need no approval | PCI DSS 4.0 §3.6.1.2, ISO 27001 A.8.24 | Approvals |
| `signed-requests` | low | Signed requests / replay protection not enforced | RFC 9421, RFC 9449 | Key Management → access settings |
| `grant-ttl` | low | Access grants can exceed 24 h | NIST SP 800-207 | Key Management → access settings |
| `no-quorum` | high | No governance (M-of-N) policy | PCI DSS 4.0 §3.6.1.2, DORA Art. 9 | Approvals |
| `default-admin` | critical | Bootstrap `admin` still has its initial password | PCI DSS 4.0 §2.2.2, CIS 5.2 | Administration |
| `too-many-admins` | medium | More than 5 active administrators | PCI DSS 4.0 §7.2.2, ISO 27001 A.5.15 | Administration |
| `cert-expired` | high | Non-revoked certificate past `not_after` | NIST SP 1800-16 | Certificates / PKI |
| `cert-expiring` | high / medium | Certificates expiring within 30 days (high if any within 7) | NIST SP 1800-16 | Certificates / PKI |
| `cert-weak` | high | Certificate with a disallowed algorithm | NIST SP 800-131A r3, CA/B Forum BR | Certificates / PKI |
| `cert-lifetime` | low | TLS leaf validity > 200 days | CA/B Forum SC-081 (200 d 2026 → 100 d 2027 → 47 d 2029) | Certificates / PKI |
| `no-backup` | critical | No enabled key backup policy | DORA Art. 12, NIST SP 800-57 Pt2, ISO 27001 A.8.13 | Backup & Restore |
| `backup-stale` | high | No successful backup in 7 days | DORA Art. 12, ISO 27001 A.8.13 | Backup & Restore |
| `backup-plain` | critical | Backup policy without encryption | PCI DSS 4.0 §3.5, FIPS 140-3 | Backup & Restore |
| `single-node` | medium | Cluster has one node | DORA Art. 11, ISO 22301 | Cluster |
| `nodes-down` | high | Degraded or down cluster nodes | DORA Art. 11 | Cluster |
| `posture-open` | high | Open critical/high posture findings | DORA Art. 10 | Posture |
| `pqc-scan` | medium | No PQC readiness scan on record | NIST IR 8547, OMB M-23-02, CNSA 2.0 | SBOM / CBOM |
| `fips-off` | low | FIPS strict mode disabled | FIPS 140-3, FedRAMP SC-13 | Administration |

Framework references indicate which control a recommendation helps satisfy;
they are not a certification or audit statement.

## Adding a rule

1. Add the check to `evaluate()` in `src/lib/recommendations.ts`. Call
   `check(id, label, category, known, failed)` so the coverage panel shows it,
   and push a `Recommendation` only when it fails.
2. If it needs new data, add an independent loader to `platformSnapshot.ts`
   (wrapped in `opt()` so a failure means "not assessed").
3. Add a unit test in `tests/unit/recommendations.test.ts`, then
   `npm run test:unit && npm run typecheck && npm run lint`.
