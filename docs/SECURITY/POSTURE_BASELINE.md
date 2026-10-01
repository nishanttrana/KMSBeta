# Posture baseline

How posture decides that today is unusual, how much history it needs before
it says anything, and what it reports until then. Implemented in
`services/posture` (`baseline.go`, `signals.go`, `service.go`), 7.19.0-beta.

## The rule

Posture judges a tenant against **its own history**, not against a fixed
number and not against yesterday. Until that history exists, the risk score
is **not assessed** and no comparison is made.

An event count alone never qualifies a baseline. Ten thousand events in one
afternoon say nothing about a normal Tuesday; thirty events a day for two
weeks do. What matters is how many **complete days** the baseline covers and,
for a rate, how many events of that kind it holds.

| Constant | Value | Why |
|---|---|---|
| `MinBaselineDays` | 14 | Two weekly cycles, so weekdays and weekends are both in the sample. Before this nothing is judged. |
| `StableBaselineDays` | 28 | The window the baseline covers once available. |
| `SpikeAlpha` | 0.001 | A count is unusual when the chance of seeing that many or more under the baseline is below this (about 3σ). |
| `MinRateEvents` | 385 | Events a rate signal needs in its baseline. With fewer, the 95% margin of error on the rate (1.96·√(p(1−p)/n), worst case p = 0.5) is wider than ±5 points. |

## Where the days come from

1. **Complete sync.** Posture reads the tenant's audit events from a cursor,
   oldest first (`GET /audit/events?order=asc&from=…`), up to 50 pages of
   1000 per tenant per run. A backlog continues on the next run; nothing is
   skipped. The first run starts 28 days back, or at the tenant's first
   audit event if that is later, so an existing deployment's baseline is
   built from the audit trail it already has.
2. **Finalized days.** When the sync has read everything up to an hour past
   the end of a UTC day, that day's signal summary is written to
   `posture_signal_daily`. A row's existence means the day is a valid
   observation. The tenant's first, partial day is never one.
3. **The baseline** is the finalized days in the last 28, ending yesterday.
   Today (the rolling last 24 hours) is what gets judged.

## What each signal counts

Signals match the exact audit subjects the platform emits (`signals.go`).
Many services publish events without a result, so a failure is identified by
its subject, not by `result`. `TestSignalSubjectsAreEmitted` fails when a
listed subject is not emitted anywhere in the repo.

| Signal | Kind | Floor | Counts |
|---|---|---|---|
| Failed authentication | count | 25 | `audit.auth.login_failed`, `mfa_failed`, `sso_login_refused`, `client_dpop_failed`, `client_http_signature_failed`, `mtls_binding_failed` |
| Refused or failed key operations | count | 10 | `audit.key.*_refused` (access, request, crypto policy, derive, HSM), `audit.signing.sign_refused`, `audit.hyok.request_denied`, `audit.ekm.key_access_denied`, `audit.cloud.key_access_denied`, and any `audit.dataprotect.<op>_refused` / `_failed` |
| Refused requests (all services) | count | 20 | any event with `result` `refused` or `denied` |
| Connector failures | count | 6 | `audit.cloud.sync_failed`, `audit.ekm.agent_disconnected`, `audit.ekm.bitlocker_client_disconnected`, `audit.kmip.authorization_denied` |
| Keys and certificates destroyed | count | 5 | `audit.key.destroyed`, `audit.key.version_deleted`, `audit.cert.deleted`, `audit.cert.ca_deleted` |
| Denied approvals | count | 3 | `audit.governance.vote_denied`, `audit.governance.quorum_denied` |
| BYOK, HYOK, EKM, KMIP, BitLocker, SDK failure rate | rate | 3 failures | failures over events of that domain (`audit.cloud.*`, `audit.hyok.*`, `audit.ekm.*`, `audit.kmip.*`, `audit.ekm.bitlocker_*`, `audit.dataprotect.field_encryption.*`) |

The floor is a materiality limit: three failed logins can be statistically
rare for a quiet tenant and still not be an incident.

## The tests

- **Counts.** From the baseline's daily values posture takes the mean and
  the day-to-day variance, then computes P(X ≥ today). When the variance
  does not exceed the mean it uses the Poisson distribution; when it does
  (weekday against weekend swings, batch days) it uses the negative binomial
  with the same mean and variance, so a tenant with a busy week and a quiet
  weekend is not flagged every Monday. Unusual means P < 0.001 **and** the
  count reaches the floor.
- **Rates.** A one-sided binomial test of today's failures out of today's
  events against the baseline's pooled failure rate. Not judged until the
  baseline is ready **and** holds 385 events for that domain; until then the
  rate is shown with "needs N more events".
- Above 20,000 the exact sums give way to the normal approximation.

Findings that state a fact are not gated: expired or expiring certificates,
missed renewal windows, emergency rotations, a failed KMIP validation,
missing SDK receipts, a non-approved algorithm, a tenant mismatch, overdue
remediation, and keycore's threat signals are raised from day one.

## The score

- `assessed: false` until the baseline has 14 days. `risk_24h` and `risk_7d`
  are then 0 and mean **not assessed**, never "no risk". The dashboard shows
  "Baseline building: n of 14 days".
- Once assessed, `risk_24h` = 45% predictive + 30% preventive + 25%
  corrective engine score. Activity volume is never part of it.
- `risk_7d` is the mean of the assessed `risk_24h` scores of the last seven
  days.
- The cross-tenant snapshot (`*`) averages assessed tenants only.
- Snapshots taken before 7.19.0-beta had no baseline and stay unassessed;
  the risk trend plots assessed snapshots only.

`audit.posture.baseline_ready` is emitted once, when a tenant's score first
becomes assessed. `GET /posture/baseline` returns the standing of every
signal.

## Removed in the same change

- The score's fallback of `events / 200`, and `risk_7d`'s
  `(this week's events − last week's) / 50`: a busy healthy tenant scored as
  risky.
- "Twice yesterday" spike rules (`isSpike`), which fired on day one against
  an empty previous day.
- The cluster drift, replication retry and cluster lag signals and their two
  findings: nothing in the platform emits those events, and "cluster lag"
  was the average request duration of cluster events, not replication lag.
- Name patterns that matched nothing the platform emits (`auth.login_failed%`
  without the `audit.` prefix, `key.delete%`, `governance.quorum_bypass%`,
  `cert.expiry%`, `fips.non_approved%`): those signals had always read zero.

## Limits

- Day boundaries are UTC.
- An audit event persisted more than ten minutes after its timestamp, behind
  the cursor, is not re-read.
- The rolling 24 hours overlaps the newest baseline day by up to a day.
- Keycore's own threat detection (new actor, volume spike, dormant key) has a
  separate baseline in keycore; this document does not cover it.
