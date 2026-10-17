# Failing closed, verifying credentials, and proving integrity checks

Security lessons that were recorded only in [learning.md](../../learning.md)
until 13.18.0-beta. Each states the rule, why it exists, and what enforces
it. The short form of every rule is in CLAUDE.md, "Rules learned from
faults".

## Fail closed

| Rule | Why | Enforced by |
|---|---|---|
| No customer-settable switch turns an outage into "allow" (`fail_open`, `FAIL_CLOSED=false`). When one dependency check is made fail closed, every such branch in the service goes in the same change. | A fail-open switch survived the fix of its sibling in the same service (learning 2026-09-30). | Review; grep `fail_open` / `FAIL_CLOSED` when touching a dependency check |
| A security listener has one configuration path. A missing input makes it wait or refuse to start; it never swaps in a weaker or `dev` configuration. | A "dev" fallback in a production path became the production behaviour (2026-09-29). | `make conformance` `tls-only`; [INTERNAL_TLS.md](INTERNAL_TLS.md) |
| A key that must verify data later has no random fallback: it is derived from the service master key (`pkg/mek`) or the service refuses. | A random fallback is lost at every restart, and everything signed under it stops verifying (2026-09-28). | [SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md); **open item below** |
| A guard keeps "not applicable" (may return quietly) apart from "unable" (a failure, audited). | An early return hid the failure it guarded (2026-09-29). | Review |
| A fetch helper returns its error; a caller of an optional service reads whether it is deployed from the deployment, and unknown fails closed; a fallback taken on every call is counted or audited. | `return empty, nil` produced fake results, and a client that never authenticated made a fail-open fallback the only path (2026-09-29, 2026-09-30). | `TestEvaluateSendsServiceToken`; CLAUDE.md "Every internal call carries a credential" |
| Unattended work re-checks the authorising person with auth when it runs, and fails closed when it can't ask. | Authority checked once was kept forever (playbooks, 2026-09-28). | [PLATFORM_CONTRACT.md](../PLATFORM_CONTRACT.md) |

## Verifying credentials and identity

- Identity comes only from a credential the service verifies (CLAUDE.md
  rule 4, [REQUEST_ORIGIN.md](REQUEST_ORIGIN.md)). A route whose credential
  is not a bearer token (a certificate, a one-time token, a signed
  assertion) lists what that credential proves and binds every request
  field to it; a public value (a certificate, an ID) proves nothing without
  a signature.
- Every token or assertion that grants access (JWT, SAML, OIDC, KACLS, SCIM
  bearer) has tests that send a forged, a tampered, an expired, a
  mis-addressed and a replayed copy and show each is refused. A collected
  signature field that is not checked was found in SAML and OIDC
  (2026-09-27).
- MFA or step-up comes from a claim auth signs after the second factor,
  never from a header.
- An M-of-N approval binds each vote to a verified identity, refuses the
  requester, and never lets the requester choose approvers or side effects;
  an identity is resolved to every form a check compares (ID and email)
  before the check runs (2026-09-27).
- A cross-tenant grant is tied to the token's tenant, never to `*` or a
  role name ([TENANT_ISOLATION.md](TENANT_ISOLATION.md), 13.14.0-beta).

## Outbound calls

- A credential on a request that may be redirected travels only in
  `Authorization`, and the client's `CheckRedirect` drops it when the host
  changes: Go keeps `Authorization` across a redirect to the same host on
  another port (2026-10-01). Today: the shared outbound client
  (`pkg/ssrfguard/client.go`) refuses every redirect, the storage source
  client returns the redirect unfollowed (`services/discovery/storage.go`),
  and the repository client follows at most five HTTPS redirects and drops
  `Authorization` on a host change (`services/discovery/repo.go`).
- An outbound address is checked where it is dialled
  (`pkg/ssrfguard.DialContext`), not by its hostname; a name is refused at
  input only when it is a bare platform name
  ([CONNECTIONS.md](CONNECTIONS.md)).
- A URL that carries a credential (a webhook) is a secret: it lives only in
  a sealed connection, and an outbound error names only the host.

## Integrity checks

- An integrity check names the trusted input an attacker who can write the
  database can't write (a key held elsewhere, a copy outside their reach).
  Without one it is decoration and is removed; two checks that compared a
  value with itself were (2026-09-27).
- Every integrity check ships with a test that alters the stored data (the
  row, a recomputed row, a deleted neighbour, the root) and expects
  rejection. Audit log integrity:
  [AUDIT_INTEGRITY.md](AUDIT_INTEGRITY.md).
- A stored audit row's `result` and actor are part of what is proven: a
  refusal stored as success is wrong evidence even when its chain verifies
  ([AUDIT_INTEGRITY.md](AUDIT_INTEGRITY.md#recorded-outcome-13150-beta)).

## Still open

- **The audit write-ahead buffer's HMAC key is random at every start.**
  `services/audit/main.go` reads `AUDIT_WAL_HMAC_KEY_B64` through
  `pkg/crypto.LoadKey32`, which returns a random key when the variable is
  unset, and no installer sets it. After a restart, every record still in
  the buffer (events held while Postgres or NATS was unavailable) fails its
  HMAC, is skipped without a word in `DrainWAL`, and is then dropped when
  the buffer is rewritten. Those audit events are lost unaudited. Recorded
  in learning.md on 2026-09-28 and not fixed since; found again in the
  13.18.0-beta review. The fix needs a key that survives restarts and is
  available before keycore is (the buffer exists for outages), and a drop
  for a bad HMAC must be audited instead of silent.
- `pkg/crypto.LoadKey32` itself still returns a random key for a missing
  variable; any new caller inherits the fault above.
