# Audit log integrity

How the audit log is made tamper-evident, what each layer proves, and what
it does not. Code: `services/audit/chain.go`, `cluster.go` (HMAC keyring),
`event_hmac_key.go`, `checkpoint.go`, `target_integrity.go`. Since 3.0.0-beta.

## Layers

| Layer | What it is | What it catches |
|---|---|---|
| Append-only storage | Postgres triggers reject `UPDATE`/`DELETE` on `audit_events` (migration 001). The API refuses `PUT`/`PATCH`/`DELETE` on audit paths. | Ordinary edits through the application or a normal database role. |
| Hash chain | `chain_hash = SHA-256(previous_hash ‖ canonical event JSON)`. Every field (actor, action, target, result, details, …) is covered. One chain per tenant per node (`chain_node`). | Any edited, inserted or removed row, unless every later hash is recomputed. |
| Per-event HMAC | `HMAC-SHA-256(chain_hash)` under a key derived from the audit master key (see below). | A rewrite that recomputes the hashes, by anyone without the HMAC key. |
| Signed checkpoints | Every 10 minutes each node signs the head of each tenant chain it writes with ECDSA-P384 (SHA-384). | A rewrite by someone holding the HMAC key: the rewritten history no longer ends at the signed head. |

## The event HMAC key

- **Source.** `HKDF-SHA256(audit MEK, info "vecta-audit-event-hmac/1")`. The
  audit MEK is a protected keycore system key (`pkg/mek`,
  [SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md)), so the HMAC key
  survives restarts and is identical on every cluster node (members follow
  the primary's MEK version). The key of every earlier MEK version is
  derived too, so events signed before a master-key rotation still verify;
  a version keycore can't derive is named in
  `audit.audit.event_hmac_key_installed` (`unavailable_mek_versions`).
- **Before the key opens** (keycore not yet reachable at start), events are
  stored unsigned and reported `unsigned`, never as a failure. Checkpoints
  start only after the key opens, so every key registration is signed.
- **`AUDIT_EVENT_SIGNING_KEY_B64`** is read only when an operator set it,
  to verify events earlier releases signed with it. Nothing is generated
  when it is unset. Until 3.0.0-beta no installer set it, so each restart
  made a random key and earlier events became `hmac_key_unknown`. Those
  HMACs are lost for good; the events' hash chain is unaffected.

## Signed checkpoints

- **What is signed.** The JSON object
  `{"format":"vecta-audit-checkpoint/1","tenant_id","chain_node","sequence","chain_hash","signed_at"}`
  (fields in that order, no whitespace). `chain_hash` commits to every
  earlier event of the chain, so one signature covers the whole history up
  to `sequence`.
- **When.** At start, then every 10 minutes, for each chain whose head moved
  since its last checkpoint. An idle chain is not re-signed.
- **The key.** ECDSA-P384 from `pkg/crypto` (FIPS-approved in all three
  modes), generated in memory when the audit service starts. It is never
  written to disk, the database or the environment, and a restart makes a
  new one. It is not the root key or any keycore key: signing thousands of
  heads a day would put a key that protects other keys on a hot path.
- **Where they go.** The public key is the audit event
  `audit.audit.checkpoint_key_created` (root tenant, `target_id` = key ID =
  SHA-256 of the SPKI DER, `details.public_key_pem`). Each checkpoint is the
  audit event `audit.audit.checkpoint_signed` in the chain it signs. Both
  are hash-chained, HMAC-signed, replicated to cluster members and
  delivered to event streams (SIEM), so copies exist outside this database.
- **Refusals.** A key that can't be generated or a signature that fails is
  `audit.audit.checkpoint_refused` (`result: refused`, `reason`), and
  nothing is recorded as signed.

### Which keys are trusted

A checkpoint verifies only under a key the verifier trusts:

1. the key this process generated (held in memory), or
2. a key whose `checkpoint_key_created` event still reproduces its chain
   hash, carries a valid HMAC, names `ECDSA-P384`, and whose PEM hashes to
   the key ID.

A key that is only present in the database is never trusted. A checkpoint
under any other key reports `key_unknown`.

## Verification

- **Two walks** (13.20.0-beta). Both check every checkpoint's signature
  under a trusted key.
  - **Full** (`VerifyChain`): every row of every chain, links, hashes and
    HMACs, and the row at every signed head must still carry the signed
    hash. The audit service runs it every hour for every tenant; a pass is
    recorded as `audit.audit.chain_verified` (`rows_checked`,
    `duration_ms`; the primary only), a failure as `audit.audit.chain_broken`.
    `GET /audit/chain/verify?full=true` runs it now.
  - **Since the checkpoint** (`GET /audit/chain/verify`, the default): each
    chain from the row its newest verified checkpoint signed. That row must
    still carry the signed hash and produce it from its own content; every
    later row must link, hash and HMAC correctly. A chain with no verified
    checkpoint is walked from its first row. The response says
    `scope`, `from_sequence` per chain, `rows_checked`, and
    `last_full_verification` (the newest `chain_verified`).
  - **Why two.** The full walk grew with the log: 78,196 rows for `root`
    took 15 to 20 seconds and then outran the edge's 20-second limit. The
    signed hash commits to every earlier row, but only the full walk
    recomputes them: an edit to a row before the newest checkpoint that
    leaves the stored hash unchanged is found by the hourly walk, not the
    quick one (`TestOnlyTheFullWalkRecomputesRowsBeforeTheCheckpoint`).
    What the quick walk catches is pinned by
    `TestQuickWalkCatchesChangesAtAndAfterTheCheckpoint`.
- Break reasons: `previous_hash_mismatch`, `chain_hash_mismatch`,
  `hmac_mismatch`, `hmac_key_unknown`, `checkpoint_key_unknown`,
  `checkpoint_signature_invalid`, `checkpoint_head_mismatch`.
- `GET /audit/targets/{target_id}/integrity` checks one target's events:
  content, links to both neighbours, HMAC, and the covering checkpoint.
  An event is `sealed` when the first checkpoint of its chain at or after it
  verifies and the stored rows from the event to the signed head are
  contiguous, linked and end at the signed hash. Events after the latest
  checkpoint are `pending`.
- `GET /audit/checkpoints` lists the newest checkpoints, each re-verified,
  with the exact signed `message`, the base64 DER `signature` and the
  `public_key_pem`.

Any failure raises the critical `audit.audit.chain_broken` (scope `chain`,
`target` or `checkpoints`).

### Verifying outside the KMS

```sh
# message.json: the checkpoint's "message", byte for byte, no trailing newline
printf '%s' "$MESSAGE" > message.json
printf '%s' "$SIGNATURE_B64" | base64 -d > sig.der
printf '%s\n' "$PUBLIC_KEY_PEM" > key.pem
openssl dgst -sha384 -verify key.pem -signature sig.der message.json
```

Pin the public keys you received through your event stream
(`audit.audit.checkpoint_key_created`) rather than the ones the API returns
now; that is what makes the check independent of this database.

## Recorded outcome (13.15.0-beta)

The chain proves a row was not changed, not that it was recorded right.
Publishers send one of two shapes: the `pkg/audit` event (outcome in
`result` at the top) or auth's legacy `{"data": {...}}` envelope (outcome
inside `data`). Until 13.15.0-beta the ingest read only the top level and
defaulted `result` to `success`, so every refusal auth published the second
way (`request_refused`, `password_change_refused`, `cli_session_refused`,
`cluster_mint_refused`, ...) was stored as a success, with no actor or
address in its columns. The ingest now takes `result`, `actor_id` (or
`actor_user_id`) and `source_ip` from `data` when the envelope has none
(`TestDataEnvelopeKeepsItsRefusal`).

Rows stored before 13.15.0-beta are not rewritten: changing them would
break the chain. On a stack upgraded from an earlier release, filter those
refusals by action and `details.result`, not by the `result` column. A new
event's test checks the row as stored at least once, not only the payload
published (CLAUDE.md, "Before calling a change done").

## One row per stream message (13.39.0-beta)

The chain proves rows weren't changed; it doesn't prove each event was
recorded once. JetStream delivers a message again whenever its ack is
lost, and replays the stream when a consumer's stored position is lost
(2026-10-21: an interrupted write zeroed `audit-ingest`'s state file).
Before 13.39.0-beta only cluster-relayed events were checked for an existing
row, so each redelivery was a second row with a new id.

An event read from the stream is stored under
`evt_` + the first 16 bytes of SHA-256 over the stream name, stream
sequence, the time the server stored the message (nanoseconds) and the
payload (`streamEventID`). A message whose id is already stored for the
tenant is skipped, whether it is a redelivery or a cluster relay. The id in
a payload is kept only for a relay; anything else gets its stream id, so a
publisher can't choose the id its event is stored under. An event the
write-ahead buffer holds carries its stream id, and the drain skips it if it
was stored before the buffer was rewritten
(`TestRedeliveredMessageIsStoredOnce`, `...Postgres`).

Rows stored before 13.39.0-beta keep their random ids and aren't rewritten.
Until their messages age out of the stream (90 days after the upgrade), a
replay would still duplicate them, so a lost consumer position is repaired
by hand (docs/OPERATIONS_GUIDE.md).

## Addresses on Postgres (13.42.0-beta)

`source_ip` is an `INET` column on Postgres, and an `INET` read as text
carries its prefix length (`192.0.2.1/32`, `2001:db8::7/128`). The chain hash
is computed over the bare address `PersistEvent` normalises. Until
13.42.0-beta the walk read the prefixed form, so on Postgres every event with
an address failed with `chain_hash_mismatch`: on the live stack Verify Chain
answered `ok: false` and the hourly full walk had never passed
(`last_full_verification: null`). No row had been changed. No Postgres chain
test stored an address, and SQLite stores the text as written.

Rows are now read with `storedSourceIP`, which drops the prefix and
normalises the address as it was hashed, in the walk, the per-target proof,
checkpoint signing and the event list. Stored rows are not rewritten: they
verify again as they are. An address changed in the table is still a break
(`TestChainVerifiesEventsWithAnAddressPostgres`). A row's hash input is read
in the form it was hashed in, and the Postgres test of a hash stores every
field the hash covers (CLAUDE.md, "Integrity and audit").

## Sessions and requests (13.42.0-beta)

`session_id` and `correlation_id` are recorded for every event a route
kernel emits, so an investigation can follow one sign-in or one request
across services. Neither is identity or a control; both come from places
a caller can't write:

- `session_id` is the `sid` claim of the verified token (auth sets it at
  sign-in and keeps it on refresh).
- `correlation_id` is the request ID of the first service the request
  reached, carried to every service it calls by `servicetoken.Authorize`
  (`pkg/correlation`). The edge removes `X-Correlation-ID` from outside
  requests (`infra/envoy/envoy.yaml`;
  `TestEdgeRemovesTheCorrelationHeaderOnRealEnvoy`), so a caller can't join
  its events to another request's. A background job starts its own.

Before 13.42.0-beta no event carried a session (0 of 32,827 in the last
week on the live stack), and 82 of 31,235 correlation IDs spanned more than
one service: each service started its own.

## The write-ahead buffer (13.20.0-beta)

With `AUDIT_FAIL_CLOSED=false`, audit buffers events on disk while Postgres
or NATS is down and ingests them later. The buffer and its HMAC key are on
the audit volume (`/app/data/audit-wal/buffer.log`,
`/app/data/audit-wal-hmac-key.b64`, `AUDIT_DATA_DIR` to move both). The key
is made once at first start (or adopted from `AUDIT_WAL_HMAC_KEY_B64` when
an operator had set it) and a damaged key file stops the service. A record
that fails its HMAC or can't be read is moved to `buffer.log.rejected` and
recorded as `audit.audit.wal_record_refused` (`reason` `hmac_mismatch` or
`unreadable`); it is never ingested and never dropped unseen.

Before 13.20.0-beta the key was random at every start and the buffer was
outside the volume, so every record still buffered at a restart was
dropped without a trace. With the default `AUDIT_FAIL_CLOSED=true` nothing
is buffered and this did not apply.

## What it does not prove

- **Events after the latest checkpoint** are protected by the chain and the
  HMAC only, for up to 10 minutes.
- **An attacker with the HMAC key and database write access** can delete the
  tail of a chain, including its latest checkpoint events, or forge a key
  registration and re-sign. The internal checks can't see that; the copies
  already delivered to your SIEM can. Stream `audit.audit.checkpoint_*` to
  a system the KMS administrators can't write.
- **Events from before 3.0.0-beta** were HMAC'd under keys that were lost at
  each restart; they report `hmac_key_unknown`. Their hash chain still
  links, and the first checkpoint signed after the upgrade covers them.

## Why not a Merkle tree

Until 2.18.0-beta the audit service also built hourly Merkle epochs, and the
certs service built a certificate "transparency" tree. Neither added
anything the chain didn't already give:

- No root ever left the database, so anyone who could rewrite events could
  rewrite the epochs.
- Both services' verify endpoints checked a proof against the root **the
  caller sent**, so any proof the caller built passed.
- The tree duplicated the last leaf of an odd level with no leaf/node domain
  separation (the CVE-2012-2459 pattern: two leaf sets, one root).
- Inclusion proofs were not used by anything.

Signing the chain head gives the same commitment to history with one
signature and no extra tables. Removed in 3.0.0-beta (docs/DECISIONS.md
2026-09-28); certificate issuance evidence is its audit events.
