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

- `GET /audit/chain/verify` walks every chain: links, hashes, HMACs, and
  every checkpoint (signature under a trusted key, and the row at the
  signed head must still carry the signed hash; a missing head row is a
  break). Break reasons: `previous_hash_mismatch`, `chain_hash_mismatch`,
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
