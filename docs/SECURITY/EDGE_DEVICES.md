# Edge devices: offline key leases and signed receipts

An edge device (a pump controller, a vehicle, a field gateway) has to encrypt
and decrypt while it can't reach the KMS. It leases a data key, works offline
under it until the lease expires, and reports what it did when it is back.
This document says how a device is enrolled, what a lease is, what is kept
where, and what the KMS can and can't prove. Since 13.52.0-beta.

Code: `services/ekm/edge.go`, `services/ekm/store_edge.go`, the agent
`services/edge-agent/`. Console: **Enterprise KM → Edge devices**.

## Enrolment

1. **An administrator adds the device** (`POST /ekm/edge/devices`,
   `ekm.write`): a name, the keys it may lease and the longest lease (1
   minute to 30 days, default 24 hours). ekm asks keycore for a data key
   under each key **as the administrator** (`pkg/delegation`, usage `wrap`)
   and keeps nothing it returns: an administrator can't let a device lease a
   key they couldn't use (`403 key_not_usable`).
2. **The administrator issues a registration token**
   (`POST /ekm/edge/devices/{id}/registration-token`): 256 random bits, one
   use, 24 hours, stored only as a SHA-256. Issuing another replaces it; for
   an enrolled device it re-enrols the device and replaces its credential.
3. **The device enrols** (`edge-agent enroll`, `POST /ekm/edge/enroll`, no
   auth-service token). It generates two keys of its own and sends their
   public halves:
   - an **ECDSA P-256** key, proven by signing `vecta-edge-enroll|` and the
     token (`400 signing_key_invalid` otherwise); it signs the device's
     receipts;
   - an **ML-KEM-768** encapsulation key (FIPS 203); leases are sealed to it.
   It receives a **device credential**, 256 random bits stored as a SHA-256.
   The token is cleared in the statement that enrols the device, so of two
   devices presenting one token only one is enrolled.

```bash
sudo sh -c 'umask 077; cat > /etc/vecta-edge/token'   # paste the token, Ctrl-D
sudo edge-agent enroll -server https://<kms-host>/svc/ekm -token-file /etc/vecta-edge/token
```

The agent speaks TLS 1.3 only, refuses a server that is not `https://`, and
takes `-ca <bundle.pem>` when the KMS certificate comes from its own CA.

## Leases

`edge-agent lease -key <key-id>` (`POST /ekm/edge/devices/{id}/leases`, with
the credential in `X-Edge-Device-Key`):

- ekm checks that the device is active and may lease the key, then asks
  keycore, as itself (`kms-ekm`), for a 256-bit data key under it. Key
  binding policies apply: list `kms-ekm` in a binding's channels for keys
  devices lease ([KEYS.md 5.6](../KEYS.md#56-binding-policies-13510-beta)).
- The data key is sealed to the device's ML-KEM key with `pkg/crypto`
  `KEMSeal` (ML-KEM-768, HKDF-SHA256, AES-256-GCM), bound to
  `vecta-edge-lease|<tenant>|<device>|<lease>`; keycore's wrap carries the
  same binding. ekm keeps only keycore's wrapped copy and the lease record;
  the plaintext data key lives in ekm's memory for the call.
- At most 32 active leases per device; a lease lasts at most the device's
  longest lease.

On the device a lease's data key is kept in `leases/<id>.json` (mode 0600)
until it expires or is revoked. Protect the state directory: disk
encryption, or a TPM-sealed volume. An expired lease encrypts and decrypts
nothing on the device.

## Offline encryption

`edge-agent encrypt -lease <id> -in F -out G` writes an envelope: the lease,
key, key version, keycore's wrapped data key and its binding, and the
AES-256-GCM ciphertext (the header is the additional data, so an altered
header doesn't decrypt). The device decrypts it while it holds the lease
(`edge-agent decrypt`). After the lease, anyone allowed to unwrap with the
key decrypts it centrally: keycore unwraps `wrapped_dek` with `aad` from the
envelope.

## Receipts

Every offline encrypt and decrypt is a receipt: a sequence number, the lease,
the operation, the byte count and the device's time. `edge-agent sync` sends
them (`POST /ekm/edge/devices/{id}/receipts`) as one JSON list signed with
the device's P-256 key:

- a batch not signed by the enrolled key is refused
  (`receipt_signature_invalid`);
- receipts are numbered one after another; a batch at or below the last
  received number is refused (`receipts_replayed`), and a batch that starts
  further on is accepted with the **gap** recorded and audited (receipts lost
  or withheld on the device);
- a receipt naming a lease the device doesn't hold is refused;
- two batches racing for one device: one is stored, the other refused
  (`receipts_conflict`).

Receipts are what the device says it did. The signature proves the enrolled
device said it; it can't prove the device reported everything. The gap
check shows when numbers are missing.

## Revocation

- **A lease** (`POST /ekm/edge/leases/{id}/revoke`): the device drops it
  at its next `sync` (check-in lists revoked leases). Until then it can keep
  using it offline; receipts for it are still accepted, so the use is on
  record. Data sealed under it stays decryptable centrally.
- **A device** (`POST /ekm/edge/devices/{id}/revoke`): its credential is
  cleared, every lease revoked, and every call answers `403 device_revoked`,
  on which the agent deletes all its leases. A revoked device is not enrolled
  again: add a new one.

A device that never reconnects keeps working until its leases expire: choose
the longest lease with that in mind.

## Audit

Every route emits `audit.ekm.<action>` (refusals included, with reasons):
`edge_device_created`, `edge_device_updated`, `edge_device_token_issued`,
`edge_device_enrolled`, `edge_lease_issued`, `edge_receipts_received` (with
`gap` when numbers are missing), `edge_device_check_in`, `edge_lease_revoked`,
`edge_device_revoked` and the list reads. None carries a token, a credential
or key material ([AUDIT_EVENTS_2026-09.md](AUDIT_EVENTS_2026-09.md)).

## Until 13.52.0-beta

Edge agents, leases and receipts were a preview in keycore
(`/enterprise/edge/agents`, `/leases`, `/receipts`) that stored records and
ran nothing. Those routes are gone; a new record of those categories is
refused (`410 feature_retired`) and old ones list as `retired`.
