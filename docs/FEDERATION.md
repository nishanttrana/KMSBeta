# Key federation across installations

Key federation (13.60.0-beta) replicates keys from one Vecta KMS
installation to another: a second region, a disaster-recovery site, or an
independent cluster with its own database and master key. The replica
serves every key operation, so data encrypted at one site decrypts at the
other. If the first site is lost, promote the replica: that site becomes
the key's primary.

This is different from [clustering](CLUSTERING.md). A cluster is one
installation: its nodes share a database through replication and fail over
automatically. Federation links installations that share nothing: each has
its own database, master key, users and grants. Keys move between them
only as you choose, one key at a time, and failover is a decision you make.

## How it works

- **Identity.** Each tenant has a federation identity: an ML-KEM-768 key, to
  which other installations seal key material, and an ECDSA P-256 key that
  signs everything the tenant sends. Its private halves are sealed under
  keycore's master key. The identity's **fingerprint** is a SHA-256 of both
  public keys.
- **Peers.** A peer is another installation's identity, its address (its
  edge, `https://`), the tenant there, and a REST client there that may
  deliver keys. Each side registers the other.
- **Links.** A link replicates one key to one peer:
  - every version's material is sealed to the peer's ML-KEM key, bound to
    tenant, key, version and recipient;
  - the bundle is signed by this installation and pushed over TLS 1.3, as
    the peer's REST client;
  - the peer checks the signature against the identity it registered, opens
    each version, and checks it against its KCV;
  - it stores the material under its own master key, or under its tenant
    HSM key when the tenant has one.
- **The replica.** The replica has the same key ID, version numbers and
  KCVs, so ciphertext, signatures and the SDKs work unchanged at either
  site. It serves encrypt, decrypt, sign, verify and the rest.
  - **Lifecycle changes are the primary's.** Rotation, metadata, status and
    destruction answer `409 federated_replica` at the replica. They arrive
    with the next push.
  - **Grants stay local.** Each installation grants its own users and
    clients.
- **Sync.** Keycore pushes a link again within a minute of its key changing
  (a rotation, a status or metadata change), and every link once an hour.
  - **Verification.** On every push the peer reports the versions and KCVs
    it holds, and the link is `in_sync` only if they match.
  - **On demand.** **Sync now** in the dashboard (or
    `POST /federation/links/{id}/sync`) pushes at once.

### What can be replicated

A key can be replicated when:
- its `export_allowed` is set (replication moves its material out of this
  installation);
- it isn't deleted;
- its material isn't inside an HSM (an HSM doesn't release it; replicate
  HSM to HSM with the vendor's tools).

Versions destroyed at the source travel as status only: their material is
gone everywhere.

## Failover

1. **Promote the replica** at the surviving site: Keys → Federation → *A
   key's role here* → **Promote here**, or `POST
   /federation/keys/{id}/promote` with a reason. The key becomes the primary
   there at the next **epoch**, and can be rotated and changed.
2. **Point applications at the surviving site.** Typically that is DNS or
   the load balancer in front of the edges; otherwise, the application's
   KMS address. Its key IDs and ciphertext are unchanged. Each
   installation has its own REST clients, so the application needs a
   client there.
3. **When the old site comes back**, it still thinks it is the primary.
   Its next push is refused with a signed statement from the new primary:
   `primary_here`, at a higher epoch. The old site then **demotes** its
   copy. A demoted key keeps serving operations and refuses changes; its
   link reads `superseded`.
4. **Fail back:** replicate the key from the new primary to the old site
   (a link in the other direction). The old site's demoted key becomes a
   replica, with every version made during the failover. To move the
   primary home again, promote it there.

### Split brain

If both sites change a key while they can't reach each other, they hold
different material under the same version number. A push never replaces or
removes a version that differs. It is refused with `version_conflict`, and
the link reads `conflict`. Data encrypted under either version stays
readable where it was written.

To resolve it, re-encrypt what each side wrote (`POST /keys/{id}/rewrap`
moves ciphertext to the current version), retire the conflicting key, and
replicate a new one. Material is never lost to a split brain.

### Fencing rules

- Only a primary pushes. A replica or demoted key's link reads `superseded`.
- A push at a lower epoch than the receiver's is refused (`stale_epoch`). A
  push to a primary at the same or lower epoch gets the signed
  `primary_here` statement, the fence.
- A push at a higher epoch is accepted by a replica or by a former primary
  (which becomes a replica), provided every version it holds is in the push
  with the same KCV.
- Pushes apply in order: an older or replayed bundle is refused
  (`stale_bundle`). A bundle more than 10 minutes from the receiver's clock
  is refused, so keep both sites on NTP.
- A key that exists at the receiver and isn't federated is never overwritten
  (`key_exists`).

## Set up

On **each** installation, for the tenant:

1. **Create a REST client** that may deliver keys: a role with
   `key.federation.receive` and nothing else
   ([CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md#1-give-the-pipeline-its-own-identity)).
   Keep its API key for the other side.
2. **Copy the identity:** Keys → Federation → **Copy identity**, or
   `GET /federation/identity`. Send it to the other site's administrator,
   and confirm the fingerprint with them by another channel (a call).
3. **Add the other site as a peer:** **Add peer**, with:
   - its name;
   - its address, `https://<its edge>`;
   - its pasted identity;
   - the REST client and API key from its step 1;
   - its CA PEM, when its certificate comes from its own CA.

   Or `POST /federation/peers`.

Then, on the site that holds the key, **Replicate** it to the peer
(`POST /federation/links`). The first push happens at once, and the link
shows `in_sync`.

## Permissions

| Permission | Allows |
|---|---|
| `key.federation.read` | the identity, peers, links, a key's federation state |
| `key.federation.write` | adding and removing peers and links, syncing, promoting |
| `key.federation.receive` | delivering keys (the other installation's REST client only) |

## API

All routes are under `/svc/keycore`, with `tenant_id`:

| Route | |
|---|---|
| `GET /federation/identity` | `identity`: `tenant_id`, `fingerprint`, `kem_public`, `sign_public_pem`. Created on first use |
| `GET /federation/peers`, `POST /federation/peers`, `DELETE /federation/peers/{id}` | `name`, `url`, `peer_tenant_id` (default: the identity's), `identity`, `ca_pem`, `client_id`, `api_key` (write-only, sealed). A peer with links can't be removed |
| `GET /federation/links`, `POST /federation/links` (`key_id`, `peer_id`), `POST /federation/links/{id}/sync`, `DELETE /federation/links/{id}` | a link's `status`: `pending`, `in_sync`, `mismatch`, `conflict`, `superseded`, `error`; `last_sync_at`, `last_error`. Removing a link stops replication; the replica stays at the peer |
| `GET /federation/keys/{id}` | `state` (`role`: `primary`, `replica`, `demoted`, or `none`; `epoch`, `source_peer_id`) and `versions` (`version`, `status`, `kcv`) |
| `POST /federation/keys/{id}/promote` | `reason` (at least 10 characters). A replica or demoted key becomes the primary at the next epoch |
| `POST /federation/receive` | the push; the other installation calls it |

Refusals are audited with their reason:
- `key_not_exportable`, `hsm_key_not_replicable`, `not_primary`;
- `bad_signature`, `unknown_peer`, `wrong_recipient`, `tenant_mismatch`;
- `stale_bundle`, `stale_epoch`, `primary_here`, `key_exists`,
  `version_conflict`, `kcv_mismatch`;
- `federated_replica`.

Events:
- `audit.key.federation_identity_created`;
- `audit.key.federation_synced` (a link's status changed);
- `audit.key.federation_demoted` (warning);
- the kernel events of every route above.

## Tests

- `TestFederationReplicatesAndFailsOver` covers two installations, each with
  its own database and master key, behind TLS edges: replicate, use at both
  sites, rotate and sync, promote, fence, demote, fail back.
- `TestFederationSplitBrainKeepsBothVersions` covers a split brain: the
  conflicting version is refused and nothing is lost.
- `TestFederationRefusesWhatItMustNotApply` covers forged, replayed,
  other-tenant and colliding pushes, and keys that can't be replicated.
- `TestFederationSyncLoopPushesChanges` covers the sync loop.
- `TestFederationStorePostgres` covers the storage on Postgres.
