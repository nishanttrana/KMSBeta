# KMS Clustering and High Availability

Platform → Cluster. A second KMS instance joins an existing one. The primary
chooses which features (components) the new member serves, and only the data
of those features is replicated to it. Customers can then use any node for
crypto operations and reads. Key and policy lifecycle writes go to the
primary. If a node fails, the others keep serving.

## Status: what works today and what doesn't

This document is the truth for the release it ships in. The UI and API report
only what the database actually does.

| Capability | Status |
|---|---|
| Table classification (replicated per component / node-local / shared-append) | **Done.** `pkg/clustercatalog`, with every table enforced by test |
| Postgres logical replication engine: per-component publications, member subscriptions, reset of member bootstrap data, real per-table sync state and lag | **Done.** `pkg/clusterrepl`, proven between two real Postgres servers (`scripts/test-cluster-replication.sh`) |
| Publications maintained on every node | **Done.** cluster-manager refreshes them every minute |
| Honest status in API and UI | **Done.** `GET /cluster/replication/status` and the Cluster tab show real subscriptions, per-table state and lag |
| Secure join: join bundle, TLS pinning, one-time token, master key sealed keycore-to-keycore (ML-KEM-768), per-member replication role, sealed replication credentials, subscriptions | **Done** (slice 2). Proven end to end with two real Postgres servers (`TestSecureJoinEndToEnd`) |
| Node-local logins and service identities never replicate (row filters on `auth_users`, `auth_client_registrations`, `auth_api_keys`) | **Done** (slice 2) |
| cluster-manager authentication: root administrator or service identity on every admin route | **Done** (slice 2; it previously had none) |
| Certs root wrapping key and audit signing key transfer | Not yet: until then, CA signing and OCSP run on the primary, via forwarding |
| Write forwarding from members to the primary | **Done** (slice 3a). Every service forwards by construction. Proven end to end on real Postgres and TLS (`TestSecureJoinEndToEnd`, `TestClusterForwarding`) |
| Members never write replicated tables: node-local operation counters, primary-only background jobs, dataprotect working-key state | **Done** (slice 3a) |
| Failover: manual promotion, and a majority vote at 3+ nodes, with fencing | Slice 4, not yet |
| Audit chains replicated from every node (shared-append) | Slice 3/4, not yet |
| Helm chart | Slice 5, not yet |

A second node can join through the UI (Platform → Cluster → Add Instance).
Any node serves crypto operations, reads and logins, and a lifecycle write
sent to a member is forwarded to the primary. Still open: if the primary is
down, lifecycle writes fail with `502 primary_unreachable` until failover
(slice 4). Crypto operations keep working. The
earlier overview text ("Nodes sync only the state for their enabled
components…") described a design that was never implemented: sync events were
recorded but never applied on another node. It was removed on 2026-09-25.

## Design (decided 2026-09-25)

- **One lifecycle writer.** The primary is the only node that performs key and
  policy lifecycle writes (create, rotate, destroy, policy changes). Members
  forward those writes to it transparently (slice 3). Crypto operations
  (encrypt, decrypt, sign, verify) and reads run locally on every node. This
  avoids split-brain on key state.
- **Failover.** An administrator can promote a member in Platform → Cluster at
  any cluster size. With 3 or more nodes, a majority vote promotes
  automatically and fences the old primary. Crypto operations keep working on
  members during a primary outage.
- **Replication:** Postgres 17 logical replication, one publication per
  component (`vecta_pub_<component>`), `publish_via_partition_root` for the
  partitioned `keys` and `audit_events`. A member creates one subscription per
  assigned component (`vecta_sub_<node>_<component>`). The initial copy, and
  streaming after it, are Postgres's own.
- **Selective sync.** Core components (auth, keycore, policy, governance) go
  to every member. Anything else goes only when the primary assigns it
  (cluster profiles: base, standard, security, full, or custom).
- **Node-local data never replicates.** 50 tables, each with a reason in
  `pkg/clustercatalog/tables.go`:
  - sessions and anti-replay nonces;
  - logs and metrics written during crypto operations;
  - the node's network, FDE, HSM and SNMP settings, TLS listeners and FIPS
    observations;
  - backups;
  - the cluster control plane itself.

  Node-specific logins (the local admin and CLI accounts) are excluded by row
  in slice 2.
- **Audit** is written on every node. Its chain tables are `shared-append`:
  each node keeps its own chain, and they'll be replicated in both directions
  (they're insert-only, so they can't conflict).

### What slice 2 must carry across (join handshake)

Replicated key material is encrypted under the primary's keycore master key,
so a member can't use it without that key. The join transfers a sealed bundle
over node-to-node mTLS:
- the master key, wrapped to a key the joining node generates for the join;
- the audit signing key;
- the certs root wrapping key;
- the JWT trust between nodes;
- the replication credentials.

The transfer is audited on both nodes.

## Joining a node (slice 2)

**Before you start:**
1. **Primary configuration:**
   - `CLUSTER_ADVERTISE_URL` (its cluster-manager URL as members reach it, https);
   - `CLUSTER_HTTP_TLS_ENABLE=true` with a certificate;
   - `CLUSTER_PG_ADVERTISE_HOST` / `_PORT` (its Postgres as members reach it);
   - Postgres TLS enabled. `CLUSTER_PG_SSLMODE` defaults to `verify-full`;
     `disable` is only for a lab.
2. **Network:** members reach the primary on the cluster-manager port (TLS)
   and the Postgres port.
3. **Client certificates:** cluster-manager requires client certificates by
   default (`CLUSTER_HTTP_REQUIRE_CLIENT_CERT=true`). Either issue the new
   node a client certificate from `CLUSTER_HTTP_TLS_CLIENT_CA_FILE` first, or
   turn that off for the join. The join itself is protected by the one-time
   token and the certificate pin.

**Steps:**
1. **On the primary**, a root admin opens Platform → Cluster → Add Instance →
   "On this primary: add a node". They enter the new node's ID, choose the
   features (replication profile) and create a **join bundle** (one-time,
   30 minutes). The bundle holds the primary's URL, its TLS certificate
   fingerprint, the token ID and the secret.
2. **On the new node** (a fresh install), a root admin opens Add Instance →
   "On a new node: join a cluster", pastes the bundle and confirms. Joining
   replaces this node's master key, and its data for the assigned features,
   with the primary's. Its local admin/CLI accounts are kept.
3. **What happens:**
   - the member's keycore creates a one-time ML-KEM-768 join key;
   - the member calls `POST /cluster/join/exchange` over TLS pinned to the
     bundle's fingerprint;
   - the primary consumes the token, registers the node, and creates a
     replication role limited to the member's components (`BYPASSRLS`,
     because the auth tables use row-level security);
   - the primary's keycore seals its master key to the member's keycore;
   - the primary seals the replication credentials to the member's
     cluster-manager;
   - the member's keycore installs the master key and restarts on it;
   - the member subscribes to each component, resetting only replicated rows.
4. **Watch progress** in the Cluster tab (real per-table sync state and lag).

Plaintext secrets never cross the network, and every step is audited (see
`docs/SECURITY/AUDIT_EVENTS_2026-09.md`).

## Write forwarding (slice 3a)

```
client ──▶ member service (pkg/config wrapper)
             │ verify token locally; strip client cluster headers
             │ Decide(service, method, path): local | forward | refuse
             ▼
           primary cluster-manager  POST /cluster/forward/{svc}/{path}
             │ member credential (hash, constant time), pinned TLS
             │ auth /auth/cluster/mint → 5-minute primary-signed token
             ▼
           primary service (its own authz, validation and audit)
```

- **Forward by default.** `pkg/clusterroute.Local` lists the few writes that
  run on a member. Each one writes only node-local tables.
  `TestLocalRoutesExist` checks that every entry is a real route. A new write
  endpoint is forwarded unless someone adds it there, so it can't silently
  diverge a member.
- **Why mint on the primary:** JWT verification keys differ per node and
  per service. The member proves who the caller is, the primary re-issues an
  equivalent token its own services trust, and the member credential proves
  which member is asking. Tokens carry `fwd_node` for the audit trail.
- **Node state:** cluster-manager writes the node-local `cluster_local_state`
  on join. Services read it through `pkg/clusterstate` (10-second cache).
- **Removal revokes forwarding:** `RemoveNode` revokes the member's
  credential before deleting it. Proven by `TestSecureJoinEndToEnd`.

### What a member must never write

A member's write to a replicated table either diverges from the primary, or
clashes with the primary's row. With `REPLICA IDENTITY FULL` a later update is
then skipped, and a duplicate insert stops the component's replication
entirely. So:

- **Crypto counters:** keycore counts a member's operations in the node-local
  `key_op_counters`, and the key's ops limit still applies against the sum.
- **Background jobs** that write replicated state run only where
  `clusterstate.RunsPrimaryJobs(ctx)` is true: compliance, reporting,
  posture and SBOM schedules, certs expiry sweep, CA signer rewrap and mesh
  discovery, governance approval expiry, and the dataprotect receipt
  reconciler. Keycore's zeroization check still runs everywhere, because it
  verifies each node's own copy and only emits audit.
- **dataprotect working-key state:** a member computes a key's initial
  derivation state from replicated inputs without recording it, and records
  legacy (v1) use only in the audit event.
- `fle_metadata` is node-local (written during `/app/encrypt-fields`).

Still open (slice 3b): the event-driven consumers that write replicated
tables from a node's own audit stream (reporting alerts, compliance
triggers). They need member audit to reach the primary, which is the
shared-append audit replication.

Also open: the login lockout counter is per node (in memory), so an
attacker spreading password guesses across N nodes gets N times the
configured attempts before lockout. Per-node rate limits still apply.

## Rules for development

- **Every new table is classified.** Add it to `Replicated[<component>]`,
  `NodeLocal` (with a reason) or `SharedAppend` in
  `pkg/clustercatalog/tables.go`. `TestEveryTableIsClassified` fails the build
  otherwise.
- **A table written during crypto operations is node-local.** Otherwise a
  member's write would diverge from the primary's copy.
- **A background job that writes replicated state checks
  `clusterstate.RunsPrimaryJobs(ctx)`** each time it runs.
- **Add a write to `clusterroute.Local` only if it writes nothing
  replicated** on a member. Otherwise leave it forwarded.
- **Don't claim replication in docs or UI text** unless the status comes from
  `clusterrepl`.
- **cluster-manager routes require a root administrator or a service
  identity** (`services/cluster-manager/auth.go`). A node-to-node route must
  authenticate itself (join token, HMAC signature) and be listed in
  `publicClusterRoutes`.

## Operating notes

- Postgres runs with `wal_level=logical`, `max_replication_slots=64`,
  `max_wal_senders=64`, `max_worker_processes=96`,
  `max_logical_replication_workers=64` and
  `max_sync_workers_per_subscription=4` (compose). A member runs one apply
  worker per component (up to 26) plus table-copy workers. With Postgres's
  default of 4 logical workers, every component but one stays stuck in its
  initial copy; the join test found this. Changing these settings needs a
  Postgres restart.
- To run the two-node test: `./scripts/test-cluster-replication.sh` (Docker
  required). CI runs it too (`cluster-replication` job).
