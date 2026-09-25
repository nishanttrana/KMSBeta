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
| Secure join handshake (node-to-node mTLS, cluster secrets transfer) | Slice 2, not yet |
| Write forwarding from members to the primary | Slice 3, not yet |
| Failover: manual promotion, and a majority vote at 3+ nodes, with fencing | Slice 4, not yet |
| Audit chains replicated from every node (shared-append) | Slice 3/4, not yet |
| Helm chart | Slice 5, not yet |

Until slices 2–4 land, a second node cannot be joined through the UI. The
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

## Rules for development

- **Every new table is classified.** Add it to `Replicated[<component>]`,
  `NodeLocal` (with a reason) or `SharedAppend` in
  `pkg/clustercatalog/tables.go`. `TestEveryTableIsClassified` fails the build
  otherwise.
- **A table written during crypto operations is node-local.** Otherwise a
  member's write would diverge from the primary's copy.
- **Don't claim replication in docs or UI text** unless the status comes from
  `clusterrepl`.

## Operating notes

- Postgres runs with `wal_level=logical`, `max_replication_slots=64` and
  `max_wal_senders=64` (compose). Changing `wal_level` needs a Postgres restart.
- To run the two-node test: `./scripts/test-cluster-replication.sh` (Docker
  required). CI runs it too (`cluster-replication` job).
