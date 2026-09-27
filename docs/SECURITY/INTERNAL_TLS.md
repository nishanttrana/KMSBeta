# Every connection is TLS; internal connections are mTLS

**Standing rule** (owner directive, 2026-09-26; CLAUDE.md rule 10): nothing in
the KMS speaks plain HTTP or any other unencrypted protocol.

- **Internal traffic uses mTLS** with certificates from the internal Vecta
  CA. That covers service to service, Envoy to service, services to
  Postgres, NATS, Valkey and Consul, and health checks.
- **External traffic uses TLS**: the dashboard and API edge, KMIP, and
  outbound calls to clouds and webhooks. The external certificate can come
  from the internal CA or from an external CA, chosen in the PKI tab.

## Internal PKI

```
vecta-runtime-root           (root CA, ECDSA P-384; created at first start)
└── vecta-internal-services  (Sub CA; issues every internal certificate)
    ├── kms-keycore, kms-auth, kms-governance, ... (one per service)
    ├── envoy (client certificate to the services), postgres, nats, valkey, consul
    └── future internal features
```

- **Both CAs are created when the KMS is deployed** and appear in the CA
  hierarchy in the PKI tab.
- **Internal certificates come only from the Sub CA.** The root stays
  offline in day-to-day use, and the internal Sub CA can be rotated or
  revoked without touching anything else under the root.
- **Each service generates its own key and enrols with a CSR.** The request
  is authenticated by its platform service identity, and the issued
  certificate names that identity. The private key never leaves the
  service. A shared volume of keys was rejected: any compromised service
  could read every other service's key.
- **Only public material is shared.** The CA bundle goes to every service
  read-only.

## Mechanisms, including post-quantum

Each identity's mTLS is set in the dashboard (Certificates / PKI > Service
mTLS). There are two independent choices:

| Choice | Options |
|---|---|
| Certificate key | ECDSA P-256 (default), ECDSA P-384, RSA-3072 |
| Key exchange (server side) | **PQC required:** `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` only; **PQC preferred** (default): those, then P-256, P-384 (and X25519 with FIPS mode off); **Classical:** no ML-KEM |

- **The profile decides what a service's server accepts.** A peer that
  can't meet it is refused in the handshake; the tests show this with real
  handshakes.
- **Every platform client offers every group, and the profile only orders
  them.** No choice cuts a service off from its callers; a mismatch costs a
  HelloRetryRequest.
  - Envoy offers `X25519MLKEM768`, X25519, P-256 and P-384.
  - So a service behind the gateway can require PQC, but can't require a
    group Envoy doesn't offer. ML-KEM-1024 groups aren't offered as a
    profile for that reason.
- **With FIPS mode on** (`on` or `only`), Go's TLS refuses X25519 alone. It
  is dropped from every profile automatically.
- **Certificate signatures stay classical.**
  - The platform builds on the certified Go Cryptographic Module v1.0.0,
    which has no ML-DSA.
  - Go's TLS does support ML-DSA certificates from module v1.26.0. This
    document used to say Go's TLS couldn't; that was wrong about Go, right
    about this platform.
  - Post-quantum protection is the key exchange.
- **Envoy, the dashboard, Postgres, NATS, Valkey and Consul** have their
  certificate key chosen the same way. Certs writes their files, and their
  TLS groups are the daemon's own configuration.

## How a change reaches a service

1. **Publish.** Certs publishes the policy of every service identity in the
   public trust directory as `mtls-policy.json` (algorithms and
   generations, no secrets).
2. **Apply at start.** A service reads its entry before it enrols, so its
   key and groups are right from the first handshake.
3. **Watch.** The service re-reads its entry every 15 s. When the
   generation, key or profile changes, it restarts:
   - **Graceful:** SIGTERM; the service drains its requests and the
     container restart policy starts it again. This is the same path as a
     FIPS mode change.
   - **Forced:** an immediate exit.
4. **Re-enrol.** The new process generates a new key and enrols. The old
   key existed only in the old process's memory.
5. **Report.** Each instance writes what it actually runs to
   `platform_mtls_observed` every 30 s: serial, key, profile, generation,
   and the group and time of its last handshake.
   - The page shows those reports, not the request.
   - `audit.certs.internal_mtls_applied` is emitted once every instance
     runs the new generation.

## Status

### Done in slice 3 (1.16.0-beta)

**Certificates / PKI > Service mTLS** lists every internal identity:
- its policy, its active certificate from the Sub CA, and what each instance
  reports it runs;
- whether a change has been applied.

Per identity, with one click each:
- **Change** the certificate key and the key-exchange profile.
- **Rotate:** revoke the certificate, then a graceful restart.
- **Force restart:** revoke the certificate as `keyCompromise`, then an
  immediate exit.
- **Rotate every certificate:** services restart one every 20 s, certs
  last; this needs a typed confirmation.

Daemons don't restart: certs reissues their files, and they reload them
within 30 s. A forced restart is refused for them.

Every action and every refusal is audited:
- `audit.certs.internal_mtls_policy_updated`, `internal_mtls_rotated`,
  `internal_mtls_rotated_all` and `internal_mtls_inventory_read`;
- `internal_mtls_applied` once a change is running.

**Proven by:**
- `pkg/svctls`, with real TLS handshakes:
  - `TestPQCRequiredServerRefusesClassicalOnlyPeers`
  - `TestClassicalServerRefusesHybridOnlyPeers`
  - `TestPolicyKeyAlgorithmIsEnrolled`
  - `TestPolicyChangeTriggersRestart`
- `services/certs`, with the SQLite and real Postgres stores:
  - `TestMTLSRotateServiceRevokesAndPublishes`
  - `TestMTLSPolicyChangesAndRefusals`
  - `TestMTLSFileIdentityReissueSparesOtherCAs`
  - `TestMTLSAppliedOnlyWhenReportedAndAuditedOnce`
  - `TestMTLSRoutesRefusalsAudited`
  - `TestMTLSRoutesRootOnlyAndAudited`
  - `TestMTLSStorePostgres`

**Found and fixed along the way:**
- **Key sizes were ignored.** Key generation ignored the size in the
  algorithm name:
  - every RSA certificate got 2048 bits and every ECDSA certificate P-256;
  - every CA got RSA-3072 or P-384;
  - the records kept the requested name.

  Keys are now generated as named. On the primary, certs corrects existing
  records to the key their certificate carries
  (`audit.certs.certificate_key_label_corrected`), and it reissues the edge
  certificate at the RSA-3072 it was supposed to have.
- **PQC certificates removed (1.19.0-beta).** A "PQC" (ML-DSA)
  certificate issued without a CSR got an ECDSA key. On the owner's
  decision the feature is removed: such requests are refused, and existing
  records are relabelled to their real key (docs/DECISIONS.md).

### Done in slice 1 (1.8.0-beta)

**Services, Envoy and the dashboard use mTLS end to end.** Verified on the
running stack:
- plain HTTP to a service gets Go's TLS error and no data;
- TLS without a client certificate is refused with `certificate required`;
- a Sub CA client certificate negotiates TLS 1.3 with `X25519MLKEM768`,
  against a server certificate `kms-<service>` issued by
  `vecta-internal-services`;
- Envoy's upstream stats show TLS 1.3 and `X25519MLKEM768` to every
  service.

**How it is built:**
- `pkg/svctls` handles enrolment, renewal, the server and client
  configuration, and the client router.
- `platform.Boot` enrols automatically. Services with their own `main.go`
  call `svctls.Init` before serving.
- Certs starts in this order, because keycore can only be reached over mTLS:
  1. the internal PKI;
  2. its own certificate, signed locally;
  3. the enrolment listener;
  4. only then its master key from keycore.

### Done in slice 2 (1.9.0-beta)

**Postgres, NATS, Valkey and Consul require TLS 1.3 and a client
certificate from the internal CA**, plus their password or token. Verified
from the host:
- plaintext, and TLS without a client certificate, are refused on all four;
- a Sub CA client certificate works;
- `pg_stat_ssl` shows every service connection on TLS 1.3 with its own
  certificate.

**How the daemons are wired:**
- They get Sub CA server certificates from the certs service, installed by
  `infra/tls/tls-entry.sh`, which also reloads them on renewal.
- The certs service issues them before it connects to the database, from
  its sealed internal-PKI cache (`internal_bootstrap.go`).
- **Residual:** Postgres and Valkey verify clients with OpenSSL, which needs
  the chain up to the root. A certificate issued directly by
  `vecta-runtime-root` with client auth would also pass their TLS check;
  the password is still required. NATS and Consul (Go) trust only the Sub
  CA.

### Still open
- **Cluster members** apply the replicated policy, but only the primary
  audits "applied", from its own node's reports.
- **Cluster replication** between nodes (clustering profile) still builds
  its subscription connection strings without client certificates. That is
  next when clustering is enabled.
- **Internal verifiers don't check revocation.** Short lifetimes (7 days)
  are the control. A rotation revokes the old certificate and restarts the
  service, which removes the old key. Until the restart completes, peers
  still accept the old certificate.
- **The edge certificate** still comes from `vecta-runtime-root`, chosen in
  code, and port 80 still answers with a redirect. That's slice 4.

## Delivery plan

1. **Slice 1:** the internal Sub CA, CSR enrolment, and one shared
   server/client TLS package. Every service listener and client, Envoy's
   upstreams and the health checks move to mTLS. No `http://` remains
   between services.
2. **Slice 2:** TLS to Postgres (`verify-full`), NATS and Valkey (mTLS),
   and Consul (HTTPS).
3. **Slice 3:** the service TLS page: inventory, one-click rotation,
   per-service algorithm and PQC selection, and graceful or forced restart.
4. **Slice 4:** choose the edge certificate in the PKI tab (internal or
   external CA), and remove the port-80 listener.

Each slice ships with tests against the real dependencies: a real TLS
handshake with a wrong or missing client certificate refused, Postgres over
TLS, and the NATS TLS client. It also emits audit events for every action
and refusal, and runs in all three FIPS modes.
