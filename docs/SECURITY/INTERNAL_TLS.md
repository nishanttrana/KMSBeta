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

Each service's mTLS has two independent choices, set per service in the
dashboard with one click:

| Choice | Options |
|---|---|
| Certificate key | ECDSA P-256, ECDSA P-384, RSA-3072 |
| Key exchange (TLS 1.3 group) | **PQC hybrids:** `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`; classical: P-256, P-384, X25519 |

- **Post-quantum protection applies to key exchange.** Go's TLS stack (the
  certified module) negotiates the hybrid ML-KEM groups above, which protect
  recorded traffic against a future quantum attacker.
- **Certificate signatures stay classical.** Go's TLS can't use ML-DSA
  certificates yet, and the UI says so instead of offering it.
- **In FIPS `only` mode**, the choices shown are the ones the Go runtime
  accepts in that mode.

## Rotation

- **One click per service, or for all of them:**
  1. The Sub CA issues the new certificate through a fresh CSR.
  2. The old certificate is revoked, and its key is deleted from the
     service.
  3. The service swaps to the new one.
- **Graceful swap (default):** the service stops accepting new connections,
  finishes the requests in flight, and re-executes with the new certificate.
  This reuses the staggered self-restart the FIPS mode change already uses.
- **Force restart:** for when a key is suspected compromised.
- **Every rotation, algorithm change, restart and refusal is audited.**
- **The service TLS page shows each service's real state:** certificate
  serial, issuer, key algorithm, negotiated group, expiry, and the last
  successful mTLS handshake.

## Status

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

### Still open

- **Postgres** runs `sslmode=disable`. **NATS, Valkey and Consul** are
  plaintext. That's slice 2.
- **`infra/consul/bootstrap-mesh.sh`** writes Consul Connect allow-all
  intentions that no service uses, and its PUT fails with 405. It's handled
  in slice 2.
- **Internal verifiers don't check revocation.** Short lifetimes (7 days)
  are the control, and a rotation in slice 3 revokes the old certificate
  and swaps the new one immediately.
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
