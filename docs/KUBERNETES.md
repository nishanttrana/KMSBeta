# Vecta KMS on Kubernetes (Helm)

`deploy/helm/vecta-kms` installs **one KMS node per release**: the same
containers `docker-compose.yml` runs on one host, in one pod. Several nodes
form a cluster through Platform → Cluster, exactly as Docker installs do
([CLUSTERING.md](CLUSTERING.md)).

```bash
helm install kms deploy/helm/vecta-kms -n vecta --create-namespace \
  --set image.registry=registry.example.com/ --set image.tag=13.38.0-beta
kubectl -n vecta port-forward svc/kms-vecta-kms 8443:443   # then https://localhost:8443
```

Sign in as `admin` with `changeit`; the console makes you change it at once.

## Why one pod per node

- **The services share files.** certs writes the trust bundle, each
  daemon's TLS files and the edge certificates; governance writes the
  platform state; about thirty services read them. In a pod they share
  volumes the way they do on one Docker host.
- **The runtime TLS keys stay in memory.** Compose keeps the edge and KMIP
  private keys on tmpfs; the chart keeps them in a memory `emptyDir`, which
  only containers of one pod can share.
- **The product clusters between nodes, not between service replicas.**
  Each node has its own Postgres; nodes replicate by Postgres logical
  replication and fail over by election (CLUSTERING.md). Scaling a
  service's replicas inside a node is not a supported topology on Docker
  either.

Compose service names (`auth`, `postgres`, ...) resolve to the pod itself
(`hostAliases`), so every internal URL and certificate name is unchanged and
every internal connection keeps its mTLS. Two compose services listen on one
port (Envoy's KMIP edge and kmip, both 5696); in the pod kmip listens on
25696 and Envoy and certs are pointed there.

## Start order

1. `prepare` (init container, root): lays out the node volume as
   `infra/scripts/compose-volumes.sh` does (each writer owns its directory),
   installs auth's token signing key from the release Secret, and makes the
   certs root wrapping key passphrase (`infra/scripts/crwk-passphrase.sh`).
2. certs, Postgres, NATS, Valkey and Consul as native sidecars, in that
   order (Kubernetes 1.29 or later). The services start once Postgres
   answers, as compose's `depends_on: service_healthy` does.
3. Every service of the enabled features.

## Values

| Value | Meaning |
|---|---|
| `image.registry`, `image.tag` | Vecta images are `<registry>vecta/<service>:<tag>` (tag defaults to the chart's appVersion) |
| `images.<service>` | Another image for a service (`postgres`, `envoy`, ...); `images.prepare` for the prepare step |
| `deployment.features`, `deployment.hsm_mode`, `deployment.cert_security` | As in `infra/deployment/deployment.yaml`; each feature is the compose profile of its services |
| `fipsMode` | `on`, `only` or `off` at first start (docs/SECURITY/FIPS.md) |
| `existingSecret` | Use your Secret (keys below) instead of generated ones |
| `persistence.size`, `.storageClass` | The node volume |
| `service.type` | The edge Service (443 HTTPS, 5696 KMIP) |
| `env`, `serviceEnv.<service>` | Extra environment |

**Secrets.** Unless `existingSecret` is set, the chart generates
`POSTGRES_PASSWORD`, `NATS_AUTH_TOKEN`, `VALKEY_PASSWORD`,
`WORKLOAD_IDENTITY_SHARED_SECRET`, `INTERNAL_API_TOKEN`,
`INTERNAL_SERVICE_BOOTSTRAP_SECRET`, `AUTH_BOOTSTRAP_CLI_PASSWORD`, auth's
RSA signing key (`jwt_private.pem`) and `JWT_PUBLIC_KEY_B64`, once. An
upgrade reads them back; uninstall keeps the Secret
(`helm.sh/resource-policy: keep`), because the node's data is sealed under
them. `JWT_PUBLIC_KEY_B64` is a self-signed certificate for the signing key:
Helm can make one from a key but cannot write out a bare public key, and
the services accept either (`pkg/jwtauth`).

## Kept in step with compose

`files/stack.json` and `files/infra/` are generated from
`docker-compose.yml` by `scripts/helm-chart.sh` (resolved with placeholder
secrets, so no value reaches the chart). CI fails if they are stale
(`scripts/helm-chart.sh --check`), lints the chart and validates the
rendered manifests against the Kubernetes 1.31 schema. The generator
refuses what it can't carry: two services on one port, a writable volume
whose owner it doesn't know, a mount type it doesn't map.

`scripts/test-helm-kind.sh` installs the chart on a throwaway kind cluster
with locally built images, waits for every container to be ready, signs in
through the edge with TLS verified against the node's own CA, upgrades, and
checks the generated secrets survive. It needs Docker and builds nothing;
run it after `deploy-local.sh` (or any build of the images).

## Clustering on Kubernetes

Each release is a node. For members to reach a primary, expose the
primary's cluster-manager (8210) and Postgres (5432) to the other nodes
(a Service of your choice), and set on every promotable node, through
`serviceEnv.cluster-manager`: `CLUSTER_ADVERTISE_URL`,
`CLUSTER_HTTP_TLS_ENABLE` with its certificate, `CLUSTER_PG_ADVERTISE_HOST`
and `CLUSTER_PG_ADVERTISE_PORT`. Postgres accepts the members' replication
roles (`vecta_repl_*`) over TLS from any address; every other remote
connection still needs the internal CA's client certificate.

## Not done

- **Per-service horizontal scaling** inside a node.
- **An external Postgres** (managed database): the chart runs the node's
  own, as compose does.
- **Cluster exposure is manual**: the chart does not create the Services
  that let nodes reach each other, nor mount a cluster-manager TLS
  certificate from values (`CLUSTER_HTTP_TLS_*` point at files).
