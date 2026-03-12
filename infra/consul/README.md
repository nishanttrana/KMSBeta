# Consul Service Mesh Bootstrap

`consul.hcl` enables Connect service mesh, DNS, and gRPC APIs.

The edge proxy now runs Envoy 1.37.1 via the static config in
`infra/envoy/envoy.yaml`. That works independently of Consul Connect, but
Consul 1.21.x does not list Envoy 1.37.x as a supported Connect sidecar
version. Keep using the static edge proxy unless Consul is moved to a release
line that supports Envoy 1.37.x for mesh use.

Apply default mesh config entries for all KMS services:

```bash
CONSUL_HTTP_ADDR=http://127.0.0.1:8500 ./infra/consul/bootstrap-mesh.sh
```

The script writes:

- `service-defaults` for each service (`Protocol=grpc`, `MutualTLSMode=strict`)
- `service-intentions` with baseline allow rules (`* -> service`)
