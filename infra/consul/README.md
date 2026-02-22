# Consul Service Mesh Bootstrap

`consul.hcl` enables Connect service mesh, DNS, and gRPC APIs.

Apply default mesh config entries for all KMS services:

```bash
CONSUL_HTTP_ADDR=http://127.0.0.1:8500 ./infra/consul/bootstrap-mesh.sh
```

The script writes:

- `service-defaults` for each service (`Protocol=grpc`, `MutualTLSMode=strict`)
- `service-intentions` with baseline allow rules (`* -> service`)
