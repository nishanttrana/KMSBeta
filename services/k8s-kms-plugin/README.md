# Vecta Kubernetes KMS v2 plugin

Encrypts a cluster's Secrets at rest with a Vecta AES-256 key through
keycore. Setup, configuration and behaviour: [docs/KUBERNETES_KMS.md](../../docs/KUBERNETES_KMS.md).

```bash
docker build -f services/k8s-kms-plugin/Dockerfile -t vecta/k8s-kms-plugin:<version> .
vecta-k8s-kms-plugin -config /etc/vecta-kms/k8s-kms-plugin.json
```

The API key is read from `api_key_file`; it never appears in the config or
on a command line.
