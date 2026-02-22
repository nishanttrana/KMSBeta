# Runtime Certificate Output (Sensitive)

`infra/certs/out` is a local runtime output directory for generated mTLS materials.

Security rules:

1. Do not commit this directory contents (private keys, CA keys, cert chains).
2. Keep key files with restrictive permissions (`0600`).
3. Prefer setting `VECTA_CERTS_OUT` to an external secured path (for example `/var/lib/vecta-kms/certs`) so key material is outside the source tree.
4. Rotate CA and leaf certificates if this directory was ever exposed.

