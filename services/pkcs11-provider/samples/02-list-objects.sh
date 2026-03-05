#!/usr/bin/env bash
# List all key objects from KMS via PKCS#11.

export VECTA_BASE_URL="${VECTA_BASE_URL:-https://localhost/svc/ekm}"
export VECTA_TENANT_ID="${VECTA_TENANT_ID:-root}"
export VECTA_AUTH_TOKEN="${VECTA_AUTH_TOKEN:-your-token}"

MODULE="${PKCS11_MODULE:-./libvecta-pkcs11.so}"

echo "==> Listing objects..."
pkcs11-tool --module "${MODULE}" --list-objects --type privkey
