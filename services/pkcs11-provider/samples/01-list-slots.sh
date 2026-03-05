#!/usr/bin/env bash
# List available slots using pkcs11-tool.
# Requires: opensc (pkcs11-tool), libvecta-pkcs11.so

export VECTA_BASE_URL="${VECTA_BASE_URL:-https://localhost/svc/ekm}"
export VECTA_TENANT_ID="${VECTA_TENANT_ID:-root}"
export VECTA_AUTH_TOKEN="${VECTA_AUTH_TOKEN:-your-token}"

MODULE="${PKCS11_MODULE:-./libvecta-pkcs11.so}"

echo "==> Listing slots..."
pkcs11-tool --module "${MODULE}" --list-slots

echo ""
echo "==> Listing token info..."
pkcs11-tool --module "${MODULE}" --list-token-slots
