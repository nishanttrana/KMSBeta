#!/usr/bin/env bash
# Encrypt and decrypt using the PKCS#11 provider.

export VECTA_BASE_URL="${VECTA_BASE_URL:-https://localhost/svc/ekm}"
export VECTA_TENANT_ID="${VECTA_TENANT_ID:-root}"
export VECTA_AUTH_TOKEN="${VECTA_AUTH_TOKEN:-your-token}"

MODULE="${PKCS11_MODULE:-./libvecta-pkcs11.so}"

echo "Hello, Vecta PKCS#11!" > /tmp/plaintext.bin

echo "==> Encrypting..."
pkcs11-tool --module "${MODULE}" --encrypt --mechanism AES-GCM \
  --id 01 --input-file /tmp/plaintext.bin --output-file /tmp/ciphertext.bin

echo "==> Decrypting..."
pkcs11-tool --module "${MODULE}" --decrypt --mechanism AES-GCM \
  --id 01 --input-file /tmp/ciphertext.bin --output-file /tmp/decrypted.bin

echo "==> Result:"
cat /tmp/decrypted.bin

rm -f /tmp/plaintext.bin /tmp/ciphertext.bin /tmp/decrypted.bin
