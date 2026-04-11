#!/usr/bin/env bash
# Build vecta-pkcs11-encrypt.jar from VectaPKCS11Encrypt.java
# Requires Java 11+.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Compiling VectaPKCS11Encrypt.java..."
javac -source 11 -target 11 VectaPKCS11Encrypt.java

echo "Packaging vecta-pkcs11-encrypt.jar..."
jar cfe vecta-pkcs11-encrypt.jar VectaPKCS11Encrypt VectaPKCS11Encrypt.class

echo ""
echo "Built: $SCRIPT_DIR/vecta-pkcs11-encrypt.jar"
echo ""
echo "Usage examples:"
echo "  # Generate key on token:"
echo "  java -jar vecta-pkcs11-encrypt.jar keygen \\"
echo "    --module /usr/lib/libvecta-pkcs11.so --slot 0 \\"
echo "    --pin-env PKCS11_PIN --key-label vecta-aes256-01"
echo ""
echo "  # Encrypt:"
echo "  java -jar vecta-pkcs11-encrypt.jar encrypt \\"
echo "    --module /usr/lib/libvecta-pkcs11.so --slot 0 \\"
echo "    --pin-env PKCS11_PIN --key-label vecta-aes256-01 \\"
echo "    --input plaintext.bin --output ciphertext.enc"
echo ""
echo "  # Decrypt:"
echo "  java -jar vecta-pkcs11-encrypt.jar decrypt \\"
echo "    --module /usr/lib/libvecta-pkcs11.so --slot 0 \\"
echo "    --pin-env PKCS11_PIN --key-label vecta-aes256-01 \\"
echo "    --input ciphertext.enc --output decrypted.bin"
