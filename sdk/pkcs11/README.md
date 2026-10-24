# Vecta KMS PKCS#11 module

A PKCS#11 v2.40 library over the KMS's REST API, in C, linked only against
libcurl. Applications sign, verify, encrypt and decrypt with the KMS keys a
REST client may use; key material never leaves the KMS.

```sh
make            # build/libvecta-pkcs11.so (.dylib on macOS)
make check      # unit tests under AddressSanitizer and UBSan
```

Configuration, mechanisms, behaviour and tests: [docs/PKCS11.md](../../docs/PKCS11.md).
`include/` holds the OASIS PKCS#11 v2.40 headers, unchanged.
