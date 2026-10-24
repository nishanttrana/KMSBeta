# PKCS#11 module

`sdk/pkcs11` (13.59.0-beta) is a PKCS#11 v2.40 library: `libvecta-pkcs11.so`
on Linux, `.dylib` on macOS. Applications that speak PKCS#11 use Vecta KMS
keys through it, for example:

- OpenSSL's pkcs11 provider (TLS servers, `openssl dgst -sign`);
- Java's SunPKCS11;
- OpenSC's `pkcs11-tool`;
- signing tools (osslsigncode, cosign);
- Vault's PKCS#11 seal.

Key material never leaves the KMS. Every sign, verify, encrypt and decrypt is
a KMS call, audited there like any other.

The module is a REST client written in C. It links only libcurl. A Go
library can't be loaded into Go programs (Vault, cosign) and isn't safe
across `fork` (nginx, Apache, PostgreSQL); this one is both.

## What it offers

The module exposes one slot with one token, the tenant. Its objects are the
keys the REST client can see:

| KMS key | PKCS#11 objects |
|---|---|
| AES-128/192/256 (GCM) | a secret key (`CKK_AES`) |
| ECDSA P-256/P-384/P-521, purpose `sign` | a private key and a public key (`CKK_EC`) |
| RSA-2048/3072/4096, purpose `sign` | a private key and a public key (`CKK_RSA`) |

- **Labels and IDs.** `CKA_LABEL` is the key's name and `CKA_ID` its KMS ID.
- **Status.** An active key encrypts and signs. A deactivated key only
  decrypts and verifies. Other keys aren't shown.
- **Sensitive attributes.** `CKA_VALUE` and the private RSA components
  answer `CKR_ATTRIBUTE_SENSITIVE`.
- **Refreshing.** The object list is read again at login, and at a search
  more than 10 seconds after the last.

| Mechanism | Notes |
|---|---|
| `CKM_ECDSA_SHA256`, `_SHA384`, `_SHA512` | hashed in the module; the KMS signs the digest |
| `CKM_ECDSA` | the caller passes a SHA-256/384/512 digest |
| `CKM_SHA256_RSA_PKCS_PSS`, `SHA384`, `SHA512` | params: the same hash, `CKG_MGF1` with it, `sLen` = hash length |
| `CKM_RSA_PKCS_PSS` | the caller passes the digest; the params as above |
| `CKM_AES_GCM` | 96-bit IV, 128-bit tag, any AAD |

Signatures follow PKCS#11 conventions: ECDSA as `r || s`, RSA-PSS as the
modulus-length value. The KMS signs RSA with PSS only, so there's no
`CKM_RSA_PKCS`.

`C_GenerateRandom` reads the KMS's random source.

Some operations aren't offered, and answer `CKR_FUNCTION_NOT_SUPPORTED`:
- creating, changing, copying or destroying objects;
- generating, wrapping, unwrapping or deriving keys;
- digests.

Keys are made and managed in the KMS, with its policies, approvals and
audit.

## Build

```sh
# Debian/Ubuntu: apt-get install build-essential libcurl4-openssl-dev
make -C sdk/pkcs11          # build/libvecta-pkcs11.so
make -C sdk/pkcs11 check    # unit tests, AddressSanitizer and UBSan
```

The libcurl it links must be able to require TLS 1.3. Linux libcurl on
OpenSSL 3 can. macOS's own libcurl (SecureTransport) can't. On macOS, build
with Homebrew's curl (`PATH="$(brew --prefix curl)/bin:$PATH" make`). With
the system libcurl, every call fails and the log says
`this libcurl can't require TLS 1.3`. The module never connects below
TLS 1.3.

## Configure

The token signs in as a **REST client**, never as a person. Register one,
give it a role with the key permissions it needs, and grant it the keys
([CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md#1-give-the-pipeline-its-own-identity)).
The module needs a grant of `read` to see a key, and a grant of each
operation it performs on it: `sign`, `verify`, `encrypt`, `decrypt`.

Settings come from `/etc/vecta/pkcs11.conf`, or the file named by
`VECTA_PKCS11_CONF`, with environment variables over them:

```ini
url        = https://kms.example.com    # VECTA_URL
tenant_id  = acme                       # VECTA_TENANT_ID
client_id  = payments-signer            # VECTA_CLIENT_ID
ca_file    = /etc/vecta/kms-ca.pem      # VECTA_CA_FILE, when the KMS has its own CA
# token_label = acme                    # default: the tenant
# gcm_iv      = caller                  # or generated, below
# log_file    = /var/log/vecta-pkcs11.log  # VECTA_PKCS11_LOG
```

**The PIN is the credential.** With `client_id` set, the PIN is the client's
API key, exchanged for short-lived tokens and renewed by the module. Without
`client_id`, the PIN is a bearer token. Keep the PIN where the application
keeps a PIN (its own secret store), not in this file.

The log, when set, records refusals and failures with the KMS's request ID.
It never records a PIN, a token, or data.

## AES-GCM IVs

By default the caller supplies the IV, as PKCS#11 specifies. **Never reuse an
IV with the same key:** AES-GCM loses confidentiality and integrity when an
IV repeats.

Two cases refuse a caller's IV with `CKR_MECHANISM_PARAM_INVALID`:
- KMS FIPS strict mode, under SP 800-38D;
- HSM keys, which generate every IV inside the HSM.

For those, set `gcm_iv = generated`. The KMS then generates each IV and
the module writes it into the `pIv` buffer of the application's
`CK_GCM_PARAMS` after `C_Encrypt`, as several FIPS HSMs do. The
application must keep that buffer until the call returns, and store the IV
with the ciphertext.

Ciphertext keeps no key version, so the module decrypts with whichever
version of the key opens it (`any_version`). Data encrypted before a
rotation still decrypts.

## Behaviour

- **Login and logout.** One login serves every session of the process, as
  PKCS#11 specifies. Closing the last session logs out. A wrong PIN answers
  `CKR_PIN_INCORRECT`.
- **Errors.**
  - A KMS refusal (no grant, a policy, a binding policy) answers
    `CKR_KEY_FUNCTION_NOT_PERMITTED`.
  - A key the client no longer sees answers `CKR_KEY_HANDLE_INVALID`.
  - A KMS that can't be reached answers `CKR_DEVICE_ERROR`.
  - A change waiting for approval answers `CKR_FUNCTION_REJECTED`.
- **Threads.** Each thread uses its own session; calls run in parallel
  over shared connections.
- **Fork.** After `fork`, the child opens its own connections and never
  touches the parent's TLS sessions.
- **Rotation.** After a key rotates, signatures come from the new version,
  and its public key object follows within the 10-second refresh. A
  signature made by an older version doesn't verify under the current
  public key.
- **PKCS#11 3.0.** The module answers `C_GetInterface` and
  `C_GetInterfaceList` with its v2.40 function list.

## Tests

- **Unit tests.** `make check` covers SHA-2 (FIPS 180-4 vectors), base64,
  the JSON reader, the public-key DER reader and ECDSA signature
  conversion. Each parser also gets 50,000 mutated inputs, under
  AddressSanitizer and UBSan.
- **Contract test.** `TestPKCS11AgainstKeycore` (`services/keycore`)
  builds the module with sanitizers and runs `test/p11check.c` against the
  real keycore over TLS, with both IV settings and in every FIPS mode. It
  checks:
  - login, objects and attributes;
  - ECDSA and RSA-PSS signing, hashed and prehashed;
  - AES-GCM, single- and multi-part;
  - decryption after a rotation;
  - four threads at once, and fork.

  `pkcs11-tool` then lists, signs and reads the public key on its own, and
  the test verifies that signature in Go.
- **CI.** The "PKCS#11 module" step in the race-detector job requires all
  of this (`VECTA_REQUIRE_PKCS11=1`).
