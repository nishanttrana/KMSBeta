# Vecta KMS JCA provider

A Java Cryptography Architecture provider for key wrapping under a Vecta KMS
key. It registers one service:

| Service | What it does |
|---|---|
| `Cipher.VectaKeyWrap` | `WRAP_MODE`: sends a key to Vecta KMS, which wraps it under a TDE key (`POST /svc/ekm/ekm/tde/keys/{id}/wrap`). `UNWRAP_MODE`: sends the wrapped key back to be unwrapped (`.../unwrap`). The Vecta key never leaves the KMS. |

There is no local cipher, signature or key store: the provider offers only
what the KMS API does. Bulk `ENCRYPT_MODE` / `DECRYPT_MODE` are refused.

## Use

```java
Security.addProvider(new VectaKMSProvider());          // reads the environment
Cipher c = Cipher.getInstance("VectaKeyWrap", "VectaKMS");
c.init(Cipher.WRAP_MODE, new VectaKMSKey("tde_key_123"));
byte[] wrapped = c.wrap(dataKey);
byte[] iv = c.getIV();                                 // store with the wrapped key (null if the key uses none)

c.init(Cipher.UNWRAP_MODE, new VectaKMSKey("tde_key_123"), new IvParameterSpec(iv));
SecretKey dataKey2 = (SecretKey) c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
```

A wrap or unwrap that the tenant's key access policy holds for approval
throws `InvalidKeyException` naming the approval request; retry once it is
approved. Every call is audited by the KMS (`audit.ekm.tde_key_accessed`).

## Configuration

| Variable | Meaning |
|---|---|
| `VECTA_BASE_URL` | The ekm service through the edge, e.g. `https://kms.example.com/svc/ekm`. Must be `https://`. |
| `VECTA_TENANT_ID` | The Vecta tenant. |
| `VECTA_AUTH_TOKEN` | A Vecta access token for that tenant. Sent only in the `Authorization` header, never logged. |
| `VECTA_CA_CERT` | Optional PEM file of the CA that issued the KMS edge certificate; otherwise the JVM trust store. |

Or construct `new VectaKMSProvider(new VectaKMSConfig(uri, tenant, token, caPath))`.
TLS is 1.3 only.

## JDK support

Runs on OpenJDK builds (Temurin, Corretto, Zulu, Red Hat). **Oracle JDK**
loads a `Cipher` provider only from a jar signed with an Oracle-issued JCE
code-signing certificate; this source is not signed, so on Oracle JDK
`Cipher.getInstance` fails with "JCE cannot authenticate the provider".

## Build and test

```bash
mvn package
```

`services/ekm/jca_consumer_test.go` compiles this source and drives it
through `javax.crypto.Cipher` against the real ekm API over TLS
(`VECTA_TEST_JDK_IMAGE=eclipse-temurin:17-jdk go test ./services/ekm -run JCA`).
