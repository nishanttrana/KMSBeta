# JCA Provider Samples

| Sample | Description |
|--------|-------------|
| `EncryptDecryptExample.java` | AES-GCM encrypt/decrypt via KMS-backed Cipher |
| `KeyStoreExample.java` | List all KMS keys via JCA KeyStore |
| `SignVerifyExample.java` | SHA256withRSA sign/verify via KMS |

## Setup

```bash
# Build the provider JAR
cd services/jca-provider
mvn package

# Run an example
java -cp target/vecta-jca-provider-1.0.0.jar:samples \
  -DVECTA_BASE_URL=https://kms.example.com/svc/ekm \
  EncryptDecryptExample
```

## Registration

Add the provider programmatically:
```java
Security.addProvider(new VectaKMSProvider());
```

Or via `java.security` file:
```
security.provider.N=com.vecta.kms.VectaKMSProvider
```

## Environment Variables

Same as PKCS#11 provider — see `VECTA_BASE_URL`, `VECTA_TENANT_ID`, `VECTA_AUTH_TOKEN`, etc.
