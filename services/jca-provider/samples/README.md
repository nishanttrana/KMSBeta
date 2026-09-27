# JCA provider samples

| Sample | Description |
|--------|-------------|
| `KeyWrapExample.java` | Wrap an AES data key under a Vecta KMS TDE key and unwrap it (`Cipher.VectaKeyWrap`) |

```bash
cd services/jca-provider && mvn package
export VECTA_BASE_URL=https://kms.example.com/svc/ekm VECTA_TENANT_ID=acme VECTA_AUTH_TOKEN=...   # see ../README.md
javac -cp target/vecta-jca-provider-*.jar -d /tmp/samples samples/KeyWrapExample.java
java -cp target/vecta-jca-provider-*.jar:/tmp/samples KeyWrapExample tde_key_123
```

Run on an OpenJDK build; Oracle JDK needs an Oracle-signed JCE jar (../README.md).
