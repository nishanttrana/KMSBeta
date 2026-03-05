package com.vecta.kms.spi;

import com.vecta.kms.internal.KMSHttpClient;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * KeyStore SPI backed by Vecta KMS key list.
 */
public class VectaKeyStoreSpi extends KeyStoreSpi {

    private static final KMSHttpClient client = new KMSHttpClient();
    private final Map<String, String> keys = new LinkedHashMap<>(); // alias -> keyId

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        // Fetch key list from KMS
        try {
            String resp = client.get("/ekm/tde/keys");
            // Simple extraction of key_id values
            int idx = 0;
            while (true) {
                int start = resp.indexOf("\"key_id\":\"", idx);
                if (start < 0) break;
                start += "\"key_id\":\"".length();
                int end = resp.indexOf("\"", start);
                if (end < 0) break;
                String keyId = resp.substring(start, end);
                keys.put(keyId, keyId);
                idx = end + 1;
            }
        } catch (Exception e) {
            // Empty keystore on failure
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        String keyId = keys.get(alias);
        if (keyId == null) return null;
        // Return a proxy key that carries the keyId
        return new VectaKMSKey(keyId);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(keys.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return keys.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return keys.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return keys.containsKey(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) { return false; }
    @Override
    public Certificate[] engineGetCertificateChain(String alias) { return null; }
    @Override
    public Certificate engineGetCertificate(String alias) { return null; }
    @Override
    public Date engineGetCreationDate(String alias) { return new Date(); }
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {}
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {}
    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {}
    @Override
    public void engineDeleteEntry(String alias) { keys.remove(alias); }
    @Override
    public String engineGetCertificateAlias(Certificate cert) { return null; }
    @Override
    public void engineStore(OutputStream stream, char[] password) {}

    /**
     * Proxy key that carries the KMS key ID for use with CipherSpi/SignatureSpi.
     */
    public static class VectaKMSKey implements Key {
        private static final long serialVersionUID = 1L;
        private final String keyId;

        public VectaKMSKey(String keyId) {
            this.keyId = keyId;
        }

        @Override
        public String getAlgorithm() { return "AES"; }

        @Override
        public String getFormat() { return "VectaKMS"; }

        @Override
        public byte[] getEncoded() { return keyId.getBytes(); }
    }
}
