package com.vecta.kms.spi;

import com.vecta.kms.internal.KMSHttpClient;

import java.security.SecureRandomSpi;
import java.util.Base64;

/**
 * SecureRandom SPI backed by Vecta QRNG endpoint.
 * Falls back to local SecureRandom on network failure.
 */
public class VectaSecureRandomSpi extends SecureRandomSpi {

    private static final long serialVersionUID = 1L;
    private static final KMSHttpClient client = new KMSHttpClient();
    private final java.security.SecureRandom fallback = new java.security.SecureRandom();

    @Override
    protected void engineSetSeed(byte[] seed) {
        // QRNG is hardware-sourced; seed is ignored
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        try {
            String body = String.format("{\"length\":%d}", bytes.length);
            String resp = client.post("/qrng/bytes", body);
            // Extract base64-encoded random bytes from response
            String search = "\"data\":\"";
            int start = resp.indexOf(search);
            if (start >= 0) {
                start += search.length();
                int end = resp.indexOf("\"", start);
                if (end > start) {
                    byte[] decoded = Base64.getDecoder().decode(resp.substring(start, end));
                    System.arraycopy(decoded, 0, bytes, 0, Math.min(decoded.length, bytes.length));
                    return;
                }
            }
        } catch (Exception e) {
            // Fall through to local
        }
        fallback.nextBytes(bytes);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}
