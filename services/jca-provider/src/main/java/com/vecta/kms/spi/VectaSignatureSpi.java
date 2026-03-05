package com.vecta.kms.spi;

import com.vecta.kms.internal.KMSHttpClient;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.util.Base64;

/**
 * Signature SPI — always proxies to KMS (asymmetric operations).
 */
public class VectaSignatureSpi extends SignatureSpi {

    private static final KMSHttpClient client = new KMSHttpClient();

    private final String algorithm;
    private String keyId;
    private boolean signing;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    protected VectaSignatureSpi(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.keyId = extractKeyId(privateKey);
        this.signing = true;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.keyId = extractKeyId(publicKey);
        this.signing = false;
        buffer.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            String b64Data = Base64.getEncoder().encodeToString(buffer.toByteArray());
            String body = String.format("{\"data\":\"%s\",\"algorithm\":\"%s\"}", b64Data, algorithm);
            String resp = client.post("/ekm/tde/keys/" + keyId + "/sign", body);
            String sig = extractJson(resp, "signature");
            return Base64.getDecoder().decode(sig);
        } catch (Exception e) {
            throw new SignatureException("KMS sign failed: " + e.getMessage());
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            String b64Data = Base64.getEncoder().encodeToString(buffer.toByteArray());
            String b64Sig = Base64.getEncoder().encodeToString(sigBytes);
            String body = String.format("{\"data\":\"%s\",\"signature\":\"%s\",\"algorithm\":\"%s\"}",
                    b64Data, b64Sig, algorithm);
            String resp = client.post("/ekm/tde/keys/" + keyId + "/verify", body);
            return resp.contains("\"valid\":true");
        } catch (Exception e) {
            throw new SignatureException("KMS verify failed: " + e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value) {}

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) {
        return null;
    }

    private String extractKeyId(Key key) throws InvalidKeyException {
        if (key == null) throw new InvalidKeyException("null key");
        byte[] enc = key.getEncoded();
        if (enc != null && enc.length > 0) return new String(enc).trim();
        return key.getAlgorithm();
    }

    private static String extractJson(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        return end > start ? json.substring(start, end) : "";
    }

    // Concrete algorithm inner classes for provider registration
    public static class SHA256withRSA extends VectaSignatureSpi {
        public SHA256withRSA() { super("SHA256withRSA"); }
    }

    public static class SHA256withECDSA extends VectaSignatureSpi {
        public SHA256withECDSA() { super("SHA256withECDSA"); }
    }
}
