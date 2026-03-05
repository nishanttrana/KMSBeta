package com.vecta.kms.spi;

import com.vecta.kms.internal.KMSHttpClient;
import com.vecta.kms.internal.KeyCache;

import javax.crypto.CipherSpi;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

/**
 * AES/GCM/NoPadding cipher backed by Vecta KMS.
 * If key is cached locally, performs local AES-GCM; otherwise proxies to KMS.
 */
public class VectaCipherSpi extends CipherSpi {

    private static final KMSHttpClient client = new KMSHttpClient();
    private static final KeyCache cache = new KeyCache();

    private int opmode;
    private String keyId;
    private byte[] iv;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"GCM".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("Only GCM mode supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("Only NoPadding supported");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen + 16; // GCM tag
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        this.keyId = extractKeyId(key);
        this.iv = new byte[12];
        random.nextBytes(this.iv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.keyId = extractKeyId(key);
        if (params instanceof GCMParameterSpec) {
            this.iv = ((GCMParameterSpec) params).getIV();
        } else {
            this.iv = new byte[12];
            random.nextBytes(this.iv);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.keyId = extractKeyId(key);
        this.iv = new byte[12];
        random.nextBytes(this.iv);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return new byte[0]; // GCM accumulates until doFinal
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] data = new byte[inputLen];
        System.arraycopy(input, inputOffset, data, 0, inputLen);

        // Try local cache
        KeyCache.CacheEntry entry = cache.get(keyId);
        if (entry != null) {
            try {
                javax.crypto.Cipher localCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                javax.crypto.spec.SecretKeySpec sks = new javax.crypto.spec.SecretKeySpec(entry.material, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                localCipher.init(opmode, sks, gcmSpec);
                return localCipher.doFinal(data);
            } catch (Exception e) {
                // Fall through to KMS
            }
        }

        // Remote KMS
        try {
            String b64Data = Base64.getEncoder().encodeToString(data);
            if (opmode == Cipher.ENCRYPT_MODE) {
                String body = String.format("{\"plaintext\":\"%s\"}", b64Data);
                String resp = client.post("/ekm/tde/keys/" + keyId + "/wrap", body);
                String ct = extractJson(resp, "ciphertext");
                return Base64.getDecoder().decode(ct);
            } else {
                String b64Iv = Base64.getEncoder().encodeToString(iv);
                String body = String.format("{\"ciphertext\":\"%s\",\"iv\":\"%s\"}", b64Data, b64Iv);
                String resp = client.post("/ekm/tde/keys/" + keyId + "/unwrap", body);
                String pt = extractJson(resp, "plaintext");
                return Base64.getDecoder().decode(pt);
            }
        } catch (Exception e) {
            throw new IllegalBlockSizeException("KMS operation failed: " + e.getMessage());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private String extractKeyId(Key key) throws InvalidKeyException {
        if (key == null) throw new InvalidKeyException("null key");
        // Key ID is stored in the key's algorithm or encoded form
        String encoded = new String(key.getEncoded() != null ? key.getEncoded() : new byte[0]);
        if (!encoded.isEmpty()) return encoded.trim();
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
}
