package com.vecta.kms.spi;

import com.vecta.kms.VectaKMSKey;
import com.vecta.kms.internal.KMSHttpClient;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code Cipher.VectaKeyWrap}: wraps a key under a Vecta KMS TDE key, and
 * unwraps it, by calling the ekm service. Only WRAP_MODE and UNWRAP_MODE are
 * supported; there is no bulk encryption. The IV the KMS used is returned by
 * {@link #engineGetIV()} after a wrap and must be given back on unwrap as an
 * {@link IvParameterSpec} (keys whose wrap uses no IV return none).
 */
public final class VectaKeyWrapCipherSpi extends CipherSpi {

    private final KMSHttpClient kms;
    private int mode;
    private VectaKMSKey key;
    private byte[] iv;

    public VectaKeyWrapCipherSpi(KMSHttpClient kms) {
        this.kms = kms;
    }

    @Override
    protected void engineSetMode(String m) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("VectaKeyWrap has no modes");
    }

    @Override
    protected void engineSetPadding(String p) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("VectaKeyWrap has no padding");
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        throw new IllegalStateException("VectaKeyWrap only wraps and unwraps keys");
    }

    @Override
    protected byte[] engineGetIV() {
        return iv == null ? null : iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key k, SecureRandom random) throws InvalidKeyException {
        init(opmode, k, null);
    }

    @Override
    protected void engineInit(int opmode, Key k, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("VectaKeyWrap takes an IvParameterSpec (the IV from wrap)");
        }
        if (params != null && opmode != Cipher.UNWRAP_MODE) {
            throw new InvalidAlgorithmParameterException("the KMS chooses the IV when wrapping");
        }
        init(opmode, k, params == null ? null : ((IvParameterSpec) params).getIV());
    }

    @Override
    protected void engineInit(int opmode, Key k, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("pass the IV as an IvParameterSpec");
        }
        init(opmode, k, null);
    }

    private void init(int opmode, Key k, byte[] unwrapIV) throws InvalidKeyException {
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE) {
            throw new UnsupportedOperationException("VectaKeyWrap supports only WRAP_MODE and UNWRAP_MODE");
        }
        if (!(k instanceof VectaKMSKey)) {
            throw new InvalidKeyException("VectaKeyWrap needs a VectaKMSKey naming the Vecta KMS key");
        }
        this.mode = opmode;
        this.key = (VectaKMSKey) k;
        this.iv = unwrapIV == null ? null : unwrapIV.clone();
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int off, int len) {
        throw new IllegalStateException("VectaKeyWrap only wraps and unwraps keys: use Cipher.wrap / Cipher.unwrap");
    }

    @Override
    protected int engineUpdate(byte[] input, int off, int len, byte[] out, int outOff) {
        throw new IllegalStateException("VectaKeyWrap only wraps and unwraps keys: use Cipher.wrap / Cipher.unwrap");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int off, int len) {
        throw new IllegalStateException("VectaKeyWrap only wraps and unwraps keys: use Cipher.wrap / Cipher.unwrap");
    }

    @Override
    protected int engineDoFinal(byte[] input, int off, int len, byte[] out, int outOff) {
        throw new IllegalStateException("VectaKeyWrap only wraps and unwraps keys: use Cipher.wrap / Cipher.unwrap");
    }

    @Override
    protected byte[] engineWrap(Key toWrap) throws InvalidKeyException {
        if (mode != Cipher.WRAP_MODE) {
            throw new IllegalStateException("cipher is not in WRAP_MODE");
        }
        byte[] material = toWrap == null ? null : toWrap.getEncoded();
        if (material == null || material.length == 0) {
            throw new InvalidKeyException("the key to wrap has no encoded form");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("tenant_id", kms.tenantId());
        body.put("plaintext", Base64.getEncoder().encodeToString(material));
        Arrays.fill(material, (byte) 0);
        Map<String, Object> result = call("/ekm/tde/keys/" + KMSHttpClient.segment(key.keyId()) + "/wrap", body);
        if ("pending_approval".equalsIgnoreCase(String.valueOf(result.get("status")))) {
            throw new InvalidKeyException("Vecta KMS needs an approval before this wrap (request "
                    + result.get("approval_request_id") + "); retry once it is approved");
        }
        String ct = str(result, "ciphertext");
        if (ct.isEmpty()) {
            throw new InvalidKeyException("Vecta KMS returned no wrapped key");
        }
        String ivB64 = str(result, "iv");
        this.iv = ivB64.isEmpty() ? null : Base64.getDecoder().decode(ivB64);
        return Base64.getDecoder().decode(ct);
    }

    @Override
    protected Key engineUnwrap(byte[] wrapped, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (mode != Cipher.UNWRAP_MODE) {
            throw new IllegalStateException("cipher is not in UNWRAP_MODE");
        }
        if (type != Cipher.SECRET_KEY) {
            throw new NoSuchAlgorithmException("VectaKeyWrap unwraps secret keys only");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("tenant_id", kms.tenantId());
        body.put("ciphertext", Base64.getEncoder().encodeToString(wrapped));
        body.put("iv", iv == null ? "" : Base64.getEncoder().encodeToString(iv));
        Map<String, Object> result = call("/ekm/tde/keys/" + KMSHttpClient.segment(key.keyId()) + "/unwrap", body);
        if ("pending_approval".equalsIgnoreCase(String.valueOf(result.get("status")))) {
            throw new InvalidKeyException("Vecta KMS needs an approval before this unwrap (request "
                    + result.get("approval_request_id") + "); retry once it is approved");
        }
        String pt = str(result, "plaintext");
        if (pt.isEmpty()) {
            throw new InvalidKeyException("Vecta KMS returned no key");
        }
        byte[] material = Base64.getDecoder().decode(pt);
        try {
            return new SecretKeySpec(material, algorithm);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    private Map<String, Object> call(String path, Map<String, String> body) throws InvalidKeyException {
        try {
            return kms.postResult(path, body);
        } catch (KMSHttpClient.KMSException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? "" : String.valueOf(v).trim();
    }
}
