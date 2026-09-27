package com.vecta.kms;

import javax.crypto.SecretKey;

/**
 * A reference to a Vecta KMS TDE key by its ID. It carries no key material:
 * the key stays in the KMS, so {@link #getEncoded()} returns null.
 */
public final class VectaKMSKey implements SecretKey {

    private static final long serialVersionUID = 1L;
    private final String keyId;

    public VectaKMSKey(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("key id is required");
        }
        this.keyId = keyId.trim();
    }

    public String keyId() {
        return keyId;
    }

    @Override
    public String getAlgorithm() {
        return VectaKMSProvider.KEY_WRAP;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
