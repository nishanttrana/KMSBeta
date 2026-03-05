package com.vecta.kms;

import com.vecta.kms.spi.VectaCipherSpi;
import com.vecta.kms.spi.VectaKeyStoreSpi;
import com.vecta.kms.spi.VectaSecureRandomSpi;
import com.vecta.kms.spi.VectaSignatureSpi;

import java.security.Provider;

/**
 * Vecta KMS JCA Provider.
 *
 * Registers cryptographic services backed by the Vecta KMS:
 * - Cipher: AES/GCM/NoPadding (local cache or remote)
 * - Signature: SHA256withRSA, SHA256withECDSA (always remote)
 * - KeyStore: VectaKMS (fetch keys from KMS)
 * - SecureRandom: VectaQRNG (proxy to QRNG endpoint)
 *
 * Configuration via environment variables:
 *   VECTA_BASE_URL, VECTA_TENANT_ID, VECTA_AUTH_TOKEN,
 *   VECTA_MTLS_CERT, VECTA_MTLS_KEY, VECTA_MTLS_CA,
 *   VECTA_API_KEY, VECTA_JWT_ENDPOINT, VECTA_KEY_CACHE_TTL
 */
public class VectaKMSProvider extends Provider {

    private static final long serialVersionUID = 1L;
    public static final String PROVIDER_NAME = "VectaKMS";
    public static final double VERSION = 1.0;

    public VectaKMSProvider() {
        super(PROVIDER_NAME, String.valueOf(VERSION), "Vecta KMS JCA Provider — AES-GCM, RSA/ECDSA sign, KeyStore, QRNG");
        registerServices();
    }

    private void registerServices() {
        // Cipher
        put("Cipher.AES/GCM/NoPadding", VectaCipherSpi.class.getName());

        // Signature
        put("Signature.SHA256withRSA", VectaSignatureSpi.class.getName() + "$SHA256withRSA");
        put("Signature.SHA256withECDSA", VectaSignatureSpi.class.getName() + "$SHA256withECDSA");

        // KeyStore
        put("KeyStore.VectaKMS", VectaKeyStoreSpi.class.getName());

        // SecureRandom
        put("SecureRandom.VectaQRNG", VectaSecureRandomSpi.class.getName());
    }
}
