package com.vecta.kms;

import java.net.URI;
import java.nio.file.Path;

/**
 * Where the provider reaches Vecta KMS and as whom.
 *
 * @param baseUrl       the ekm service through the edge, for example
 *                      {@code https://kms.example.com/svc/ekm}; HTTPS only
 * @param tenantId      the Vecta tenant
 * @param bearerToken   a Vecta access token for that tenant; never logged
 * @param caCertificate PEM file of the CA that issued the KMS edge
 *                      certificate, or null to use the JVM trust store
 */
public record VectaKMSConfig(URI baseUrl, String tenantId, String bearerToken, Path caCertificate) {

    public VectaKMSConfig {
        if (baseUrl == null || !"https".equalsIgnoreCase(baseUrl.getScheme())) {
            throw new IllegalArgumentException("VECTA_BASE_URL must be an https:// URL");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("VECTA_TENANT_ID is required");
        }
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new IllegalArgumentException("VECTA_AUTH_TOKEN is required");
        }
    }

    /**
     * Reads VECTA_BASE_URL, VECTA_TENANT_ID, VECTA_AUTH_TOKEN and, optionally,
     * VECTA_CA_CERT (a PEM file path).
     */
    public static VectaKMSConfig fromEnvironment() {
        String ca = env("VECTA_CA_CERT");
        String base = env("VECTA_BASE_URL");
        return new VectaKMSConfig(base == null ? null : URI.create(base), env("VECTA_TENANT_ID"),
                env("VECTA_AUTH_TOKEN"), ca == null ? null : Path.of(ca));
    }

    @Override
    public String toString() {
        return "VectaKMSConfig[baseUrl=" + baseUrl + ", tenantId=" + tenantId + ", caCertificate=" + caCertificate + "]";
    }

    private static String env(String key) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? null : v.trim();
    }
}
