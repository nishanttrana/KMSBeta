package com.vecta.kms.internal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

/**
 * Mirrors the Go agentauth.Provider: mTLS → JWT → API Key → Bearer.
 */
public class AuthManager {

    private final String apiKey;
    private final String jwtEndpoint;
    private final String authToken;
    private final String tenantId;

    private volatile String jwt;
    private volatile Instant jwtExpiry = Instant.MIN;

    public AuthManager() {
        this.apiKey = env("VECTA_API_KEY", "");
        this.jwtEndpoint = env("VECTA_JWT_ENDPOINT", "");
        this.authToken = env("VECTA_AUTH_TOKEN", "");
        this.tenantId = env("VECTA_TENANT_ID", "");
    }

    /**
     * Apply auth headers to a request builder.
     */
    public HttpRequest.Builder applyAuth(HttpRequest.Builder builder) {
        if (!tenantId.isEmpty()) {
            builder.header("X-Tenant-ID", tenantId);
        }

        // Try JWT
        if (jwt != null && Instant.now().isBefore(jwtExpiry)) {
            return builder.header("Authorization", "Bearer " + jwt);
        }

        // Try JWT refresh
        if (!jwtEndpoint.isEmpty() && !apiKey.isEmpty()) {
            try {
                refreshJwt();
                if (jwt != null) {
                    return builder.header("Authorization", "Bearer " + jwt);
                }
            } catch (Exception ignored) {
                // Fall through
            }
        }

        // API Key
        if (!apiKey.isEmpty()) {
            return builder.header("X-API-Key", apiKey);
        }

        // Static bearer token
        if (!authToken.isEmpty()) {
            return builder.header("Authorization", "Bearer " + authToken);
        }

        return builder;
    }

    public String getTenantId() {
        return tenantId;
    }

    private void refreshJwt() throws Exception {
        String body = String.format("{\"api_key\":\"%s\",\"tenant_id\":\"%s\"}", apiKey, tenantId);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(jwtEndpoint))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 200) {
            // Simple JSON parse (no external deps)
            String respBody = resp.body();
            String token = extractJsonString(respBody, "token");
            int expiresIn = extractJsonInt(respBody, "expires_in", 900);
            if (token != null && !token.isEmpty()) {
                this.jwt = token;
                this.jwtExpiry = Instant.now().plusSeconds(expiresIn - 30);
            }
        }
    }

    static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    static int extractJsonInt(String json, String key, int defaultValue) {
        String search = "\"" + key + "\":";
        int start = json.indexOf(search);
        if (start < 0) return defaultValue;
        start += search.length();
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (Character.isDigit(c)) sb.append(c);
            else break;
        }
        try {
            return Integer.parseInt(sb.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static String env(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }
}
