package com.vecta.kms.internal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * HTTP client for Vecta KMS API calls with multi-auth support.
 */
public class KMSHttpClient {

    private final String baseUrl;
    private final AuthManager auth;
    private final HttpClient http;

    public KMSHttpClient() {
        this.baseUrl = env("VECTA_BASE_URL", "https://localhost/svc/ekm");
        this.auth = new AuthManager();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public String get(String path) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(15))
                .GET();
        auth.applyAuth(builder);
        HttpResponse<String> resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() > 299) {
            throw new RuntimeException("KMS GET " + path + " failed: " + resp.statusCode());
        }
        return resp.body();
    }

    public String post(String path, String jsonBody) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        auth.applyAuth(builder);
        HttpResponse<String> resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() > 299) {
            throw new RuntimeException("KMS POST " + path + " failed: " + resp.statusCode());
        }
        return resp.body();
    }

    public AuthManager getAuth() {
        return auth;
    }

    private static String env(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }
}
