package com.vecta.kms.internal;

import com.vecta.kms.VectaKMSConfig;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Map;

/**
 * Calls the Vecta KMS ekm API over TLS 1.3 with the configured bearer token.
 * The token is sent only in the Authorization header and never appears in
 * an exception or log.
 */
public final class KMSHttpClient {

    private final String base;
    private final String tenantId;
    private final String bearerToken;
    private final HttpClient http;

    public KMSHttpClient(VectaKMSConfig config) {
        this.base = config.baseUrl().toString().replaceAll("/+$", "");
        this.tenantId = config.tenantId();
        this.bearerToken = config.bearerToken();
        SSLParameters tls = new SSLParameters();
        tls.setProtocols(new String[] {"TLSv1.3"});
        try {
            this.http = HttpClient.newBuilder()
                    .sslContext(sslContext(config))
                    .sslParameters(tls)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("cannot set up TLS to Vecta KMS: " + e.getMessage(), e);
        }
    }

    /** POSTs a JSON object to the ekm API and returns its "result" object. */
    public Map<String, Object> postResult(String path, Map<String, String> body) throws KMSException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + bearerToken)
                .header("X-Tenant-ID", tenantId)
                .POST(HttpRequest.BodyPublishers.ofString(Json.object(body)))
                .build();
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new KMSException("Vecta KMS unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new KMSException("interrupted calling Vecta KMS", e);
        }
        Map<String, Object> doc;
        try {
            doc = Json.parseObject(resp.body());
        } catch (RuntimeException e) {
            throw new KMSException("Vecta KMS returned invalid JSON (HTTP " + resp.statusCode() + ")");
        }
        if (resp.statusCode() / 100 != 2) {
            Object err = doc.get("error");
            String message = err instanceof Map<?, ?> m ? String.valueOf(m.get("message")) : "HTTP " + resp.statusCode();
            throw new KMSException("Vecta KMS refused " + path + " (" + resp.statusCode() + "): " + message);
        }
        Object result = doc.get("result");
        if (!(result instanceof Map<?, ?>)) {
            throw new KMSException("Vecta KMS response has no result");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) result;
        return out;
    }

    public String tenantId() {
        return tenantId;
    }

    /** Encodes one path segment. */
    public static String segment(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static SSLContext sslContext(VectaKMSConfig config) throws GeneralSecurityException, IOException {
        if (config.caCertificate() == null) {
            return SSLContext.getDefault();
        }
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        try (InputStream in = Files.newInputStream(config.caCertificate())) {
            int i = 0;
            for (Certificate cert : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                trust.setCertificateEntry("vecta-ca-" + i++, cert);
            }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }

    /** A call to Vecta KMS that failed or was refused. */
    public static final class KMSException extends Exception {
        private static final long serialVersionUID = 1L;

        public KMSException(String message) {
            super(message);
        }

        public KMSException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
