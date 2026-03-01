package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

func (s *Service) BuildFieldEncryptionWrapperSDKArtifact(ctx context.Context, tenantID string, targetOS string) (FieldEncryptionSDKArtifact, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetOS = normalizeWrapperSDKTargetOS(targetOS)
	if tenantID == "" {
		return FieldEncryptionSDKArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if targetOS == "" {
		targetOS = "linux"
	}
	payload, filename, err := buildFieldEncryptionWrapperArchive(targetOS)
	if err != nil {
		return FieldEncryptionSDKArtifact{}, err
	}
	sum := sha256.Sum256(payload)
	out := FieldEncryptionSDKArtifact{
		TargetOS:    targetOS,
		Filename:    filename,
		ContentType: "application/zip",
		Encoding:    "base64",
		Content:     base64.StdEncoding.EncodeToString(payload),
		SizeBytes:   len(payload),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.sdk_downloaded", tenantID, map[string]interface{}{
		"target_os":  targetOS,
		"filename":   filename,
		"size_bytes": len(payload),
		"sha256":     out.SHA256,
	})
	return out, nil
}

func normalizeWrapperSDKTargetOS(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "linux":
		return "linux"
	case "windows", "win":
		return "windows"
	case "macos", "darwin", "mac":
		return "macos"
	default:
		return ""
	}
}

func buildFieldEncryptionWrapperArchive(targetOS string) ([]byte, string, error) {
	files := map[string]string{
		"README.md":                        wrapperSDKReadme(targetOS),
		"config/vecta-wrapper.env.example": wrapperSDKEnvExample(),
		"java/pom.xml":                     wrapperSDKJavaPom(),
		"java/src/main/java/com/vecta/fieldencryption/NativeKeyCache.java":                 wrapperSDKJavaNativeBridge(),
		"java/src/main/java/com/vecta/fieldencryption/FieldEncryptionRuntime.java":         wrapperSDKJavaRuntime(),
		"java/src/main/java/com/vecta/fieldencryption/FieldPolicy.java":                    wrapperSDKJavaFieldPolicy(),
		"java/src/main/java/com/vecta/fieldencryption/FieldProtectionRule.java":            wrapperSDKJavaFieldProtectionRule(),
		"java/src/main/java/com/vecta/fieldencryption/FieldProtectionBundle.java":          wrapperSDKJavaFieldProtectionBundle(),
		"java/src/main/java/com/vecta/fieldencryption/LeaseContext.java":                   wrapperSDKJavaLeaseContext(),
		"java/src/main/java/com/vecta/fieldencryption/RuntimeContext.java":                 wrapperSDKJavaRuntimeContext(),
		"java/src/main/java/com/vecta/fieldencryption/PolicyResolverClient.java":           wrapperSDKJavaPolicyResolverClient(),
		"java/src/main/java/com/vecta/fieldencryption/HttpPolicyResolverClient.java":       wrapperSDKJavaHTTPPolicyResolverClient(),
		"java/src/main/java/com/vecta/fieldencryption/PolicyBundleCache.java":              wrapperSDKJavaPolicyBundleCache(),
		"java/src/main/java/com/vecta/fieldencryption/PolicyAwareRuntimeContext.java":      wrapperSDKJavaPolicyAwareRuntimeContext(),
		"java/src/main/java/com/vecta/fieldencryption/JdbcFieldEncryptionInterceptor.java": wrapperSDKJavaJdbcInterceptor(),
		"native/vecta_field_native.c":                                                      wrapperSDKNativeC(),
	}
	switch targetOS {
	case "windows":
		files["scripts/build-windows.ps1"] = wrapperSDKBuildWindows()
	case "macos":
		files["scripts/build-macos.sh"] = wrapperSDKBuildMacOS()
	default:
		files["scripts/build-linux.sh"] = wrapperSDKBuildLinux()
	}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, path := range paths {
		content := files[path]
		w, err := zw.Create(path)
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), fmt.Sprintf("vecta-field-encryption-wrapper-sdk-%s.zip", targetOS), nil
}

func wrapperSDKReadme(targetOS string) string {
	buildScript := "scripts/build-linux.sh"
	switch targetOS {
	case "windows":
		buildScript = "scripts/build-windows.ps1"
	case "macos":
		buildScript = "scripts/build-macos.sh"
	}
	const readmeTemplate = `# Vecta Field Encryption Wrapper SDK (%s)

This package contains a JDBC/runtime wrapper pattern for local field crypto with KMS policy fallback.

## Security model
- Wrapper must register via challenge/response (/field-encryption/register/init -> /field-encryption/register/complete).
- Registration completion returns:
  - scoped JWT profile (short lived),
  - optional signed client certificate from CSR,
  - immutable wrapper binding (tenant/app/keys/fingerprint).
- Local key material is only from lease package (/field-encryption/leases) and must be submitted as signed usage receipts (/field-encryption/receipts).
- Lease package wrapping defaults to RFC 9180 HPKE:
  - KEM: DHKEM(X25519)
  - KDF: HKDF-SHA256
  - AEAD: AES-256-GCM
  - package fields: alg, enc_b64, ciphertext_b64, aad_b64, info_b64.
- Compatibility modes for migration:
  - DATAPROTECT_LEASE_WRAP_MODE=hpke (default)
  - DATAPROTECT_LEASE_WRAP_MODE=dual (hpke + legacy nested package)
  - DATAPROTECT_LEASE_WRAP_MODE=legacy (X25519+AES-256-GCM)
- Wrapper API calls must send:
  - X-Wrapper-Token: JWT from registration auth_profile,
  - X-Wrapper-Cert-Fingerprint: SHA-256 cert fingerprint (when policy requires mTLS).

## Runtime behavior
- cache_enabled=false: wrapper must use remote KMS crypto path.
- cache_enabled=true: wrapper can execute local crypto using leased wrapped keys.
- Forbidden operations/policies must hard-fallback to remote KMS API.
- Lease renewal endpoint: /field-encryption/leases/{id}/renew
- JDBC intercept runtime entrypoint: com.vecta.fieldencryption.JdbcFieldEncryptionInterceptor
  - wraps DataSource/Connection/PreparedStatement/ResultSet using dynamic proxies,
  - applies policy-driven encrypt/tokenize/redact on write and decrypt/mask/token_only/redact on read,
  - emits lease usage receipts for local decrypt/encrypt operations.

## Attestation and non-exportable keys
- TPM attestation evidence is verified server-side during registration completion (challenge-bound signed evidence).
- require_non_exportable_wrapper_keys enforces signed attestation claim only.
- Actual OS-keystore non-exportable guarantees must be provided by wrapper host configuration.

## Native memory hardening module
- NativeKeyCache.hardenProcess():
  - disables core dumps (best effort),
  - marks process as non-dumpable on Linux (best effort).
- NativeKeyCache.lock(...):
  - Linux: mlock
  - Windows: VirtualLock
- Memory is explicitly zeroized and unlocked on key eviction.

## Build
1. Build Java artifact:
   - mvn -f java/pom.xml -DskipTests package
2. Build native hardening library:
   - %s
3. Use generated artifact:
   - java/target/vecta-jdbc-protect-1.0.0.jar

## Integration steps
1. Generate wrapper signing/encryption keys locally.
2. Call register init endpoint with wrapper metadata + public keys.
3. Sign challenge with wrapper private signing key.
4. Optionally provide CSR during complete registration for mTLS cert issuance.
5. Use returned JWT profile and lease package APIs for local runtime.
6. Submit signed usage receipts to maintain lease validity.
`
	return fmt.Sprintf(readmeTemplate, strings.ToUpper(targetOS), buildScript)
}

func wrapperSDKJavaPom() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.vecta</groupId>
  <artifactId>vecta-jdbc-protect</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <name>vecta-jdbc-protect</name>
  <description>Vecta JDBC field protection wrapper runtime</description>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <maven.compiler.source>11</maven.compiler.source>
    <maven.compiler.target>11</maven.compiler.target>
  </properties>

  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.2</version>
    </dependency>
  </dependencies>
</project>
`
}

func wrapperSDKEnvExample() string {
	return `VECTA_BASE_URL=https://kms.example.com/svc/dataprotect
VECTA_TENANT_ID=root
VECTA_WRAPPER_ID=wrapper-prod-01
VECTA_APP_ID=payments-api
VECTA_WRAPPER_JWT=<issued_during_registration>
VECTA_TLS_CERT=wrapper.crt.pem
VECTA_TLS_KEY=wrapper.key.pem
`
}

func wrapperSDKJavaNativeBridge() string {
	return `package com.vecta.fieldencryption;

public final class NativeKeyCache {
  static {
    try {
      System.loadLibrary("vecta_field_native");
    } catch (UnsatisfiedLinkError ignored) {
    }
  }

  private NativeKeyCache() {}

  public static native int hardenProcess();
  public static native int lockMemory(byte[] keyMaterial);
  public static native int unlockMemory(byte[] keyMaterial);
  public static native void zeroize(byte[] keyMaterial);
}
`
}

func wrapperSDKJavaRuntime() string {
	return `package com.vecta.fieldencryption;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class FieldEncryptionRuntime {
  private static final SecureRandom RNG = new SecureRandom();
  private static final String WRAPPED_PREFIX = "vecta:gcm";

  private FieldEncryptionRuntime() {}

  // Local encrypt path: use only when lease + policy permit local crypto.
  public static Map<String, String> encryptLocal(byte[] leasedKey, String plaintext, String aad, String leaseId) throws Exception {
    NativeKeyCache.hardenProcess();
    NativeKeyCache.lockMemory(leasedKey);
    try {
      byte[] iv = new byte[12];
      RNG.nextBytes(iv);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(leasedKey, "AES"), new GCMParameterSpec(128, iv));
      if (aad != null && !aad.isEmpty()) {
        cipher.updateAAD(aad.getBytes("UTF-8"));
      }
      byte[] out = cipher.doFinal(plaintext.getBytes("UTF-8"));
      Map<String, String> result = new HashMap<>();
      result.put("alg", "AES-GCM");
      result.put("iv_b64", Base64.getEncoder().encodeToString(iv));
      result.put("ct_b64", Base64.getEncoder().encodeToString(out));
      result.put("payload", encodeWrappedPayload(leaseId, result.get("iv_b64"), result.get("ct_b64")));
      return result;
    } finally {
      NativeKeyCache.zeroize(leasedKey);
      NativeKeyCache.unlockMemory(leasedKey);
    }
  }

  public static String decryptLocal(byte[] leasedKey, String payload, String aad) throws Exception {
    NativeKeyCache.hardenProcess();
    NativeKeyCache.lockMemory(leasedKey);
    try {
      Map<String, String> parsed = decodeWrappedPayload(payload);
      byte[] iv = Base64.getDecoder().decode(parsed.get("iv_b64"));
      byte[] ciphertext = Base64.getDecoder().decode(parsed.get("ct_b64"));
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(leasedKey, "AES"), new GCMParameterSpec(128, iv));
      if (aad != null && !aad.isEmpty()) {
        cipher.updateAAD(aad.getBytes("UTF-8"));
      }
      byte[] plaintext = cipher.doFinal(ciphertext);
      return new String(plaintext, "UTF-8");
    } finally {
      NativeKeyCache.zeroize(leasedKey);
      NativeKeyCache.unlockMemory(leasedKey);
    }
  }

  public static String encodeWrappedPayload(String leaseId, String ivB64, String ciphertextB64) {
    return WRAPPED_PREFIX + ":" + safe(leaseId) + ":" + safe(ivB64) + ":" + safe(ciphertextB64);
  }

  public static Map<String, String> decodeWrappedPayload(String payload) {
    if (payload == null || payload.isEmpty()) {
      throw new IllegalArgumentException("payload is empty");
    }
    String[] parts = payload.split(":", 5);
    if (parts.length != 5 || !WRAPPED_PREFIX.equals(parts[0] + ":" + parts[1])) {
      throw new IllegalArgumentException("payload format is invalid");
    }
    Map<String, String> out = new HashMap<>();
    out.put("lease_id", parts[2]);
    out.put("iv_b64", parts[3]);
    out.put("ct_b64", parts[4]);
    return out;
  }

  private static String safe(String value) {
    return value == null ? "" : value;
  }

  // For policy-denied operations, wrappers must call remote KMS endpoints.
  public static boolean requiresRemoteFallback(boolean cacheEnabled, boolean localAllowed) {
    return !cacheEnabled || !localAllowed;
  }
}
`
}

func wrapperSDKJavaFieldPolicy() string {
	return `package com.vecta.fieldencryption;

public final class FieldPolicy {
  public final String fieldId;
  public final String writeAction;
  public final String readAction;
  public final boolean localAllowed;
  public final String aad;

  public FieldPolicy(String fieldId, String writeAction, String readAction, boolean localAllowed, String aad) {
    this.fieldId = fieldId == null ? "" : fieldId;
    this.writeAction = normalizeWriteAction(writeAction);
    this.readAction = normalizeReadAction(readAction);
    this.localAllowed = localAllowed;
    this.aad = aad == null ? "" : aad;
  }

  public boolean requiresWriteTransform() {
    return !"passthrough".equals(this.writeAction);
  }

  public boolean requiresReadTransform() {
    return !"passthrough".equals(this.readAction);
  }

  public boolean canLocalEncrypt() {
    return this.localAllowed && "encrypt".equals(this.writeAction);
  }

  public boolean canLocalDecrypt() {
    return this.localAllowed && "decrypt".equals(this.readAction);
  }

  private static String normalizeWriteAction(String action) {
    String raw = action == null ? "" : action.trim().toLowerCase();
    switch (raw) {
      case "encrypt":
      case "tokenize":
      case "redact":
      case "passthrough":
        return raw;
      default:
        return "passthrough";
    }
  }

  private static String normalizeReadAction(String action) {
    String raw = action == null ? "" : action.trim().toLowerCase();
    switch (raw) {
      case "decrypt":
      case "mask":
      case "token_only":
      case "redact":
      case "passthrough":
        return raw;
      default:
        return "passthrough";
    }
  }
}
`
}

func wrapperSDKJavaFieldProtectionRule() string {
	return `package com.vecta.fieldencryption;

public final class FieldProtectionRule {
  public String profileId = "";
  public String profileName = "";
  public int priority = 0;

  public String ruleId = "";
  public String dataClass = "";
  public String table = "";
  public String column = "";
  public String jsonPath = "";

  public String writeAction = "passthrough";
  public String readAction = "passthrough";
  public String algorithm = "";
  public String keyId = "";
  public String tokenVaultId = "";
  public String maskPattern = "";
  public String redactionPolicyId = "";
}
`
}

func wrapperSDKJavaFieldProtectionBundle() string {
	return `package com.vecta.fieldencryption;

import java.util.ArrayList;
import java.util.List;

public final class FieldProtectionBundle {
  public String tenantId = "";
  public String appId = "";
  public String wrapperId = "";
  public String etag = "";
  public int cacheTtlSec = 300;
  public String generatedAt = "";
  public List<FieldProtectionRule> rules = new ArrayList<>();

  public FieldProtectionRule findRule(String ruleId) {
    if (ruleId == null || ruleId.isEmpty()) {
      return null;
    }
    for (FieldProtectionRule item : rules) {
      if (item == null) {
        continue;
      }
      if (ruleId.equalsIgnoreCase(safe(item.ruleId))) {
        return item;
      }
    }
    return null;
  }

  public static String safe(String value) {
    return value == null ? "" : value;
  }
}
`
}

func wrapperSDKJavaPolicyResolverClient() string {
	return `package com.vecta.fieldencryption;

public interface PolicyResolverClient {
  PolicyResolverResponse resolve(ResolveRequest request, String ifNoneMatch) throws Exception;

  final class ResolveRequest {
    public final String tenantId;
    public final String appId;
    public final String wrapperId;
    public final String role;
    public final String purpose;
    public final String workflow;
    public final String wrapperToken;
    public final String wrapperCertFingerprint;

    public ResolveRequest(
      String tenantId,
      String appId,
      String wrapperId,
      String role,
      String purpose,
      String workflow,
      String wrapperToken,
      String wrapperCertFingerprint
    ) {
      this.tenantId = safe(tenantId);
      this.appId = safe(appId);
      this.wrapperId = safe(wrapperId);
      this.role = safe(role);
      this.purpose = safe(purpose);
      this.workflow = safe(workflow);
      this.wrapperToken = safe(wrapperToken);
      this.wrapperCertFingerprint = safe(wrapperCertFingerprint);
    }
  }

  final class PolicyResolverResponse {
    public final int statusCode;
    public final String etag;
    public final int cacheTtlSec;
    public final FieldProtectionBundle bundle;

    public PolicyResolverResponse(int statusCode, String etag, int cacheTtlSec, FieldProtectionBundle bundle) {
      this.statusCode = statusCode;
      this.etag = safe(etag);
      this.cacheTtlSec = cacheTtlSec <= 0 ? 300 : cacheTtlSec;
      this.bundle = bundle;
    }
  }

  static String safe(String value) {
    return value == null ? "" : value;
  }
}
`
}

func wrapperSDKJavaHTTPPolicyResolverClient() string {
	return `package com.vecta.fieldencryption;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public final class HttpPolicyResolverClient implements PolicyResolverClient {
  private final String baseUrl;
  private final HttpClient client;
  private final ObjectMapper mapper;
  private final Duration timeout;

  public HttpPolicyResolverClient(String baseUrl) {
    this(baseUrl, HttpClient.newBuilder().build(), Duration.ofSeconds(10));
  }

  public HttpPolicyResolverClient(String baseUrl, HttpClient client, Duration timeout) {
    this.baseUrl = trimSlash(baseUrl);
    this.client = client;
    this.timeout = timeout == null ? Duration.ofSeconds(10) : timeout;
    this.mapper = new ObjectMapper();
    this.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    this.mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
  }

  @Override
  public PolicyResolverResponse resolve(ResolveRequest request, String ifNoneMatch) throws Exception {
    String url = buildURL(request);
    HttpRequest.Builder httpReq = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(timeout)
      .header("Accept", "application/json")
      .header("X-Tenant-ID", request.tenantId)
      .GET();
    if (request.wrapperToken != null && !request.wrapperToken.isEmpty()) {
      httpReq.header("X-Wrapper-Token", request.wrapperToken);
    }
    if (request.wrapperCertFingerprint != null && !request.wrapperCertFingerprint.isEmpty()) {
      httpReq.header("X-Wrapper-Cert-Fingerprint", request.wrapperCertFingerprint);
    }
    if (ifNoneMatch != null && !ifNoneMatch.isEmpty()) {
      httpReq.header("If-None-Match", ifNoneMatch);
    }

    HttpResponse<String> response = client.send(httpReq.build(), HttpResponse.BodyHandlers.ofString());
    String etag = normalizeETag(response.headers().firstValue("etag").orElse(""));

    if (response.statusCode() == 304) {
      int ttl = extractTTL(response.headers().firstValue("cache-control").orElse(""));
      return new PolicyResolverResponse(304, etag, ttl, null);
    }
    if (response.statusCode() != 200) {
      throw new IllegalStateException("policy resolve failed with status " + response.statusCode() + ": " + response.body());
    }

    JsonNode root = mapper.readTree(response.body());
    JsonNode bundleNode = root.get("bundle");
    if (bundleNode == null || bundleNode.isNull()) {
      throw new IllegalStateException("policy resolve response is missing bundle");
    }
    FieldProtectionBundle bundle = mapper.treeToValue(bundleNode, FieldProtectionBundle.class);
    if ((etag == null || etag.isEmpty()) && bundle != null) {
      etag = normalizeETag(bundle.etag);
    }
    int ttl = bundle == null ? 300 : bundle.cacheTtlSec;
    if (ttl <= 0) {
      ttl = extractTTL(response.headers().firstValue("cache-control").orElse(""));
    }
    return new PolicyResolverResponse(200, etag, ttl, bundle);
  }

  private String buildURL(ResolveRequest request) {
    StringBuilder out = new StringBuilder();
    out.append(baseUrl).append("/field-protection/resolve");
    out.append("?app_id=").append(encode(request.appId));
    if (!safe(request.wrapperId).isEmpty()) {
      out.append("&wrapper_id=").append(encode(request.wrapperId));
    }
    if (!safe(request.role).isEmpty()) {
      out.append("&role=").append(encode(request.role));
    }
    if (!safe(request.purpose).isEmpty()) {
      out.append("&purpose=").append(encode(request.purpose));
    }
    if (!safe(request.workflow).isEmpty()) {
      out.append("&workflow=").append(encode(request.workflow));
    }
    return out.toString();
  }

  private static String encode(String value) {
    return URLEncoder.encode(safe(value), StandardCharsets.UTF_8);
  }

  private static String safe(String value) {
    return value == null ? "" : value;
  }

  private static String trimSlash(String value) {
    String out = safe(value).trim();
    while (out.endsWith("/")) {
      out = out.substring(0, out.length() - 1);
    }
    return out;
  }

  private static String normalizeETag(String value) {
    String out = safe(value).trim();
    if (out.startsWith("W/")) {
      out = out.substring(2).trim();
    }
    if (out.startsWith("\"") && out.endsWith("\"") && out.length() >= 2) {
      out = out.substring(1, out.length() - 1);
    }
    return out.trim();
  }

  private static int extractTTL(String cacheControl) {
    String raw = safe(cacheControl).toLowerCase();
    String[] parts = raw.split(",");
    for (String part : parts) {
      String token = part.trim();
      if (!token.startsWith("max-age=")) {
        continue;
      }
      try {
        int ttl = Integer.parseInt(token.substring("max-age=".length()).trim());
        if (ttl > 0) {
          return ttl;
        }
      } catch (NumberFormatException ignored) {
      }
    }
    return 300;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class Envelope {
    public FieldProtectionBundle bundle;
  }
}
`
}

func wrapperSDKJavaPolicyBundleCache() string {
	return `package com.vecta.fieldencryption;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class PolicyBundleCache {
  private final ConcurrentMap<String, Entry> items = new ConcurrentHashMap<>();

  public Entry get(String key) {
    if (key == null || key.isEmpty()) {
      return null;
    }
    return items.get(key);
  }

  public void put(String key, String etag, int ttlSec, FieldProtectionBundle bundle, long nowMillis) {
    if (key == null || key.isEmpty() || bundle == null) {
      return;
    }
    int ttl = ttlSec <= 0 ? 300 : ttlSec;
    long expiresAt = nowMillis + (ttl * 1000L);
    items.put(key, new Entry(etag, expiresAt, bundle));
  }

  public void touch(String key, int ttlSec, long nowMillis) {
    Entry existing = get(key);
    if (existing == null) {
      return;
    }
    int ttl = ttlSec <= 0 ? 300 : ttlSec;
    items.put(key, new Entry(existing.etag, nowMillis + (ttl * 1000L), existing.bundle));
  }

  public static final class Entry {
    public final String etag;
    public final long expiresAtMillis;
    public final FieldProtectionBundle bundle;

    public Entry(String etag, long expiresAtMillis, FieldProtectionBundle bundle) {
      this.etag = etag == null ? "" : etag;
      this.expiresAtMillis = expiresAtMillis;
      this.bundle = bundle;
    }

    public boolean isExpired(long nowMillis) {
      return bundle == null || expiresAtMillis <= nowMillis;
    }
  }
}
`
}

func wrapperSDKJavaPolicyAwareRuntimeContext() string {
	return `package com.vecta.fieldencryption;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class PolicyAwareRuntimeContext implements RuntimeContext {
  public interface Delegate {
    LeaseContext leaseForRule(FieldProtectionRule rule, String operation) throws Exception;
    String remoteWriteTransform(FieldProtectionRule rule, String plaintext) throws Exception;
    String remoteReadTransform(FieldProtectionRule rule, String ciphertext) throws Exception;
    void submitReceipt(LeaseContext lease, String operation, int opCount, String status) throws Exception;
  }

  private final PolicyResolverClient resolver;
  private final PolicyBundleCache cache;
  private final PolicyResolverClient.ResolveRequest resolveRequest;
  private final Delegate delegate;
  private final ConcurrentMap<String, String> parameterRuleMapping = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, String> columnRuleMapping = new ConcurrentHashMap<>();
  private final Object sync = new Object();

  public PolicyAwareRuntimeContext(
    PolicyResolverClient resolver,
    PolicyBundleCache cache,
    PolicyResolverClient.ResolveRequest resolveRequest,
    Delegate delegate
  ) {
    this.resolver = Objects.requireNonNull(resolver, "resolver");
    this.cache = cache == null ? new PolicyBundleCache() : cache;
    this.resolveRequest = Objects.requireNonNull(resolveRequest, "resolveRequest");
    this.delegate = Objects.requireNonNull(delegate, "delegate");
  }

  public void registerParameterMapping(String sql, int parameterIndex, String ruleId) {
    parameterRuleMapping.put(paramMappingKey(sql, parameterIndex), safe(ruleId));
  }

  public void registerColumnMapping(String sql, String columnLabel, String ruleId) {
    columnRuleMapping.put(columnMappingKey(sql, columnLabel), safe(ruleId));
  }

  @Override
  public FieldPolicy policyForParameter(String sql, int parameterIndex) {
    String ruleId = parameterRuleMapping.get(paramMappingKey(sql, parameterIndex));
    if (ruleId == null || ruleId.isEmpty()) {
      return null;
    }
    FieldProtectionRule rule = findRule(ruleId);
    if (rule == null) {
      return null;
    }
    return toFieldPolicy(rule);
  }

  @Override
  public FieldPolicy policyForColumn(String sql, String columnLabel) {
    String ruleId = columnRuleMapping.get(columnMappingKey(sql, columnLabel));
    if (ruleId == null || ruleId.isEmpty()) {
      return null;
    }
    FieldProtectionRule rule = findRule(ruleId);
    if (rule == null) {
      return null;
    }
    return toFieldPolicy(rule);
  }

  @Override
  public LeaseContext leaseForPolicy(FieldPolicy policy, String operation) throws Exception {
    FieldProtectionRule rule = findRule(policy == null ? "" : policy.fieldId);
    if (rule == null) {
      throw new IllegalStateException("field policy rule is not resolved");
    }
    return delegate.leaseForRule(rule, operation);
  }

  @Override
  public String remoteWriteTransform(FieldPolicy policy, String plaintext) throws Exception {
    FieldProtectionRule rule = findRule(policy == null ? "" : policy.fieldId);
    if (rule == null) {
      throw new IllegalStateException("field policy rule is not resolved");
    }
    return delegate.remoteWriteTransform(rule, plaintext);
  }

  @Override
  public String remoteReadTransform(FieldPolicy policy, String ciphertext) throws Exception {
    FieldProtectionRule rule = findRule(policy == null ? "" : policy.fieldId);
    if (rule == null) {
      throw new IllegalStateException("field policy rule is not resolved");
    }
    return delegate.remoteReadTransform(rule, ciphertext);
  }

  @Override
  public void submitReceipt(LeaseContext lease, String operation, int opCount, String status) throws Exception {
    delegate.submitReceipt(lease, operation, opCount, status);
  }

  private FieldProtectionRule findRule(String ruleId) {
    if (ruleId == null || ruleId.isEmpty()) {
      return null;
    }
    try {
      FieldProtectionBundle bundle = resolveBundle();
      if (bundle == null) {
        return null;
      }
      return bundle.findRule(ruleId);
    } catch (Exception ignored) {
      return null;
    }
  }

  private FieldProtectionBundle resolveBundle() throws Exception {
    String cacheKey = cacheKey(resolveRequest);
    long now = System.currentTimeMillis();
    PolicyBundleCache.Entry existing = cache.get(cacheKey);
    if (existing != null && !existing.isExpired(now)) {
      return existing.bundle;
    }

    synchronized (sync) {
      existing = cache.get(cacheKey);
      if (existing != null && !existing.isExpired(now)) {
        return existing.bundle;
      }
      String ifNoneMatch = existing == null ? "" : existing.etag;
      PolicyResolverClient.PolicyResolverResponse response = resolver.resolve(resolveRequest, ifNoneMatch);
      if (response.statusCode == 304) {
        if (existing == null || existing.bundle == null) {
          throw new IllegalStateException("policy resolver returned 304 without cached bundle");
        }
        cache.touch(cacheKey, response.cacheTtlSec, now);
        return existing.bundle;
      }
      if (response.bundle == null) {
        throw new IllegalStateException("policy resolver returned empty bundle");
      }
      cache.put(cacheKey, response.etag, response.cacheTtlSec, response.bundle, now);
      return response.bundle;
    }
  }

  private static FieldPolicy toFieldPolicy(FieldProtectionRule rule) {
    String writeAction = lower(rule.writeAction);
    String readAction = lower(rule.readAction);
    boolean localAllowed = "encrypt".equals(writeAction) || "decrypt".equals(readAction);
    String aad = "tenant=" + safe(rule.profileId) + "|rule=" + safe(rule.ruleId);
    return new FieldPolicy(safe(rule.ruleId), writeAction, readAction, localAllowed, aad);
  }

  private static String cacheKey(PolicyResolverClient.ResolveRequest request) {
    return safe(request.tenantId) + "|" +
      safe(request.appId) + "|" +
      safe(request.wrapperId) + "|" +
      safe(request.role) + "|" +
      safe(request.purpose) + "|" +
      safe(request.workflow);
  }

  private static String paramMappingKey(String sql, int parameterIndex) {
    return safe(sql) + "|p|" + parameterIndex;
  }

  private static String columnMappingKey(String sql, String columnLabel) {
    return safe(sql) + "|c|" + lower(columnLabel);
  }

  private static String safe(String value) {
    return value == null ? "" : value.trim();
  }

  private static String lower(String value) {
    return safe(value).toLowerCase();
  }
}
`
}

func wrapperSDKJavaLeaseContext() string {
	return `package com.vecta.fieldencryption;

public final class LeaseContext {
  public final String leaseId;
  public final String wrapperId;
  public final String keyId;
  public final byte[] keyMaterial;

  public LeaseContext(String leaseId, String wrapperId, String keyId, byte[] keyMaterial) {
    this.leaseId = leaseId == null ? "" : leaseId;
    this.wrapperId = wrapperId == null ? "" : wrapperId;
    this.keyId = keyId == null ? "" : keyId;
    this.keyMaterial = keyMaterial;
  }
}
`
}

func wrapperSDKJavaRuntimeContext() string {
	return `package com.vecta.fieldencryption;

public interface RuntimeContext {
  FieldPolicy policyForParameter(String sql, int parameterIndex);
  FieldPolicy policyForColumn(String sql, String columnLabel);
  LeaseContext leaseForPolicy(FieldPolicy policy, String operation) throws Exception;
  String remoteWriteTransform(FieldPolicy policy, String plaintext) throws Exception;
  String remoteReadTransform(FieldPolicy policy, String ciphertext) throws Exception;
  void submitReceipt(LeaseContext lease, String operation, int opCount, String status) throws Exception;
}
`
}

func wrapperSDKJavaJdbcInterceptor() string {
	return `package com.vecta.fieldencryption;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.Map;
import java.util.logging.Logger;

public final class JdbcFieldEncryptionInterceptor {
  private JdbcFieldEncryptionInterceptor() {}

  public static DataSource wrap(DataSource delegate, RuntimeContext runtime) {
    return new WrappedDataSource(delegate, runtime);
  }

  private static Connection wrapConnection(Connection delegate, RuntimeContext runtime) {
    return (Connection) Proxy.newProxyInstance(
      Connection.class.getClassLoader(),
      new Class[]{Connection.class},
      new ConnectionHandler(delegate, runtime)
    );
  }

  private static PreparedStatement wrapPreparedStatement(PreparedStatement delegate, String sql, RuntimeContext runtime) {
    return (PreparedStatement) Proxy.newProxyInstance(
      PreparedStatement.class.getClassLoader(),
      new Class[]{PreparedStatement.class},
      new PreparedStatementHandler(delegate, sql, runtime)
    );
  }

  private static ResultSet wrapResultSet(ResultSet delegate, String sql, RuntimeContext runtime) {
    return (ResultSet) Proxy.newProxyInstance(
      ResultSet.class.getClassLoader(),
      new Class[]{ResultSet.class},
      new ResultSetHandler(delegate, sql, runtime)
    );
  }

  private static final class ConnectionHandler implements InvocationHandler {
    private final Connection delegate;
    private final RuntimeContext runtime;

    private ConnectionHandler(Connection delegate, RuntimeContext runtime) {
      this.delegate = delegate;
      this.runtime = runtime;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String name = method.getName();
      try {
        if ("prepareStatement".equals(name) && args != null && args.length > 0 && args[0] instanceof String) {
          String sql = (String) args[0];
          Object out = method.invoke(delegate, args);
          if (out instanceof PreparedStatement) {
            return wrapPreparedStatement((PreparedStatement) out, sql, runtime);
          }
          return out;
        }
        if ("createStatement".equals(name)) {
          Object out = method.invoke(delegate, args);
          if (out instanceof Statement) {
            return out;
          }
        }
        return method.invoke(delegate, args);
      } catch (InvocationTargetException ex) {
        throw ex.getTargetException();
      }
    }
  }

  private static final class PreparedStatementHandler implements InvocationHandler {
    private final PreparedStatement delegate;
    private final String sql;
    private final RuntimeContext runtime;

    private PreparedStatementHandler(PreparedStatement delegate, String sql, RuntimeContext runtime) {
      this.delegate = delegate;
      this.sql = sql;
      this.runtime = runtime;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String name = method.getName();
      try {
        if (("setString".equals(name) || "setNString".equals(name)) && args != null && args.length >= 2 && args[0] instanceof Integer) {
          int index = ((Integer) args[0]).intValue();
          String value = args[1] == null ? null : String.valueOf(args[1]);
          FieldPolicy policy = runtime.policyForParameter(sql, index);
          if (policy != null && policy.requiresWriteTransform() && value != null) {
            args[1] = transformWrite(runtime, policy, value);
          }
          return method.invoke(delegate, args);
        }
        if ("setObject".equals(name) && args != null && args.length >= 2 && args[0] instanceof Integer) {
          int index = ((Integer) args[0]).intValue();
          Object raw = args[1];
          if (raw instanceof String) {
            FieldPolicy policy = runtime.policyForParameter(sql, index);
            if (policy != null && policy.requiresWriteTransform()) {
              args[1] = transformWrite(runtime, policy, (String) raw);
            }
          }
          return method.invoke(delegate, args);
        }
        Object out = method.invoke(delegate, args);
        if (out instanceof ResultSet) {
          return wrapResultSet((ResultSet) out, sql, runtime);
        }
        return out;
      } catch (InvocationTargetException ex) {
        throw ex.getTargetException();
      }
    }
  }

  private static final class ResultSetHandler implements InvocationHandler {
    private final ResultSet delegate;
    private final String sql;
    private final RuntimeContext runtime;

    private ResultSetHandler(ResultSet delegate, String sql, RuntimeContext runtime) {
      this.delegate = delegate;
      this.sql = sql;
      this.runtime = runtime;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String name = method.getName();
      try {
        Object out = method.invoke(delegate, args);
        if ("getString".equals(name) && out instanceof String) {
          String columnLabel = "";
          if (args != null && args.length > 0 && args[0] != null) {
            columnLabel = String.valueOf(args[0]);
          }
          FieldPolicy policy = runtime.policyForColumn(sql, columnLabel);
          if (policy != null && policy.requiresReadTransform()) {
            return transformRead(runtime, policy, (String) out);
          }
        }
        return out;
      } catch (InvocationTargetException ex) {
        throw ex.getTargetException();
      }
    }
  }

  private static String transformWrite(RuntimeContext runtime, FieldPolicy policy, String plaintext) throws Exception {
    if (plaintext == null || plaintext.isEmpty()) {
      return plaintext;
    }
    if (policy == null || !policy.requiresWriteTransform()) {
      return plaintext;
    }
    String writeAction = lower(policy.writeAction);
    if ("passthrough".equals(writeAction)) {
      return plaintext;
    }
    if (!"encrypt".equals(writeAction)) {
      return runtime.remoteWriteTransform(policy, plaintext);
    }
    if (!policy.canLocalEncrypt()) {
      return runtime.remoteWriteTransform(policy, plaintext);
    }
    try {
      LeaseContext lease = runtime.leaseForPolicy(policy, "encrypt");
      Map<String, String> local = FieldEncryptionRuntime.encryptLocal(lease.keyMaterial, plaintext, policy.aad, lease.leaseId);
      runtime.submitReceipt(lease, "encrypt", 1, "ok");
      return local.get("payload");
    } catch (Exception localError) {
      return runtime.remoteWriteTransform(policy, plaintext);
    }
  }

  private static String transformRead(RuntimeContext runtime, FieldPolicy policy, String ciphertext) throws Exception {
    if (ciphertext == null || ciphertext.isEmpty()) {
      return ciphertext;
    }
    if (policy == null || !policy.requiresReadTransform()) {
      return ciphertext;
    }
    String readAction = lower(policy.readAction);
    if ("passthrough".equals(readAction)) {
      return ciphertext;
    }
    if (!"decrypt".equals(readAction)) {
      return runtime.remoteReadTransform(policy, ciphertext);
    }
    if (!policy.canLocalDecrypt() || !ciphertext.startsWith("vecta:gcm:")) {
      return runtime.remoteReadTransform(policy, ciphertext);
    }
    try {
      LeaseContext lease = runtime.leaseForPolicy(policy, "decrypt");
      String plaintext = FieldEncryptionRuntime.decryptLocal(lease.keyMaterial, ciphertext, policy.aad);
      runtime.submitReceipt(lease, "decrypt", 1, "ok");
      return plaintext;
    } catch (Exception localError) {
      return runtime.remoteReadTransform(policy, ciphertext);
    }
  }

  private static String lower(String value) {
    return value == null ? "" : value.trim().toLowerCase();
  }

  private static final class WrappedDataSource implements DataSource {
    private final DataSource delegate;
    private final RuntimeContext runtime;

    private WrappedDataSource(DataSource delegate, RuntimeContext runtime) {
      this.delegate = delegate;
      this.runtime = runtime;
    }

    @Override
    public Connection getConnection() throws SQLException {
      return wrapConnection(delegate.getConnection(), runtime);
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
      return wrapConnection(delegate.getConnection(username, password), runtime);
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
      return delegate.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
      delegate.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
      delegate.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
      return delegate.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
      return delegate.getParentLogger();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
      return delegate.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
      return delegate.isWrapperFor(iface);
    }
  }
}
`
}

func wrapperSDKNativeC() string {
	return `#include <jni.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#endif

static void wipe(uint8_t *p, size_t n) {
  if (!p || n == 0) return;
  volatile uint8_t *v = (volatile uint8_t*)p;
  while (n--) {
    *v++ = 0;
  }
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_hardenProcess
  (JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
#if defined(_WIN32)
  return 0;
#else
  struct rlimit lim;
  lim.rlim_cur = 0;
  lim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &lim); // best effort
#if defined(__linux__)
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); // best effort
#endif
  return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_lockMemory
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return -1;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return -2;
  jsize n = (*env)->GetArrayLength(env, arr);
#if defined(_WIN32)
  BOOL ok = VirtualLock((LPVOID)p, (SIZE_T)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return ok ? 0 : -3;
#else
  int rc = mlock((const void*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return rc == 0 ? 0 : -3;
#endif
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_unlockMemory
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return -1;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return -2;
  jsize n = (*env)->GetArrayLength(env, arr);
#if defined(_WIN32)
  BOOL ok = VirtualUnlock((LPVOID)p, (SIZE_T)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return ok ? 0 : -3;
#else
  int rc = munlock((const void*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return rc == 0 ? 0 : -3;
#endif
}

JNIEXPORT void JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_zeroize
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return;
  jsize n = (*env)->GetArrayLength(env, arr);
  wipe((uint8_t*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
}
`
}

func wrapperSDKBuildLinux() string {
	return `#!/usr/bin/env bash
set -euo pipefail
JAVA_HOME="${JAVA_HOME:-}"
if [[ -z "${JAVA_HOME}" ]]; then
  echo "JAVA_HOME is required"
  exit 1
fi
mkdir -p native/build
cc -O2 -fPIC -shared \
  -I"${JAVA_HOME}/include" \
  -I"${JAVA_HOME}/include/linux" \
  native/vecta_field_native.c \
  -o native/build/libvecta_field_native.so
echo "Built native/build/libvecta_field_native.so"
`
}

func wrapperSDKBuildMacOS() string {
	return `#!/usr/bin/env bash
set -euo pipefail
JAVA_HOME="${JAVA_HOME:-}"
if [[ -z "${JAVA_HOME}" ]]; then
  echo "JAVA_HOME is required"
  exit 1
fi
mkdir -p native/build
cc -O2 -fPIC -dynamiclib \
  -I"${JAVA_HOME}/include" \
  -I"${JAVA_HOME}/include/darwin" \
  native/vecta_field_native.c \
  -o native/build/libvecta_field_native.dylib
echo "Built native/build/libvecta_field_native.dylib"
`
}

func wrapperSDKBuildWindows() string {
	newline := "\r\n"
	lines := []string{
		"$ErrorActionPreference = \"Stop\"",
		"if (-not $env:JAVA_HOME) {",
		"  throw \"JAVA_HOME is required\"",
		"}",
		"New-Item -ItemType Directory -Force -Path native\\build | Out-Null",
		"cl /LD /O2 /I\"$env:JAVA_HOME\\include\" /I\"$env:JAVA_HOME\\include\\win32\" native\\vecta_field_native.c /Fe:native\\build\\vecta_field_native.dll",
		"Write-Host \"Built native\\build\\vecta_field_native.dll\"",
	}
	return strings.Join(lines, newline) + newline
}
