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
	"strings"
	"time"
)

// GetSDKOverview lists the client SDK Vecta ships: the Java JCA provider,
// with the services it registers (services/jca-provider). Vecta ships no
// PKCS#11 module, and nothing observes SDK sessions or mechanisms, so no
// usage figures are reported.
func (s *Service) GetSDKOverview(ctx context.Context, tenantID string) (SDKOverview, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return SDKOverview{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	out := SDKOverview{
		RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Providers: []SDKProviderSummary{{
			ID:           "jca",
			Name:         "Java JCA/JCE Provider",
			ArtifactName: "vecta-jca-sdk-all.zip",
			Version:      "source",
			Status:       "available",
			SizeLabel:    humanizeBytes(estimatedSDKSize("jca", "all")),
			Transport:    "HTTPS (mTLS or bearer token)",
			Platforms:    []string{"Java 11+"},
			Capabilities: []string{"Cipher AES/GCM/NoPadding", "Signature SHA256withRSA", "Signature SHA256withECDSA", "KeyStore VectaKMS"},
		}},
		Mechanisms: []SDKMechanismUsage{},
		Clients:    []SDKClient{},
	}
	_ = s.publishAudit(ctx, "audit.ekm.sdk_overview_viewed", tenantID, map[string]interface{}{"providers": len(out.Providers)})
	return out, nil
}

func (s *Service) BuildSDKArtifact(ctx context.Context, tenantID string, provider string, targetOS string) (SDKDownloadArtifact, error) {
	tenantID = strings.TrimSpace(tenantID)
	provider = normalizeSDKProvider(provider)
	targetOS = normalizeSDKTargetOS(targetOS)
	if tenantID == "" {
		return SDKDownloadArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if provider == "" {
		return SDKDownloadArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "provider is required")
	}
	if targetOS == "" {
		targetOS = defaultSDKTarget(provider)
	}

	payload, filename, err := buildSDKArchive(provider, targetOS)
	if err != nil {
		return SDKDownloadArtifact{}, err
	}
	sum := sha256.Sum256(payload)
	out := SDKDownloadArtifact{
		Provider:    provider,
		TargetOS:    targetOS,
		Filename:    filename,
		ContentType: "application/zip",
		Encoding:    "base64",
		Content:     base64.StdEncoding.EncodeToString(payload),
		SizeBytes:   len(payload),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	_ = s.publishAudit(ctx, "audit.ekm.sdk_downloaded", tenantID, map[string]interface{}{
		"provider":   provider,
		"target_os":  targetOS,
		"filename":   filename,
		"size_bytes": len(payload),
		"sha256":     out.SHA256,
	})
	return out, nil
}

func buildSDKArchive(provider string, targetOS string) ([]byte, string, error) {
	files := sdkFiles(provider, targetOS)
	if len(files) == 0 {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "unsupported sdk provider")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, content := range files {
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
	filename := fmt.Sprintf("vecta-%s-sdk-%s.zip", provider, targetOS)
	return buf.Bytes(), filename, nil
}

func sdkFiles(provider string, targetOS string) map[string]string {
	switch normalizeSDKProvider(provider) {
	case "jca":
		return jcaSDKFiles()
	default:
		return map[string]string{}
	}
}

func jcaSDKFiles() map[string]string {
	readme := `# Vecta Java SDK (JCA/JCE Provider)

This package includes both the full JCA security provider and a Java client starter.

## Full JCA Provider

The Vecta JCA Provider (vecta-jca-provider.jar) for Java 11+ registers:
  Cipher: AES/GCM/NoPadding (local cache if exportable, else remote KMS)
  Signature: SHA256withRSA, SHA256withECDSA (always remote)
  KeyStore: VectaKMS (enumerate/load keys from KMS)

Source: services/jca-provider/ in the Vecta KMS repository.

Setup:
  Security.addProvider(new VectaKMSProvider());
  // OR add to java.security: security.provider.N=com.vecta.kms.VectaKMSProvider

Build from source:
  cd services/jca-provider && mvn package

## Authentication

Four methods (priority order):
  1. mTLS: VECTA_MTLS_CERT, VECTA_MTLS_KEY, VECTA_MTLS_CA
  2. JWT: VECTA_API_KEY + VECTA_JWT_ENDPOINT
  3. API Key: VECTA_API_KEY
  4. Bearer: VECTA_AUTH_TOKEN

## Key Caching

Set VECTA_KEY_CACHE_TTL=300 for local key caching. Uses java.lang.ref.Cleaner
for GC-triggered zeroization plus explicit Arrays.fill on eviction.

## Java Client Starter

Build:
  mvn -q -DskipTests package

Run:
  java -jar target/vecta-jca-provider.jar register-client root app1 ops@acme.com
  java -jar target/vecta-jca-provider.jar wrap root key_123 BASE64PLAINTEXT

Environment:
  VECTA_BASE_URL, VECTA_AUTH_BASE_URL, VECTA_TOKEN, VECTA_AGENT_ID, VECTA_DATABASE_ID
`
	pom := `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.vecta</groupId>
  <artifactId>vecta-jca-provider</artifactId>
  <version>1.0.0</version>
  <properties><maven.compiler.source>11</maven.compiler.source><maven.compiler.target>11</maven.compiler.target></properties>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-jar-plugin</artifactId>
        <version>3.3.0</version>
        <configuration>
          <archive><manifest><mainClass>com.vecta.kms.Main</mainClass></manifest></archive>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
`
	client := `package com.vecta.kms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class VectaKMSClient {
  private final HttpClient client = HttpClient.newBuilder().build();
  private final String ekmBaseUrl;
  private final String authBaseUrl;
  private final String token;

  public VectaKMSClient(String ekmBaseUrl, String authBaseUrl, String token) {
    this.ekmBaseUrl = ekmBaseUrl;
    this.authBaseUrl = authBaseUrl;
    this.token = token;
  }

  private static String escapeJson(String value) {
    if (value == null) return "";
    return value
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r")
      .replace("\t", "\\t");
  }

  private String send(String method, String url, String tenantId, String body, boolean withAuth) throws IOException, InterruptedException {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .header("Content-Type", "application/json")
      .header("X-Tenant-ID", tenantId);
    if (withAuth) {
      if (token == null || token.isBlank()) {
        throw new IOException("VECTA_TOKEN is required for this operation");
      }
      builder.header("Authorization", "Bearer " + token);
    }
    if (body == null) {
      builder.method(method, HttpRequest.BodyPublishers.noBody());
    } else {
      builder.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
    }
    HttpResponse<String> out = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    if (out.statusCode() >= 300) {
      throw new IOException("request failed: " + out.statusCode() + " " + out.body());
    }
    return out.body();
  }

  public String registerClient(String tenantId, String clientName, String contactEmail, String clientType, String requestedRole)
      throws IOException, InterruptedException {
    String body = String.format(
      "{\"tenant_id\":\"%s\",\"client_name\":\"%s\",\"client_type\":\"%s\",\"contact_email\":\"%s\",\"requested_role\":\"%s\"}",
      escapeJson(tenantId), escapeJson(clientName), escapeJson(clientType), escapeJson(contactEmail), escapeJson(requestedRole)
    );
    return send("POST", authBaseUrl + "/auth/register", tenantId, body, false);
  }

  public String wrap(String tenantId, String keyId, String plaintextB64, String agentId, String databaseId)
      throws IOException, InterruptedException {
    String body = String.format(
      "{\"tenant_id\":\"%s\",\"plaintext\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
      escapeJson(tenantId), escapeJson(plaintextB64), escapeJson(agentId), escapeJson(databaseId)
    );
    return send("POST", ekmBaseUrl + "/ekm/tde/keys/" + keyId + "/wrap", tenantId, body, true);
  }

  public String unwrap(String tenantId, String keyId, String ciphertextB64, String ivB64, String agentId, String databaseId)
      throws IOException, InterruptedException {
    String body = String.format(
      "{\"tenant_id\":\"%s\",\"ciphertext\":\"%s\",\"iv\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
      escapeJson(tenantId), escapeJson(ciphertextB64), escapeJson(ivB64), escapeJson(agentId), escapeJson(databaseId)
    );
    return send("POST", ekmBaseUrl + "/ekm/tde/keys/" + keyId + "/unwrap", tenantId, body, true);
  }

  public String rotate(String tenantId, String keyId, String reason) throws IOException, InterruptedException {
    String body = String.format("{\"tenant_id\":\"%s\",\"reason\":\"%s\"}", escapeJson(tenantId), escapeJson(reason));
    return send("POST", ekmBaseUrl + "/ekm/tde/keys/" + keyId + "/rotate", tenantId, body, true);
  }

  public String publicKey(String tenantId, String keyId) throws IOException, InterruptedException {
    return send("GET", ekmBaseUrl + "/ekm/tde/keys/" + keyId + "/public?tenant_id=" + tenantId, tenantId, null, true);
  }
}
`
	main := `package com.vecta.kms;

public final class Main {
  private static void usage() {
    System.err.println("Usage:");
    System.err.println("  register-client <tenant_id> <client_name> <contact_email> [client_type] [requested_role]");
    System.err.println("  wrap           <tenant_id> <key_id> <plaintext_b64> [agent_id] [database_id]");
    System.err.println("  unwrap         <tenant_id> <key_id> <ciphertext_b64> <iv_b64> [agent_id] [database_id]");
    System.err.println("  rotate         <tenant_id> <key_id> [reason]");
    System.err.println("  public         <tenant_id> <key_id>");
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      usage();
      throw new IllegalArgumentException("operation is required");
    }
    String op = args[0];
    String base = System.getenv("VECTA_BASE_URL");
    String authBase = System.getenv("VECTA_AUTH_BASE_URL");
    String token = System.getenv("VECTA_TOKEN");
    String agent = System.getenv("VECTA_AGENT_ID");
    String db = System.getenv("VECTA_DATABASE_ID");
    if (base == null || base.isBlank()) {
      throw new IllegalStateException("VECTA_BASE_URL is required");
    }
    if (authBase == null || authBase.isBlank()) {
      throw new IllegalStateException("VECTA_AUTH_BASE_URL is required");
    }
    VectaKMSClient c = new VectaKMSClient(base, authBase, token);

    switch (op.toLowerCase()) {
      case "register-client": {
        if (args.length < 4) {
          usage();
          throw new IllegalArgumentException("register-client requires tenant_id, client_name, contact_email");
        }
        String tenantId = args[1];
        String clientName = args[2];
        String contactEmail = args[3];
        String clientType = args.length > 4 ? args[4] : "service";
        String requestedRole = args.length > 5 ? args[5] : "app-service";
        System.out.println(c.registerClient(tenantId, clientName, contactEmail, clientType, requestedRole));
        break;
      }
      case "wrap": {
        if (args.length < 4) {
          usage();
          throw new IllegalArgumentException("wrap requires tenant_id, key_id, plaintext_b64");
        }
        String tenantId = args[1];
        String keyId = args[2];
        String plaintextB64 = args[3];
        String agentId = args.length > 4 ? args[4] : (agent == null ? "" : agent);
        String databaseId = args.length > 5 ? args[5] : (db == null ? "" : db);
        System.out.println(c.wrap(tenantId, keyId, plaintextB64, agentId, databaseId));
        break;
      }
      case "unwrap": {
        if (args.length < 5) {
          usage();
          throw new IllegalArgumentException("unwrap requires tenant_id, key_id, ciphertext_b64, iv_b64");
        }
        String tenantId = args[1];
        String keyId = args[2];
        String ciphertextB64 = args[3];
        String ivB64 = args[4];
        String agentId = args.length > 5 ? args[5] : (agent == null ? "" : agent);
        String databaseId = args.length > 6 ? args[6] : (db == null ? "" : db);
        System.out.println(c.unwrap(tenantId, keyId, ciphertextB64, ivB64, agentId, databaseId));
        break;
      }
      case "rotate": {
        if (args.length < 3) {
          usage();
          throw new IllegalArgumentException("rotate requires tenant_id and key_id");
        }
        String tenantId = args[1];
        String keyId = args[2];
        String reason = args.length > 3 ? args[3] : "manual";
        System.out.println(c.rotate(tenantId, keyId, reason));
        break;
      }
      case "public": {
        if (args.length < 3) {
          usage();
          throw new IllegalArgumentException("public requires tenant_id and key_id");
        }
        String tenantId = args[1];
        String keyId = args[2];
        System.out.println(c.publicKey(tenantId, keyId));
        break;
      }
      default:
        usage();
        throw new IllegalArgumentException("Unsupported operation: " + op);
    }
  }
}
`
	return map[string]string{
		"README.md": readme,
		"pom.xml":   pom,
		"src/main/java/com/vecta/kms/VectaKMSClient.java": client,
		"src/main/java/com/vecta/kms/Main.java":           main,
	}
}






func normalizeSDKProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "jca", "jce", "java":
		return "jca"
	default:
		return ""
	}
}

func normalizeSDKTargetOS(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "linux", "linux-amd64", "linux-x64":
		return "linux"
	case "windows", "win", "windows-x64":
		return "windows"
	case "mac", "macos", "darwin":
		return "macos"
	case "all", "":
		return "all"
	default:
		return ""
	}
}

func defaultSDKTarget(provider string) string {
	if normalizeSDKProvider(provider) == "jca" {
		return "all"
	}
	return "linux"
}

func estimatedSDKSize(provider string, targetOS string) int {
	raw, _, err := buildSDKArchive(provider, targetOS)
	if err != nil {
		return 0
	}
	return len(raw)
}

func humanizeBytes(n int) string {
	if n <= 0 {
		return "-"
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	kb := float64(n) / 1024.0
	if kb < 1024 {
		return fmt.Sprintf("%.0f KB", kb)
	}
	mb := kb / 1024.0
	if mb < 10 {
		return fmt.Sprintf("%.1f MB", mb)
	}
	return fmt.Sprintf("%.0f MB", mb)
}
