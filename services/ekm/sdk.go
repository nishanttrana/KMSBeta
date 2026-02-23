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
	"time"
)

func (s *Service) GetSDKOverview(ctx context.Context, tenantID string) (SDKOverview, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return SDKOverview{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	agents, err := s.ListAgents(ctx, tenantID)
	if err != nil {
		return SDKOverview{}, err
	}
	logs, err := s.store.ListKeyAccessByTenant(ctx, tenantID, time.Now().UTC().Add(-24*time.Hour), 20000)
	if err != nil {
		return SDKOverview{}, err
	}

	type mechAgg struct {
		total int64
	}
	mechanismOps := map[string]*mechAgg{}
	agentOps := map[string]int64{}
	agentMechOps := map[string]map[string]int64{}
	keyAlgByID := map[string]string{}

	for _, item := range logs {
		if strings.ToLower(strings.TrimSpace(item.Status)) != "success" {
			continue
		}
		keyID := strings.TrimSpace(item.KeyID)
		keyAlg := ""
		if keyID != "" {
			if v, ok := keyAlgByID[keyID]; ok {
				keyAlg = v
			} else if key, keyErr := s.store.GetTDEKey(ctx, tenantID, keyID); keyErr == nil {
				keyAlg = strings.TrimSpace(key.Algorithm)
				keyAlgByID[keyID] = keyAlg
			}
		}
		mech := mapOperationMechanism(strings.TrimSpace(item.Operation), keyAlg)
		if mech == "" {
			mech = "CKM_AES_GCM"
		}
		if _, ok := mechanismOps[mech]; !ok {
			mechanismOps[mech] = &mechAgg{}
		}
		mechanismOps[mech].total++

		agentID := strings.TrimSpace(item.AgentID)
		if agentID != "" {
			agentOps[agentID]++
			if _, ok := agentMechOps[agentID]; !ok {
				agentMechOps[agentID] = map[string]int64{}
			}
			agentMechOps[agentID][mech]++
		}
	}

	mechRows := make([]SDKMechanismUsage, 0, len(mechanismOps))
	totalOps := int64(0)
	for _, v := range mechanismOps {
		totalOps += v.total
	}
	for mech, v := range mechanismOps {
		pct := 0.0
		if totalOps > 0 {
			pct = (float64(v.total) / float64(totalOps)) * 100.0
		}
		mechRows = append(mechRows, SDKMechanismUsage{
			Mechanism: mech,
			Ops24h:    v.total,
			Percent:   pct,
		})
	}
	sort.Slice(mechRows, func(i, j int) bool {
		if mechRows[i].Ops24h == mechRows[j].Ops24h {
			return mechRows[i].Mechanism < mechRows[j].Mechanism
		}
		return mechRows[i].Ops24h > mechRows[j].Ops24h
	})

	pkcsOps := int64(0)
	jcaOps := int64(0)
	pkcsClients := 0
	jcaClients := 0
	sessionsActive := 0
	clientRows := make([]SDKClient, 0, len(agents))
	for _, agent := range agents {
		agentID := strings.TrimSpace(agent.ID)
		agentStatus := sdkStatusLabel(agent.Status)
		if strings.EqualFold(agentStatus, "Active") {
			sessionsActive++
		}
		meta := parseJSONMap(agent.MetadataJSON)
		clientSDK := detectClientSDK(agent, meta)
		ops := agentOps[agentID]
		topMech := topMechanism(agentMechOps[agentID])
		if topMech == "" {
			topMech = "CKM_AES_GCM"
		}
		if clientSDK == "jca" {
			jcaOps += ops
			jcaClients++
		} else {
			pkcsOps += ops
			pkcsClients++
		}
		clientRows = append(clientRows, SDKClient{
			ID:        agentID,
			Name:      defaultString(agent.Name, agentID),
			SDK:       sdkArtifactName(clientSDK),
			Mechanism: topMech,
			Ops24h:    ops,
			Status:    agentStatus,
		})
	}
	sort.Slice(clientRows, func(i, j int) bool {
		if clientRows[i].Ops24h == clientRows[j].Ops24h {
			return clientRows[i].Name < clientRows[j].Name
		}
		return clientRows[i].Ops24h > clientRows[j].Ops24h
	})

	// Keep the most relevant mechanism rows in dashboard summary.
	if len(mechRows) > 8 {
		mechRows = mechRows[:8]
	}
	topMech := "CKM_AES_GCM"
	if len(mechRows) > 0 {
		topMech = mechRows[0].Mechanism
	}

	pkcsSize := humanizeBytes(estimatedSDKSize("pkcs11", "linux"))
	jcaSize := humanizeBytes(estimatedSDKSize("jca", "all"))
	providers := []SDKProviderSummary{
		{
			ID:               "pkcs11",
			Name:             "PKCS#11 C Provider",
			ArtifactName:     "libvecta-pkcs11.so",
			Version:          "v2.40 / v3.0",
			Status:           "active",
			SizeLabel:        pkcsSize,
			Transport:        "HTTPS + mTLS",
			SessionsActive:   sessionsActive,
			Ops24h:           pkcsOps,
			ClientsConnected: pkcsClients,
			TopMechanism:     topMech,
			Platforms:        []string{"Linux .so", "macOS .dylib", "Windows .dll"},
			Capabilities:     []string{"Cipher", "Sign", "Verify", "Wrap", "Unwrap"},
		},
		{
			ID:               "jca",
			Name:             "Java JCA/JCE Provider",
			ArtifactName:     "vecta-jca-provider.jar",
			Version:          "VECTA v1.0",
			Status:           "active",
			SizeLabel:        jcaSize,
			Transport:        "HTTPS + mTLS",
			SessionsActive:   sessionsActive,
			Ops24h:           jcaOps,
			ClientsConnected: jcaClients,
			TopMechanism:     topMech,
			Platforms:        []string{"Java 11 LTS", "Java 17 LTS", "Java 21 LTS"},
			Capabilities:     []string{"Cipher", "Signature", "KeyStore", "KeyGen", "Mac", "SecureRandom"},
		},
	}
	out := SDKOverview{
		RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Providers:   providers,
		Mechanisms:  mechRows,
		Clients:     clientRows,
	}
	_ = s.publishAudit(ctx, "audit.ekm.sdk_overview_viewed", tenantID, map[string]interface{}{
		"providers": len(providers),
		"clients":   len(clientRows),
		"ops_24h":   totalOps,
	})
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
	case "pkcs11":
		return pkcs11SDKFiles(targetOS)
	case "jca":
		return jcaSDKFiles()
	default:
		return map[string]string{}
	}
}

func pkcs11SDKFiles(targetOS string) map[string]string {
	osLabel := strings.ToUpper(defaultString(targetOS, "linux"))
	readme := fmt.Sprintf(`# Vecta PKCS11 SDK (%s)

This package provides a real C client starter for Vecta EKM/TDE APIs.
Tenant binding model:
- Client chooses tenant at registration ("register-client" operation).
- Every crypto call requires explicit tenant_id argument.
- Server enforces tenant isolation and rejects tenant mismatch.

Files:
- examples/c/vecta_kms_client.c (libcurl-based C client)
- examples/c/Makefile
- config/vecta-kms.env.example
- scripts/run_sdk_demo.sh
- scripts/run_sdk_demo.ps1

Required environment:
- VECTA_BASE_URL (example: https://kms.example.com/svc/ekm)
- VECTA_AUTH_BASE_URL (example: https://kms.example.com)
- VECTA_TOKEN (required for crypto operations)
- VECTA_AGENT_ID
- VECTA_DATABASE_ID

Build:
  make -C examples/c

Examples:
  ./examples/c/vecta_kms_client register-client bank-alpha app1 ops@acme.com service app-service
  ./examples/c/vecta_kms_client wrap bank-alpha key_123 BASE64PLAINTEXT
  ./examples/c/vecta_kms_client public bank-alpha key_123

Target OS profile: %s
`, osLabel, osLabel)

	cClient := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct resp_buf { char *data; size_t size; };

static size_t on_write(void *ptr, size_t size, size_t nmemb, void *userdata) {
  size_t realsz = size * nmemb;
  struct resp_buf *buf = (struct resp_buf *)userdata;
  char *next = realloc(buf->data, buf->size + realsz + 1);
  if (!next) return 0;
  buf->data = next;
  memcpy(buf->data + buf->size, ptr, realsz);
  buf->size += realsz;
  buf->data[buf->size] = '\0';
  return realsz;
}

static void print_usage(void) {
  fprintf(stderr,
    "Usage:\n"
    "  vecta_kms_client register-client <tenant_id> <client_name> <contact_email> [client_type] [requested_role]\n"
    "  vecta_kms_client wrap           <tenant_id> <key_id> <plaintext_b64> [agent_id] [database_id]\n"
    "  vecta_kms_client unwrap         <tenant_id> <key_id> <ciphertext_b64> <iv_b64> [agent_id] [database_id]\n"
    "  vecta_kms_client rotate         <tenant_id> <key_id> [reason]\n"
    "  vecta_kms_client public         <tenant_id> <key_id>\n"
  );
}

static int http_json(
  const char *method,
  const char *url,
  const char *tenant,
  const char *token,
  const char *body,
  struct resp_buf *out
) {
  CURL *curl = curl_easy_init();
  if (!curl) return 2;
  struct curl_slist *headers = NULL;
  char auth[2048];
  char tenantHdr[512];
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (tenant && tenant[0]) {
    snprintf(tenantHdr, sizeof(tenantHdr), "X-Tenant-ID: %s", tenant);
    headers = curl_slist_append(headers, tenantHdr);
  }
  if (token && token[0]) {
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
    headers = curl_slist_append(headers, auth);
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
  if (body && body[0]) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (rc != CURLE_OK) return 3;
  return (code >= 300) ? 4 : 0;
}

int vecta_register_client(
  const char *auth_base,
  const char *tenant_id,
  const char *client_name,
  const char *contact_email,
  const char *client_type,
  const char *requested_role,
  struct resp_buf *out
) {
  char url[1024];
  char body[4096];
  snprintf(url, sizeof(url), "%s/auth/register", auth_base);
  snprintf(body, sizeof(body),
           "{\"tenant_id\":\"%s\",\"client_name\":\"%s\",\"client_type\":\"%s\",\"contact_email\":\"%s\",\"requested_role\":\"%s\"}",
           tenant_id, client_name, client_type, contact_email, requested_role);
  return http_json("POST", url, tenant_id, NULL, body, out);
}

int vecta_wrap(
  const char *base,
  const char *token,
  const char *tenant_id,
  const char *key_id,
  const char *plaintext_b64,
  const char *agent_id,
  const char *database_id,
  struct resp_buf *out
) {
  char url[1024];
  char body[4096];
  snprintf(url, sizeof(url), "%s/ekm/tde/keys/%s/wrap", base, key_id);
  snprintf(body, sizeof(body),
           "{\"tenant_id\":\"%s\",\"plaintext\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
           tenant_id, plaintext_b64, agent_id ? agent_id : "", database_id ? database_id : "");
  return http_json("POST", url, tenant_id, token, body, out);
}

int vecta_unwrap(
  const char *base,
  const char *token,
  const char *tenant_id,
  const char *key_id,
  const char *ciphertext_b64,
  const char *iv_b64,
  const char *agent_id,
  const char *database_id,
  struct resp_buf *out
) {
  char url[1024];
  char body[4096];
  snprintf(url, sizeof(url), "%s/ekm/tde/keys/%s/unwrap", base, key_id);
  snprintf(body, sizeof(body),
           "{\"tenant_id\":\"%s\",\"ciphertext\":\"%s\",\"iv\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
           tenant_id, ciphertext_b64, iv_b64, agent_id ? agent_id : "", database_id ? database_id : "");
  return http_json("POST", url, tenant_id, token, body, out);
}

int vecta_rotate(
  const char *base,
  const char *token,
  const char *tenant_id,
  const char *key_id,
  const char *reason,
  struct resp_buf *out
) {
  char url[1024];
  char body[1024];
  snprintf(url, sizeof(url), "%s/ekm/tde/keys/%s/rotate", base, key_id);
  snprintf(body, sizeof(body), "{\"tenant_id\":\"%s\",\"reason\":\"%s\"}", tenant_id, reason ? reason : "manual");
  return http_json("POST", url, tenant_id, token, body, out);
}

int vecta_public(
  const char *base,
  const char *token,
  const char *tenant_id,
  const char *key_id,
  struct resp_buf *out
) {
  char url[1024];
  snprintf(url, sizeof(url), "%s/ekm/tde/keys/%s/public?tenant_id=%s", base, key_id, tenant_id);
  return http_json("GET", url, tenant_id, token, NULL, out);
}

int main(int argc, char **argv) {
  const char *base = getenv("VECTA_BASE_URL");
  const char *authBase = getenv("VECTA_AUTH_BASE_URL");
  const char *token = getenv("VECTA_TOKEN");
  const char *defaultAgent = getenv("VECTA_AGENT_ID");
  const char *defaultDB = getenv("VECTA_DATABASE_ID");
  struct resp_buf out = {0};
  int rc = 0;

  if (argc < 2) {
    print_usage();
    return 1;
  }
  const char *op = argv[1];

  if (strcmp(op, "register-client") == 0) {
    if (!authBase || argc < 5) {
      fprintf(stderr, "VECTA_AUTH_BASE_URL is required for register-client\n");
      print_usage();
      return 1;
    }
    const char *tenant = argv[2];
    const char *clientName = argv[3];
    const char *contactEmail = argv[4];
    const char *clientType = (argc > 5) ? argv[5] : "service";
    const char *requestedRole = (argc > 6) ? argv[6] : "app-service";
    rc = vecta_register_client(authBase, tenant, clientName, contactEmail, clientType, requestedRole, &out);
  } else if (strcmp(op, "wrap") == 0) {
    if (!base || !token || argc < 5) {
      fprintf(stderr, "VECTA_BASE_URL and VECTA_TOKEN are required for wrap\n");
      print_usage();
      return 1;
    }
    const char *tenant = argv[2];
    const char *keyID = argv[3];
    const char *plaintextB64 = argv[4];
    const char *agent = (argc > 5) ? argv[5] : defaultAgent;
    const char *database = (argc > 6) ? argv[6] : defaultDB;
    rc = vecta_wrap(base, token, tenant, keyID, plaintextB64, agent, database, &out);
  } else if (strcmp(op, "unwrap") == 0) {
    if (!base || !token || argc < 6) {
      fprintf(stderr, "VECTA_BASE_URL and VECTA_TOKEN are required for unwrap\n");
      print_usage();
      return 1;
    }
    const char *tenant = argv[2];
    const char *keyID = argv[3];
    const char *cipherB64 = argv[4];
    const char *ivB64 = argv[5];
    const char *agent = (argc > 6) ? argv[6] : defaultAgent;
    const char *database = (argc > 7) ? argv[7] : defaultDB;
    rc = vecta_unwrap(base, token, tenant, keyID, cipherB64, ivB64, agent, database, &out);
  } else if (strcmp(op, "rotate") == 0) {
    if (!base || !token || argc < 4) {
      fprintf(stderr, "VECTA_BASE_URL and VECTA_TOKEN are required for rotate\n");
      print_usage();
      return 1;
    }
    const char *tenant = argv[2];
    const char *keyID = argv[3];
    const char *reason = (argc > 4) ? argv[4] : "manual";
    rc = vecta_rotate(base, token, tenant, keyID, reason, &out);
  } else if (strcmp(op, "public") == 0) {
    if (!base || !token || argc < 4) {
      fprintf(stderr, "VECTA_BASE_URL and VECTA_TOKEN are required for public\n");
      print_usage();
      return 1;
    }
    const char *tenant = argv[2];
    const char *keyID = argv[3];
    rc = vecta_public(base, token, tenant, keyID, &out);
  } else {
    fprintf(stderr, "Unsupported operation: %s\n", op);
    print_usage();
    return 1;
  }

  if (rc != 0) {
    fprintf(stderr, "Request failed rc=%d body=%s\n", rc, out.data ? out.data : "");
    free(out.data);
    return rc;
  }
  printf("%s\n", out.data ? out.data : "{}");
  free(out.data);
  return 0;
}
`

	makefile := `CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?= -lcurl

all: vecta_kms_client

vecta_kms_client: vecta_kms_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f vecta_kms_client
`

	env := `VECTA_BASE_URL=https://localhost/svc/ekm
VECTA_AUTH_BASE_URL=https://localhost
VECTA_TOKEN=replace-with-jwt
VECTA_AGENT_ID=replace-with-agent-id
VECTA_DATABASE_ID=replace-with-database-id
`

	sh := `#!/usr/bin/env bash
set -euo pipefail
if [ -f ./config/vecta-kms.env.example ]; then
  source ./config/vecta-kms.env.example
fi
if [ $# -lt 1 ]; then
  echo "Usage: ./scripts/run_sdk_demo.sh <operation> [args...]"
  exit 1
fi
./examples/c/vecta_kms_client "$@"
`
	ps := `$ErrorActionPreference = "Stop"
if (Test-Path ".\config\vecta-kms.env.example") {
  Get-Content ".\config\vecta-kms.env.example" | ForEach-Object {
    if ($_ -match "^[A-Za-z_][A-Za-z0-9_]*=") {
      $idx = $_.IndexOf("=")
      $k = $_.Substring(0, $idx)
      $v = $_.Substring($idx + 1)
      [Environment]::SetEnvironmentVariable($k, $v, "Process")
    }
  }
}
if ($args.Count -lt 1) {
  Write-Host "Usage: .\scripts\run_sdk_demo.ps1 <operation> [args...]"
  exit 1
}
.\examples\c\vecta_kms_client.exe @args
`

	return map[string]string{
		"README.md":                     readme,
		"config/vecta-kms.env.example":  env,
		"examples/c/vecta_kms_client.c": cClient,
		"examples/c/Makefile":           makefile,
		"scripts/run_sdk_demo.sh":       sh,
		"scripts/run_sdk_demo.ps1":      ps,
	}
}

func jcaSDKFiles() map[string]string {
	readme := `# Vecta Java SDK (JCA/JCE Starter)

This package includes a real Java client starter for Vecta KMS APIs over HTTPS + mTLS-friendly transport.

Tenant binding model:
- Register client using explicit tenant ("register-client").
- Every SDK method requires tenantId argument per call.
- Server enforces tenant isolation and denies cross-tenant usage.

Build:
  mvn -q -DskipTests package

Run:
  java -jar target/vecta-jca-provider.jar register-client bank-alpha app1 ops@acme.com
  java -jar target/vecta-jca-provider.jar wrap bank-alpha key_123 BASE64PLAINTEXT

Environment:
- VECTA_BASE_URL
- VECTA_AUTH_BASE_URL
- VECTA_TOKEN
- VECTA_AGENT_ID
- VECTA_DATABASE_ID
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

func mapOperationMechanism(operation string, keyAlg string) string {
	op := strings.ToLower(strings.TrimSpace(operation))
	alg := strings.ToUpper(strings.TrimSpace(keyAlg))
	if strings.HasPrefix(alg, "ML-DSA") {
		return "CKM_VECTA_ML_DSA"
	}
	if strings.HasPrefix(alg, "ML-KEM") {
		return "CKM_ML_KEM"
	}
	if strings.Contains(alg, "ECDSA") || strings.Contains(alg, "ECDH") {
		return "CKM_ECDSA_SHA256"
	}
	if strings.Contains(alg, "RSA") {
		return "CKM_RSA_PKCS_PSS"
	}
	if strings.Contains(alg, "AES") {
		return "CKM_AES_GCM"
	}
	if strings.Contains(alg, "HMAC") {
		return "CKM_SHA256_HMAC"
	}
	switch op {
	case "wrap", "unwrap":
		return "CKM_AES_GCM"
	case "public":
		return "CKM_ECDSA_SHA256"
	default:
		return "CKM_AES_GCM"
	}
}

func topMechanism(mechOps map[string]int64) string {
	best := ""
	bestCount := int64(0)
	for mech, count := range mechOps {
		if count > bestCount || (count == bestCount && (best == "" || mech < best)) {
			best = mech
			bestCount = count
		}
	}
	return best
}

func detectClientSDK(agent Agent, metadata map[string]interface{}) string {
	sdk := strings.ToLower(mapStringAny(metadata, "sdk", "client_sdk", "provider", "runtime"))
	if strings.Contains(sdk, "jca") || strings.Contains(sdk, "java") || strings.Contains(strings.ToLower(agent.Role), "java") {
		return "jca"
	}
	return "pkcs11"
}

func sdkArtifactName(kind string) string {
	if normalizeSDKProvider(kind) == "jca" {
		return "vecta-jca-provider.jar"
	}
	return "libvecta-pkcs11.so"
}

func sdkStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case AgentStatusConnected:
		return "Active"
	case AgentStatusDegraded:
		return "Degraded"
	default:
		return "Down"
	}
}

func normalizeSDKProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "pkcs11", "pkcs11_c", "c", "pkcs":
		return "pkcs11"
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
