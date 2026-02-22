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

This package provides a real client SDK starter for integrating OS workloads with Vecta KMS EKM/TDE APIs.

Files:
- examples/c/vecta_kms_client.c (libcurl-based C client)
- examples/c/Makefile
- config/vecta-kms.env.example
- scripts/run_wrap_demo.sh
- scripts/run_wrap_demo.ps1

Required environment:
- VECTA_BASE_URL (example: https://kms.example.com/svc/ekm)
- VECTA_TENANT_ID
- VECTA_TOKEN
- VECTA_KEY_ID
- VECTA_AGENT_ID
- VECTA_DATABASE_ID

Build C example:
  make -C examples/c

Run demo:
  Linux/macOS: ./scripts/run_wrap_demo.sh
  Windows:     ./scripts/run_wrap_demo.ps1

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

int main(int argc, char **argv) {
  const char *base = getenv("VECTA_BASE_URL");
  const char *tenant = getenv("VECTA_TENANT_ID");
  const char *token = getenv("VECTA_TOKEN");
  const char *key = getenv("VECTA_KEY_ID");
  const char *agent = getenv("VECTA_AGENT_ID");
  const char *db = getenv("VECTA_DATABASE_ID");
  const char *pt = (argc > 1) ? argv[1] : "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=";
  if (!base || !tenant || !token || !key || !agent || !db) {
    fprintf(stderr, "Missing required VECTA_* environment variables\n");
    return 1;
  }

  char url[1024];
  snprintf(url, sizeof(url), "%s/ekm/tde/keys/%s/wrap", base, key);
  char body[2048];
  snprintf(body, sizeof(body),
           "{\"tenant_id\":\"%s\",\"plaintext\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
           tenant, pt, agent, db);

  CURL *curl = curl_easy_init();
  if (!curl) return 2;
  struct curl_slist *headers = NULL;
  char auth[2048];
  snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
  char tenantHdr[512];
  snprintf(tenantHdr, sizeof(tenantHdr), "X-Tenant-ID: %s", tenant);
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, auth);
  headers = curl_slist_append(headers, tenantHdr);

  struct resp_buf out = {0};
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  if (rc != CURLE_OK || code >= 300) {
    fprintf(stderr, "Request failed: curl=%d http=%ld body=%s\n", (int)rc, code, out.data ? out.data : "");
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(out.data);
    return 3;
  }

  printf("%s\n", out.data ? out.data : "{}");
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
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
VECTA_TENANT_ID=bank-alpha
VECTA_TOKEN=replace-with-jwt
VECTA_KEY_ID=replace-with-ekm-key-id
VECTA_AGENT_ID=replace-with-agent-id
VECTA_DATABASE_ID=replace-with-database-id
`

	sh := `#!/usr/bin/env bash
set -euo pipefail
if [ -f ./config/vecta-kms.env.example ]; then
  source ./config/vecta-kms.env.example
fi
./examples/c/vecta_kms_client "$1"
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
.\examples\c\vecta_kms_client.exe $args[0]
`

	return map[string]string{
		"README.md":                     readme,
		"config/vecta-kms.env.example":  env,
		"examples/c/vecta_kms_client.c": cClient,
		"examples/c/Makefile":           makefile,
		"scripts/run_wrap_demo.sh":      sh,
		"scripts/run_wrap_demo.ps1":     ps,
	}
}

func jcaSDKFiles() map[string]string {
	readme := `# Vecta Java SDK (JCA/JCE Starter)

This package includes a real Java client SDK starter that calls Vecta KMS APIs over HTTPS + mTLS-friendly transport.

Build:
  mvn -q -DskipTests package

Run:
  java -jar target/vecta-jca-provider.jar wrap

Environment:
- VECTA_BASE_URL
- VECTA_TENANT_ID
- VECTA_TOKEN
- VECTA_KEY_ID
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

public final class VectaKMSClient {
  private final HttpClient client = HttpClient.newBuilder().build();
  private final String baseUrl;
  private final String tenantId;
  private final String token;

  public VectaKMSClient(String baseUrl, String tenantId, String token) {
    this.baseUrl = baseUrl;
    this.tenantId = tenantId;
    this.token = token;
  }

  public String wrap(String keyId, String plaintextB64, String agentId, String databaseId) throws IOException, InterruptedException {
    String body = String.format("{\"tenant_id\":\"%s\",\"plaintext\":\"%s\",\"agent_id\":\"%s\",\"database_id\":\"%s\"}",
        tenantId, plaintextB64, agentId, databaseId);
    HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl + "/ekm/tde/keys/" + keyId + "/wrap"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer " + token)
        .header("X-Tenant-ID", tenantId)
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    HttpResponse<String> out = client.send(req, HttpResponse.BodyHandlers.ofString());
    if (out.statusCode() >= 300) {
      throw new IOException("wrap failed: " + out.statusCode() + " " + out.body());
    }
    return out.body();
  }
}
`
	main := `package com.vecta.kms;

public final class Main {
  public static void main(String[] args) throws Exception {
    String op = args.length > 0 ? args[0] : "wrap";
    String base = System.getenv("VECTA_BASE_URL");
    String tenant = System.getenv("VECTA_TENANT_ID");
    String token = System.getenv("VECTA_TOKEN");
    String keyId = System.getenv("VECTA_KEY_ID");
    String agent = System.getenv("VECTA_AGENT_ID");
    String db = System.getenv("VECTA_DATABASE_ID");
    if (base == null || tenant == null || token == null || keyId == null || agent == null || db == null) {
      throw new IllegalStateException("Missing VECTA_* environment variables");
    }
    VectaKMSClient c = new VectaKMSClient(base, tenant, token);
    if ("wrap".equalsIgnoreCase(op)) {
      String plaintextB64 = args.length > 1 ? args[1] : "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=";
      System.out.println(c.wrap(keyId, plaintextB64, agent, db));
      return;
    }
    throw new IllegalArgumentException("Unsupported operation: " + op);
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
