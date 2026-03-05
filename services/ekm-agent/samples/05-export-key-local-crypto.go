// Sample: Export a key from KMS, cache locally, and perform local AES-GCM encryption.
//
// Build: go build -o local-crypto-demo ./samples/05-export-key-local-crypto.go
// Usage: ./local-crypto-demo -base-url https://localhost/svc/ekm -token <token> -tenant <id> -key-id <key>
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/agentauth"
	"vecta-kms/pkg/keycache"
)

func main() {
	var (
		baseURL  string
		token    string
		tenantID string
		keyID    string
	)
	flag.StringVar(&baseURL, "base-url", "https://localhost/svc/ekm", "KMS base URL")
	flag.StringVar(&token, "token", "", "Bearer token")
	flag.StringVar(&tenantID, "tenant", "", "Tenant ID")
	flag.StringVar(&keyID, "key-id", "", "Key ID to export")
	flag.Parse()

	if token == "" || tenantID == "" || keyID == "" {
		log.Fatal("--token, --tenant, and --key-id are required")
	}

	auth, err := agentauth.New(agentauth.Config{
		AuthToken: token,
		TenantID:  tenantID,
	})
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	cache := keycache.New(true, 5*time.Minute)
	defer cache.Close()

	// Export key from KMS
	ctx := context.Background()
	exportURL := fmt.Sprintf("%s/ekm/tde/keys/%s/export", strings.TrimRight(baseURL, "/"), keyID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, exportURL, strings.NewReader(fmt.Sprintf(
		`{"tenant_id":"%s","purpose":"demo"}`, tenantID)))
	req.Header.Set("Content-Type", "application/json")
	_ = auth.ApplyAuth(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("export request: %v", err)
	}
	defer resp.Body.Close()

	var exportResp struct {
		Material  string `json:"material"`
		Algorithm string `json:"algorithm"`
		Version   int    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exportResp); err != nil {
		log.Fatalf("decode export: %v", err)
	}

	material, _ := base64.StdEncoding.DecodeString(exportResp.Material)
	cache.Put(keyID, exportResp.Version, exportResp.Algorithm, material)
	fmt.Printf("Key %s cached (algo=%s, v%d)\n", keyID, exportResp.Algorithm, exportResp.Version)

	// Encrypt locally
	entry, ok := cache.Get(keyID)
	if !ok {
		log.Fatal("key not in cache")
	}

	plaintext := []byte("Hello, Vecta KMS local crypto!")
	ct, iv, err := keycache.EncryptAESGCM(entry, plaintext)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	fmt.Printf("Encrypted: %s (iv: %s)\n",
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(iv))

	// Decrypt locally
	pt, err := keycache.DecryptAESGCM(entry, ct, iv)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", string(pt))
}
