package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The network scan reports what the handshake negotiated, from a real TLS
// server; nothing is picked or assumed.
func TestNetworkScanHandshakes(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	assets, err := svc.scanNetwork(context.Background(), "t1", "scan-1")
	if err != nil {
		t.Fatal(err)
	}
	var kex, cert *CryptoAsset
	for i := range assets {
		switch assets[i].AssetType {
		case "tls_endpoint":
			kex = &assets[i]
		case "tls_certificate":
			cert = &assets[i]
		}
	}
	if kex == nil || cert == nil {
		t.Fatalf("assets: %+v", assets)
	}
	if kex.Metadata["protocol"] != "TLS 1.3" || kex.Algorithm == "" || kex.Algorithm == "RSA-KEX" {
		t.Fatalf("key exchange asset: %+v", kex)
	}
	if !strings.HasPrefix(cert.Algorithm, "RSA-") && !strings.HasPrefix(cert.Algorithm, "ECDSA-") {
		t.Fatalf("certificate asset: %+v", cert)
	}
	if cert.Metadata["chain_trusted"] != false {
		t.Fatalf("httptest's self-signed chain reported trusted: %+v", cert.Metadata)
	}
}

// Unconfigured or unreachable sources are errors, never invented assets.
func TestScansNeverInventAssets(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", "")
	if a, err := svc.scanNetwork(ctx, "t1", "s"); err == nil || len(a) != 0 {
		t.Fatalf("network with no endpoints: %d assets, %v", len(a), err)
	}
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", "127.0.0.1:1")
	if a, err := svc.scanNetwork(ctx, "t1", "s"); err == nil || len(a) != 0 {
		t.Fatalf("unreachable endpoint: %d assets, %v", len(a), err)
	}
	svc.certs = emptyCerts{}
	if a, err := svc.scanCertificates(ctx, "t1", "s"); err != nil || len(a) != 0 {
		t.Fatalf("no certificates: %d assets, %v", len(a), err)
	}
	svc.cloud = &testCloud{err: os.ErrDeadlineExceeded}
	if _, err := svc.scanCloud(ctx, "t1", "s"); err == nil {
		t.Fatal("failed cloud inventory reported as success")
	}
	svc.cloud = nil
	if a, err := svc.scanCloud(ctx, "t1", "s"); err == nil || len(a) != 0 {
		t.Fatalf("no cloud client: %d assets, %v", len(a), err)
	}
	svc.root = ""
	if _, err := svc.scanCode(ctx, "t1", "s"); err == nil {
		t.Fatal("code scan ran without WORKSPACE_ROOT")
	}

	scan, err := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"network", "code"}})
	if err != nil {
		t.Fatal(err)
	}
	if scan.Status != "failed" || scan.Stats["errors"] == nil {
		t.Fatalf("scan with every source failing: %+v", scan)
	}
}

type emptyCerts struct{}

func (emptyCerts) ListCertificates(context.Context, string, int) ([]map[string]interface{}, error) {
	return nil, nil
}

// A code finding records location and fingerprint, never the secret, and a
// private key is named by the key it actually parses to.
func TestCodeScanNeverStoresTheSecret(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	dir := t.TempDir()
	const akia = "AKIAABCDEFGHIJKLMNOP"
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("region: x\naws_key: "+akia+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "deploy.pem"), pemKey, 0o600)
	svc.root = dir
	assets, err := svc.scanCode(context.Background(), "t1", "s")
	if err != nil || len(assets) != 2 {
		t.Fatalf("assets %d, %v", len(assets), err)
	}
	raw, _ := json.Marshal(assets)
	if strings.Contains(string(raw), akia) || strings.Contains(string(raw), "MII") {
		t.Fatalf("a secret reached the asset record: %s", raw)
	}
	for _, a := range assets {
		switch a.AssetType {
		case "cloud_access_key":
			if a.Location != "config.yaml:2" || a.Algorithm != "" {
				t.Fatalf("access key asset: %+v", a)
			}
		case "private_key_material":
			if a.Algorithm != "RSA-2048" {
				t.Fatalf("private key named %q, want RSA-2048", a.Algorithm)
			}
		default:
			t.Fatalf("unexpected asset %+v", a)
		}
	}
}
