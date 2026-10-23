package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// fakeKMS answers the edge protocol as services/ekm does (edge.go), so the
// agent is tested over real TLS against what it must send. It verifies the
// enrolment proof and the receipt signatures with the device's own key.
type fakeKMS struct {
	t        *testing.T
	mu       sync.Mutex
	signPEM  string
	kemKey   []byte
	lastSeq  int64
	got      []receipt
	revoked  map[string]bool
	cutOff   bool
	leaseN   int
	leaseTTL time.Duration
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	refuse := func(code int, reason string) {
		reply(code, map[string]any{"error": map[string]any{"code": reason, "message": reason}})
	}
	if r.URL.Query().Get("tenant_id") != "t1" {
		refuse(400, "tenant_mismatch")
		return
	}
	if r.URL.Path != "/ekm/edge/enroll" {
		if f.cutOff {
			refuse(403, "device_revoked")
			return
		}
		if r.Header.Get(deviceKeyHeader) != "device-secret" {
			refuse(401, "invalid_device_key")
			return
		}
	}
	switch {
	case r.URL.Path == "/ekm/edge/enroll":
		token := body["token"].(string)
		pub, err := pkgcrypto.ParsePublicKeyPEM(body["signing_public_key"].(string))
		proof, _ := base64.StdEncoding.DecodeString(body["proof"].(string))
		if err != nil || pkgcrypto.Verify(pkgcrypto.AlgECDSAP256, pub, []byte(enrollProof+token), proof) != nil {
			refuse(400, "signing_key_invalid")
			return
		}
		f.signPEM = body["signing_public_key"].(string)
		f.kemKey, _ = base64.StdEncoding.DecodeString(body["kem_public_key"].(string))
		reply(200, map[string]any{"device_id": "edge_1", "device_key": "device-secret"})
	case strings.HasSuffix(r.URL.Path, "/leases"):
		f.leaseN++
		id := "lease_" + string(rune('0'+f.leaseN))
		aad := []byte("vecta-edge-lease|t1|edge_1|" + id)
		dek := bytes.Repeat([]byte{byte(f.leaseN)}, 32)
		sealed, err := pkgcrypto.KEMSeal(f.kemKey, dek, aad, leaseLabel)
		if err != nil {
			refuse(500, "seal")
			return
		}
		reply(201, map[string]any{
			"lease":      map[string]any{"id": id, "key_id": body["key_id"], "key_version": 3, "wrapped_dek": "d3JhcHBlZA==", "wrapped_dek_iv": "aXY=", "expires_at": time.Now().Add(f.leaseTTL)},
			"sealed_dek": base64.StdEncoding.EncodeToString(sealed), "aad": base64.StdEncoding.EncodeToString(aad),
		})
	case strings.HasSuffix(r.URL.Path, "/receipts"):
		raw := body["receipts"].(string)
		sig, _ := base64.StdEncoding.DecodeString(body["signature"].(string))
		pub, _ := pkgcrypto.ParsePublicKeyPEM(f.signPEM)
		if pkgcrypto.Verify(pkgcrypto.AlgECDSAP256, pub, []byte(raw), sig) != nil {
			refuse(401, "receipt_signature_invalid")
			return
		}
		var batch []receipt
		_ = json.Unmarshal([]byte(raw), &batch)
		if batch[0].Seq <= f.lastSeq {
			refuse(409, "receipts_replayed")
			return
		}
		f.lastSeq = batch[len(batch)-1].Seq
		f.got = append(f.got, batch...)
		reply(200, map[string]any{"received": len(batch)})
	case strings.HasSuffix(r.URL.Path, "/check-in"):
		ids := []string{}
		for id := range f.revoked {
			ids = append(ids, id)
		}
		reply(200, map[string]any{"status": "active", "revoked_lease_ids": ids})
	default:
		refuse(404, "not_found")
	}
}

func startKMS(t *testing.T) (*fakeKMS, string, string) {
	t.Helper()
	f := &fakeKMS{t: t, revoked: map[string]bool{}, leaseTTL: time.Hour}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return f, srv.URL, ca
}

func writeToken(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "token")
	_ = os.WriteFile(path, []byte("vedge-reg."+base64.RawURLEncoding.EncodeToString([]byte("t1"))+".edge_1.secret\n"), 0o600)
	return path
}

// The whole device cycle over TLS: enrol (token spent, keys kept 0600), lease
// a key and open it, encrypt and decrypt offline, send signed receipts once,
// drop a revoked lease, and wipe every lease when the device is revoked.
func TestEdgeAgentCycle(t *testing.T) {
	kms, url, ca := startKMS(t)
	dir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	tok := writeToken(t, t.TempDir())
	if _, err := enroll(ctx, dir, strings.Replace(url, "https://", "http://", 1), tok, ca); err == nil {
		t.Fatal("enrolled over plain HTTP")
	}
	if _, err := enroll(ctx, dir, url, tok, ca); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tok); !os.IsNotExist(err) {
		t.Fatal("the spent token file was kept")
	}
	for _, name := range []string{"state.json", "signing.pem", "kem.seed"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi.Mode(), err)
		}
	}
	a, err := loadAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.takeLease(ctx, "key-a", 600)
	if err != nil {
		t.Fatal(err)
	}
	if dek, _ := base64.StdEncoding.DecodeString(l.DEK); !bytes.Equal(dek, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("the lease's data key didn't open to what the KMS sealed")
	}

	sealed, err := a.encrypt(l.ID, []byte("meter reading 42"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("meter reading")) || !bytes.Contains(sealed, []byte(`"wrapped_dek":"d3JhcHBlZA=="`)) {
		t.Fatalf("envelope: %s", sealed)
	}
	plain, err := a.decrypt(sealed)
	if err != nil || string(plain) != "meter reading 42" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	tampered := bytes.Replace(sealed, []byte(`"key_version":3`), []byte(`"key_version":4`), 1)
	if _, err := a.decrypt(tampered); err == nil {
		t.Fatal("an altered header decrypted")
	}

	res, err := a.sync(ctx)
	if err != nil || res.Sent != 2 || len(kms.got) != 2 || kms.got[0].Operation != "encrypt" || kms.got[1].Seq != 2 {
		t.Fatalf("sync: %+v %v %+v", res, err, kms.got)
	}
	if res, err := a.sync(ctx); err != nil || res.Sent != 0 {
		t.Fatalf("receipts sent twice: %+v %v", res, err)
	}

	kms.revoked[l.ID] = true
	if res, err := a.sync(ctx); err != nil || len(res.Dropped) != 1 {
		t.Fatalf("revoked lease: %+v %v", res, err)
	}
	if _, err := a.encrypt(l.ID, []byte("x")); err == nil {
		t.Fatal("encrypted under a revoked lease")
	}

	l2, err := a.takeLease(ctx, "key-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	kms.cutOff = true
	if res, err := a.sync(ctx); err == nil || !res.Revoked {
		t.Fatalf("revoked device: %+v %v", res, err)
	}
	if _, err := a.encrypt(l2.ID, []byte("x")); err == nil {
		t.Fatal("a revoked device kept its leases")
	}
	if _, err := a.takeLease(ctx, "key-a", 0); err == nil {
		t.Fatal("a revoked device leased")
	}
}

// An expired lease encrypts and decrypts nothing on the device.
func TestEdgeAgentExpiredLease(t *testing.T) {
	_, url, ca := startKMS(t)
	dir := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	a, err := enroll(ctx, dir, url, writeToken(t, t.TempDir()), ca)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.takeLease(ctx, "key-a", 600)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.encrypt(l.ID, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := a.decrypt(sealed); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("decrypt after expiry: %v", err)
	}
	if err := validateConfig(state{Server: "http://x", TenantID: "t", DeviceID: "d", DeviceKey: "k"}); err == nil {
		t.Fatal("an http server was accepted")
	}
}
