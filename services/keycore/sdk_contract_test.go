package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"

	pkgauth "vecta-kms/pkg/auth"
)

// sdkRig is keycore behind a TLS edge, as a REST client reaches it: a key it
// may encrypt with, one it may sign with, and one it wasn't granted.
type sdkRig struct {
	srv                 *httptest.Server
	caPEM               []byte
	aes, signer, hidden string
}

func newSDKRig(t *testing.T) sdkRig {
	t.Helper()
	h, svc, _ := newActorTestHandler(t)
	ctx := context.Background()
	aes := ownedKey(t, svc)
	signer, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "signer", Algorithm: "ECDSA-P256", KeyType: "asymmetric", Purpose: "sign", CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "hidden", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	for id, ops := range map[string][]string{aes.ID: {"encrypt", "decrypt", "wrap", "unwrap", "read"}, signer.ID: {"sign", "verify", "read"}} {
		if err := svc.store.ReplaceKeyAccessGrants(ctx, "t1", id, []KeyAccessGrant{{SubjectType: AccessSubjectClient, SubjectID: "release-pipeline", Operations: ops}}, "owner-1"); err != nil {
			t.Fatal(err)
		}
	}
	// The edge: /svc/keycore is keycore, and the client's verified token.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer client-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims := &pkgauth.Claims{ClientID: "release-pipeline", UserID: "release-pipeline", TenantID: "t1", Role: "client-service",
			Permissions: []string{"key.encrypt", "key.decrypt", "key.wrap", "key.unwrap", "key.sign", "key.verify", "key.read", "key.rotate", "key.create"}}
		claims.Subject = "release-pipeline"
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/svc/keycore")
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	}))
	t.Cleanup(srv.Close)
	return sdkRig{srv: srv, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), aes: aes.ID, signer: signer.ID, hidden: hidden.ID}
}

// The Go SDK (sdk/go) against keycore's real routes: what it sends is what
// keycore takes and what keycore answers is what it reads. A REST client
// granted the keys uses them; a key it wasn't granted is hidden.
func TestGoSDKAgainstKeycore(t *testing.T) {
	rig := newSDKRig(t)
	ctx := context.Background()
	srv := rig.srv
	aes, signer, hidden := struct{ ID string }{rig.aes}, struct{ ID string }{rig.signer}, struct{ ID string }{rig.hidden}
	c, err := vecta.New(vecta.Config{BaseURL: srv.URL, TenantID: "t1", Token: "client-token", CAPEM: rig.caPEM})
	if err != nil {
		t.Fatal(err)
	}

	k, err := c.GetKey(ctx, aes.ID)
	if err != nil || k.ID != aes.ID || k.Algorithm != "AES-256" || k.CurrentVersion < 1 {
		t.Fatalf("get: %+v %v", k, err)
	}
	ct, err := c.Encrypt(ctx, aes.ID, []byte("card 4111"), []byte("order-7"))
	if err != nil || len(ct.Ciphertext) == 0 || ct.KeyID != aes.ID {
		t.Fatalf("encrypt: %+v %v", ct, err)
	}
	if plain, err := c.Decrypt(ctx, ct, []byte("order-7")); err != nil || string(plain) != "card 4111" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	if _, err := c.Decrypt(ctx, ct, []byte("order-8")); err == nil {
		t.Fatal("decrypted under other additional data")
	}
	dk, err := c.GenerateDataKey(ctx, aes.ID, []byte("blob-1"))
	if err != nil || len(dk.Plaintext) != 32 {
		t.Fatalf("data key: %v", err)
	}
	if again, err := c.Decrypt(ctx, dk.Wrapped, []byte("blob-1")); err != nil || !bytes.Equal(again, dk.Plaintext) {
		t.Fatalf("unwrap the data key: %v", err)
	}
	sig, err := c.Sign(ctx, signer.ID, []byte("release v1"), "")
	if err != nil || len(sig.Signature) == 0 {
		t.Fatalf("sign: %v", err)
	}
	if ok, err := c.Verify(ctx, sig, []byte("release v1"), ""); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := c.Verify(ctx, sig, []byte("release v2"), ""); ok {
		t.Fatal("a signature verified for other data")
	}

	var seen []string
	if err := c.ListKeys(ctx, func(k vecta.Key) bool { seen = append(seen, k.ID); return true }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || strings.Contains(strings.Join(seen, ","), hidden.ID) {
		t.Fatalf("listed %v, want the two granted keys", seen)
	}
	// The client creates a key (it is the creator, so it may use and rotate it).
	newID, err := c.CreateKey(ctx, vecta.CreateKeyInput{Name: "pipeline-key", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Labels: map[string]string{"team": "release"}})
	if err != nil || newID == "" {
		t.Fatalf("create: %q %v", newID, err)
	}
	if v, err := c.RotateKey(ctx, newID, "scheduled"); err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	if k, err := c.GetKey(ctx, newID); err != nil || k.CurrentVersion != 2 || k.Labels["team"] != "release" {
		t.Fatalf("created key: %+v %v", k, err)
	}
	if _, err := c.GetKey(ctx, hidden.ID); !vecta.IsNotFound(err) {
		t.Fatalf("a key not granted: %v", err)
	}
	if _, err := c.Encrypt(ctx, hidden.ID, []byte("x"), nil); !vecta.IsRefused(err) && !vecta.IsNotFound(err) {
		t.Fatalf("encrypt with a key not granted: %v", err)
	}
}

// The Python (sdk/python) and Node (sdk/node) SDKs against keycore's real
// routes over TLS: each runs its contract script against the same rig. A
// runtime that isn't installed (or a Python without TLS 1.3, as macOS's
// system Python) is skipped; CI has both.
func TestSDKsAgainstKeycore(t *testing.T) {
	for _, sdk := range []struct{ name, check, run string }{
		{"python", "import ssl,sys; sys.exit(0 if ssl.HAS_TLSv1_3 else 1)", "../../sdk/python/contract.py"},
		{"node", "process.exit(Number(process.versions.node.split('.')[0]) >= 18 ? 0 : 1)", "../../sdk/node/contract.mjs"},
	} {
		t.Run(sdk.name, func(t *testing.T) {
			bin := map[string]string{"python": "python3", "node": "node"}[sdk.name]
			flag := map[string]string{"python": "-c", "node": "-e"}[sdk.name]
			if _, err := exec.LookPath(bin); err != nil {
				t.Skipf("%s is not installed", bin)
			}
			if err := exec.Command(bin, flag, sdk.check).Run(); err != nil {
				t.Skipf("this %s can't speak TLS 1.3 or is too old", bin)
			}
			rig := newSDKRig(t)
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, rig.caPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, sdk.run)
			cmd.Env = append(os.Environ(), "VECTA_URL="+rig.srv.URL, "VECTA_TENANT=t1", "VECTA_TOKEN=client-token", "VECTA_CA="+ca,
				"AES_KEY="+rig.aes, "SIGN_KEY="+rig.signer, "HIDDEN_KEY="+rig.hidden)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "contract ok") {
				t.Fatalf("%s contract: %v\n%s", sdk.name, err, out)
			}
		})
	}
}
