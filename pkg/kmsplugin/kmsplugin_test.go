package kmsplugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	kmsapi "k8s.io/kms/apis/v2"
	"k8s.io/kms/pkg/service"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// keycore answers in its own shapes (GET /keys/{id}, POST encrypt/decrypt)
// and does AES-GCM per key version, so the test uses what was produced.
type fakeKeycore struct {
	mu       sync.Mutex
	versions [][]byte
	status   string
	sawAuth  []string
}

func (f *fakeKeycore) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := make([]byte, 32)
	_, _ = pkgcrypto.Reader.Read(k)
	f.versions = append(f.versions, k)
}

func (f *fakeKeycore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.sawAuth = append(f.sawAuth, r.Header.Get("Authorization"))
	versions, status := f.versions, f.status
	f.mu.Unlock()
	fail := func(code int, c, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": c, "message": msg}})
	}
	if r.URL.Query().Get("tenant_id") != "t1" || r.Header.Get("Authorization") != "Bearer client-jwt" {
		fail(401, "unauthorized", "no token")
		return
	}
	var body map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&body)
	str := func(k string) []byte { b, _ := base64.StdEncoding.DecodeString(body[k].(string)); return b }
	switch r.URL.Path {
	case "/svc/keycore/keys/key_k8s":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"key": map[string]interface{}{"id": "key_k8s", "status": status, "current_version": len(versions), "algorithm": "AES-256"}})
	case "/svc/keycore/keys/key_k8s/encrypt":
		if body["iv_mode"] != "internal" {
			fail(400, "bad_request", "iv_mode")
			return
		}
		iv, ct, err := pkgcrypto.SealDetached(versions[len(versions)-1], str("plaintext"), str("aad"))
		if err != nil {
			fail(500, "x", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"key_id": "key_k8s", "version": len(versions), "ciphertext": base64.StdEncoding.EncodeToString(ct), "iv": base64.StdEncoding.EncodeToString(iv)})
	case "/svc/keycore/keys/key_k8s/decrypt":
		v := int(body["version"].(float64))
		if v < 1 || v > len(versions) {
			fail(400, "decrypt_failed", "version")
			return
		}
		plain, err := pkgcrypto.OpenDetached(versions[v-1], str("iv"), str("ciphertext"), str("aad"))
		if err != nil {
			fail(400, "decrypt_failed", "message authentication failed")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"key_id": "key_k8s", "version": v, "plaintext": base64.StdEncoding.EncodeToString(plain)})
	default:
		fail(404, "not_found", r.URL.Path)
	}
}

// kube-apiserver's side: the generated KMS v2 client over the Unix socket
// the plugin serves with k8s.io/kms's GRPCService.
func startPlugin(t *testing.T) (*fakeKeycore, kmsapi.KeyManagementServiceClient) {
	t.Helper()
	old := statusCache
	statusCache = 0
	t.Cleanup(func() { statusCache = old })
	kc := &fakeKeycore{status: "active"}
	kc.rotate()
	edge := httptest.NewTLSServer(kc)
	t.Cleanup(edge.Close)
	svc, err := New(Config{Server: edge.URL, TenantID: "t1", KeyID: "key_k8s"}, edge.Client(), func(r *http.Request) error {
		r.Header.Set("Authorization", "Bearer client-jwt")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "kms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "kms.sock")
	srv := service.NewGRPCService(sock, 5*time.Second, svc)
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(srv.Close)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix://"))
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return kc, kmsapi.NewKeyManagementServiceClient(conn)
}

func TestKMSv2WrapsAndUnwrapsAcrossRotation(t *testing.T) {
	kc, client := startPlugin(t)
	ctx := context.Background()
	st, err := client.Status(ctx, &kmsapi.StatusRequest{})
	if err != nil || st.Version != "v2" || st.Healthz != "ok" || st.KeyId != "key_k8s:v1" {
		t.Fatalf("status %+v %v", st, err)
	}
	seed := bytes.Repeat([]byte{7}, 32)
	enc, err := client.Encrypt(ctx, &kmsapi.EncryptRequest{Plaintext: seed, Uid: "uid-1"})
	if err != nil || enc.KeyId != "key_k8s:v1" || len(enc.Ciphertext) != 12+32+16 || bytes.Contains(enc.Ciphertext, seed) {
		t.Fatalf("encrypt %d bytes key_id %q %v", len(enc.GetCiphertext()), enc.GetKeyId(), err)
	}
	// The wire value is iv || AES-GCM under the key keycore holds.
	direct, err := pkgcrypto.OpenDetached(kc.versions[0], enc.Ciphertext[:12], enc.Ciphertext[12:], []byte("vecta-k8s-kms-v2:t1:key_k8s"))
	if err != nil || !bytes.Equal(direct, seed) {
		t.Fatalf("not AES-GCM under the key: %v", err)
	}
	dec, err := client.Decrypt(ctx, &kmsapi.DecryptRequest{Ciphertext: enc.Ciphertext, KeyId: enc.KeyId, Uid: "uid-2"})
	if err != nil || !bytes.Equal(dec.Plaintext, seed) {
		t.Fatalf("decrypt %v", err)
	}

	// Rotation changes the key_id Status reports (kube-apiserver then
	// re-wraps), and what was wrapped before still unwraps.
	kc.rotate()
	if st, _ := client.Status(ctx, &kmsapi.StatusRequest{}); st.GetKeyId() != "key_k8s:v2" {
		t.Fatalf("status after rotation %+v", st)
	}
	if dec, err := client.Decrypt(ctx, &kmsapi.DecryptRequest{Ciphertext: enc.Ciphertext, KeyId: enc.KeyId, Uid: "uid-3"}); err != nil || !bytes.Equal(dec.Plaintext, seed) {
		t.Fatalf("decrypt after rotation %v", err)
	}
	if enc2, err := client.Encrypt(ctx, &kmsapi.EncryptRequest{Plaintext: seed, Uid: "uid-4"}); err != nil || enc2.KeyId != "key_k8s:v2" {
		t.Fatalf("encrypt after rotation %v %v", enc2, err)
	}

	// Altered ciphertext, another key's key_id, or a wrong version fail.
	bad := append([]byte{}, enc.Ciphertext...)
	bad[len(bad)-1] ^= 1
	for name, req := range map[string]*kmsapi.DecryptRequest{
		"tampered":      {Ciphertext: bad, KeyId: enc.KeyId, Uid: "u"},
		"other key":     {Ciphertext: enc.Ciphertext, KeyId: "key_other:v1", Uid: "u"},
		"wrong version": {Ciphertext: enc.Ciphertext, KeyId: "key_k8s:v2", Uid: "u"},
		"no version":    {Ciphertext: enc.Ciphertext, KeyId: "key_k8s", Uid: "u"},
	} {
		if _, err := client.Decrypt(ctx, req); err == nil {
			t.Fatalf("%s decrypted", name)
		}
	}
	for _, a := range kc.sawAuth {
		if a != "Bearer client-jwt" {
			t.Fatalf("a call went to keycore with %q", a)
		}
	}
}

func TestKMSv2StatusIsUnhealthyWhenTheKeyIsNotActive(t *testing.T) {
	kc, client := startPlugin(t)
	kc.mu.Lock()
	kc.status = "disabled"
	kc.mu.Unlock()
	st, err := client.Status(context.Background(), &kmsapi.StatusRequest{})
	if err != nil || st.Healthz == "ok" {
		t.Fatalf("a disabled key reported healthy: %+v %v", st, err)
	}
}

func TestNewRefusesAPlainHTTPServer(t *testing.T) {
	if _, err := New(Config{Server: "http://kms.example.com", TenantID: "t1", KeyID: "k"}, http.DefaultClient, nil); err == nil {
		t.Fatal("an http:// server was accepted")
	}
}
