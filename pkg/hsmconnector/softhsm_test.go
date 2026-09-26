package hsmconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route/routetest"
)

// These tests drive a real PKCS#11 library, SoftHSM2, through the
// connector's HTTP API. CI installs it (apt softhsm2); the tests skip only
// when it is missing. SOFTHSM_LIB overrides the library path.

const testPIN = "481516"

var softhsmLib string

func TestMain(m *testing.M) {
	softhsmLib = firstNonEmpty(os.Getenv("SOFTHSM_LIB"), "/usr/lib/softhsm/libsofthsm2.so")
	if _, err := os.Stat(softhsmLib); err == nil {
		dir, err := os.MkdirTemp("", "softhsm")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir) //nolint:errcheck
		conf := filepath.Join(dir, "softhsm2.conf")
		tokens := filepath.Join(dir, "tokens")
		_ = os.Mkdir(tokens, 0o700)
		_ = os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o600)
		os.Setenv("SOFTHSM2_CONF", conf) //nolint:errcheck
		for _, label := range []string{"vecta-a", "vecta-b"} {
			out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--pin", testPIN, "--so-pin", "1234567").CombinedOutput()
			if err != nil {
				panic(fmt.Sprintf("softhsm2-util: %v %s", err, out))
			}
		}
		real, _ := filepath.EvalSymlinks(softhsmLib)
		os.Setenv("HSM_LIBRARY_ROOTS", filepath.Dir(real)) //nolint:errcheck
		os.Setenv("TEST_HSM_PIN", testPIN)                 //nolint:errcheck
	} else {
		softhsmLib = ""
	}
	os.Exit(m.Run())
}

// staticConfigs: tenants t1 and t2 share token vecta-a (one partition, two
// tenants); t3 has its own token; nothing else is configured.
type staticConfigs struct{}

func (staticConfigs) Load(_ context.Context, tenant string) (TenantConfig, error) {
	token := map[string]string{"t1": "vecta-a", "t2": "vecta-a", "t3": "vecta-b"}[tenant]
	if token == "" {
		return TenantConfig{}, ErrNotConfigured
	}
	return Resolve(TenantConfig{TenantID: tenant, Provider: "softhsm2", Library: softhsmLib, TokenLabel: token, PINEnvVar: "TEST_HSM_PIN"})
}

func newTestHandler(t *testing.T) (*Handler, *routetest.Recorder) {
	t.Helper()
	if softhsmLib == "" {
		t.Skip("SoftHSM2 not installed (apt install softhsm2); CI runs these")
	}
	rec := &routetest.Recorder{}
	return NewHandler(staticConfigs{}, sharedProvider, rec, nil), rec
}

// One provider for the process: a PKCS#11 library is initialised once.
var sharedProvider = NewProvider()

func service(id string) *pkgauth.Claims {
	c := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: id, Permissions: []string{"service.internal"}}
	c.Subject = id
	return c
}

func call(t *testing.T, h *Handler, claims *pkgauth.Claims, method, path string, body map[string]string) (int, map[string]interface{}) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func field(t *testing.T, out map[string]interface{}, name string) []byte {
	t.Helper()
	s, _ := out[name].(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v (%v)", name, err, out)
	}
	return b
}

func TestAESKeyLivesInHSMAndEncrypts(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	label := hsm.KeyLabel("t1", "key_aes", 1)
	code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256-GCM"})
	if code != http.StatusCreated {
		t.Fatalf("generate: %d %v", code, out)
	}
	if kcv := field(t, out, "kcv_b64"); len(kcv) != 3 {
		t.Fatalf("kcv = %x", kcv)
	}
	if ev := rec.Last(t); ev.Action != "key_generated" || ev.Event.Result != "success" {
		t.Fatalf("audit: %+v", ev)
	}
	// A second key with the same label is refused.
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256"}); code != http.StatusConflict {
		t.Fatalf("duplicate label: %d", code)
	}

	aad := []byte("key_aes|v1")
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t1", "label": label, "plaintext_b64": b64s([]byte("secret payload")), "aad_b64": b64s(aad)})
	if code != http.StatusOK {
		t.Fatalf("encrypt: %d %v", code, out)
	}
	iv, ct := field(t, out, "iv_b64"), field(t, out, "ciphertext_b64")
	if len(iv) != 12 || len(ct) != len("secret payload")+16 {
		t.Fatalf("iv %d bytes, ciphertext %d bytes", len(iv), len(ct))
	}
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/decrypt", map[string]string{"tenant_id": "t1", "label": label, "iv_b64": b64s(iv), "ciphertext_b64": b64s(ct), "aad_b64": b64s(aad)})
	if code != http.StatusOK || string(field(t, out, "plaintext_b64")) != "secret payload" {
		t.Fatalf("decrypt: %d %v", code, out)
	}

	// Tampering with the ciphertext or the AAD is caught by the HSM.
	ct[0] ^= 1
	if code, out2 := call(t, h, keycore, http.MethodPost, "/hsm/decrypt", map[string]string{"tenant_id": "t1", "label": label, "iv_b64": b64s(iv), "ciphertext_b64": b64s(ct), "aad_b64": b64s(aad)}); code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered ciphertext: %d %v", code, out2)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "integrity_check_failed" {
		t.Fatalf("tamper refusal audit: %+v", ev.Event)
	}

	// The key can't be read out of the HSM: it is sensitive and non-extractable.
	cfg, _ := staticConfigs{}.Load(context.Background(), "t1")
	ctx, sh, release, err := sharedProvider.session(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	obj, err := findOne(ctx, sh, 4 /* CKO_SECRET_KEY */, label)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.GetAttributeValue(sh, obj, valueAttr()); err == nil {
		t.Fatal("the HSM returned the key value")
	}

	// Destroyed means gone.
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t1", "label": label}); code != http.StatusOK {
		t.Fatalf("destroy: %d", code)
	}
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t1", "label": label, "plaintext_b64": b64s([]byte("x")), "aad_b64": ""}); code != http.StatusNotFound {
		t.Fatalf("use after destroy: %d", code)
	}
}

func TestSignVerifyInHSM(t *testing.T) {
	h, _ := newTestHandler(t)
	keycore := service("kms-keycore")
	digest := sha256.Sum256([]byte("release-1.2.0.tar.gz"))
	for _, alg := range []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048"} {
		label := hsm.KeyLabel("t1", "key_"+strings.ToLower(alg), 1)
		code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": "t1", "label": label, "algorithm": alg})
		if code != http.StatusCreated {
			t.Fatalf("%s generate: %d %v", alg, code, out)
		}
		pub, err := x509.ParsePKIXPublicKey(field(t, out, "public_key_b64"))
		if err != nil {
			t.Fatalf("%s public key: %v", alg, err)
		}
		code, out = call(t, h, keycore, http.MethodPost, "/hsm/sign", map[string]string{"tenant_id": "t1", "label": label, "hash": "SHA-256", "digest_b64": b64s(digest[:])})
		if code != http.StatusOK {
			t.Fatalf("%s sign: %d %v", alg, code, out)
		}
		sig := field(t, out, "signature_b64")
		// The signature verifies with standard software against the exported
		// public key, so it is a real RSA-PSS / ECDSA (ASN.1) signature.
		if err := verifySoftware(pub, digest[:], sig); err != nil {
			t.Fatalf("%s: software verification of the HSM signature: %v", alg, err)
		}
		for name, d := range map[string][]byte{"valid": digest[:], "other data": append([]byte{digest[0] ^ 1}, digest[1:]...)} {
			code, out = call(t, h, keycore, http.MethodPost, "/hsm/verify", map[string]string{"tenant_id": "t1", "label": label, "hash": "SHA-256", "digest_b64": b64s(d), "signature_b64": b64s(sig)})
			if code != http.StatusOK || out["verified"] != (name == "valid") {
				t.Fatalf("%s verify %s: %d %v", alg, name, code, out)
			}
		}
	}
}

// Tenants sharing a partition can't reach each other's objects, only the
// platform services that use keys may call, and each refusal is audited.
func TestTenantIsolationAndCallers(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	label := hsm.KeyLabel("t1", "key_iso", 1)
	if code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-128"}); code != http.StatusCreated {
		t.Fatalf("generate: %d %v", code, out)
	}
	// t2 is on the same token but may not name t1's label.
	code, _ := call(t, h, keycore, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t2", "label": label, "plaintext_b64": b64s([]byte("x")), "aad_b64": ""})
	if code != http.StatusForbidden {
		t.Fatalf("cross-tenant label: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "foreign_label" {
		t.Fatalf("audit: %+v", ev.Event)
	}
	// A tenant with no HSM profile is refused cleanly.
	code, _ = call(t, h, keycore, http.MethodPost, "/hsm/tenant-key", map[string]string{"tenant_id": "t9"})
	if code != http.StatusConflict || rec.Last(t).Event.Details["reason"] != "hsm_not_configured" {
		t.Fatalf("unconfigured tenant: %d", code)
	}
	// Other service identities and administrators can't use keys.
	admin := &pkgauth.Claims{TenantID: "t1", Role: "admin", UserID: "alice", Permissions: []string{"*"}}
	for name, who := range map[string]*pkgauth.Claims{"kms-secrets": service("kms-secrets"), "tenant admin": admin} {
		code, _ := call(t, h, who, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t1", "label": label, "plaintext_b64": b64s([]byte("x")), "aad_b64": ""})
		if code != http.StatusForbidden || rec.Last(t).Event.Details["reason"] != "caller_not_allowed" {
			t.Fatalf("%s: %d", name, code)
		}
	}
	// Governance may use the tenant key but not create or destroy keys.
	gov := service("kms-governance")
	if code, _ := call(t, h, gov, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t1", "label": label}); code != http.StatusForbidden {
		t.Fatalf("governance destroy: %d", code)
	}
	// The status is readable by the tenant's administrator.
	req := httptest.NewRequest(http.MethodGet, "/hsm/status?tenant_id=t1", nil)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), admin))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var st struct {
		Status hsm.Status `json:"status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if w.Code != http.StatusOK || !st.Status.Connected || st.Status.TokenLabel != "vecta-a" || st.Status.Manufacturer == "" {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
}

// Each tenant gets its own key in its HSM; it is created once, and the key
// API can't destroy it.
func TestTenantKey(t *testing.T) {
	h, _ := newTestHandler(t)
	gov := service("kms-governance")
	for i, wantCreated := range []bool{true, false} {
		code, out := call(t, h, gov, http.MethodPost, "/hsm/tenant-key", map[string]string{"tenant_id": "t3"})
		if code != http.StatusOK || out["created"] != wantCreated || out["label"] != hsm.TenantKeyLabel("t3") {
			t.Fatalf("ensure #%d: %d %v", i, code, out)
		}
	}
	code, out := call(t, h, gov, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t3", "label": hsm.TenantKeyLabel("t3"), "plaintext_b64": b64s(make([]byte, 32)), "aad_b64": b64s([]byte("backup"))})
	if code != http.StatusOK {
		t.Fatalf("wrap under tenant key: %d %v", code, out)
	}
	if code, _ := call(t, h, service("kms-keycore"), http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t3", "label": hsm.TenantKeyLabel("t3")}); code != http.StatusConflict {
		t.Fatalf("destroy tenant key: %d", code)
	}
}

func TestLibraryAndPINAreConfined(t *testing.T) {
	if softhsmLib == "" {
		t.Skip("SoftHSM2 not installed")
	}
	if _, err := checkLibrary("/usr/lib/x86_64-linux-gnu/libc.so.6"); err == nil {
		t.Fatal("a library outside the allowed roots was accepted")
	}
	if _, err := checkLibrary("relative/lib.so"); err == nil {
		t.Fatal("a relative library path was accepted")
	}
	link := filepath.Join(filepath.Dir(softhsmLib), "..", "..", "..", "tmp", "evil.so")
	if _, err := checkLibrary(link); err == nil {
		t.Fatal("a path escaping the root was accepted")
	}
	for _, name := range []string{"POSTGRES_PASSWORD", "path", "JWT_PUBLIC_KEY_B64"} {
		if _, err := pinFor(name); err == nil {
			t.Fatalf("pin_env_var %q accepted", name)
		}
	}
	t.Setenv("UNSET_HSM_PIN", "")
	if _, err := pinFor("UNSET_HSM_PIN"); err == nil {
		t.Fatal("a missing PIN was accepted")
	}
}

func TestRefusalsAudited(t *testing.T) {
	h, rec := newTestHandler(t)
	routetest.RefusalsAudited(t, h.Router(), rec)
}
