package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/delegation"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func pubKeyTestKey(t *testing.T, svc *Service, alg, keyType, creator string) Key {
	t.Helper()
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "pk-" + alg, Algorithm: alg,
		KeyType: keyType, Purpose: "wrap", Owner: "ops", CreatedBy: creator})
	if err != nil {
		t.Fatalf("create %s: %v", alg, err)
	}
	return key
}

func getPublicKeyVia(router http.Handler, keyID string, claims *pkgauth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/keys/"+keyID+"/public-key?tenant_id=t1", nil)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// A software RSA key pair holds only its encrypted private key; the route
// returns the public half of that same key as PEM SubjectPublicKeyInfo and
// audits the read as audit.key.public_key_read.
func TestPublicKeyReadReturnsTheKeysSPKI(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	key := pubKeyTestKey(t, svc, "RSA-3072", "asymmetric", "bob")
	rec := &routetest.Recorder{}
	w := getPublicKeyVia(h.publicKeyRouter(rec), key.ID, visAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		KeyID, Algorithm, Format string
		Version                  int
		PEM                      string `json:"public_key_pem"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(out.PEM))
	if block == nil || block.Type != "PUBLIC KEY" || out.Format != "spki-pem" || out.Version != 1 || out.Algorithm != "RSA-3072" {
		t.Fatalf("response %+v", out)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// It is the public half of the key keycore holds, not any RSA key.
	ver, err := svc.store.GetVersion(context.Background(), "t1", key.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := svc.decryptMaterial(ver)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	signer := priv.(crypto.Signer)
	if rsaPub, ok := pub.(*rsa.PublicKey); !ok || rsaPub.N.BitLen() != 3072 || !rsaPub.Equal(signer.Public()) {
		t.Fatalf("public key does not match the key's private half")
	}
	if ev := rec.Last(t); ev.Action != "public_key_read" || ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != key.ID || ev.Event.Details["version"] != 1 {
		t.Fatalf("audited %+v", ev)
	}
}

// A key with no public half, a deleted key, or one with no SPKI encoding
// (ML-KEM is held as raw bytes) is refused and audited as refused with the
// reason.
func TestPublicKeyReadRefusals(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	router := h.publicKeyRouter(rec)
	for _, tc := range []struct{ alg, keyType, reason string }{
		{"AES-256", "symmetric", "not_asymmetric"},
		{"ML-KEM-768", "asymmetric", "spki_unavailable"},
		{"RSA-2048", "asymmetric", "key_deleted"},
	} {
		key := pubKeyTestKey(t, svc, tc.alg, tc.keyType, "bob")
		if tc.reason == "key_deleted" {
			if err := svc.store.SetKeyStatus(context.Background(), "t1", key.ID, "deleted"); err != nil {
				t.Fatal(err)
			}
		}
		rec.Reset()
		if w := getPublicKeyVia(router, key.ID, visAdmin); w.Code != http.StatusConflict {
			t.Fatalf("%s: status %d, want 409: %s", tc.alg, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Action != "public_key_read" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != tc.reason {
			t.Fatalf("%s: audited %+v, want refused %s", tc.alg, ev, tc.reason)
		}
	}
}

// A caller who can't see the key gets a 404 (its existence isn't
// confirmed), audited as audit.key.access_refused with reason not_visible.
func TestPublicKeyReadOfAHiddenKeyIsRefused(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := pubKeyTestKey(t, svc, "ECDSA-P384", "asymmetric", "bob")
	if w := callKeycore(h, http.MethodGet, "/keys/"+key.ID+"/public-key", "", visAlice); w.Code != http.StatusNotFound {
		t.Fatalf("hidden key: status %d: %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "not_visible" || d["key_id"] != key.ID {
		t.Fatalf("refusal %+v", d)
	}
}

// ekm reads a public key for the user it serves (usage "read"): the user's
// view decides, and every keycore event names the user and the service.
func TestDelegatedPublicKeyReadUsesTheUsersView(t *testing.T) {
	h, svc, rec := delegationHandler(t)
	ekm := &pkgauth.Claims{ClientID: "kms-ekm", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	ekm.Subject = "kms-ekm"
	key := pubKeyTestKey(t, svc, "RSA-3072", "asymmetric", "bob")
	read := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/keys/"+key.ID+"/public-key?tenant_id=t1", nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), ekm))
		req.Header.Set(delegation.HeaderToken, token)
		req.Header.Set(delegation.HeaderUsage, "read")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	// ekm alone sees every key; alice, with no grant, does not.
	if w := read("alice-token"); w.Code != http.StatusNotFound {
		t.Fatalf("ungranted user read the public key through ekm: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "not_visible" ||
		d["on_behalf_of"] != "alice" || d["via"] != "kms-ekm" || d["usage"] != "read" {
		t.Fatalf("refusal does not name the reason, user and service: %+v", d)
	}
	if err := svc.store.ReplaceKeyAccessGrants(context.Background(), "t1", key.ID, []KeyAccessGrant{
		{SubjectType: AccessSubjectUser, SubjectID: "alice", Operations: []string{"wrap"}},
	}, "bob"); err != nil {
		t.Fatal(err)
	}
	if w := read("alice-token"); w.Code != http.StatusOK {
		t.Fatalf("granted user refused: %d %s", w.Code, w.Body)
	}
	// A user of another tenant is refused before any handler.
	if w := read("eve-token"); w.Code != http.StatusForbidden {
		t.Fatalf("other tenant's user: %d %s", w.Code, w.Body)
	}
}

// A delegated "read" never stands in for a key operation: with only a read
// grant, a service can't use the key for the user.
func TestDelegatedReadCannotPerformAKeyOperation(t *testing.T) {
	h, svc, rec := delegationHandler(t)
	key := bobKeyGrantedTo(t, svc, "read")
	if w := meterAs(h, key.ID, dpService, "alice-token", "read"); w.Code != http.StatusForbidden {
		t.Fatalf("a read grant allowed a key operation: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "delegation_usage_mismatch" || d["usage"] != "read" {
		t.Fatalf("refusal %+v", d)
	}
}

func TestPublicKeyRouteRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.publicKeyRouter(rec), rec)
}
