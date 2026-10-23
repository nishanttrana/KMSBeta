package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

type edgeRig struct {
	t     *testing.T
	h     *Handler
	svc   *Service
	kc    *fakeEKMKeyCore
	rec   *routetest.Recorder
	admin *pkgauth.Claims
}

func newEdgeRig(t *testing.T) *edgeRig {
	t.Helper()
	h, svc, kc, _ := newEKMHandler(t)
	rec := &routetest.Recorder{}
	kernel := route.New("ekm", rec, nil)
	h.edgeRoutes(kernel)
	kernel.MountOn(h.mux)
	return &edgeRig{t: t, h: h, svc: svc, kc: kc, rec: rec,
		admin: &pkgauth.Claims{UserID: "admin-1", TenantID: "t1", Role: "operator", Permissions: []string{"ekm.read", "ekm.write"}}}
}

func (r *edgeRig) do(method, path string, claims *pkgauth.Claims, deviceKey string, body any) (*httptest.ResponseRecorder, map[string]any) {
	r.t.Helper()
	raw, _ := json.Marshal(body)
	if body == nil {
		raw = nil
	}
	req := httptest.NewRequest(method, path+"?tenant_id=t1", bytes.NewReader(raw))
	if deviceKey != "" {
		req.Header.Set(edgeDeviceKeyHeader, deviceKey)
	}
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	r.h.mux.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func (r *edgeRig) lastRefusal(action, reason string) {
	r.t.Helper()
	ev := r.rec.Last(r.t)
	if ev.Action != action || ev.Event.Result != "refused" || ev.Event.Details["reason"] != reason {
		r.t.Fatalf("want %s refused %s, got %s %s %+v", action, reason, ev.Action, ev.Event.Result, ev.Event.Details)
	}
}

// testDevice is a device's own keys, as the edge agent keeps them.
type testDevice struct {
	signer *pkgcrypto.KeyPair
	kem    *pkgcrypto.KEMRecipient
	id     string
	key    string
}

func newTestDevice(t *testing.T) *testDevice {
	t.Helper()
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := pkgcrypto.NewKEMRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return &testDevice{signer: kp, kem: kem}
}

func (d *testDevice) enrollBody(t *testing.T, token string) map[string]any {
	t.Helper()
	pub, err := pkgcrypto.MarshalPublicKeyPEM(d.signer.Public)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pkgcrypto.Sign(d.signer, []byte(edgeEnrollProof+token))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"tenant_id": "t1", "token": token, "signing_public_key": string(pub), "proof": base64.StdEncoding.EncodeToString(proof),
		"kem_public_key": base64.StdEncoding.EncodeToString(d.kem.EncapsulationKey()), "version": "1.0.0"}
}

func (d *testDevice) receipts(t *testing.T, list []edgeReceipt) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(list)
	sig, err := pkgcrypto.Sign(d.signer, raw)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"tenant_id": "t1", "receipts": string(raw), "signature": base64.StdEncoding.EncodeToString(sig)}
}

// enrolled adds a device leasing key-a and enrols a test device for it.
func (r *edgeRig) enrolled(name string) *testDevice {
	r.t.Helper()
	w, out := r.do("POST", "/ekm/edge/devices", r.admin, "", map[string]any{"name": name, "allowed_key_ids": []string{"key-a"}, "max_lease_seconds": 3600})
	if w.Code != http.StatusCreated {
		r.t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	id := out["device"].(map[string]any)["id"].(string)
	_, tok := r.do("POST", "/ekm/edge/devices/"+id+"/registration-token", r.admin, "", nil)
	dev := newTestDevice(r.t)
	w, out = r.do("POST", "/ekm/edge/enroll", nil, "", dev.enrollBody(r.t, tok["token"].(string)))
	if w.Code != http.StatusOK {
		r.t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	dev.id, dev.key = id, out["device_key"].(string)
	return dev
}

func TestEdgeRoutesRefusalsAudited(t *testing.T) {
	r := newEdgeRig(t)
	routetest.RefusalsAudited(t, func() *route.Router { k := route.New("ekm", r.rec, nil); r.h.edgeRoutes(k); return k }(), r.rec)
}

// A device enrols once with its token and a proven signing key, leases a
// data key it alone can open (and only for keys it was allowed), reports
// signed receipts in order, and is cut off when revoked. Every refusal is
// audited with its reason.
func TestEdgeDeviceLifecycle(t *testing.T) {
	r := newEdgeRig(t)
	w, out := r.do("POST", "/ekm/edge/devices", r.admin, "", map[string]any{"name": "pump-17", "allowed_key_ids": []string{"key-a", "key-b"}, "max_lease_seconds": 3600})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if call := r.kc.dataKeyCalls[0]; !strings.HasPrefix(call, "key-a|wrap|") {
		t.Fatalf("the administrator's right to wrap with the key was not checked as them: %v", r.kc.dataKeyCalls)
	}
	id := out["device"].(map[string]any)["id"].(string)
	_, tok := r.do("POST", "/ekm/edge/devices/"+id+"/registration-token", r.admin, "", nil)
	token := tok["token"].(string)
	dev := newTestDevice(t)

	// A proof by another key, a bad ML-KEM key, then the real enrolment.
	other := newTestDevice(t)
	bad := dev.enrollBody(t, token)
	bad["proof"] = other.enrollBody(t, token)["proof"]
	if w, _ := r.do("POST", "/ekm/edge/enroll", nil, "", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("a proof by another key: %d", w.Code)
	}
	r.lastRefusal("edge_device_enrolled", "signing_key_invalid")
	bad = dev.enrollBody(t, token)
	bad["kem_public_key"] = base64.StdEncoding.EncodeToString([]byte("short"))
	if w, _ := r.do("POST", "/ekm/edge/enroll", nil, "", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("a bad KEM key: %d", w.Code)
	}
	w, out = r.do("POST", "/ekm/edge/enroll", nil, "", dev.enrollBody(t, token))
	if w.Code != http.StatusOK || out["device_key"] == nil {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	dev.id, dev.key = id, out["device_key"].(string)
	if w, _ := r.do("POST", "/ekm/edge/enroll", nil, "", dev.enrollBody(t, token)); w.Code != http.StatusUnauthorized {
		t.Fatalf("the token worked twice: %d", w.Code)
	}
	r.lastRefusal("edge_device_enrolled", "invalid_registration_token")

	// A lease opens only with the device's own ML-KEM key, for its lease.
	w, out = r.do("POST", "/ekm/edge/devices/"+id+"/leases", nil, dev.key, map[string]any{"tenant_id": "t1", "key_id": "key-a", "ttl_seconds": 600})
	if w.Code != http.StatusCreated {
		t.Fatalf("lease: %d %s", w.Code, w.Body)
	}
	lease := out["lease"].(map[string]any)
	leaseID := lease["id"].(string)
	sealed, _ := base64.StdEncoding.DecodeString(out["sealed_dek"].(string))
	aad := edgeLeaseAAD("t1", id, leaseID)
	dek, err := dev.kem.Open(sealed, aad, edgeLeaseLabel)
	if err != nil || len(dek) != 32 {
		t.Fatalf("the device can't open its lease: %v", err)
	}
	if _, err := other.kem.Open(sealed, aad, edgeLeaseLabel); err == nil {
		t.Fatal("another device opened the lease")
	}
	if _, err := dev.kem.Open(sealed, edgeLeaseAAD("t1", id, "lease_other"), edgeLeaseLabel); err == nil {
		t.Fatal("the lease opened under another lease's binding")
	}
	stored, _ := r.svc.store.GetEdgeLease(t.Context(), "t1", leaseID)
	if stored.WrappedDEK == "" || strings.Contains(w.Body.String(), "plaintext") || time.Until(stored.ExpiresAt) > 11*time.Minute {
		t.Fatalf("lease stored: %+v", stored)
	}
	if !strings.Contains(r.kc.dataKeyCalls[len(r.kc.dataKeyCalls)-1], "key-a||") {
		t.Fatalf("the lease must be made as ekm, not a user: %v", r.kc.dataKeyCalls)
	}
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/leases", nil, dev.key, map[string]any{"tenant_id": "t1", "key_id": "key-z"}); w.Code != http.StatusForbidden {
		t.Fatalf("a key the device may not lease: %d", w.Code)
	}
	r.lastRefusal("edge_lease_issued", "key_not_allowed")
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/leases", nil, "wrong", map[string]any{"tenant_id": "t1", "key_id": "key-a"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong device key: %d", w.Code)
	}
	r.lastRefusal("edge_lease_issued", "invalid_device_key")

	// Receipts: signed and in order; a replay and a forgery are refused, a gap recorded.
	now := time.Now().UTC().Truncate(time.Second)
	batch := []edgeReceipt{{Seq: 1, LeaseID: leaseID, Operation: "encrypt", Bytes: 4096, At: now}, {Seq: 2, LeaseID: leaseID, Operation: "decrypt", Bytes: 4096, At: now}}
	if w, out := r.do("POST", "/ekm/edge/devices/"+id+"/receipts", nil, dev.key, dev.receipts(t, batch)); w.Code != http.StatusOK || out["received"] != float64(2) {
		t.Fatalf("receipts: %d %s", w.Code, w.Body)
	}
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/receipts", nil, dev.key, dev.receipts(t, batch)); w.Code != http.StatusConflict {
		t.Fatalf("a replayed batch: %d", w.Code)
	}
	r.lastRefusal("edge_receipts_received", "receipts_replayed")
	forged := dev.receipts(t, []edgeReceipt{{Seq: 3, LeaseID: leaseID, Operation: "encrypt", At: now}})
	forged["signature"] = other.receipts(t, []edgeReceipt{{Seq: 3, LeaseID: leaseID, Operation: "encrypt", At: now}})["signature"]
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/receipts", nil, dev.key, forged); w.Code != http.StatusUnauthorized {
		t.Fatalf("receipts signed by another key: %d", w.Code)
	}
	r.lastRefusal("edge_receipts_received", "receipt_signature_invalid")
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/receipts", nil, dev.key, dev.receipts(t, []edgeReceipt{{Seq: 3, LeaseID: "lease_nope", Operation: "encrypt", At: now}})); w.Code != http.StatusBadRequest {
		t.Fatalf("a lease the device doesn't hold: %d", w.Code)
	}
	r.lastRefusal("edge_receipts_received", "receipt_lease_unknown")
	w, out = r.do("POST", "/ekm/edge/devices/"+id+"/receipts", nil, dev.key, dev.receipts(t, []edgeReceipt{{Seq: 6, LeaseID: leaseID, Operation: "encrypt", At: now}}))
	if w.Code != http.StatusOK || out["gap"] != float64(3) {
		t.Fatalf("a gap: %d %s", w.Code, w.Body)
	}
	if ev := r.rec.Last(t); fmt.Sprint(ev.Event.Details["gap"]) != "3" {
		t.Fatalf("the gap must be audited: %+v", ev.Event.Details)
	}

	// A revoked lease is reported at check-in.
	if w, _ := r.do("POST", "/ekm/edge/leases/"+leaseID+"/revoke", r.admin, "", nil); w.Code != http.StatusOK {
		t.Fatalf("revoke lease: %d %s", w.Code, w.Body)
	}
	if w, out := r.do("POST", "/ekm/edge/devices/"+id+"/check-in", nil, dev.key, map[string]any{"tenant_id": "t1", "version": "1.0.1"}); w.Code != http.StatusOK || !strings.Contains(fmt.Sprint(out["revoked_lease_ids"]), leaseID) {
		t.Fatalf("check-in: %d %s", w.Code, w.Body)
	}

	// The list never shows a credential; a revoked device is cut off.
	if w, _ := r.do("GET", "/ekm/edge/devices", r.admin, "", nil); strings.Contains(w.Body.String(), "hash") || strings.Contains(w.Body.String(), dev.key) {
		t.Fatalf("list: %s", w.Body)
	}
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/revoke", r.admin, "", map[string]any{"reason": "stolen"}); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/leases", nil, dev.key, map[string]any{"tenant_id": "t1", "key_id": "key-a"}); w.Code != http.StatusForbidden {
		t.Fatalf("a revoked device leased: %d", w.Code)
	}
	r.lastRefusal("edge_lease_issued", "device_revoked")
	if w, _ := r.do("POST", "/ekm/edge/devices/"+id+"/registration-token", r.admin, "", nil); w.Code != http.StatusConflict {
		t.Fatalf("a revoked device got a new token: %d", w.Code)
	}
}

// The administrator's own access decides which keys a device may lease.
func TestEdgeDeviceKeysCheckedAsTheAdministrator(t *testing.T) {
	r := newEdgeRig(t)
	r.kc.refuseDataKey = map[string]*keycoreError{"key-secret": {Status: http.StatusForbidden, Code: "no_matching_grant", Msg: "access denied"}}
	w, _ := r.do("POST", "/ekm/edge/devices", r.admin, "", map[string]any{"name": "sensor-1", "allowed_key_ids": []string{"key-secret"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "key-secret") {
		t.Fatalf("a key the administrator can't use: %d %s", w.Code, w.Body)
	}
	r.lastRefusal("edge_device_created", "key_not_usable")
	for name, body := range map[string]map[string]any{
		"no keys":  {"name": "sensor-2"},
		"bad name": {"name": "a b", "allowed_key_ids": []string{"key-a"}},
		"too long": {"name": "sensor-3", "allowed_key_ids": []string{"key-a"}, "max_lease_seconds": 40 * 24 * 3600},
	} {
		if w, _ := r.do("POST", "/ekm/edge/devices", r.admin, "", body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	reader := &pkgauth.Claims{UserID: "u-r", TenantID: "t1", Permissions: []string{"ekm.read"}}
	if w, _ := r.do("POST", "/ekm/edge/devices", reader, "", map[string]any{"name": "sensor-4", "allowed_key_ids": []string{"key-a"}}); w.Code != http.StatusForbidden {
		t.Fatalf("a reader added a device: %d", w.Code)
	}
	dev := r.enrolled("sensor-5")
	if w, _ := r.do("POST", "/ekm/edge/devices/"+dev.id+"/leases", nil, dev.key, map[string]any{"tenant_id": "t2", "key_id": "key-a"}); w.Code == http.StatusCreated {
		t.Fatal("a device leased in another tenant")
	}
}
