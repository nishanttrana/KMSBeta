package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/route/routetest"
)

// authedHandler injects verified claims, as pkg/jwtauth does in production.
type authedHandler struct {
	*Handler
	claims *pkgauth.Claims
}

func (a authedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Handler.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), a.claims)))
}

func tenantAdmin(tenant string) *pkgauth.Claims {
	return &pkgauth.Claims{UserID: "u-" + tenant, TenantID: tenant, Role: "tenant-admin", Permissions: []string{"*"}}
}

func newSecretsHandler(t *testing.T) (*Handler, *Service, *SQLStore) {
	h, svc, store, _ := newRecordedHandler(t)
	return h, svc, store
}

func newRecordedHandler(t *testing.T) (*Handler, *Service, *SQLStore, *routetest.Recorder) {
	t.Helper()
	svc, store := newSecretsService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil, nil)
	h.directory = &directory{}
	h.spawn = func(run func()) { run() } // background prunes run inline, so tests see their result
	return h, svc, store, rec
}

func serveAs(h *Handler, claims *pkgauth.Claims, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	authedHandler{h, claims}.ServeHTTP(rr, req)
	return rr
}

func TestHandlerListNeverReturnsValue(t *testing.T) {
	h, svc, _ := newSecretsHandler(t)
	_, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		TenantID:   "t1",
		Name:       "token",
		SecretType: "token",
		Value:      "abc",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/secrets?tenant_id=t1", nil)
	rr := serveAs(h, tenantAdmin("t1"), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "\"value\"") {
		t.Fatalf("list response contains secret value: %s", rr.Body.String())
	}
}

func TestHandlerExpiredSecretValueReturns410(t *testing.T) {
	h, svc, store := newSecretsHandler(t)
	secret, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		TenantID:        "t2",
		Name:            "ttl-secret",
		SecretType:      "password",
		Value:           "secret",
		LeaseTTLSeconds: 10,
		CreatedBy:       "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.SQL().Exec(`UPDATE secrets SET expires_at = DATETIME('now', '-5 minute') WHERE tenant_id='t2' AND id=?`, secret.ID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/secrets/"+secret.ID+"/value?tenant_id=t2", nil)
	rr := serveAs(h, tenantAdmin("t2"), req)
	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerGenerateSSHKeyEndpoint(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	body := map[string]interface{}{
		"tenant_id":  "t3",
		"name":       "ssh-auto",
		"created_by": "tester",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/secrets/generate/ssh_key", bytes.NewReader(raw))
	rr := serveAs(h, tenantAdmin("t3"), req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ssh-ed25519") {
		t.Fatalf("expected generated public key in response body=%s", rr.Body.String())
	}
}

func TestHandlerGenerateKeyPairEndpoint(t *testing.T) {
	fipstest.SkipIfStrict(t, "X25519 / OpenPGP (SHA-1) key types")
	h, _, _ := newSecretsHandler(t)
	body := map[string]interface{}{
		"tenant_id":  "t4",
		"name":       "wg-auto",
		"key_type":   "wireguard-curve25519",
		"created_by": "tester",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/secrets/generate/keypair", bytes.NewReader(raw))
	rr := serveAs(h, tenantAdmin("t4"), req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"key_type":"wireguard-curve25519"`) {
		t.Fatalf("expected key_type in response body=%s", rr.Body.String())
	}
}

func TestVaultCompatibleKV2WriteRead(t *testing.T) {
	h, _, _ := newSecretsHandler(t)

	writeBody := `{"data":{"username":"alice","password":"s3cr3t"}}`
	writeReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app/config", bytes.NewReader([]byte(writeBody)))
	writeReq.Header.Set("X-Vault-Namespace", "vault-tenant")
	writeRR := serveAs(h, tenantAdmin("vault-tenant"), writeReq)
	if writeRR.Code != http.StatusOK {
		t.Fatalf("kv2 write status=%d body=%s", writeRR.Code, writeRR.Body.String())
	}

	readReq := httptest.NewRequest(http.MethodGet, "/v1/secret/data/app/config", nil)
	readReq.Header.Set("X-Vault-Namespace", "vault-tenant")
	readRR := serveAs(h, tenantAdmin("vault-tenant"), readReq)
	if readRR.Code != http.StatusOK {
		t.Fatalf("kv2 read status=%d body=%s", readRR.Code, readRR.Body.String())
	}
	body := readRR.Body.String()
	if !strings.Contains(body, `"username":"alice"`) || !strings.Contains(body, `"password":"s3cr3t"`) {
		t.Fatalf("unexpected kv2 read payload=%s", body)
	}
}

func TestVaultTokenLookupSelf(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token/lookup-self", nil)
	req.Header.Set("X-Vault-Token", "test-token")
	req.Header.Set("X-Vault-Namespace", "tenant-openbao")
	rr := serveAs(h, tenantAdmin("tenant-openbao"), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup-self status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "tenant-openbao") {
		t.Fatalf("lookup-self missing tenant metadata body=%s", rr.Body.String())
	}
}

// Every secrets route refuses an unauthenticated caller, a caller without the
// route's permission and a caller naming another tenant, and audits each
// refusal as audit.secrets.<action> with result "refused" and its reason.
func TestSecretsRoutesRefuseAndAudit(t *testing.T) {
	h, _, _, rec := newRecordedHandler(t)
	routetest.RefusalsAudited(t, h.router, rec)
}

// Before the kernel, POST /secrets took tenant_id from the body without
// checking it against the token: any tenant could write into another.
func TestCreateSecretRefusesCrossTenantBody(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	body := `{"tenant_id":"victim","name":"planted","secret_type":"token","value":"x"}`
	rr := serveAs(h, tenantAdmin("attacker"), httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: status %d body=%s", rr.Code, rr.Body)
	}
	if items, _ := svc.ListSecrets(context.Background(), "victim", "", 10, 0); len(items) != 0 {
		t.Fatalf("secret planted in another tenant: %+v", items)
	}
	ev := rec.Last(t)
	if ev.Action != "created" || ev.Event.Result != "refused" || ev.Event.Details["reason"] != "tenant_mismatch" ||
		ev.Event.ActorID != "u-attacker" || ev.Event.TenantID != "attacker" || ev.Event.Details["requested_tenant"] != "victim" {
		t.Fatalf("refusal not audited: %+v", ev)
	}
}

func TestSecretLifecycleEmitsSpecificEvents(t *testing.T) {
	h, _, _, rec := newRecordedHandler(t)
	admin := tenantAdmin("t7")
	rr := serveAs(h, admin, httptest.NewRequest(http.MethodPost, "/secrets",
		strings.NewReader(`{"tenant_id":"t7","name":"db","secret_type":"password","value":"hunter2","created_by":"spoofed"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	var created struct {
		Secret Secret `json:"secret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.Secret.CreatedBy != "u-t7" {
		t.Fatalf("created_by = %q, want the verified actor", created.Secret.CreatedBy)
	}
	ev := rec.Last(t)
	if ev.Action != "created" || ev.Event.TargetID != created.Secret.ID || ev.Event.TenantID != "t7" || ev.Event.ActorID != "u-t7" {
		t.Fatalf("create event %+v", ev)
	}

	id := created.Secret.ID
	steps := []struct {
		method, path, body, action string
		status                     int
	}{
		{"GET", "/secrets/" + id + "/value", "", "value_read", http.StatusOK},
		{"POST", "/secrets/" + id + "/rotate", `{"value":"n3w"}`, "rotated", http.StatusOK},
		{"DELETE", "/secrets/" + id, "", "deleted", http.StatusOK},
		{"POST", "/secrets/" + id + "/destroy", "", "destroyed", http.StatusOK},
		{"GET", "/secrets/" + id, "", "read", http.StatusNotFound},
	}
	for _, st := range steps {
		rr := serveAs(h, admin, httptest.NewRequest(st.method, st.path, strings.NewReader(st.body)))
		if rr.Code != st.status {
			t.Fatalf("%s %s: %d %s", st.method, st.path, rr.Code, rr.Body)
		}
		ev := rec.Last(t)
		if ev.Action != st.action || ev.Event.TargetID != id {
			t.Fatalf("%s %s: event %+v", st.method, st.path, ev)
		}
		for _, v := range ev.Event.Details {
			if s, _ := v.(string); s == "hunter2" || s == "n3w" {
				t.Fatalf("secret value leaked into audit details: %+v", ev.Event.Details)
			}
		}
	}
	if ev := rec.Last(t); ev.Event.Result != "failure" || ev.Event.Details["error_code"] != "read_failed" {
		t.Fatalf("not-found read not audited as failure: %+v", ev)
	}
}

func TestVaultNamespaceMustMatchToken(t *testing.T) {
	h, _, _, rec := newRecordedHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/app/config", nil)
	req.Header.Set("X-Vault-Namespace", "someone-else")
	if rr := serveAs(h, tenantAdmin("mine"), req); rr.Code != http.StatusForbidden {
		t.Fatalf("status %d", rr.Code)
	}
	if ev := rec.Last(t); ev.Action != "vault_kv_read" || ev.Event.Details["reason"] != "tenant_mismatch" {
		t.Fatalf("event %+v", ev)
	}
}

// A KV v1 body is the secret itself; a tenant_id key in it is stored, not
// treated as a (foreign) tenant.
func TestVaultKV1BodyTenantIsData(t *testing.T) {
	h, _, _, _ := newRecordedHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/kv/app/cfg", strings.NewReader(`{"tenant_id":"acme-prod","region":"eu"}`))
	if rr := serveAs(h, tenantAdmin("mine"), req); rr.Code != http.StatusOK {
		t.Fatalf("kv1 write: %d %s", rr.Code, rr.Body)
	}
	rr := serveAs(h, tenantAdmin("mine"), httptest.NewRequest(http.MethodGet, "/v1/kv/app/cfg", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"tenant_id":"acme-prod"`) {
		t.Fatalf("kv1 read: %d %s", rr.Code, rr.Body)
	}
}

// A KV write answers with the version it produced, and a second write to the
// same path is version 2, not another "created".
func TestVaultKVWriteReportsRealVersion(t *testing.T) {
	h, _, _, rec := newRecordedHandler(t)
	write := func(body string) map[string]interface{} {
		t.Helper()
		rr := serveAs(h, tenantAdmin("mine"), httptest.NewRequest(http.MethodPost, "/v1/secret/data/app/db", strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("kv2 write: %d %s", rr.Code, rr.Body)
		}
		var out struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	if d := write(`{"data":{"p":"one"}}`); d["version"] != float64(1) || d["created"] != nil {
		t.Fatalf("first write: %+v", d)
	}
	if ev := rec.Last(t); ev.Action != "vault_kv_written" || ev.Event.Details["created"] != true {
		t.Fatalf("first write event %+v", ev)
	}
	if d := write(`{"data":{"p":"two"}}`); d["version"] != float64(2) {
		t.Fatalf("second write: %+v", d)
	}
	if ev := rec.Last(t); ev.Event.Details["created"] != false {
		t.Fatalf("second write event %+v", ev)
	}
}

// lookup-self reports the token's own permissions, never an invented policy.
func TestVaultTokenLookupSelfReportsTokenOnly(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	claims := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Permissions: []string{"secrets.read"}}
	rr := serveAs(h, claims, httptest.NewRequest(http.MethodPost, "/v1/auth/token/lookup-self", nil))
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, `"policies":["secrets.read"]`) {
		t.Fatalf("lookup-self: %d %s", rr.Code, body)
	}
	for _, invented := range []string{`"default"`, "auth/token/create", "orphan", "creation_time"} {
		if strings.Contains(body, invented) {
			t.Fatalf("lookup-self invents %s: %s", invented, body)
		}
	}
}

// The version list carries no digest of the value.
func TestVersionsCarryNoValueHash(t *testing.T) {
	h, svc, _ := newSecretsHandler(t)
	sec, err := svc.CreateSecret(context.Background(), CreateSecretRequest{TenantID: "t1", Name: "pw", SecretType: "password", Value: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	rr := serveAs(h, tenantAdmin("t1"), httptest.NewRequest(http.MethodGet, "/secrets/"+sec.ID+"/versions", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"version":1`) || strings.Contains(rr.Body.String(), "hash") {
		t.Fatalf("versions: %d %s", rr.Code, rr.Body)
	}
}

// Stats that cannot be counted are an error, not an empty vault.
func TestStatsFailureIsNotZero(t *testing.T) {
	h, svc, store := newSecretsHandler(t)
	if _, err := svc.CreateSecret(context.Background(), CreateSecretRequest{TenantID: "t1", Name: "a", SecretType: "token", Value: "v", LeaseTTLSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
	stats, err := svc.GetStats(context.Background(), "t1", nil)
	if err != nil || stats.TotalSecrets != 1 || stats.TotalVersions != 1 || stats.ExpiringWithin != 1 || stats.Expired != 0 || stats.ByType["token"] != 1 {
		t.Fatalf("stats %+v err %v", stats, err)
	}
	if _, err := store.db.SQL().Exec(`DROP TABLE secret_values`); err != nil {
		t.Fatal(err)
	}
	rr := serveAs(h, tenantAdmin("t1"), httptest.NewRequest(http.MethodGet, "/secrets/stats", nil))
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "total_secrets") {
		t.Fatalf("stats with a broken store: %d %s", rr.Code, rr.Body)
	}
}

// The secret's change history names who deleted it, not "system".
func TestDeleteRecordsTheCaller(t *testing.T) {
	h, svc, _ := newSecretsHandler(t)
	sec, err := svc.CreateSecret(context.Background(), CreateSecretRequest{TenantID: "t1", Name: "gone", SecretType: "token", Value: "v", CreatedBy: "u-t1"})
	if err != nil {
		t.Fatal(err)
	}
	if rr := serveAs(h, tenantAdmin("t1"), httptest.NewRequest(http.MethodDelete, "/secrets/"+sec.ID, nil)); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body)
	}
	log, err := svc.GetSecretAuditLog(context.Background(), "t1", sec.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	var deletedBy string
	for _, e := range log {
		if e.Action == "deleted" {
			deletedBy = e.Actor
		}
	}
	if deletedBy != "u-t1" {
		t.Fatalf("deleted by %q, log %+v", deletedBy, log)
	}
}
