package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

type clientRig struct {
	t      *testing.T
	h      *Handler
	svc    *Service
	store  *SQLStore
	rec    *routetest.Recorder
	pub    *nopEKMPublisher
	tenant string
	admin  *pkgauth.Claims
}

func newClientRig(t *testing.T) *clientRig {
	t.Helper()
	h, svc, _, pub := newEKMHandler(t)
	return rigFor(t, h, svc, pub, "t1")
}

// rigFor mounts the client routes on h, as main does, for one tenant.
func rigFor(t *testing.T, h *Handler, svc *Service, pub *nopEKMPublisher, tenant string) *clientRig {
	t.Helper()
	rec := &routetest.Recorder{}
	kernel := route.New("ekm", rec, nil)
	h.clientRoutes(kernel)
	kernel.MountOn(h.mux)
	return &clientRig{
		t: t, h: h, svc: svc, store: svc.store.(*SQLStore), rec: rec, pub: pub, tenant: tenant,
		admin: &pkgauth.Claims{UserID: "admin-1", TenantID: tenant, Role: "admin", Permissions: []string{"*"}},
	}
}

// do sends a request. claims is the caller's verified auth-service token, or
// nil for an agent, which has none.
func (r *clientRig) do(method, path string, claims *pkgauth.Claims, headers map[string]string, body interface{}) (*httptest.ResponseRecorder, map[string]interface{}) {
	r.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	r.h.mux.ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func (r *clientRig) create(name string) string {
	r.t.Helper()
	w, out := r.do("POST", "/ekm/clients", r.admin, nil, map[string]interface{}{"name": name, "db_engine": "oracle", "host": "db.corp.local"})
	if w.Code != http.StatusCreated {
		r.t.Fatalf("create %s: %d %s", name, w.Code, w.Body.String())
	}
	return out["client"].(map[string]interface{})["id"].(string)
}

func (r *clientRig) token(id string) string {
	r.t.Helper()
	w, out := r.do("POST", "/ekm/clients/"+id+"/registration-token", r.admin, nil, nil)
	if w.Code != http.StatusCreated {
		r.t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	return out["token"].(string)
}

func (r *clientRig) enroll(token string) (*httptest.ResponseRecorder, map[string]interface{}) {
	r.t.Helper()
	return r.do("POST", "/ekm/clients/enroll", nil, map[string]string{"X-Forwarded-For": "6.6.6.6, 10.20.15.32"},
		map[string]interface{}{"tenant_id": r.tenant, "token": token, "version": "2.1.0", "host": "db.corp.local"})
}

func (r *clientRig) checkIn(id, key string) *httptest.ResponseRecorder {
	r.t.Helper()
	w, _ := r.do("POST", "/ekm/clients/"+id+"/check-in", nil, map[string]string{clientKeyHeader: key},
		map[string]interface{}{"tenant_id": r.tenant, "status": "connected", "tde_state": "enabled", "version": "2.1.0"})
	return w
}

func (r *clientRig) view(id string) map[string]interface{} {
	r.t.Helper()
	w, out := r.do("GET", "/ekm/clients/"+id, r.admin, nil, nil)
	if w.Code != http.StatusOK {
		r.t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	return out
}

// refused asserts the last kernel event is the route's own, refused, with reason.
func (r *clientRig) refused(step string, w *httptest.ResponseRecorder, status int, action, reason string) {
	r.t.Helper()
	if w.Code != status {
		r.t.Fatalf("%s: status %d, want %d (%s)", step, w.Code, status, w.Body.String())
	}
	ev := r.rec.Last(r.t)
	if ev.Action != action || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != reason {
		r.t.Fatalf("%s: audited %s result=%s reason=%v, want %s refused %s", step, ev.Action, ev.Event.Result, ev.Event.Details["reason"], action, reason)
	}
}

func (r *clientRig) setLastSeen(id string, ago time.Duration) {
	r.t.Helper()
	if _, err := r.store.db.SQL().Exec(`UPDATE ekm_agents SET last_heartbeat_at = $1 WHERE tenant_id = $2 AND id = $3`, time.Now().UTC().Add(-ago), r.tenant, id); err != nil {
		r.t.Fatal(err)
	}
}

func TestClientRoutesRefuseAndAudit(t *testing.T) {
	h, _, _, _ := newEKMHandler(t)
	rec := &routetest.Recorder{}
	kernel := route.New("ekm", rec, nil)
	h.clientRoutes(kernel)
	routetest.RefusalsAudited(t, kernel, rec)
}

// A client is pending until its agent presents the one-time token; nothing
// else registers it or makes it look alive.
func TestClientIsPendingUntilItsAgentEnrols(t *testing.T) {
	r := newClientRig(t)
	id := r.create("ORCL-PROD-01")
	if ev := r.rec.Last(t); ev.Action != "client_created" || ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != id || ev.Event.ActorID != "admin-1" {
		t.Fatalf("create audit: %+v", ev)
	}
	c := r.view(id)["client"].(map[string]interface{})
	if c["registration"] != "pending" || c["health"] != "pending" || c["last_seen_at"] != nil || c["registered_at"] != nil || c["credential"] != "" {
		t.Fatalf("a new client must be pending and never seen: %+v", c)
	}
	if c["assigned_key_id"] == "" {
		t.Fatalf("no TDE key was provisioned: %+v", c)
	}
	var status string
	_ = r.store.db.SQL().QueryRow(`SELECT status FROM ekm_agents WHERE id = $1`, id).Scan(&status)
	if status == AgentStatusConnected {
		t.Fatal("a pending client is stored as connected")
	}

	if w, _ := r.do("POST", "/ekm/clients", r.admin, nil, map[string]interface{}{"name": "orcl-prod-01", "db_engine": "oracle"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate name: %d", w.Code)
	}
	for _, bad := range []map[string]interface{}{
		{"name": "x", "db_engine": "oracle"},
		{"name": "has space", "db_engine": "oracle"},
		{"name": "ORCL-02", "db_engine": "sqlite"},
		{"name": "ORCL-02", "db_engine": "oracle", "host": "bad host/"},
	} {
		if w, _ := r.do("POST", "/ekm/clients", r.admin, nil, bad); w.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, w.Code)
		}
	}

	// The token-authenticated calls can't register it or stamp a heartbeat.
	user := &pkgauth.Claims{UserID: "u2", TenantID: "t1", Role: "ops"}
	for step, call := range map[string]func() *httptest.ResponseRecorder{
		"heartbeat": func() *httptest.ResponseRecorder {
			w, _ := r.do("POST", "/ekm/agents/"+id+"/heartbeat", user, nil, map[string]interface{}{"tenant_id": "t1", "status": "connected"})
			return w
		},
		"register": func() *httptest.ResponseRecorder {
			w, _ := r.do("POST", "/ekm/agents/register", user, nil, map[string]interface{}{"tenant_id": "t1", "agent_id": id, "name": "x"})
			return w
		},
		"validate": func() *httptest.ResponseRecorder {
			w, _ := r.do("POST", "/ekm/agents/"+id+"/validate-deploy", user, nil, map[string]interface{}{"tenant_id": "t1", "connectivity": "ok"})
			return w
		},
	} {
		if w := call(); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "client_enrollment_required") {
			t.Fatalf("%s on a pending client: %d %s", step, w.Code, w.Body.String())
		}
		if ev := r.pub.Last("audit.ekm.request_refused"); ev["code"] != "client_enrollment_required" || ev["result"] != "refused" {
			t.Fatalf("%s refusal audit: %+v", step, ev)
		}
	}
	if c := r.view(id)["client"].(map[string]interface{}); c["registration"] != "pending" || c["last_seen_at"] != nil {
		t.Fatalf("a refused call changed the client: %+v", c)
	}

	// No token issued yet, a made-up token, and another tenant's body.
	w, _ := r.enroll("vekm-reg.dDE." + id + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	r.refused("made-up token", w, http.StatusUnauthorized, "client_enrolled", "invalid_registration_token")
	w, _ = r.enroll("not-a-token")
	r.refused("malformed token", w, http.StatusUnauthorized, "client_enrolled", "invalid_registration_token")

	token := r.token(id)
	if ev := r.rec.Last(t); ev.Action != "client_token_issued" || ev.Event.TargetID != id || strings.Contains(fmt.Sprint(ev.Event.Details), token) {
		t.Fatalf("token audit: %+v", ev)
	}
	var stored string
	_ = r.store.db.SQL().QueryRow(`SELECT enroll_token_hash FROM ekm_agents WHERE id = $1`, id).Scan(&stored)
	if stored == "" || stored == token || strings.Contains(token, stored) || stored != verifierHash(token) {
		t.Fatal("the registration token must be stored as its hash only")
	}
	if c := r.view(id)["client"].(map[string]interface{}); c["token_expires_at"] == nil || c["registration"] != "pending" {
		t.Fatalf("issuing a token must not register the client: %+v", c)
	}
	w, _ = r.do("POST", "/ekm/clients/enroll", nil, nil, map[string]interface{}{"tenant_id": "t2", "token": token})
	r.refused("token presented for another tenant", w, http.StatusUnauthorized, "client_enrolled", "invalid_registration_token")

	w, out := r.enroll(token)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	key, _ := out["client_key"].(string)
	ev := r.rec.Last(t)
	if ev.Action != "client_enrolled" || ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != id || ev.Event.ActorType != "ekm_client" ||
		ev.Event.TenantID != "t1" || ev.Event.Details["client_source_ip"] != "10.20.15.32" {
		t.Fatalf("enroll audit: %+v", ev)
	}
	if key == "" || strings.Contains(fmt.Sprint(ev.Event.Details), key) || strings.Contains(fmt.Sprint(ev.Event.Details), token) {
		t.Fatal("the enrolment event carries a secret, or no client key was issued")
	}
	c = out["client"].(map[string]interface{})
	if c["registration"] != "registered" || c["health"] != "healthy" || c["source_ip"] != "10.20.15.32" || c["version"] != "2.1.0" || c["credential"] != "client_key" || c["token_expires_at"] != nil {
		t.Fatalf("enrolled client: %+v", c)
	}
	_ = r.store.db.SQL().QueryRow(`SELECT credential_hash FROM ekm_agents WHERE id = $1`, id).Scan(&stored)
	if stored != verifierHash(key) {
		t.Fatal("the client key must be stored as its hash only")
	}

	// One use.
	w, _ = r.enroll(token)
	r.refused("token used twice", w, http.StatusUnauthorized, "client_enrolled", "invalid_registration_token")
}

func TestClientChecksInWithItsOwnKey(t *testing.T) {
	r := newClientRig(t)
	id, other := r.create("ORCL-PROD-01"), r.create("MSSQL-FIN-02")
	_, out := r.enroll(r.token(id))
	key := out["client_key"].(string)
	_, out = r.enroll(r.token(other))
	otherKey := out["client_key"].(string)

	r.refused("no key", r.checkIn(id, ""), http.StatusUnauthorized, "client_check_in", "invalid_client_key")
	r.refused("wrong key", r.checkIn(id, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), http.StatusUnauthorized, "client_check_in", "invalid_client_key")
	r.refused("another client's key", r.checkIn(id, otherKey), http.StatusUnauthorized, "client_check_in", "invalid_client_key")
	r.refused("unknown client", r.checkIn("ekm_nope", key), http.StatusUnauthorized, "client_check_in", "invalid_client_key")
	w, _ := r.do("POST", "/ekm/clients/"+id+"/check-in", nil, map[string]string{clientKeyHeader: key}, map[string]interface{}{"tenant_id": "t2"})
	r.refused("key presented for another tenant", w, http.StatusUnauthorized, "client_check_in", "invalid_client_key")

	// An auth-service token of the tenant is not this client's credential.
	user := &pkgauth.Claims{UserID: "u2", TenantID: "t1", Role: "ops"}
	w, _ = r.do("POST", "/ekm/agents/"+id+"/heartbeat", user, nil, map[string]interface{}{"tenant_id": "t1", "status": "connected"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "client_key_required") {
		t.Fatalf("token heartbeat for a client with a key: %d %s", w.Code, w.Body.String())
	}
	if ev := r.pub.Last("audit.ekm.request_refused"); ev["code"] != "client_key_required" {
		t.Fatalf("refusal audit: %+v", ev)
	}

	r.setLastSeen(id, 2*time.Hour)
	if c := r.view(id)["client"].(map[string]interface{}); c["health"] != "offline" {
		t.Fatalf("a client last seen two hours ago: %+v", c)
	}
	if w := r.checkIn(id, key); w.Code != http.StatusOK {
		t.Fatalf("check-in: %d %s", w.Code, w.Body.String())
	}
	if ev := r.rec.Last(t); ev.Action != "client_check_in" || ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != id || ev.Event.ActorType != "ekm_client" {
		t.Fatalf("check-in audit: %+v", ev)
	}
	detail := r.view(id)
	if c := detail["client"].(map[string]interface{}); c["health"] != "healthy" || c["tde_state"] != "enabled" {
		t.Fatalf("after a check-in: %+v", c)
	}
	// The enrolment and the check-in, oldest first, and nothing refused.
	checkIns := detail["check_ins"].([]interface{})
	if len(checkIns) != 2 {
		t.Fatalf("check-ins: %d, want 2", len(checkIns))
	}
	first, last := checkIns[0].(map[string]interface{}), checkIns[1].(map[string]interface{})
	if first["at"].(string) > last["at"].(string) || last["status"] != "connected" || last["version"] != "2.1.0" {
		t.Fatalf("check-ins out of order or incomplete: %+v", checkIns)
	}
	if detail["key"] == nil || detail["thresholds"].(map[string]interface{})["healthy_within_sec"] != float64(300) {
		t.Fatalf("detail: %+v", detail)
	}

	// Re-enrolment replaces the key.
	_, out = r.enroll(r.token(id))
	newKey := out["client_key"].(string)
	if ev := r.rec.Last(t); ev.Event.Details["reenrolment"] != true {
		t.Fatalf("re-enrolment audit: %+v", ev)
	}
	r.refused("replaced key", r.checkIn(id, key), http.StatusUnauthorized, "client_check_in", "invalid_client_key")
	if w := r.checkIn(id, newKey); w.Code != http.StatusOK {
		t.Fatalf("check-in with the new key: %d", w.Code)
	}
}

func TestClientRegistrationTokenExpires(t *testing.T) {
	r := newClientRig(t)
	id := r.create("ORCL-DR-03")
	token := r.token(id)
	if _, err := r.store.db.SQL().Exec(`UPDATE ekm_agents SET enroll_token_expires_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Minute), id); err != nil {
		t.Fatal(err)
	}
	w, _ := r.enroll(token)
	r.refused("expired token", w, http.StatusUnauthorized, "client_enrolled", "registration_token_expired")
	if c := r.view(id)["client"].(map[string]interface{}); c["registration"] != "pending" || c["token_expires_at"] != nil {
		t.Fatalf("an expired token registered the client or is still shown: %+v", c)
	}
	// A new token replaces it.
	old := token
	token = r.token(id)
	w, _ = r.enroll(old)
	r.refused("replaced token", w, http.StatusUnauthorized, "client_enrolled", "invalid_registration_token")
	if w, _ := r.enroll(token); w.Code != http.StatusOK {
		t.Fatalf("enroll with the new token: %d", w.Code)
	}
}

func TestClientHealthIsTheAgeOfTheLastCheckIn(t *testing.T) {
	now := time.Now().UTC()
	seen := func(ago time.Duration) clientRecord {
		return clientRecord{Registration: registrationRegistered, LastSeenAt: now.Add(-ago)}
	}
	for _, tc := range []struct {
		c    clientRecord
		want string
	}{
		{clientRecord{Registration: registrationPending}, clientHealthPending},
		{clientRecord{Registration: registrationPending, LastSeenAt: now}, clientHealthPending},
		{clientRecord{Registration: registrationRegistered}, clientHealthOffline},
		{seen(0), clientHealthHealthy},
		{seen(5 * time.Minute), clientHealthHealthy},
		{seen(5*time.Minute + time.Second), clientHealthDegraded},
		{seen(60 * time.Minute), clientHealthDegraded},
		{seen(60*time.Minute + time.Second), clientHealthOffline},
	} {
		if got := clientHealth(tc.c, now); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.c, got, tc.want)
		}
	}
	if v := clientView(clientRecord{Registration: registrationRegistered}, now); v.LastSeenAt != nil || v.LastSeenAgeSec != nil {
		t.Errorf("a client never seen must have no last-seen time: %+v", v)
	}
}

// A client registered through the token-authenticated call before 11.6.0-beta
// keeps working, is shown as registered, and gets a check-in history.
func TestTokenAuthenticatedAgentsKeepCheckingIn(t *testing.T) {
	r := newClientRig(t)
	agent := &pkgauth.Claims{ClientID: "agent-client", TenantID: "t1", Role: "ekm-agent"}
	w, _ := r.do("POST", "/ekm/agents/register", agent, map[string]string{"X-Forwarded-For": "10.1.1.9"},
		map[string]interface{}{"tenant_id": "t1", "agent_id": "agent-legacy", "name": "LEGACY-01", "db_engine": "mssql", "version": "1.4.0"})
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	w, _ = r.do("POST", "/ekm/agents/agent-legacy/heartbeat", agent, map[string]string{"X-Forwarded-For": "10.1.1.9"}, map[string]interface{}{"tenant_id": "t1", "status": "connected"})
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	detail := r.view("agent-legacy")
	c := detail["client"].(map[string]interface{})
	if c["registration"] != "registered" || c["credential"] != "service_token" || c["health"] != "healthy" || c["registered_at"] == nil || c["source_ip"] != "10.1.1.9" {
		t.Fatalf("legacy client: %+v", c)
	}
	if n := len(detail["check_ins"].([]interface{})); n != 2 {
		t.Fatalf("check-ins: %d, want 2", n)
	}
}

func TestClientCheckInsArePrunedAndPurged(t *testing.T) {
	r := newClientRig(t)
	id := r.create("ORCL-PROD-01")
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < checkInsKept+15; i++ {
		if err := r.store.RecordClientCheckIn(context.Background(), ClientCheckIn{TenantID: "t1", ClientID: id, At: base.Add(time.Duration(i) * time.Second), Status: AgentStatusConnected}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := r.store.ListClientCheckIns(context.Background(), "t1", id, 0)
	if err != nil || len(all) != checkInsKept {
		t.Fatalf("kept %d check-ins (%v), want %d", len(all), err, checkInsKept)
	}
	if !all[len(all)-1].At.Equal(base.Add(time.Duration(checkInsKept+14) * time.Second)) {
		t.Fatalf("the newest check-in was not kept: %v", all[len(all)-1].At)
	}
	if _, err := r.svc.DeleteAgent(context.Background(), "t1", id, "test"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = r.store.db.SQL().QueryRow(`SELECT COUNT(1) FROM ekm_agent_checkins WHERE agent_id = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatalf("%d check-ins left after the client was deleted", n)
	}
}

// The packaged heartbeat scripts can't read the database, so they must not
// report its TDE state as enabled.
func TestDeployScriptsDoNotClaimTDEIsEnabled(t *testing.T) {
	svc, _, _, _ := newEKMService(t)
	ctx := context.Background()
	if _, _, err := svc.RegisterAgent(ctx, RegisterAgentRequest{TenantID: "t1", AgentID: "agent-pkg", DBEngine: "mssql"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, os := range []string{"linux", "windows"} {
		pkg, err := svc.BuildAgentDeployPackage(ctx, "t1", "agent-pkg", os)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range pkg.Files {
			if strings.HasPrefix(f.Path, "heartbeat") && (strings.Contains(f.Content, `"tde_state":"enabled"`) || strings.Contains(f.Content, `tde_state = "enabled"`)) {
				t.Errorf("%s %s reports TDE as enabled without reading the database", os, f.Path)
			}
		}
	}
}
