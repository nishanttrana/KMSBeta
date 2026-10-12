package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func byokRouter(svc *Service) (*route.Router, *routetest.Recorder) {
	rec := &routetest.Recorder{}
	rt := route.New("cloud", rec, nil)
	(&Handler{svc: svc}).byokRoutes(rt)
	return rt, rec
}

func TestBYOKRoutesRefusalsAudited(t *testing.T) {
	svc, _, _, _ := newCloudService(t)
	rt, rec := byokRouter(svc)
	routetest.RefusalsAudited(t, rt, rec)
}

func serveBYOK(rt *route.Router, method, path string, body interface{}) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	claims := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: []string{"cloud.read", "cloud.write"}}
	claims.Subject = "alice"
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	return rr
}

// Over HTTP: each operation is audited as its own action with the run, the
// KMS key and the cloud key; a refusal is audited as refused with its
// reason; a failed run returns its steps and is audited as a failure.
func TestBYOKRoutesAuditEachOperation(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	kc.Seed("t1", "key-1", "AES-256")
	rt, rec := byokRouter(svc)

	rr := serveBYOK(rt, http.MethodPost, "/cloud/byok/keys", map[string]interface{}{"account_id": acct.ID, "key_id": "key-1"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	var out struct {
		Key BYOKKey `json:"key"`
		Run BYOKRun `json:"run"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	e := rec.Last(t)
	if e.Action != "byok_created" || e.Event.Result != "success" || e.Event.TargetID != out.Key.ID || e.Event.Details["run_id"] != out.Run.ID ||
		e.Event.Details["key_id"] != "key-1" || e.Event.Details["cloud_key_id"] != out.Key.CloudKeyID || e.Event.Details["source"] != SourceKMS {
		t.Fatalf("create event %+v", e.Event)
	}
	// In this order: a restore needs the revoke before it (a map here ran
	// them in random order and failed about one run in five).
	for _, step := range []struct{ op, action string }{
		{"rotate", "byok_rotated"}, {"verify", "byok_verified"}, {"sync", "byok_synced"}, {"revoke", "byok_revoked"}, {"restore", "byok_restored"},
	} {
		op, action := step.op, step.action
		if rr := serveBYOK(rt, http.MethodPost, "/cloud/byok/keys/"+out.Key.ID+"/"+op, nil); rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", op, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Action != action || e.Event.Result != "success" || e.Event.TargetID != out.Key.ID {
			t.Fatalf("%s event %+v", op, e.Event)
		}
	}

	// Refused: an unknown account, with its reason.
	if rr := serveBYOK(rt, http.MethodPost, "/cloud/byok/keys", map[string]interface{}{"account_id": "nope", "key_id": "key-1"}); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown account: %d", rr.Code)
	}
	if e := rec.Last(t); e.Event.Result != "refused" || e.Event.Details["reason"] != "account_not_found" {
		t.Fatalf("refusal event %+v", e.Event)
	}

	// A failed run: the cloud loses the key; verify fails with its steps.
	delete(d.keys, out.Key.CloudKeyID)
	rr = serveBYOK(rt, http.MethodPost, "/cloud/byok/keys/"+out.Key.ID+"/verify", nil)
	var failed struct {
		Run BYOKRun `json:"run"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &failed)
	if rr.Code != http.StatusBadGateway || failed.Run.Status != "failed" || len(failed.Run.Steps) != 1 {
		t.Fatalf("failed run: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "byok_verified" || e.Event.Result != "failure" {
		t.Fatalf("failure event %+v", e.Event)
	}

	if rr := serveBYOK(rt, http.MethodGet, "/cloud/byok/keys/"+out.Key.ID, nil); rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"materials"`)) {
		t.Fatalf("detail: %d %s", rr.Code, rr.Body)
	}
	if rr := serveBYOK(rt, http.MethodGet, "/cloud/byok/providers", nil); rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"salesforce"`)) {
		t.Fatalf("providers: %d %s", rr.Code, rr.Body)
	}
}
