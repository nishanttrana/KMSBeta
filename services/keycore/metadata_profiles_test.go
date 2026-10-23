package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

var metaAdmin = &pkgauth.Claims{UserID: "u-meta", TenantID: "t1", Role: "operator", Permissions: []string{"key.metadata.read", "key.metadata.write", "key.create", "key.update"}}

func metaCall(t *testing.T, h http.Handler, claims *pkgauth.Claims, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path+"?tenant_id=t1", bytes.NewReader(raw))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMetadataProfileRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.metadataProfileRouter(rec), rec)
}

// A profile is enforced where keys are made and changed: a key that lacks
// what it requires is refused with every problem listed and audited, a
// default fills a missing label, keys of other purposes aren't affected,
// an update can't drop a required label, and a disabled profile is not
// applied.
func TestMetadataProfilesAreEnforced(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	ctx := context.Background()
	before, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "before", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "u-meta"})
	if err != nil {
		t.Fatal(err)
	}
	w := metaCall(t, h, metaAdmin, http.MethodPost, "/metadata-profiles", map[string]any{
		"name": "encryption keys", "purposes": []string{"encrypt"}, "require_owner": true,
		"labels": []map[string]any{
			{"key": "env", "required": true, "allowed": []string{"prod", "dev"}},
			{"key": "cost_center", "required": true, "pattern": "CC-[0-9]{4}"},
			{"key": "data_class", "default": "internal"},
		},
		"required_tags": []string{"pci"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", w.Code, w.Body)
	}
	var created struct {
		Profile MetadataProfile `json:"profile"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	_, err = svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "bad", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Labels: map[string]string{"env": "staging", "cost_center": "1234"}, CreatedBy: "u-meta"})
	var v *MetadataViolation
	if !errors.As(err, &v) || len(v.Problems) != 4 || v.Profiles[0] != "encryption keys" {
		t.Fatalf("violation: %v %+v", err, v)
	}
	joined := strings.Join(v.Problems, "|")
	for _, want := range []string{"an owner is required", `label "env": "staging" is not one of prod, dev`, `label "cost_center": "1234" doesn't match CC-[0-9]{4}`, `tag "pci" is required`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing problem %q in %v", want, v.Problems)
		}
	}
	if d := refusalDetails(t, rec, "audit.key.create_refused"); d["reason"] != "metadata_profile_violation" {
		t.Fatalf("refusal audited: %+v", d)
	}

	good, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "good", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "payments",
		Tags: []string{"pci"}, Labels: map[string]string{"env": "prod", "cost_center": "CC-0042"}, CreatedBy: "u-meta"})
	if err != nil {
		t.Fatal(err)
	}
	if good.Labels["data_class"] != "internal" {
		t.Fatalf("default not applied: %v", good.Labels)
	}
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "signer", Algorithm: "ECDSA-P256", KeyType: "asymmetric", Purpose: "sign", CreatedBy: "u-meta"}); err != nil {
		t.Fatalf("a key of another purpose was refused: %v", err)
	}

	// Through the API: 400 with the problems.
	w = metaCall(t, h, metaAdmin, http.MethodPost, "/keys", map[string]any{"tenant_id": "t1", "name": "api-bad", "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"metadata_profile_violation"`) || !strings.Contains(w.Body.String(), "an owner is required") {
		t.Fatalf("API create: %d %s", w.Code, w.Body)
	}

	// An update can't drop a required label.
	err = svc.UpdateKey(ctx, "t1", good.ID, UpdateKeyRequest{Name: "good", Purpose: "encrypt", Owner: "payments", Tags: []string{"pci"}, Labels: map[string]string{"env": "prod"}})
	if !errors.As(err, &v) || !strings.Contains(strings.Join(v.Problems, "|"), `label "cost_center" is required`) {
		t.Fatalf("update: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.update_refused"); d["reason"] != "metadata_profile_violation" {
		t.Fatalf("update refusal audited: %+v", d)
	}
	w = metaCall(t, h, metaAdmin, http.MethodPut, "/keys/"+good.ID, map[string]any{"name": "good", "purpose": "encrypt", "owner": "", "tags": []string{"pci"},
		"labels": map[string]string{"env": "prod", "cost_center": "CC-0042"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("API update: %d %s", w.Code, w.Body)
	}

	// Keys made before the profile are listed, not changed.
	w = metaCall(t, h, metaAdmin, http.MethodGet, "/metadata-profiles/"+created.Profile.ID+"/violations", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), before.ID) || strings.Contains(w.Body.String(), good.ID) {
		t.Fatalf("violations: %d %s", w.Code, w.Body)
	}

	// Disabled, it applies to nothing.
	in := created.Profile
	if w := metaCall(t, h, metaAdmin, http.MethodPut, "/metadata-profiles/"+in.ID, metadataProfileInput{Name: in.Name, Purposes: in.Purposes, Status: "disabled", MetadataProfileRules: in.MetadataProfileRules}); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "free", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "u-meta"}); err != nil {
		t.Fatalf("a disabled profile was enforced: %v", err)
	}
	if w := metaCall(t, h, metaAdmin, http.MethodDelete, "/metadata-profiles/"+in.ID, nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
}

// A profile that couldn't be applied as written is refused and audited.
func TestMetadataProfileValidation(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	router := h.metadataProfileRouter(rec)
	for name, body := range map[string]map[string]any{
		"no name":            {"labels": []map[string]any{}},
		"bad pattern":        {"name": "p1", "labels": []map[string]any{{"key": "env", "pattern": "(unclosed"}}},
		"default not listed": {"name": "p2", "labels": []map[string]any{{"key": "env", "allowed": []string{"prod"}, "default": "dev"}}},
		"two rules":          {"name": "p3", "labels": []map[string]any{{"key": "env"}, {"key": "env"}}},
		"platform label":     {"name": "p4", "labels": []map[string]any{{"key": "hsm_profile"}}},
		"bad status":         {"name": "p5", "status": "maybe"},
	} {
		w := metaCall(t, router, metaAdmin, http.MethodPost, "/metadata-profiles", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_metadata_profile" {
			t.Fatalf("%s: %+v", name, ev.Event)
		}
	}
	if w := metaCall(t, router, metaAdmin, http.MethodPost, "/metadata-profiles", map[string]any{"name": "dup"}); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := metaCall(t, router, metaAdmin, http.MethodPost, "/metadata-profiles", map[string]any{"name": "dup"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate name: %d %s", w.Code, w.Body)
	}
	reader := &pkgauth.Claims{UserID: "u-r", TenantID: "t1", Permissions: []string{"key.metadata.read"}}
	if w := metaCall(t, router, reader, http.MethodPost, "/metadata-profiles", map[string]any{"name": "x"}); w.Code != http.StatusForbidden {
		t.Fatalf("a reader wrote a profile: %d", w.Code)
	}
}

// The stored-only preview is retired: a new record of its category is
// refused and audited, the old route is gone, and records saved before
// read as retired so their content can be moved to a real profile.
func TestMetadataProfilePreviewRetired(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	ops := h.keyOpsRouter(rec)
	if _, err := svc.store.UpsertEnterpriseControlRecord(context.Background(), EnterpriseControlRecord{RecordID: "old-1", TenantID: "t1", Category: "metadata_profile", Name: "old", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	admin := &pkgauth.Claims{UserID: "u-e", TenantID: "t1", Permissions: []string{"key.enterprise.write", "key.enterprise.read"}}
	w := metaCall(t, ops, admin, http.MethodPost, "/enterprise/controls", map[string]any{"category": "metadata", "name": "new"})
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "/metadata-profiles") {
		t.Fatalf("retired category: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "enterprise_control_upserted" || ev.Event.Result != "refused" || ev.Event.Details["reason"] != "feature_retired" {
		t.Fatalf("refusal audited: %+v", ev)
	}
	if w := metaCall(t, h, admin, http.MethodPost, "/enterprise/metadata/profiles", map[string]any{"name": "new"}); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("the preview route still answers: %d", w.Code)
	}
	w = metaCall(t, h, admin, http.MethodGet, "/enterprise/controls", nil)
	if !strings.Contains(w.Body.String(), `"feature_status":"retired"`) {
		t.Fatalf("old record: %s", w.Body)
	}
}
