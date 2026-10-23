package main

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

func TestKeyPatchRouteRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.keyAdminRouter(rec), rec)
}

// PATCH changes only the fields it names; owner, cloud, region and the
// rest stay as stored, which a PUT built from what the API returns can't
// guarantee. The change is audited with the fields that changed.
func TestKeyPatchKeepsWhatItDoesntName(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "orders", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "payments", Cloud: "aws", Region: "eu-west-1", Compliance: []string{"pci"}, Tags: []string{"prod"}, Labels: map[string]string{"env": "prod"}, CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	owner := &pkgauth.Claims{UserID: "owner-1", TenantID: "t1", Role: "operator", Permissions: []string{"key.update", "key.read"}}
	rec := &routetest.Recorder{}
	router := h.keyAdminRouter(rec)
	w := metaCall(t, router, owner, http.MethodPatch, "/keys/"+key.ID, map[string]any{"labels": map[string]string{"env": "prod", "team": "orders"}, "description": "order data"})
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body)
	}
	var out struct {
		Key map[string]any `json:"key"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Key["owner"] != "payments" || out.Key["description"] != "order data" || out.Key["name"] != "orders" {
		t.Fatalf("patched key: %+v", out.Key)
	}
	stored, _ := svc.store.GetKey(ctx, "t1", key.ID)
	if stored.Owner != "payments" || stored.Cloud != "aws" || stored.Region != "eu-west-1" || !slices.Contains(stored.Compliance, "pci") ||
		!slices.Contains(stored.Tags, "prod") || stored.Labels["team"] != "orders" {
		t.Fatalf("PATCH changed fields it didn't name: %+v", stored)
	}
	ev := rec.Last(t)
	if ev.Action != "metadata_patched" || !strings.Contains(strings.Join(anyStrings(ev.Event.Details["changed"]), ","), "labels") {
		t.Fatalf("audit: %+v", ev.Event)
	}
	if w := metaCall(t, router, owner, http.MethodPatch, "/keys/"+key.ID, map[string]any{"name": " "}); w.Code != http.StatusBadRequest {
		t.Fatalf("an empty name: %d", w.Code)
	}
}

// Both update routes need the caller to see the key and manage it. A
// caller with key.update and only an encrypt grant used to be able to
// rename any key; a caller who can't see it gets not found.
func TestKeyUpdateNeedsToManageTheKey(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	ctx := context.Background()
	key := ownedKey(t, svc)
	if err := svc.store.ReplaceKeyAccessGrants(ctx, "t1", key.ID, []KeyAccessGrant{
		{SubjectType: AccessSubjectUser, SubjectID: "user-enc", Operations: []string{"encrypt"}},
		{SubjectType: AccessSubjectUser, SubjectID: "user-all", Operations: []string{"all"}},
	}, "owner-1"); err != nil {
		t.Fatal(err)
	}
	as := func(id string) *pkgauth.Claims {
		return &pkgauth.Claims{UserID: id, TenantID: "t1", Role: "operator", Permissions: []string{"key.update", "key.read"}}
	}
	put := map[string]any{"name": "renamed", "purpose": "encrypt"}
	for _, method := range []string{http.MethodPatch, http.MethodPut} {
		if w := metaCall(t, h, as("user-enc"), method, "/keys/"+key.ID, put); w.Code != http.StatusForbidden {
			t.Fatalf("%s by an encrypt-only grantee: %d %s", method, w.Code, w.Body)
		}
		if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "no_matching_grant" {
			t.Fatalf("%s refusal: %+v", method, d)
		}
		if w := metaCall(t, h, as("stranger"), method, "/keys/"+key.ID, put); w.Code != http.StatusNotFound {
			t.Fatalf("%s by a caller who can't see it: %d", method, w.Code)
		}
	}
	if w := metaCall(t, h, as("user-all"), http.MethodPatch, "/keys/"+key.ID, map[string]any{"name": "renamed"}); w.Code != http.StatusOK {
		t.Fatalf("a grant of all: %d %s", w.Code, w.Body)
	}
	if stored, _ := svc.store.GetKey(ctx, "t1", key.ID); stored.Name != "renamed" {
		t.Fatalf("name %q", stored.Name)
	}
}

// The tenant's metadata profiles apply to a PATCH as to any update.
func TestKeyPatchFollowsMetadataProfiles(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Labels: map[string]string{"env": "prod"}, CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	p := MetadataProfile{ID: "mdp_1", TenantID: "t1", Name: "env", MetadataProfileRules: MetadataProfileRules{Labels: []MetadataLabelRule{{Key: "env", Required: true}}}}
	if err := normalizeMetadataProfile(&p); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.CreateMetadataProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	owner := &pkgauth.Claims{UserID: "owner-1", TenantID: "t1", Role: "operator", Permissions: []string{"key.update"}}
	w := metaCall(t, h, owner, http.MethodPatch, "/keys/"+key.ID, map[string]any{"labels": map[string]string{"team": "x"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "metadata_profile_violation") {
		t.Fatalf("a patch dropping a required label: %d %s", w.Code, w.Body)
	}
}

func anyStrings(v any) []string {
	out := []string{}
	if list, ok := v.([]string); ok {
		return list
	}
	if list, ok := v.([]any); ok {
		for _, s := range list {
			out = append(out, toString(s))
		}
	}
	return out
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}
