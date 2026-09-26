package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

func mintRequest(t *testing.T, h *Handler, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/cluster/mint", bytes.NewReader(raw))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestClusterMintOnlyForClusterManager(t *testing.T) {
	h, logic, _, pub := newTestHandler(t)
	service := func(clientID string) string {
		tok, _, err := logic.IssueClientJWT("root", clientID, clientID, "rest", []string{"service.internal"}, time.Minute, "api_key", nil, false, "")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	user, _, _ := logic.IssueJWT("root", "admin", []string{"*"}, "u-admin", false)
	body := map[string]any{"forwarded_by": "node-2", "claims": pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "alice"}}

	for name, bearer := range map[string]string{"none": "", "admin user": user, "other service": service("kms-keycore")} {
		if rr := mintRequest(t, h, bearer, body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s: mint must require the cluster-manager identity, got %d", name, rr.Code)
		}
	}

	rr := mintRequest(t, h, service("kms-cluster-manager"), body)
	if rr.Code != http.StatusOK {
		t.Fatalf("cluster-manager mint: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Token string `json:"access_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	claims, err := logic.ParseJWT(out.Token)
	if err != nil || claims.UserID != "alice" || claims.TenantID != "t1" || claims.Role != "tenant-admin" || claims.ForwardedBy != "node-2" {
		t.Fatalf("minted token must carry the verified identity and the forwarding node: %+v %v", claims, err)
	}
	if time.Until(claims.ExpiresAt.Time) > 6*time.Minute {
		t.Fatal("minted tokens must be short-lived")
	}
	minted := 0
	for _, s := range pub.subjects {
		if s == "audit.auth.cluster_token_minted" {
			minted++
		}
	}
	if minted != 1 {
		t.Fatalf("each mint must be audited once, got %d", minted)
	}

	pw := map[string]any{"forwarded_by": "node-2", "claims": pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "bob", MustChangePassword: true}}
	if rr := mintRequest(t, h, service("kms-cluster-manager"), pw); rr.Code != http.StatusForbidden {
		t.Fatalf("a user who must change their password must not get a forwarded token, got %d", rr.Code)
	}
	refused := 0
	for _, s := range pub.subjects {
		if s == "audit.auth.cluster_mint_refused" {
			refused++
		}
	}
	if refused != 4 {
		t.Fatalf("every refused mint must be audited (3 wrong callers + password change), got %d", refused)
	}
}
