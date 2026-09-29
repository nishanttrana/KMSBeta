package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/delegation"
)

var (
	dpService = func() *pkgauth.Claims {
		c := &pkgauth.Claims{ClientID: "kms-dataprotect", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
		c.Subject = "kms-dataprotect"
		return c
	}()
	delegAlice = &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator"}
	delegEve   = &pkgauth.Claims{UserID: "eve", TenantID: "t2", Role: "operator"}
)

// delegationHandler verifies forwarded tokens by name: the parser is the
// test's stand-in for JWT verification, which keycore does with its key.
func delegationHandler(t *testing.T) (*Handler, *Service, *eventRecorder) {
	t.Helper()
	h, svc, rec := newActorTestHandler(t)
	tokens := map[string]*pkgauth.Claims{"alice-token": delegAlice, "eve-token": delegEve, "service-token": dpService}
	h.SetTokenParser(func(raw string) (*pkgauth.Claims, error) {
		if c, ok := tokens[raw]; ok {
			return c, nil
		}
		return nil, errors.New("invalid token")
	})
	return h, svc, rec
}

// meterAs calls POST /keys/{id}/usage/meter as caller, forwarding token and
// usage the way pkg/delegation does ("" token: no delegation).
func meterAs(h *Handler, keyID string, caller *pkgauth.Claims, token, usage string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/usage/meter?tenant_id=t1", bytes.NewBufferString(`{"operation":"encrypt"}`))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), caller))
	if token != "" {
		req.Header.Set(delegation.HeaderToken, token)
		req.Header.Set(delegation.HeaderUsage, usage)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func bobKeyGrantedTo(t *testing.T, svc *Service, ops ...string) Key {
	t.Helper()
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "fpe", Algorithm: "AES-256",
		KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "bob", ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) > 0 {
		if err := svc.store.ReplaceKeyAccessGrants(context.Background(), "t1", key.ID, []KeyAccessGrant{
			{SubjectType: AccessSubjectUser, SubjectID: "alice", Operations: ops},
		}, "bob"); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

// A service acting for a user is decided with the user's grants for the
// usage: before, the service identity alone passed for any key.
func TestDelegatedUseDecidesWithUserGrant(t *testing.T) {
	h, svc, rec := delegationHandler(t)
	key := bobKeyGrantedTo(t, svc, "encrypt")

	if w := meterAs(h, key.ID, dpService, "alice-token", "fpe-encrypt"); w.Code != http.StatusForbidden {
		t.Fatalf("an encrypt grant allowed fpe-encrypt: %d %s", w.Code, w.Body)
	}
	d := refusalDetails(t, rec, "audit.key.access_refused")
	if d["operation"] != "encrypt" || d["usage"] != "fpe-encrypt" || d["via"] != "kms-dataprotect" || d["actor"] != "alice" {
		t.Fatalf("refusal details %+v", d)
	}

	if err := svc.store.ReplaceKeyAccessGrants(context.Background(), "t1", key.ID, []KeyAccessGrant{
		{SubjectType: AccessSubjectUser, SubjectID: "alice", Operations: []string{"fpe-encrypt"}},
	}, "bob"); err != nil {
		t.Fatal(err)
	}
	if w := meterAs(h, key.ID, dpService, "alice-token", "fpe-encrypt"); w.Code != http.StatusOK {
		t.Fatalf("fpe-encrypt grant refused: %d %s", w.Code, w.Body)
	}
	// With no user behind the request the service still acts as itself.
	if w := meterAs(h, key.ID, dpService, "", ""); w.Code != http.StatusOK {
		t.Fatalf("service without a user refused: %d %s", w.Code, w.Body)
	}
}

// The export decision for payment is the user's translate grant, and the user
// can't export the key themselves. (Keycore exports only under a wrapping
// key, which payment doesn't send yet: KEY_ACCESS_MODEL.md, "Payment key
// references".)
func TestDelegatedExportIsDecidedByTheTranslateGrant(t *testing.T) {
	h, svc, rec := delegationHandler(t)
	key := bobKeyGrantedTo(t, svc, "translate-decrypt")
	kek, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "kek", Algorithm: "AES-256",
		KeyType: "symmetric", Purpose: "wrap-unwrap", Owner: "ops", CreatedBy: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	payment := &pkgauth.Claims{ClientID: "kms-payment", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	payment.Subject = "kms-payment"
	export := func(caller *pkgauth.Claims, token, usage string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/export?tenant_id=t1", bytes.NewBufferString(`{"wrapping_key_id":"`+kek.ID+`"}`))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), caller))
		if token != "" {
			req.Header.Set(delegation.HeaderToken, token)
			req.Header.Set(delegation.HeaderUsage, usage)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := export(payment, "alice-token", "translate-encrypt"); w.Code != http.StatusForbidden {
		t.Fatalf("usage alice has no grant for: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["usage"] != "translate-encrypt" || d["via"] != "kms-payment" {
		t.Fatalf("details %+v", d)
	}
	if w := export(payment, "alice-token", "translate-decrypt"); w.Code != http.StatusOK {
		t.Fatalf("granted usage refused: %d %s", w.Code, w.Body)
	}
	if w := export(delegAlice, "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("alice exported the key directly: %d %s", w.Code, w.Body)
	}
}

// Every malformed delegation is refused before any handler and audited.
func TestDelegationRefusals(t *testing.T) {
	h, svc, rec := delegationHandler(t)
	key := bobKeyGrantedTo(t, svc, "all")
	cases := []struct {
		name         string
		caller       *pkgauth.Claims
		token, usage string
		reason       string
	}{
		{"user delegating", delegAlice, "alice-token", "fpe-encrypt", "delegation_by_non_service"},
		{"forged token", dpService, "forged", "fpe-encrypt", "delegation_token_invalid"},
		{"service token forwarded", dpService, "service-token", "fpe-encrypt", "delegation_token_is_service"},
		{"other tenant", dpService, "eve-token", "fpe-encrypt", "delegation_tenant_mismatch"},
		{"unknown usage", dpService, "alice-token", "everything", "delegation_usage_invalid"},
	}
	for _, c := range cases {
		if w := meterAs(h, key.ID, c.caller, c.token, c.usage); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", c.name, w.Code, w.Body)
		}
		if d := refusalDetails(t, rec, "audit.key.delegation_refused"); d["reason"] != c.reason {
			t.Fatalf("%s: reason %v, want %s", c.name, d["reason"], c.reason)
		}
	}
}

// A delegated user from another tenant is refused against the key's tenant
// even when the request names no tenant up front.
func TestDelegatedTenantMustOwnTheKey(t *testing.T) {
	_, svc, rec := newActorTestHandler(t)
	key := bobKeyGrantedTo(t, svc, "all")
	ctx := contextWithAccessActor(context.Background(), AccessActor{UserID: "eve", Username: "eve", Authenticated: true,
		TenantID: "t2", Via: "kms-dataprotect", Usage: "fpe-encrypt"})
	if err := svc.enforceKeyAccess(ctx, key, "encrypt"); err == nil {
		t.Fatal("user of another tenant used the key")
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "delegation_tenant_mismatch" {
		t.Fatalf("details %+v", d)
	}
}
