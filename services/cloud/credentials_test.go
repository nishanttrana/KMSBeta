package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// recordingProvider is the AWS test provider, recording the credentials each
// inventory call was given and failing on demand.
type recordingProvider struct {
	*mockProvider
	seen []map[string]interface{}
	err  error
}

func (p *recordingProvider) Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error) {
	p.seen = append(p.seen, in.Credentials)
	if p.err != nil {
		return nil, p.err
	}
	return p.mockProvider.Inventory(ctx, in)
}

func recordAWS(svc *Service) *recordingProvider {
	p := &recordingProvider{mockProvider: newMockProvider(ProviderAWS)}
	svc.providers.Register(p)
	return p
}

func refusalReason(t *testing.T, err error) string {
	t.Helper()
	var se serviceError
	if !errors.As(err, &se) {
		t.Fatalf("not a refusal: %v", err)
	}
	return se.code
}

// A cloud account names a credential that already exists. Inline
// credentials, a missing credential, another provider's credential and a
// caller without the use permission are each refused and audited, and no
// account is stored.
func TestAccountNeedsACredentialFromTheStore(t *testing.T) {
	svc, store, _, pub := newCloudService(t)
	ctx := attachCtx("t1")
	base := RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAWS, Name: "prod", DefaultRegion: "us-east-1"}
	refused := func(step string, ctx context.Context, mutate func(*RegisterCloudAccountRequest), reason string) {
		t.Helper()
		req := base
		mutate(&req)
		_, err := svc.RegisterAccount(ctx, req)
		if got := refusalReason(t, err); got != reason {
			t.Fatalf("%s: %s, want %s", step, got, reason)
		}
		if ev := pub.Last("audit.cloud.account_refused"); ev["reason"] != reason || ev["result"] != "refused" {
			t.Fatalf("%s audit: %+v", step, ev)
		}
	}
	refused("inline credentials", ctx, func(r *RegisterCloudAccountRequest) { r.CredentialsJSON = `{"access_key_id":"AKIA","secret_access_key":"inline"}` }, "inline_credentials_not_accepted")
	refused("no credential", ctx, func(r *RegisterCloudAccountRequest) {}, "credential_required")
	refused("unknown credential", ctx, func(r *RegisterCloudAccountRequest) { r.ConnectionID = "pbconn_nope" }, "credential_not_found")
	refused("another provider's credential", ctx, func(r *RegisterCloudAccountRequest) { r.ConnectionID = "cred-azure" }, "credential_wrong_type")
	refused("an HSM credential", ctx, func(r *RegisterCloudAccountRequest) { r.ConnectionID = "cred-hsm" }, "credential_wrong_type")
	noUse := pkgauth.ContextWithClaims(context.Background(), &pkgauth.Claims{UserID: "u", TenantID: "t1", Permissions: []string{"cloud.write", "compliance.playbook.write"}})
	refused("caller without the use permission", noUse, func(r *RegisterCloudAccountRequest) { r.ConnectionID = "cred-aws" }, "credential_use_not_permitted")
	svc.SetCredentials(nil)
	refused("no credential store", ctx, func(r *RegisterCloudAccountRequest) { r.ConnectionID = "cred-aws" }, "credentials_not_deployed")
	if accounts, _ := store.ListAccounts(context.Background(), "t1", ""); len(accounts) != 0 {
		t.Fatalf("a refused registration stored %d account(s)", len(accounts))
	}

	creds := newTestCredentials()
	svc.SetCredentials(creds)
	req := base
	req.ConnectionID = "cred-aws"
	acc, err := svc.RegisterAccount(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := store.GetAccount(context.Background(), "t1", acc.ID)
	if row.ConnectionID != "cred-aws" || len(row.CredentialsCiphertext) != 0 || len(row.CredentialsWrappedDEK) != 0 {
		t.Fatalf("the account holds its own credentials: %+v", row)
	}
	if ev := pub.Last("audit.cloud.connector_configured"); ev["connection_id"] != "cred-aws" {
		t.Fatalf("register audit: %+v", ev)
	}

	// Every provider call opens the credential; what the store holds now
	// is what the provider gets.
	aws := recordAWS(svc)
	if _, err := svc.DiscoverInventory(context.Background(), DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: acc.ID}); err != nil {
		t.Fatal(err)
	}
	if got := aws.seen[0]; got["secret_access_key"] != "from-the-store" || got["access_key_id"] != "AKIA" {
		t.Fatalf("provider credentials: %v", got)
	}
	creds.creds["cred-aws"] = credstore.Credential{ID: "cred-aws", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA2", "secret_access_key": "rotated",
		"role_arn": "arn:aws:iam::1:role/kms", optionsField: `{"endpoint_url":"https://kms.example","access_key_id":"overridden"}`}}
	if _, err := svc.DiscoverInventory(context.Background(), DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: acc.ID}); err != nil {
		t.Fatal(err)
	}
	got := aws.seen[1]
	if got["secret_access_key"] != "rotated" || got["role_arn"] != "arn:aws:iam::1:role/kms" || got["endpoint_url"] != "https://kms.example" || got["access_key_id"] != "AKIA2" {
		t.Fatalf("after the credential changed: %v", got)
	}
	// A credential that is gone, or a store that is down, stops the call:
	// nothing is cached and nothing falls back.
	delete(creds.creds, "cred-aws")
	if _, err := svc.DiscoverInventory(context.Background(), DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: acc.ID}); refusalReason(t, err) != "credential_not_found" {
		t.Fatalf("deleted credential: %v", err)
	}
	creds.err = credstore.ErrUnavailable
	if _, err := svc.DiscoverInventory(context.Background(), DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: acc.ID}); refusalReason(t, err) != "credentials_unavailable" {
		t.Fatalf("store down: %v", err)
	}
	if len(aws.seen) != 2 {
		t.Fatal("the provider was called without a credential")
	}
}

// An account an earlier release registered keeps working from its own
// sealed credentials until the primary moves them into the store; a member
// moves nothing, and an account the store won't take is reported once.
func TestLegacyAccountCredentialsMoveIntoTheStore(t *testing.T) {
	svc, store, _, pub := newCloudService(t)
	creds := svc.creds.(*testCredentials)
	ctx := context.Background()
	primary, member := func(context.Context) bool { return true }, func(context.Context) bool { return false }
	aws := legacyAccount(t, svc, "t1", ProviderAWS, "old-aws", `{"aws_access_key_id":"AKIAOLD","aws_secret_access_key":"old-secret","region":"eu-west-1","endpoint":"https://kms.internal.example","custom_header":"x"}`)
	gcp := legacyAccount(t, svc, "t2", ProviderGCP, "old-gcp", `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----","project_id":"p1","key_ring":"vecta"}`)

	rec := recordAWS(svc)
	if _, err := svc.DiscoverInventory(ctx, DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: aws.ID}); err != nil || rec.seen[0]["aws_secret_access_key"] != "old-secret" {
		t.Fatalf("a legacy account stopped working before migration: %v %v", err, rec.seen)
	}
	if n, err := svc.migrateAccountCredentials(ctx, member); n != 0 || err != nil {
		t.Fatalf("a cluster member migrated %d account(s): %v", n, err)
	}
	// The store refuses (down): the accounts stay as they are, reported once.
	creds.err = errors.New("service_account_json must be the service account key file's JSON")
	for i := 0; i < 2; i++ {
		if n, err := svc.migrateAccountCredentials(ctx, primary); n != 0 || err == nil {
			t.Fatalf("migration with the store refusing: %d %v", n, err)
		}
	}
	if pub.Count("audit.cloud.credentials_migration_refused") != 2 { // one per account, not per attempt
		t.Fatalf("refusal events: %d", pub.Count("audit.cloud.credentials_migration_refused"))
	}
	creds.err = nil
	if row, _ := store.GetAccount(ctx, "t1", aws.ID); row.ConnectionID != "" || len(row.CredentialsCiphertext) == 0 {
		t.Fatal("a refused migration changed the account")
	}

	n, err := svc.migrateAccountCredentials(ctx, primary)
	if err != nil || n != 2 {
		t.Fatalf("migration: %d %v", n, err)
	}
	row, _ := store.GetAccount(ctx, "t1", aws.ID)
	if row.ConnectionID != "pbconn_cloud_"+aws.ID || len(row.CredentialsCiphertext) != 0 || len(row.CredentialsWrappedDEK) != 0 {
		t.Fatalf("after migration the account still holds credentials: %+v", row)
	}
	moved := creds.creds[row.ConnectionID]
	if moved.Type != "aws" || moved.Fields["access_key_id"] != "AKIAOLD" || moved.Fields["secret_access_key"] != "old-secret" ||
		moved.Fields["region"] != "eu-west-1" || moved.Fields["endpoint_url"] != "https://kms.internal.example" || !strings.Contains(moved.Fields[optionsField], `"custom_header":"x"`) {
		t.Fatalf("migrated AWS credential: %+v", moved.Fields)
	}
	g := creds.creds["pbconn_cloud_"+gcp.ID]
	if g.Type != "gcp" || !strings.Contains(g.Fields["service_account_json"], `"private_key"`) || g.Fields["project_id"] != "p1" || g.Fields["key_ring"] != "vecta" || g.Fields[optionsField] != "" {
		t.Fatalf("migrated Google credential: %+v", g.Fields)
	}
	if ev := pub.Last("audit.cloud.credentials_migrated"); ev["result"] != "success" || ev["connection_id"] == "" {
		t.Fatalf("migration audit: %+v", ev)
	}
	// The provider now gets the same values, from the store.
	if _, err := svc.DiscoverInventory(ctx, DiscoverInventoryRequest{TenantID: "t1", Provider: ProviderAWS, AccountID: aws.ID}); err != nil {
		t.Fatal(err)
	}
	last := rec.seen[len(rec.seen)-1]
	if last["secret_access_key"] != "old-secret" || last["endpoint_url"] != "https://kms.internal.example" || last["custom_header"] != "x" {
		t.Fatalf("provider credentials after migration: %v", last)
	}
	if n, _ := svc.migrateAccountCredentials(ctx, primary); n != 0 {
		t.Fatal("an account was migrated twice")
	}
}

func cloudRouter(svc *Service) (*route.Router, *routetest.Recorder) {
	rec := &routetest.Recorder{}
	rt := route.New("cloud", rec, nil)
	(&Handler{svc: svc}).credentialRoutes(rt)
	return rt, rec
}

func TestCredentialRoutesRefusalsAudited(t *testing.T) {
	svc, _, _, _ := newCloudService(t)
	rt, rec := cloudRouter(svc)
	routetest.RefusalsAudited(t, rt, rec)
}

// Testing an account makes a real provider call with its credential and
// records the result on the credential. The credential store's own test and
// usage lookups are for the compliance service only.
func TestAccountTestIsRecordedOnTheCredential(t *testing.T) {
	svc, _, _, pub := newCloudService(t)
	creds := svc.creds.(*testCredentials)
	aws := recordAWS(svc)
	acc, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAWS, Name: "prod", ConnectionID: "cred-aws"})
	if err != nil {
		t.Fatal(err)
	}
	rt, rec := cloudRouter(svc)
	do := func(claims *pkgauth.Claims, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		return w
	}
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	compliance := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}}
	other := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: "kms-audit", Permissions: []string{"service.internal"}}

	if w := do(admin, http.MethodPost, "/cloud/accounts/"+acc.ID+"/test"); w.Code != http.StatusOK {
		t.Fatalf("account test: %d %s", w.Code, w.Body.String())
	}
	if msg, ok := creds.tests["cred-aws"]; !ok || msg != "" || len(aws.seen) != 1 {
		t.Fatalf("a passing test was not reported: %v (%d provider calls)", creds.tests, len(aws.seen))
	}
	if ev := pub.Last("audit.cloud.account_tested"); ev["result"] != "success" || ev["connection_id"] != "cred-aws" {
		t.Fatalf("test audit: %+v", ev)
	}
	aws.err = errors.New("AccessDeniedException: not authorized to perform kms:ListKeys")
	if w := do(admin, http.MethodPost, "/cloud/accounts/"+acc.ID+"/test"); w.Code != http.StatusBadGateway {
		t.Fatalf("failing account test: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(creds.tests["cred-aws"], "AccessDenied") {
		t.Fatalf("a failing test was not reported: %v", creds.tests)
	}
	if ev := pub.Last("audit.cloud.account_tested"); ev["result"] != "failure" {
		t.Fatalf("failing test audit: %+v", ev)
	}
	if w := do(admin, http.MethodPost, "/cloud/accounts/ca_nope/test"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown account: %d", w.Code)
	}

	// The credential store tests a credential before any account uses it.
	for _, who := range []*pkgauth.Claims{admin, other} {
		for _, r := range []struct{ method, path string }{{http.MethodPost, "/cloud/credentials/cred-aws/test?tenant_id=t1"}, {http.MethodGet, "/cloud/credential-usage?tenant_id=t1"}} {
			if w := do(who, r.method, r.path); w.Code != http.StatusForbidden {
				t.Fatalf("%s%s on %s: %d", who.UserID, who.ClientID, r.path, w.Code)
			}
			if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "caller_not_allowed" {
				t.Fatalf("refusal audit: %+v", ev.Event)
			}
		}
	}
	if w := do(compliance, http.MethodPost, "/cloud/credentials/cred-aws/test?tenant_id=t1"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("credential test (provider failing): %d %s", w.Code, w.Body.String())
	}
	aws.err = nil
	if w := do(compliance, http.MethodPost, "/cloud/credentials/cred-aws/test?tenant_id=t1"); w.Code != http.StatusOK {
		t.Fatalf("credential test: %d %s", w.Code, w.Body.String())
	}
	if w := do(compliance, http.MethodPost, "/cloud/credentials/cred-hsm/test?tenant_id=t1"); w.Code != http.StatusConflict {
		t.Fatalf("an HSM credential tested as a cloud one: %d", w.Code)
	}
	w := do(compliance, http.MethodGet, "/cloud/credential-usage?tenant_id=t1")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"connection_id":"cred-aws"`) || !strings.Contains(w.Body.String(), "cloud account prod (aws)") {
		t.Fatalf("usage: %d %s", w.Code, w.Body.String())
	}
}

// A request body can't name another tenant than the verified token's.
func TestBodyTenantMustMatchTheToken(t *testing.T) {
	h, _, _, _ := newCloudHandler(t)
	body := `{"tenant_id":"victim","provider":"aws","name":"x","connection_id":"cred-aws"}`
	req := httptest.NewRequest(http.MethodPost, "/cloud/accounts", strings.NewReader(body))
	req = req.WithContext(attachCtx("t1"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an account was registered in another tenant: %d %s", w.Code, w.Body.String())
	}
}
