package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func consoleRouter(svc *Service) (*route.Router, *routetest.Recorder) {
	rec := &routetest.Recorder{}
	rt := route.New("cloud", rec, nil)
	h := &Handler{svc: svc}
	h.byokRoutes(rt)
	h.consoleRoutes(rt)
	return rt, rec
}

func TestConsoleRoutesRefusalsAudited(t *testing.T) {
	svc, _, _, _ := newCloudService(t)
	rt, rec := consoleRouter(svc)
	routetest.RefusalsAudited(t, rt, rec)
}

type consoleOut struct {
	Result json.RawMessage `json:"result"`
	CLI    string          `json:"cli"`
	Error  struct {
		Code, Message string
	} `json:"error"`
}

func runOp(t *testing.T, rt *route.Router, perms []string, op string, body map[string]interface{}) (int, consoleOut) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/cloud/console/"+op, bytes.NewReader(raw))
	claims := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: perms}
	claims.Subject = "alice"
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	var out consoleOut
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

var rw = []string{"cloud.read", "cloud.write"}

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Every AWS operation of the catalogue, over HTTP against AWS KMS's
// protocol: each is audited under its own action with the operation and
// key, never a parameter value, and each changes what the cloud then
// reports.
func TestConsoleAWSOperations(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	kc.Seed("t1", "key-1", "AES-256")
	kc.Seed("t1", "mac-1", "HMAC-SHA256")
	ctx := context.Background()
	_, k, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if err != nil {
		t.Fatal(err)
	}
	_, mk, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "mac-1"})
	if err != nil {
		t.Fatal(err)
	}
	rt, rec := consoleRouter(svc)
	ok := func(op string, key string, params map[string]string) consoleOut {
		t.Helper()
		code, out := runOp(t, rt, rw, op, map[string]interface{}{"account_id": acct.ID, "key": key, "params": params})
		if code != http.StatusOK {
			t.Fatalf("%s: %d %+v", op, code, out)
		}
		e := rec.Last(t)
		if e.Action != consoleOpByName[op].action || e.Event.Result != "success" || e.Event.Details["operation"] != op || e.Event.Details["provider"] != "aws" {
			t.Fatalf("%s audit %+v", op, e.Event)
		}
		for _, v := range params {
			if len(v) > 3 && strings.Contains(string(mustJSON(e.Event.Details)), v) {
				t.Fatalf("%s: a parameter value is in the audit record", op)
			}
		}
		if out.CLI == "" || !strings.HasPrefix(out.CLI, "aws kms ") {
			t.Fatalf("%s: CLI %q", op, out.CLI)
		}
		return out
	}
	has := func(out consoleOut, s string) bool { return strings.Contains(string(out.Result), s) }

	if !has(ok("list-keys", "", nil), k.CloudKeyID) || !has(ok("describe-key", k.CloudKeyID, nil), "EXTERNAL") {
		t.Fatal("list/describe")
	}
	if !has(ok("list-versions", k.CloudKeyID, nil), k.CurrentMatID) {
		t.Fatal("list-versions shows no key material")
	}
	// Try it: encrypt then decrypt.
	enc := ok("encrypt", k.CloudKeyID, map[string]string{"plaintext_b64": b64s("hello cloud")})
	var e struct {
		Ciphertext string `json:"ciphertext_b64"`
	}
	_ = json.Unmarshal(enc.Result, &e)
	if dec := ok("decrypt", k.CloudKeyID, map[string]string{"ciphertext_b64": e.Ciphertext}); !has(dec, "hello cloud") {
		t.Fatalf("decrypt %s", dec.Result)
	}
	// State: disable stops encryption; enable restores it.
	ok("disable-key", k.CloudKeyID, nil)
	if code, _ := runOp(t, rt, rw, "encrypt", map[string]interface{}{"account_id": acct.ID, "key": k.CloudKeyID, "params": map[string]string{"plaintext_b64": b64s("x")}}); code != http.StatusBadGateway {
		t.Fatalf("encrypt with a disabled key: %d", code)
	}
	if e := rec.Last(t); e.Event.Result != "failure" {
		t.Fatalf("cloud error audited as %s", e.Event.Result)
	}
	ok("enable-key", k.CloudKeyID, nil)
	// Policy, grants, aliases, tags, rotation.
	pol := `{"Version":"2012-10-17","Statement":[{"Sid":"Admins","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}]}`
	ok("put-key-policy", k.CloudKeyID, map[string]string{"policy": pol})
	if !has(ok("get-key-policy", k.CloudKeyID, nil), "Admins") {
		t.Fatal("policy not stored")
	}
	g := ok("create-grant", k.CloudKeyID, map[string]string{"grantee": "arn:aws:iam::111122223333:role/app", "operations": "Encrypt,Decrypt"})
	if !has(ok("list-grants", k.CloudKeyID, nil), "role/app") {
		t.Fatal("grant missing")
	}
	var gid struct {
		ID string `json:"grant_id"`
	}
	_ = json.Unmarshal(g.Result, &gid)
	ok("revoke-grant", k.CloudKeyID, map[string]string{"grant_id": gid.ID})
	if has(ok("list-grants", k.CloudKeyID, nil), "role/app") {
		t.Fatal("grant not revoked")
	}
	ok("create-alias", k.CloudKeyID, map[string]string{"alias": "orders"})
	if !has(ok("list-aliases", k.CloudKeyID, nil), "alias/orders") {
		t.Fatal("alias missing")
	}
	ok("delete-alias", "", map[string]string{"alias": "alias/orders"})
	ok("tag-key", k.CloudKeyID, map[string]string{"tag_key": "team", "tag_value": "payments"})
	if !has(ok("list-tags", k.CloudKeyID, nil), "payments") {
		t.Fatal("tag missing")
	}
	ok("untag-key", k.CloudKeyID, map[string]string{"tag_key": "team"})
	ok("enable-rotation", k.CloudKeyID, map[string]string{"period_days": "180"})
	if !has(ok("get-rotation-status", k.CloudKeyID, nil), "180") {
		t.Fatal("rotation period")
	}
	ok("disable-rotation", k.CloudKeyID, nil)
	// MAC on the HMAC key.
	mac := ok("generate-mac", mk.CloudKeyID, map[string]string{"message_b64": b64s("m")})
	var m struct {
		Mac string `json:"mac_b64"`
	}
	_ = json.Unmarshal(mac.Result, &m)
	if !has(ok("verify-mac", mk.CloudKeyID, map[string]string{"message_b64": b64s("m"), "mac_b64": m.Mac}), "true") {
		t.Fatal("MAC did not verify")
	}
	// Deletion: scheduled, then cancelled.
	ok("schedule-key-deletion", k.CloudKeyID, map[string]string{"pending_days": "7"})
	if d.keys[k.CloudKeyID].state != "PendingDeletion" {
		t.Fatal("not pending deletion")
	}
	ok("cancel-key-deletion", k.CloudKeyID, nil)
	if d.keys[k.CloudKeyID].state != "Disabled" {
		t.Fatal("deletion not cancelled")
	}
}

func mustJSON(v interface{}) []byte { b, _ := json.Marshal(v); return b }

// Nothing free-form reaches a cloud: unknown or malformed parameters, a
// missing key, an operation the cloud doesn't have, and a reader who isn't
// allowed to change anything are refused and audited with the reason.
func TestConsoleRefusals(t *testing.T) {
	svc, _, _, _ := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	setCred(svc, "cred-sf", "salesforce", map[string]string{"instance_url": "https://example.my.salesforce.com", "access_token": "x"})
	sf, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderSalesforce, Name: "org", ConnectionID: "cred-sf"})
	if err != nil {
		t.Fatal(err)
	}
	rt, rec := consoleRouter(svc)
	cases := []struct {
		name   string
		perms  []string
		op     string
		body   map[string]interface{}
		status int
		reason string
	}{
		{"unknown parameter", rw, "describe-key", map[string]interface{}{"account_id": acct.ID, "key": "k", "params": map[string]string{"command": "rm -rf /"}}, 400, "bad_request"},
		{"missing key", rw, "disable-key", map[string]interface{}{"account_id": acct.ID}, 400, "bad_request"},
		{"policy not JSON", rw, "put-key-policy", map[string]interface{}{"account_id": acct.ID, "key": "k", "params": map[string]string{"policy": "{not json"}}, 400, "bad_request"},
		{"not base64", rw, "encrypt", map[string]interface{}{"account_id": acct.ID, "key": "k", "params": map[string]string{"plaintext_b64": "%%%"}}, 400, "bad_request"},
		{"cloud lacks it", rw, "disable-key", map[string]interface{}{"account_id": sf.ID, "key": "k"}, 409, "operation_not_supported"},
		{"unknown account", rw, "list-keys", map[string]interface{}{"account_id": "nope"}, 404, "account_not_found"},
		{"reader changes", []string{"cloud.read"}, "disable-key", map[string]interface{}{"account_id": acct.ID, "key": "k"}, 403, "permission_denied"},
		{"reader uses a key", []string{"cloud.read"}, "decrypt", map[string]interface{}{"account_id": acct.ID, "key": "k", "params": map[string]string{"ciphertext_b64": b64s("x")}}, 403, "permission_denied"},
	}
	for _, c := range cases {
		code, _ := runOp(t, rt, c.perms, c.op, c.body)
		if code != c.status {
			t.Fatalf("%s: %d, want %d", c.name, code, c.status)
		}
		if e := rec.Last(t); e.Event.Result != "refused" || e.Event.Details["reason"] != c.reason {
			t.Fatalf("%s: audit %+v", c.name, e.Event)
		}
	}
	if len(d.calls) != 0 {
		t.Fatalf("refused requests reached AWS: %v", d.calls)
	}
	// A reader may read.
	if code, _ := runOp(t, rt, []string{"cloud.read"}, "list-keys", map[string]interface{}{"account_id": acct.ID}); code != http.StatusOK {
		t.Fatalf("reader list-keys: %d", code)
	}
}

// The catalogue lists what each cloud supports.
func TestConsoleOperationsListSupport(t *testing.T) {
	svc, _, _, _ := newCloudService(t)
	_, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	rt, _ := consoleRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/cloud/console/operations?account_id="+acct.ID, nil)
	claims := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: []string{"cloud.read"}}
	rr := httptest.NewRecorder()
	rt.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	var out struct {
		Items []consoleOpView `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Items) != len(consoleOps) {
		t.Fatalf("%d operations listed", len(out.Items))
	}
	for _, it := range out.Items {
		if !it.Supported {
			t.Fatalf("AWS should support %s", it.Name)
		}
	}
	// Each cloud's implementation names only catalogue operations.
	for name, p := range defaultBYOKProviders() {
		cp, ok := p.(consoleProvider)
		if !ok {
			t.Fatalf("%s has no console", name)
		}
		for op := range cp.Console() {
			if _, ok := consoleOpByName[op]; !ok {
				t.Fatalf("%s implements %q, which is not in the catalogue", name, op)
			}
		}
	}
}

// Automation: a rule the cloud can act on is saved and audited; the sweep
// emits material_expiring and rotation_due once per piece of material, on
// the primary only.
func TestBYOKAutomation(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	_, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	_, k, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", ValidityDays: 10})
	if err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	svc.SetAuditEmitter(rec)
	rt, krec := consoleRouter(svc)

	put := func(body map[string]int) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/cloud/byok/keys/"+k.ID+"/automation", bytes.NewReader(raw))
		claims := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: rw}
		claims.Subject = "alice"
		rr := httptest.NewRecorder()
		rt.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
		return rr.Code
	}
	if code := put(map[string]int{"renew_before_days": 400}); code != http.StatusBadRequest {
		t.Fatalf("400-day rule: %d", code)
	}
	if code := put(map[string]int{"renew_before_days": 30, "renew_validity_days": 90, "rotate_every_days": 1}); code != http.StatusOK {
		t.Fatalf("save: %d", code)
	}
	if e := krec.Last(t); e.Action != "byok_automation_updated" || e.Event.Result != "success" || e.Event.Details["renew_before_days"] != 30 {
		t.Fatalf("audit %+v", e.Event)
	}

	// Member: the loop does nothing.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	svc.byokAutomationLoop(cctx, func(context.Context) bool { return false }, time.Hour, t.Logf)
	if len(rec.Events()) != 0 {
		t.Fatalf("a member emitted %d events", len(rec.Events()))
	}
	now := time.Now().UTC().Add(48 * time.Hour)
	n, err := svc.sweepBYOKAutomation(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	actions := map[string]routetest.Recorded{}
	for _, e := range rec.Events() {
		actions[e.Action] = e
	}
	exp, rot := actions["byok_material_expiring"], actions["byok_rotation_due"]
	if exp.Event.TargetID != k.ID || exp.Event.Details["validity_days"] != 90 || exp.Event.Details["key_id"] != "key-1" {
		t.Fatalf("expiring event %+v", exp.Event)
	}
	if rot.Event.TargetID != k.ID || rot.Event.Details["rotate_every_days"] != 1 {
		t.Fatalf("rotation event %+v", rot.Event)
	}
	if n, _ := svc.sweepBYOKAutomation(ctx, now); n != 0 {
		t.Fatalf("the same material was announced again (%d)", n)
	}
	// New material is announced afresh.
	if _, _, err := svc.RunBYOK(ctx, "t1", k.ID, OpRotate, "playbook", BYOKOperationRequest{ValidityDays: 10}); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.sweepBYOKAutomation(ctx, now.Add(72*time.Hour)); n != 2 {
		t.Fatalf("after rotation: %d events", n)
	}
}

// A rule the cloud can't act on is refused: Alibaba takes no new material,
// Google has no expiry.
func TestBYOKAutomationRefusesWhatTheCloudCantDo(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	_, endpoint := newAlibabaDouble(t)
	setCred(svc, "cred-ali", "alibaba", map[string]string{"access_key_id": "LTAItest", "access_key_secret": "test-only-000000000000000000000000", "region": "cn-hangzhou", "endpoint_url": endpoint})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAlibaba, Name: "ali", ConnectionID: "cred-ali"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	key := BYOKKey{ID: "byok_ali", TenantID: "t1", AccountID: acct.ID, Provider: ProviderAlibaba, KeyID: "key-1", Origin: OriginBYOK, KeySpec: SpecAES256,
		MaterialState: MaterialCurrent, Settings: map[string]string{}}
	if err := svc.byokStore.CreateBYOKKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetBYOKAutomation(context.Background(), "t1", key.ID, AutomationSettings{RotateEveryDays: 90}); byokReason(err) != "operation_not_supported" {
		t.Fatalf("rotation rule on Alibaba: %v", err)
	}
	if _, err := svc.SetBYOKAutomation(context.Background(), "t1", key.ID, AutomationSettings{RenewBeforeDays: 30}); byokReason(err) != "bad_request" {
		t.Fatalf("renew rule without a validity: %v", err)
	}
	if _, err := svc.SetBYOKAutomation(context.Background(), "t1", key.ID, AutomationSettings{RenewBeforeDays: 30, RenewValidityDays: 90}); err != nil {
		t.Fatalf("renew rule on Alibaba: %v", err)
	}
}
