package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
)

var (
	// pbAttacher may attach a credential to a feature and nothing else.
	pbAttacher = &pkgauth.Claims{UserID: "u-attach", TenantID: "t1", Role: "ops", Permissions: []string{permConnectionUse}}
)

func hsmFields() map[string]string {
	return map[string]string{"library_path": "/var/lib/vecta/hsm/providers/t1/libsofthsm2.so", "token_label": "prod", "pin": "123456", "topology": "ha_group"}
}

// Each new credential type checks its own fields; a bad one is refused
// before anything is sealed.
func TestCredentialTypesValidateTheirFields(t *testing.T) {
	ok := []Connection{
		{Name: "a", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA", "secret_access_key": "0123456789abcdef", "role_arn": "arn:aws:iam::123456789012:role/kms", "external_id": "x"}},
		{Name: "a", Type: "azure", Fields: map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "s"}},
		{Name: "a", Type: "gcp", Fields: map[string]string{"service_account_json": `{"type":"service_account","private_key":"k"}`}},
		{Name: "a", Type: "smtp", Fields: map[string]string{"host": "1.1.1.1", "port": "587", "from": "kms@example.com"}},
		{Name: "a", Type: "pkcs11_hsm", Fields: hsmFields()},
	}
	for _, c := range ok {
		if err := validateConnection(c, nil); err != nil {
			t.Fatalf("%s refused: %v", c.Type, err)
		}
	}
	bad := map[string]Connection{
		"external id without a role": {Name: "a", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA", "secret_access_key": "0123456789abcdef", "external_id": "x"}},
		"role that is not an ARN":    {Name: "a", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA", "secret_access_key": "0123456789abcdef", "role_arn": "kms-role"}},
		"private custom endpoint":    {Name: "a", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA", "secret_access_key": "0123456789abcdef", "endpoint_url": "https://10.0.0.5"}},
		"service account not JSON":   {Name: "a", Type: "gcp", Fields: map[string]string{"service_account_json": "key"}},
		"mail port":                  {Name: "a", Type: "smtp", Fields: map[string]string{"host": "1.1.1.1", "port": "smtp", "from": "kms@example.com"}},
		"mail password alone":        {Name: "a", Type: "smtp", Fields: map[string]string{"host": "1.1.1.1", "port": "587", "from": "kms@example.com", "password": "p"}},
		"mail relay on loopback":     {Name: "a", Type: "smtp", Fields: map[string]string{"host": "127.0.0.1", "port": "587", "from": "kms@example.com"}},
		"relative HSM library":       {Name: "a", Type: "pkcs11_hsm", Fields: map[string]string{"library_path": "libsofthsm2.so", "token_label": "p", "pin": "123456"}},
		"HSM library with ..":        {Name: "a", Type: "pkcs11_hsm", Fields: map[string]string{"library_path": "/var/lib/vecta/hsm/providers/../../../etc/x.so", "token_label": "p", "pin": "123456"}},
		"HSM without slot or token":  {Name: "a", Type: "pkcs11_hsm", Fields: map[string]string{"library_path": "/a/b.so", "pin": "123456"}},
		"HSM topology":               {Name: "a", Type: "pkcs11_hsm", Fields: map[string]string{"library_path": "/a/b.so", "token_label": "p", "pin": "123456", "topology": "cluster-of-three"}},
		"options not an object":      {Name: "a", Type: "azure", Fields: map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "s", optionsField: "[1]"}},
		"unknown field":              {Name: "a", Type: "azure", Fields: map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "s", "pin": "1"}},
	}
	for name, c := range bad {
		if err := validateConnection(c, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A credential is opened only by the service that uses its type: the cloud
// service can't open an HSM PIN, the HSM connector can't open a cloud key,
// and each refusal is audited.
func TestCredentialResolveAdmitsOnlyTheServiceThatUsesTheType(t *testing.T) {
	hs := newPlaybookHarness(t)
	ids := map[string]string{
		"aws":        hs.conn(t, "aws", map[string]string{"access_key_id": "AKIA", "secret_access_key": "aws-secret-value"}),
		"azure":      hs.conn(t, "azure", map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "azure-secret-value"}),
		"pkcs11_hsm": hs.conn(t, "pkcs11_hsm", hsmFields()),
		"smtp":       hs.conn(t, "smtp", map[string]string{"host": "1.1.1.1", "port": "587", "from": "kms@example.com"}),
		"database":   hs.conn(t, "database", map[string]string{"host": "1.1.1.1", "database": "app", "username": "admin", "password": "db-secret-value"}),
		"aws_xks":    hs.conn(t, "aws_xks", map[string]string{"access_key_id": "ABCDEFGHIJKLMNOPQRST234567", "secret_access_key": strings.Repeat("s", 43) + "-secret-value"}),
	}
	allowed := map[string][]string{
		"kms-cloud": {"aws", "azure"}, "kms-hsm": {"pkcs11_hsm"}, "kms-governance": {"smtp"}, "kms-audit": {}, "kms-discovery": {}, "kms-hyok-proxy": {"aws_xks"}, "kms-secrets": {"database"},
	}
	for client, types := range allowed {
		for typ, id := range ids {
			w := hs.do(t, http.MethodPost, "/compliance/connections/"+id+"/resolve?tenant_id=t1", svcClaims(client), map[string]any{})
			if contains(types, typ) {
				if w.Code != http.StatusOK {
					t.Fatalf("%s opening %s: %d %s", client, typ, w.Code, w.Body.String())
				}
				continue
			}
			if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "secret-value") || strings.Contains(w.Body.String(), "123456") {
				t.Fatalf("%s opened %s: %d %s", client, typ, w.Code, w.Body.String())
			}
			wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)
		}
	}
	// A service that uses no credential (ekm since its Azure vaults were
	// removed, 13.30.0-beta), and an administrator, open none.
	for _, who := range []*pkgauth.Claims{svcClaims("kms-keycore"), svcClaims("kms-ekm"), pbAdmin} {
		if w := hs.do(t, http.MethodPost, "/compliance/connections/"+ids["pkcs11_hsm"]+"/resolve?tenant_id=t1", who, map[string]any{}); w.Code != http.StatusForbidden {
			t.Fatalf("%s%s opened an HSM PIN: %d", who.ClientID, who.UserID, w.Code)
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionCaller)
	}
}

// Attaching a credential to a feature needs compliance.connection.use, and
// that permission alone neither lists nor changes credentials. The answer
// shows the type's public fields and no secret.
func TestConnectionUsePermissionIsSeparateFromManaging(t *testing.T) {
	hs := newPlaybookHarness(t)
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "Luna HA", "type": "pkcs11_hsm", "fields": hsmFields()})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Data Connection `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := created.Data.ID
	if created.Data.Attributes["topology"] != "ha_group" || created.Data.Attributes["token_label"] != "prod" || created.Data.Endpoint != "token prod" {
		t.Fatalf("attributes: %+v endpoint %q", created.Data.Attributes, created.Data.Endpoint)
	}
	if strings.Contains(w.Body.String(), "123456") {
		t.Fatal("PIN returned")
	}
	// The writer manages credentials but was not given the use permission.
	if w := hs.do(t, http.MethodGet, "/compliance/connections/"+id, pbWriter, nil); w.Code != http.StatusForbidden {
		t.Fatalf("writer attached without the use permission: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_use_checked"), route.ReasonPermissionDenied)
	w = hs.do(t, http.MethodGet, "/compliance/connections/"+id, pbAttacher, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "123456") || !strings.Contains(w.Body.String(), `"topology":"ha_group"`) {
		t.Fatalf("attach check: %d %s", w.Code, w.Body.String())
	}
	if ev := lastEvent(t, hs.rec, "connection_use_checked"); ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != id {
		t.Fatalf("attach audit: %+v", ev.Event)
	}
	// The use permission is not a way in to the store.
	for _, tc := range []struct{ method, path, action string }{
		{http.MethodGet, "/compliance/playbooks/connections", "connections_listed"},
		{http.MethodPut, "/compliance/playbooks/connections/" + id, "connection_updated"},
		{http.MethodDelete, "/compliance/playbooks/connections/" + id, "connection_deleted"},
		{http.MethodPost, "/compliance/playbooks/connections/" + id + "/test", "connection_tested"},
	} {
		if w := hs.do(t, tc.method, tc.path, pbAttacher, map[string]any{}); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s with only the use permission: %d", tc.method, tc.path, w.Code)
		}
		wantRefused(t, lastEvent(t, hs.rec, tc.action), route.ReasonPermissionDenied)
	}
	// Another tenant's credential is not found.
	other := &pkgauth.Claims{UserID: "u2", TenantID: "t2", Role: "admin", Permissions: []string{"*"}}
	if w := hs.do(t, http.MethodGet, "/compliance/connections/"+id, other, nil); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant attach: %d", w.Code)
	}
}

type recordedEvents struct {
	actions []string
	events  []pkgaudit.Event
}

func (r *recordedEvents) emit(action string, evt pkgaudit.Event) {
	r.actions, r.events = append(r.actions, action), append(r.events, evt)
}

// Reminders are raised once per secret: before the recorded expiry, when it
// passes, and when the secret is older than its rotation interval. A cluster
// member raises none, and replacing the secret starts over.
func TestCredentialRemindersAreRaisedOncePerSecret(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	svc := hs.h.svc
	primary := func(context.Context) bool { return true }
	now := time.Now().UTC()
	id := hs.conn(t, "azure", map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "s1"})
	set := func(expires time.Time, rotate int) {
		c, _ := hs.store.GetConnection(ctx, "t1", id)
		c.ExpiresAt, c.RotateAfterDays = &expires, rotate
		if _, err := hs.store.UpdateConnection(ctx, c, false, true); err != nil {
			t.Fatal(err)
		}
	}
	set(now.Add(20*24*time.Hour), 90)

	rec := &recordedEvents{}
	if n, _ := svc.remindCredentials(ctx, now, func(context.Context) bool { return false }, rec.emit); n != 0 || len(rec.actions) != 0 {
		t.Fatalf("a cluster member raised %d reminder(s)", n)
	}
	if n, err := svc.remindCredentials(ctx, now, primary, rec.emit); err != nil || n != 1 || rec.actions[0] != "credential_expiring" {
		t.Fatalf("20 days out: n=%d %v %v", n, rec.actions, err)
	}
	if d := rec.events[0].Details; d["reminder"] != remindExpiring30 || d["days_left"] != 20 || rec.events[0].TargetID != id || rec.events[0].TenantID != "t1" {
		t.Fatalf("event: %+v", rec.events[0])
	}
	if n, _ := svc.remindCredentials(ctx, now, primary, rec.emit); n != 0 {
		t.Fatal("the same reminder was raised twice")
	}
	// Five days out, then past: one event each, the last one critical.
	if n, _ := svc.remindCredentials(ctx, now.Add(15*24*time.Hour), primary, rec.emit); n != 1 || rec.events[1].Details["reminder"] != remindExpiring7 {
		t.Fatalf("7-day reminder: %v", rec.actions)
	}
	if n, _ := svc.remindCredentials(ctx, now.Add(21*24*time.Hour), primary, rec.emit); n != 1 || rec.actions[2] != "credential_expired" || rec.events[2].Details["severity"] != "critical" {
		t.Fatalf("expired: %v %+v", rec.actions, rec.events[len(rec.events)-1].Details)
	}
	if n, _ := svc.remindCredentials(ctx, now.Add(91*24*time.Hour), primary, rec.emit); n != 1 || rec.actions[3] != "credential_rotation_due" {
		t.Fatalf("rotation: %v", rec.actions)
	}
	if n, _ := svc.remindCredentials(ctx, now.Add(200*24*time.Hour), primary, rec.emit); n != 0 {
		t.Fatal("reminders repeated")
	}
	// Replacing the secret through the API restarts its age and reminders.
	far := now.Add(400 * 24 * time.Hour)
	w := hs.do(t, http.MethodPut, "/compliance/playbooks/connections/"+id, pbAdmin, map[string]any{"name": "azure", "type": "azure",
		"fields": map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": "s2"}, "expires_at": far, "rotate_after_days": 90})
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	c, _ := hs.store.GetConnection(ctx, "t1", id)
	if len(c.Notified) != 0 || time.Since(c.CredentialsChangedAt) > time.Minute {
		t.Fatalf("after a new secret: notified=%v changed=%s", c.Notified, c.CredentialsChangedAt)
	}
	if ev := lastEvent(t, hs.rec, "connection_updated"); ev.Event.Details["secret_changed"] != true {
		t.Fatalf("update audit: %+v", ev.Event.Details)
	}
	// Keeping the secret (********) keeps its age.
	before := c.CredentialsChangedAt
	hs.do(t, http.MethodPut, "/compliance/playbooks/connections/"+id, pbAdmin, map[string]any{"name": "azure renamed", "type": "azure",
		"fields": map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": keepField}, "expires_at": far, "rotate_after_days": 90})
	if c, _ := hs.store.GetConnection(ctx, "t1", id); !c.CredentialsChangedAt.Equal(before) || c.Name != "azure renamed" {
		t.Fatalf("a kept secret restarted its age: %s vs %s", c.CredentialsChangedAt, before)
	}
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/connections/"+id, pbAdmin, map[string]any{"name": "azure", "type": "azure",
		"fields": map[string]string{"tenant_id": "t", "client_id": "c", "client_secret": keepField}, "rotate_after_days": -1}); w.Code != http.StatusBadRequest {
		t.Fatalf("negative rotation interval: %d", w.Code)
	}
}

// A mail relay may sit on a private range a root administrator approved for
// the tenant (private_endpoints.go); any other private address is refused,
// and governance is given the approved ranges to dial inside.
func TestMailRelayOnAnApprovedPrivateRange(t *testing.T) {
	hs := newPlaybookHarness(t)
	relay := map[string]any{"name": "internal relay", "type": "smtp", "fields": map[string]string{"host": "10.20.3.4", "port": "587", "from": "kms@example.com"}}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, relay); w.Code != http.StatusBadRequest {
		t.Fatalf("a relay on an unapproved private address was accepted: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_created"), reasonURLBlocked)
	if err := hs.store.CreatePrivateEndpoint(context.Background(), PrivateEndpoint{ID: "pvt_1", TenantID: "t1", CIDR: "10.20.0.0/16", CreatedBy: "root-admin"}); err != nil {
		t.Fatal(err)
	}
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, relay)
	if w.Code != http.StatusCreated {
		t.Fatalf("a relay inside the approved range: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Data Connection `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	// Outside the range, on loopback, and from another tenant: still refused.
	for name, host := range map[string]string{"outside the range": "10.21.0.1", "loopback": "127.0.0.1", "metadata": "169.254.169.254"} {
		body := map[string]any{"name": name, "type": "smtp", "fields": map[string]string{"host": host, "port": "587", "from": "kms@example.com"}}
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, body); w.Code != http.StatusBadRequest {
			t.Fatalf("relay %s accepted: %d", name, w.Code)
		}
	}
	other := &pkgauth.Claims{UserID: "u2", TenantID: "t2", Role: "admin", Permissions: []string{"*"}}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", other, relay); w.Code != http.StatusBadRequest {
		t.Fatalf("another tenant used t1's approved range: %d", w.Code)
	}
	// Governance gets the ranges with the relay, and with a Slack notice.
	w = hs.do(t, http.MethodPost, "/compliance/connections/"+created.Data.ID+"/resolve?tenant_id=t1", svcClaims("kms-governance"), map[string]any{})
	var out struct {
		Data resolvedConnection `json:"data"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Data.PrivateRanges) != 1 || out.Data.PrivateRanges[0] != "10.20.0.0/16" {
		t.Fatalf("resolve for governance: %d %s", w.Code, w.Body.String())
	}
	slack := hs.conn(t, "slack", map[string]string{"webhook_url": "https://1.1.1.1/x"})
	w = hs.do(t, http.MethodPost, "/compliance/connections/"+slack+"/resolve?tenant_id=t1", svcClaims("kms-governance"), map[string]any{})
	out.Data = resolvedConnection{}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Data.PrivateRanges) != 1 {
		t.Fatalf("a Slack notice was not given the tenant's ranges: %d %s", w.Code, w.Body.String())
	}
}

// Notification, ticketing and SIEM destinations may sit on a private range a
// root administrator approved for the tenant (8.1.0-beta): refused before
// the approval, outside it and for another tenant, and dialled through a
// client that reaches nothing else private.
func TestNotifyTicketingAndSIEMOnAnApprovedPrivateRange(t *testing.T) {
	hs := newPlaybookHarness(t)
	create := func(who *pkgauth.Claims, typ string, fields map[string]string) *httptest.ResponseRecorder {
		return hs.do(t, http.MethodPost, "/compliance/playbooks/connections?tenant_id="+who.TenantID, who, map[string]any{"name": typ + " on-prem", "type": typ, "fields": fields})
	}
	inside := map[string]map[string]string{
		"webhook":    {"url": "https://10.20.3.4/hook"},
		"jira":       {"base_url": "https://10.20.3.5", "api_token": "user:token"},
		"splunk_hec": {"url": "https://10.20.3.6:8088/services/collector", "token": "hec-token"},
		"syslog":     {"address": "10.20.3.7:6514"},
	}
	for typ, fields := range inside {
		w := create(pbAdmin, typ, fields)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "root administrator can approve") {
			t.Fatalf("%s on a private address before approval: %d %s", typ, w.Code, w.Body.String())
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_created"), reasonURLBlocked)
	}
	if err := hs.store.CreatePrivateEndpoint(context.Background(), PrivateEndpoint{ID: "pvt_1", TenantID: "t1", CIDR: "10.20.0.0/16", CreatedBy: "root-admin"}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for typ, fields := range inside {
		w := create(pbAdmin, typ, fields)
		var out struct{ Data Connection }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusCreated {
			t.Fatalf("%s inside the approved range: %d %s", typ, w.Code, w.Body.String())
		}
		if ev := lastEvent(t, hs.rec, "connection_created"); ev.Event.Details["private_endpoint"] != true {
			t.Fatalf("%s: the audit event does not say the endpoint is private: %+v", typ, ev.Event.Details)
		}
		ids[typ] = out.Data.ID
	}
	other := &pkgauth.Claims{UserID: "u2", TenantID: "t2", Role: "admin", Permissions: []string{"*"}}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"outside the range":  create(pbAdmin, "webhook", map[string]string{"url": "https://10.21.0.1/hook"}),
		"another tenant":     create(other, "webhook", inside["webhook"]),
		"loopback":           create(pbAdmin, "webhook", map[string]string{"url": "https://127.0.0.1/hook"}),
		"metadata":           create(pbAdmin, "splunk_hec", map[string]string{"url": "https://169.254.169.254/", "token": "t"}),
		"a platform service": create(pbAdmin, "webhook", map[string]string{"url": "https://keycore:8010/keys"}),
		"syslog outside":     create(pbAdmin, "syslog", map[string]string{"address": "10.21.0.1:6514"}),
	} {
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", name, w.Code, w.Body.String())
		}
	}
	// A public address needs no approval and is not marked private.
	if w := create(pbAdmin, "webhook", map[string]string{"url": "https://1.1.1.1/hook"}); w.Code != http.StatusCreated {
		t.Fatalf("public webhook: %d %s", w.Code, w.Body.String())
	} else if ev := lastEvent(t, hs.rec, "connection_created"); ev.Event.Details["private_endpoint"] == true {
		t.Fatal("a public webhook was recorded as a private endpoint")
	}

	// The audit service is given the ranges with a stream's connection.
	w := hs.do(t, http.MethodPost, "/compliance/connections/"+ids["splunk_hec"]+"/resolve?tenant_id=t1", svcClaims("kms-audit"), map[string]any{})
	var out struct {
		Data resolvedConnection `json:"data"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Data.PrivateRanges) != 1 || out.Data.PrivateRanges[0] != "10.20.0.0/16" {
		t.Fatalf("resolve for audit: %d %s", w.Code, w.Body.String())
	}

	// A delivery: the shared client without an approval, its own with one,
	// and that one still refuses every other private address at the dial.
	allow := approvedAllow(context.Background(), hs.store, "t1", "webhook")
	if c, _ := hs.exec.clientFor(nil); c != hs.exec.outbound {
		t.Fatal("a tenant with no approved range did not get the shared public-only client")
	}
	c, done := hs.exec.clientFor(allow)
	done()
	if len(allow) != 1 || c == hs.exec.outbound {
		t.Fatalf("a delivery under an approval shared the public client (allow %v)", allow)
	}
	ctx := context.Background()
	if _, err := hs.exec.outboundVia(ctx, allow, http.MethodPost, "https://10.21.0.1/hook", map[string]string{}, nil); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("dial outside the approved range: %v", err)
	}
	if _, err := hs.exec.outboundVia(ctx, approvedAllow(ctx, hs.store, "t2", "webhook"), http.MethodPost, "https://10.20.3.4/hook", map[string]string{}, nil); err == nil {
		t.Fatal("another tenant's delivery reached t1's approved range")
	}
	if a := approvedAllow(ctx, hs.store, "t1", "aws"); a != nil {
		t.Fatalf("a cloud account was given a private allowance: %v", a)
	}
}

// A credential in use by a cloud account or HSM key can't be deleted, and
// when the owning service can't answer the delete is refused, not allowed.
func TestCredentialUsageGuardsDelete(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := hs.conn(t, "pkcs11_hsm", hsmFields())
	var users []string
	var usageErr error
	hs.h.credUsage = func(_ context.Context, tenant string, conn Connection) ([]string, error) {
		if tenant != "t1" || conn.ID != id {
			t.Fatalf("usage asked for %s/%s", tenant, conn.ID)
		}
		return users, usageErr
	}
	users = []string{"3 HSM keys"}
	w := hs.do(t, http.MethodGet, "/compliance/connections/"+id+"/usage", pbAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "3 HSM keys") {
		t.Fatalf("usage: %d %s", w.Code, w.Body.String())
	}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("deleted a credential in use: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_in_use")

	users, usageErr = nil, errors.New("HSM keys: keycore unreachable")
	if w := hs.do(t, http.MethodGet, "/compliance/connections/"+id+"/usage", pbAdmin, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("usage shown as empty when it is unknown: %d %s", w.Code, w.Body.String())
	}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("deleted with usage unverified: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_usage_unverified")
	usageErr = nil
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("unused credential: %d %s", w.Code, w.Body.String())
	}
}

// A test's real result is kept on the credential; a failure raises
// credential_test_failed, and only the service that uses a type may report
// a test of it.
func TestCredentialTestResultIsRecorded(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	id := hs.conn(t, "aws", map[string]string{"access_key_id": "AKIA", "secret_access_key": "0123456789abcdef"})
	if c, _ := hs.store.GetConnection(ctx, "t1", id); c.LastTestedAt != nil {
		t.Fatal("a new credential claims to have been tested")
	}
	var testErr error = errors.New("aws: the security token included in the request is invalid")
	hs.h.credTest = func(context.Context, Connection) error { return testErr }
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+id+"/test", pbAdmin, map[string]any{}); w.Code != http.StatusBadGateway {
		t.Fatalf("failed test: %d %s", w.Code, w.Body.String())
	}
	c, _ := hs.store.GetConnection(ctx, "t1", id)
	if c.LastTestedAt == nil || c.LastTestOK || !strings.Contains(c.LastTestError, "security token") {
		t.Fatalf("failed test not recorded: %+v", c)
	}
	if ev := lastEvent(t, hs.rec, "credential_test_failed"); ev.Event.TargetID != id || ev.Event.Result != route.ResultFailure || ev.Event.Details["type"] != "aws" {
		t.Fatalf("test failure event: %+v", ev.Event)
	}
	failures := len(events(hs.rec, "credential_test_failed"))
	testErr = nil
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+id+"/test", pbAdmin, map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("passing test: %d %s", w.Code, w.Body.String())
	}
	if c, _ := hs.store.GetConnection(ctx, "t1", id); !c.LastTestOK || c.LastTestError != "" {
		t.Fatalf("passing test not recorded: %+v", c)
	}
	if len(events(hs.rec, "credential_test_failed")) != failures {
		t.Fatal("a passing test raised credential_test_failed")
	}
	// The cloud service reports a test it ran on an account.
	path := "/compliance/connections/" + id + "/tested?tenant_id=t1"
	if w := hs.do(t, http.MethodPost, path, svcClaims("kms-cloud"), map[string]any{"ok": false, "error": "AccessDenied"}); w.Code != http.StatusOK {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	if c, _ := hs.store.GetConnection(ctx, "t1", id); c.LastTestOK || c.LastTestError != "AccessDenied" {
		t.Fatalf("reported test not recorded: %+v", c)
	}
	// The HSM connector doesn't use AWS credentials; a user reports nothing.
	if w := hs.do(t, http.MethodPost, path, svcClaims("kms-hsm"), map[string]any{"ok": true}); w.Code != http.StatusConflict {
		t.Fatalf("another service reported a test: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_test_reported"), reasonConnectionUse)
	if w := hs.do(t, http.MethodPost, path, pbAdmin, map[string]any{"ok": true}); w.Code != http.StatusForbidden {
		t.Fatalf("a user reported a test: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_test_reported"), reasonConnectionCaller)
	if c, _ := hs.store.GetConnection(ctx, "t1", id); c.LastTestOK {
		t.Fatal("a refused report changed the result")
	}
	// A new secret clears the result: the last test was of the old one.
	hs.do(t, http.MethodPut, "/compliance/playbooks/connections/"+id, pbAdmin, map[string]any{"name": "aws", "type": "aws",
		"fields": map[string]string{"access_key_id": "AKIA", "secret_access_key": "fedcba9876543210"}})
	if c, _ := hs.store.GetConnection(ctx, "t1", id); c.LastTestedAt != nil || c.LastTestError != "" {
		t.Fatalf("test result kept across a new secret: %+v", c)
	}
}

// A service admitted to open credentials must be able to prove who it is:
// auth provisions its identity, and its main obtains a token as it. (The HSM
// connector was first given a credential source and no identity: every
// credential request would have been refused in a deployment, and a test
// double at the interface hid it.)
func TestEveryCredentialUserHasAServiceIdentity(t *testing.T) {
	root := filepath.Join("..", "..")
	auth, err := os.ReadFile(filepath.Join(root, "services", "auth", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	mains := map[string]string{
		"kms-audit": "audit", "kms-governance": "governance", "kms-discovery": "discovery",
		"kms-cloud": "cloud", "kms-hsm": "hsm-connector", "kms-hyok-proxy": "hyok", "kms-secrets": "secrets",
	}
	for id := range connectionUsers {
		if !strings.Contains(string(auth), `"`+id+`"`) {
			t.Errorf("%s may open credentials but auth provisions no such service identity (internalServiceClients)", id)
		}
		dir, ok := mains[id]
		if !ok {
			t.Errorf("%s: name its service directory in this test", id)
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, "services", dir, "main.go"))
		if err != nil || !strings.Contains(string(src), `servicetoken.FromEnv("`+id+`")`) {
			t.Errorf("services/%s/main.go does not obtain a service token as %s", dir, id)
		}
	}
}

// An XKS credential has the shape AWS requires, or it is refused at the store.
func TestXKSCredentialShape(t *testing.T) {
	ok := Connection{Type: "aws_xks", Fields: map[string]string{"access_key_id": "ABCDEFGHIJKLMNOPQRST", "secret_access_key": strings.Repeat("a", 43)}}
	if err := validateCredential(ok, nil); err != nil {
		t.Fatalf("valid credential refused: %v", err)
	}
	for name, f := range map[string]map[string]string{
		"lowercase id":  {"access_key_id": "abcdefghijklmnopqrst", "secret_access_key": strings.Repeat("a", 43)},
		"short id":      {"access_key_id": "ABCDEFGHIJ", "secret_access_key": strings.Repeat("a", 43)},
		"digit 1 in id": {"access_key_id": "ABCDEFGHIJKLMNOPQRS1", "secret_access_key": strings.Repeat("a", 43)},
		"short secret":  {"access_key_id": "ABCDEFGHIJKLMNOPQRST", "secret_access_key": strings.Repeat("a", 42)},
		"long secret":   {"access_key_id": "ABCDEFGHIJKLMNOPQRST", "secret_access_key": strings.Repeat("a", 65)},
	} {
		if err := validateCredential(Connection{Type: "aws_xks", Fields: f}, nil); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
