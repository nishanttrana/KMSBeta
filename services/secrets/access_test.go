package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterstate"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

// The same flows on real Postgres, with the shipped migrations: the access
// decision, paging, recoverable delete and version operations depend on SQL
// (conditional updates, reused parameters) that SQLite alone does not prove.
func TestAccessAndVersionsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	for name, run := range map[string]func(*testing.T, *Handler, *Service, *routetest.Recorder){
		"access rules": runAccessRules, "paging": runListPaging, "soft delete": runSoftDelete, "versions": runVersions,
		"mounts": runMounts, "default deny": runDefaultDeny, "groups": runGroups, "version cap": runVersionCap, "retention": runRetention,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE secrets, secret_values, secret_audit_log, secret_access_rules, secret_vault_settings`); err != nil {
				t.Fatalf("reset: %v", err)
			}
			svc := NewService(NewSQLStore(conn), []byte("0123456789ABCDEF0123456789ABCDEF"))
			rec := &routetest.Recorder{}
			run(t, NewHandler(svc, rec, nil, nil), svc, rec)
		})
	}
}

func user(tenant, id, role string, perms ...string) *pkgauth.Claims {
	return &pkgauth.Claims{UserID: id, TenantID: tenant, Role: role, Permissions: perms}
}

func call(t *testing.T, h *Handler, who *pkgauth.Claims, method, path, body string) (int, map[string]interface{}) {
	t.Helper()
	rr := serveAs(h, who, httptest.NewRequest(method, path, strings.NewReader(body)))
	out := map[string]interface{}{}
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
	}
	return rr.Code, out
}

func mustCreate(t *testing.T, h *Handler, who *pkgauth.Claims, name, folder string) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"secret_type":"password","value":"v-%s","labels":{"path":%q}}`, name, name, folder)
	code, out := call(t, h, who, "POST", "/secrets", body)
	if code != http.StatusCreated {
		t.Fatalf("create %s: %d %v", name, code, out)
	}
	return out["secret"].(map[string]interface{})["id"].(string)
}

func refused(t *testing.T, rec *routetest.Recorder, action, reason string) {
	t.Helper()
	ev := rec.Last(t)
	if ev.Action != action || ev.Event.Result != "refused" || ev.Event.Details["reason"] != reason {
		t.Fatalf("want %s refused %s, audited %s result=%s details=%v", action, reason, ev.Action, ev.Event.Result, ev.Event.Details)
	}
}

func TestDecide(t *testing.T) {
	alice := user("t", "alice", "finance", "*")
	bob := user("t", "bob", "ops", "*")
	rule := func(path, subject, effect string, caps ...string) AccessRule {
		kind, id, _ := strings.Cut(subject, ":")
		return AccessRule{Path: path, SubjectType: kind, SubjectID: id, Effect: effect, Capabilities: caps}
	}
	rules := []AccessRule{
		rule("/finance/*", "role:finance", effectAllow, capRead, capValue),
		rule("/finance/prod/db", "user:alice", effectDeny, capValue),
		rule("/exact", "user:bob", effectAllow, capValue),
	}
	for _, tc := range []struct {
		who        *pkgauth.Claims
		path, capa string
		want       string
	}{
		{alice, "/finance/x", capValue, ""},
		{alice, "/finance/deep/er/x", capRead, ""},
		{bob, "/finance/x", capValue, reasonNotInRule},
		{bob, "/finance/x", capWrite, ""},                       // no rule covers write
		{alice, "/finance/prod/db", capValue, reasonRuleDenied}, // deny wins
		{alice, "/finance/prod/db", capRead, ""},
		{bob, "/financex", capValue, ""}, // a folder rule is not a prefix match
		{bob, "/finance", capValue, ""},  // nor the folder name itself
		{bob, "/exact", capValue, ""},
		{alice, "/exact", capValue, reasonNotInRule},
		{alice, "/exact/child", capValue, ""}, // an exact path covers only itself
		{nil, "/finance/x", capValue, reasonNotInRule},
		{bob, "/open", capValue, ""},
	} {
		if got := decide(rules, false, &caller{claims: tc.who}, tc.path, tc.capa); got != tc.want {
			t.Errorf("decide(%v, %s, %s) = %q, want %q", tc.who, tc.path, tc.capa, got, tc.want)
		}
	}
	if secretPath(map[string]string{"path": "/a/b/"}, "c/d") != "/a/b/c/d" || secretPath(nil, "x") != "/x" {
		t.Fatal("secretPath")
	}
}

func TestAccessRuleValidation(t *testing.T) {
	h, _, _, rec := newRecordedHandler(t)
	admin := tenantAdmin("t1")
	for _, bad := range []string{
		`{"path":"finance/*","subject_type":"user","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/fin*/x","subject_type":"user","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/finance*","subject_type":"user","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/finance/","subject_type":"user","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/","subject_type":"user","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/x","subject_type":"team","subject_id":"a","capabilities":["value"]}`,
		`{"path":"/x","subject_type":"user","subject_id":"","capabilities":["value"]}`,
		`{"path":"/x","subject_type":"user","subject_id":"a","capabilities":[]}`,
		`{"path":"/x","subject_type":"user","subject_id":"a","capabilities":["value","admin"]}`,
		`{"path":"/x","subject_type":"user","subject_id":"a","capabilities":["value"],"effect":"maybe"}`,
	} {
		if code, out := call(t, h, admin, "POST", "/secrets/access/rules", bad); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", bad, code, out)
		}
	}
	code, out := call(t, h, admin, "POST", "/secrets/access/rules", `{"path":"/*","subject_type":"role","subject_id":"ops","capabilities":["delete","read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	rule := out["rule"].(map[string]interface{})
	if fmt.Sprint(rule["capabilities"]) != "[read delete]" || rule["effect"] != "allow" || rule["created_by"] != "u-t1" {
		t.Fatalf("rule %v", rule)
	}
	ev := rec.Last(t)
	if ev.Action != "access_rule_created" || ev.Event.TargetID != rule["id"] || ev.Event.Details["subject"] != "role:ops" || ev.Event.Details["path"] != "/*" {
		t.Fatalf("event %+v", ev)
	}

	// Managing rules and destroying are not granted by the coarse kms.write.
	writer := user("t1", "w", "ops", "kms.read", "kms.write")
	if code, _ := call(t, h, writer, "POST", "/secrets/access/rules", `{"path":"/x","subject_type":"user","subject_id":"w","capabilities":["value"]}`); code != http.StatusForbidden {
		t.Fatalf("kms.write created a rule: %d", code)
	}
	refused(t, rec, "access_rule_created", "permission_denied")
	if code, _ := call(t, h, writer, "DELETE", "/secrets/access/rules/"+rule["id"].(string), ""); code != http.StatusForbidden {
		t.Fatalf("kms.write deleted a rule: %d", code)
	}
	if code, _ := call(t, h, admin, "DELETE", "/secrets/access/rules/"+rule["id"].(string), ""); code != http.StatusOK {
		t.Fatalf("delete rule: %d", code)
	}
	if ev := rec.Last(t); ev.Action != "access_rule_deleted" || ev.Event.Details["subject"] != "role:ops" {
		t.Fatalf("delete event %+v", ev)
	}
	if code, _ := call(t, h, admin, "DELETE", "/secrets/access/rules/"+rule["id"].(string), ""); code != http.StatusNotFound {
		t.Fatalf("second delete: %d", code)
	}
}

// A rule on a folder limits its secrets to the callers it names, on every
// route, whatever route permissions the others hold.
func TestAccessRulesAreEnforcedOnEveryRoute(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runAccessRules(t, h, svc, rec)
}

func runAccessRules(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	alice := user("t1", "alice", "finance", "*")
	bob := user("t1", "bob", "ops", "*")
	ledger := mustCreate(t, h, alice, "ledger", "/finance/prod")
	open := mustCreate(t, h, alice, "wiki", "")
	if code, out := call(t, h, alice, "POST", "/v1/secret/data/finance/kv-item", `{"data":{"k":"v"}}`); code != http.StatusOK {
		t.Fatalf("kv seed: %d %v", code, out)
	}
	if code, out := call(t, h, alice, "POST", "/secrets/access/rules",
		`{"path":"/finance/*","subject_type":"user","subject_id":"alice","capabilities":["read","value","write","delete"]}`); code != http.StatusCreated {
		t.Fatalf("rule: %d %v", code, out)
	}

	for _, tc := range []struct{ method, path, body, action string }{
		{"GET", "/secrets/" + ledger, "", "read"},
		{"GET", "/secrets/" + ledger + "/value", "", "value_read"},
		{"GET", "/secrets/" + ledger + "/value?version=1", "", "value_read"},
		{"GET", "/secrets/" + ledger + "/versions", "", "versions_listed"},
		{"GET", "/secrets/" + ledger + "/audit", "", "audit_log_read"},
		{"GET", "/secrets/" + ledger + "/access", "", "access_read"},
		{"PUT", "/secrets/" + ledger, `{"description":"x"}`, "updated"},
		{"POST", "/secrets/" + ledger + "/rotate", `{"value":"n"}`, "rotated"},
		{"POST", "/secrets/" + ledger + "/rollback", `{"version":1}`, "rolled_back"},
		{"DELETE", "/secrets/" + ledger + "/versions/1", "", "version_destroyed"},
		{"DELETE", "/secrets/" + ledger, "", "deleted"},
		{"POST", "/secrets/" + ledger + "/restore", "", "restored"},
		{"POST", "/secrets/" + ledger + "/destroy", "", "destroyed"},
		{"POST", "/secrets", `{"name":"planted","secret_type":"token","value":"x","labels":{"path":"/finance"}}`, "created"},
		{"POST", "/secrets/generate/keypair", `{"name":"k","key_type":"ed25519","labels":{"path":"/finance"}}`, "generated"},
		{"PUT", "/secrets/" + open, `{"labels":{"path":"/finance"}}`, "updated"}, // moving a secret in
		{"GET", "/v1/secret/data/finance/kv-item", "", "vault_kv_read"},
		{"GET", "/v1/secret/finance/kv-item", "", "vault_kv_read"},
		{"GET", "/v1/secret/metadata/finance/kv-item", "", "vault_metadata_read"},
		{"POST", "/v1/secret/data/finance/kv-item", `{"data":{"k":"2"}}`, "vault_kv_written"},
		{"POST", "/v1/secret/data/finance/new-item", `{"data":{"k":"2"}}`, "vault_kv_written"},
		{"DELETE", "/v1/secret/data/finance/kv-item", "", "vault_kv_deleted"},
	} {
		code, out := call(t, h, bob, tc.method, tc.path, tc.body)
		if code != http.StatusForbidden {
			t.Fatalf("%s %s as bob: %d %v", tc.method, tc.path, code, out)
		}
		refused(t, rec, tc.action, reasonNotInRule)
	}
	if ev := rec.Last(t); ev.Event.Details["path"] != "/finance/kv-item" || ev.Event.Details["capability"] != capDelete {
		t.Fatalf("refusal lacks path and capability: %v", ev.Event.Details)
	}

	// Bob's listing and counts leave the folder out; Alice's include it.
	names := func(who *pkgauth.Claims) string {
		_, out := call(t, h, who, "GET", "/secrets", "")
		var got []string
		for _, it := range out["items"].([]interface{}) {
			got = append(got, it.(map[string]interface{})["name"].(string))
		}
		return strings.Join(got, ",")
	}
	if got := names(bob); got != "wiki" {
		t.Fatalf("bob lists %q", got)
	}
	if got := names(alice); !strings.Contains(got, "ledger") || !strings.Contains(got, "finance/kv-item") {
		t.Fatalf("alice lists %q", got)
	}
	total := func(who *pkgauth.Claims) float64 {
		_, out := call(t, h, who, "GET", "/secrets/stats", "")
		return out["stats"].(map[string]interface{})["total_secrets"].(float64)
	}
	if total(bob) != 1 || total(alice) != 3 {
		t.Fatalf("stats: bob %v alice %v", total(bob), total(alice))
	}

	// Nothing bob tried took effect, and alice still works.
	code, out := call(t, h, alice, "GET", "/secrets/"+ledger+"/value", "")
	if code != http.StatusOK || out["value"] != "v-ledger" || out["version"] != float64(1) {
		t.Fatalf("alice value: %d %v", code, out)
	}
	_, out = call(t, h, alice, "GET", "/secrets/"+ledger, "")
	if s := out["secret"].(map[string]interface{}); s["restricted"] != true || s["path"] != "/finance/prod/ledger" {
		t.Fatalf("secret %v", s)
	}
	_, out = call(t, h, alice, "GET", "/secrets/"+ledger+"/access", "")
	if len(out["rules"].([]interface{})) != 1 || out["caller"].(map[string]interface{})["value"] != true {
		t.Fatalf("access %v", out)
	}
	// The open secret stays open to bob.
	if code, _ := call(t, h, bob, "GET", "/secrets/"+open+"/value", ""); code != http.StatusOK {
		t.Fatalf("open secret: %d", code)
	}

	// A deny rule naming alice wins over her allow rule.
	if code, _ := call(t, h, alice, "POST", "/secrets/access/rules",
		`{"path":"/finance/prod/ledger","subject_type":"role","subject_id":"finance","capabilities":["value"],"effect":"deny"}`); code != http.StatusCreated {
		t.Fatal("deny rule")
	}
	if code, _ := call(t, h, alice, "GET", "/secrets/"+ledger+"/value", ""); code != http.StatusForbidden {
		t.Fatalf("deny did not win: %d", code)
	}
	refused(t, rec, "value_read", reasonRuleDenied)
	if code, _ := call(t, h, alice, "GET", "/secrets/"+ledger, ""); code != http.StatusOK {
		t.Fatal("deny on value must not hide metadata")
	}
}

// With rules hiding secrets, a page is still full until the last one.
func TestListPagesCountVisibleSecrets(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runListPaging(t, h, svc, rec)
}

func runListPaging(t *testing.T, h *Handler, _ *Service, _ *routetest.Recorder) {
	alice := user("t1", "alice", "finance", "*")
	bob := user("t1", "bob", "ops", "*")
	for i := 0; i < 6; i++ {
		mustCreate(t, h, alice, fmt.Sprintf("hidden-%d", i), "/finance")
		mustCreate(t, h, alice, fmt.Sprintf("open-%d", i), "")
	}
	call(t, h, alice, "POST", "/secrets/access/rules", `{"path":"/finance/*","subject_type":"user","subject_id":"alice","capabilities":["read"]}`)
	seen := map[string]bool{}
	for offset := 0; ; offset += 4 {
		_, out := call(t, h, bob, "GET", fmt.Sprintf("/secrets?limit=4&offset=%d", offset), "")
		items := out["items"].([]interface{})
		for _, it := range items {
			name := it.(map[string]interface{})["name"].(string)
			if seen[name] || strings.HasPrefix(name, "hidden") {
				t.Fatalf("page at %d returned %s", offset, name)
			}
			seen[name] = true
		}
		if len(items) < 4 {
			break
		}
	}
	if len(seen) != 6 {
		t.Fatalf("bob paged %d secrets, want 6", len(seen))
	}
}

func TestSoftDeleteRestoreDestroy(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runSoftDelete(t, h, svc, rec)
}

func runSoftDelete(t *testing.T, h *Handler, svc *Service, rec *routetest.Recorder) {
	admin := tenantAdmin("t1")
	id := mustCreate(t, h, admin, "db", "")

	if code, out := call(t, h, admin, "DELETE", "/secrets/"+id, ""); code != http.StatusOK || out["recoverable"] != true {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := call(t, h, admin, "GET", "/secrets/"+id+"/value", ""); code != http.StatusGone {
		t.Fatalf("value of a deleted secret: %d", code)
	}
	refused(t, rec, "value_read", "secret_deleted")
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/rotate", `{"value":"n"}`); code != http.StatusGone {
		t.Fatalf("rotate of a deleted secret: %d", code)
	}
	if code, _ := call(t, h, admin, "DELETE", "/secrets/"+id, ""); code != http.StatusGone {
		t.Fatalf("second delete: %d", code)
	}
	_, out := call(t, h, admin, "GET", "/secrets", "")
	if len(out["items"].([]interface{})) != 0 {
		t.Fatalf("deleted secret still listed: %v", out)
	}
	_, out = call(t, h, admin, "GET", "/secrets?deleted=true", "")
	items := out["items"].([]interface{})
	if len(items) != 1 || items[0].(map[string]interface{})["deleted_by"] != "u-t1" || items[0].(map[string]interface{})["deleted_at"] == nil {
		t.Fatalf("deleted listing: %v", out)
	}
	if stats, _ := svc.GetStats(context.Background(), "t1", nil); stats.TotalSecrets != 0 || stats.TotalVersions != 0 {
		t.Fatalf("stats count a deleted secret: %+v", stats)
	}

	// The name stays taken while the secret is only deleted.
	if code, _ := call(t, h, admin, "POST", "/secrets", `{"name":"db","secret_type":"password","value":"x"}`); code != http.StatusConflict {
		t.Fatalf("create over a deleted secret: %d", code)
	}
	refused(t, rec, "created", "name_held_by_deleted_secret")

	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/restore", ""); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if ev := rec.Last(t); ev.Action != "restored" || ev.Event.Result != "success" {
		t.Fatalf("restore event %+v", ev)
	}
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/restore", ""); code != http.StatusConflict {
		t.Fatalf("restore of an active secret: %d", code)
	}
	refused(t, rec, "restored", "secret_not_deleted")
	if code, out := call(t, h, admin, "GET", "/secrets/"+id+"/value", ""); code != http.StatusOK || out["value"] != "v-db" {
		t.Fatalf("value after restore: %d %v", code, out)
	}

	// Destroy needs its own permission and removes every version.
	deleter := user("t1", "d", "ops", "secrets.read", "secrets.delete")
	if code, _ := call(t, h, deleter, "POST", "/secrets/"+id+"/destroy", ""); code != http.StatusForbidden {
		t.Fatalf("secrets.delete destroyed a secret: %d", code)
	}
	refused(t, rec, "destroyed", "permission_denied")
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/destroy", ""); code != http.StatusOK {
		t.Fatalf("destroy: %d", code)
	}
	if counts, _ := svc.store.VersionCounts(context.Background(), "t1"); len(counts) != 0 {
		t.Fatalf("versions survive destroy: %v", counts)
	}
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/restore", ""); code != http.StatusNotFound {
		t.Fatalf("restore after destroy: %d", code)
	}
}

func TestVersionReadRollbackDestroyAndConditionalWrite(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runVersions(t, h, svc, rec)
}

func runVersions(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	admin := tenantAdmin("t1")
	id := mustCreate(t, h, admin, "api", "") // v1 = "v-api"
	for _, v := range []string{"two", "three"} {
		if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/rotate", `{"value":"`+v+`"}`); code != http.StatusOK {
			t.Fatal("rotate")
		}
	}
	value := func(query string) (int, interface{}, interface{}) {
		code, out := call(t, h, admin, "GET", "/secrets/"+id+"/value"+query, "")
		return code, out["value"], out["version"]
	}
	if code, v, n := value("?version=1"); code != http.StatusOK || v != "v-api" || n != float64(1) {
		t.Fatalf("version 1: %d %v %v", code, v, n)
	}
	if ev := rec.Last(t); ev.Action != "value_read" || ev.Event.Details["version"] != 1 {
		t.Fatalf("value_read event %+v", ev.Event.Details)
	}
	if code, v, n := value(""); code != http.StatusOK || v != "three" || n != float64(3) {
		t.Fatalf("current: %d %v %v", code, v, n)
	}
	if code, _, _ := value("?version=9"); code != http.StatusNotFound {
		t.Fatalf("missing version: %d", code)
	}

	// A conditional write is refused when the secret has moved on.
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/rotate", `{"value":"lost","expected_version":2}`); code != http.StatusConflict {
		t.Fatalf("stale rotate: %d", code)
	}
	refused(t, rec, "rotated", "version_conflict")
	if code, _ := call(t, h, admin, "PUT", "/secrets/"+id, `{"description":"d","expected_version":1}`); code != http.StatusConflict {
		t.Fatalf("stale update: %d", code)
	}
	if _, v, n := value(""); v != "three" || n != float64(3) {
		t.Fatalf("a refused write changed the secret: %v %v", v, n)
	}

	// Rollback restores the old value as a new version.
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/rollback", `{"version":3}`); code != http.StatusConflict {
		t.Fatalf("rollback to the current version: %d", code)
	}
	refused(t, rec, "rolled_back", "already_current")
	code, out := call(t, h, admin, "POST", "/secrets/"+id+"/rollback", `{"version":1,"expected_version":3}`)
	if code != http.StatusOK || out["secret"].(map[string]interface{})["current_version"] != float64(4) {
		t.Fatalf("rollback: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Action != "rolled_back" || ev.Event.Details["from_version"] != 1 || ev.Event.Details["new_version"] != 4 {
		t.Fatalf("rollback event %+v", ev.Event.Details)
	}
	if _, v, n := value(""); v != "v-api" || n != float64(4) {
		t.Fatalf("after rollback: %v %v", v, n)
	}
	_, out = call(t, h, admin, "GET", "/secrets/"+id+"/audit", "")
	if !strings.Contains(fmt.Sprint(out["entries"]), "rolled_back") {
		t.Fatalf("change history lacks the rollback: %v", out)
	}

	// One earlier version can be destroyed; the current one cannot.
	if code, _ := call(t, h, admin, "DELETE", "/secrets/"+id+"/versions/4", ""); code != http.StatusConflict {
		t.Fatalf("destroy current version: %d", code)
	}
	refused(t, rec, "version_destroyed", "version_is_current")
	if code, _ := call(t, h, admin, "DELETE", "/secrets/"+id+"/versions/2", ""); code != http.StatusOK {
		t.Fatalf("destroy version 2: %d", code)
	}
	if code, _, _ := value("?version=2"); code != http.StatusNotFound {
		t.Fatalf("destroyed version still readable: %d", code)
	}
	if code, _ := call(t, h, admin, "DELETE", "/secrets/"+id+"/versions/2", ""); code != http.StatusNotFound {
		t.Fatalf("destroy twice: %d", code)
	}
	if code, _ := call(t, h, admin, "POST", "/secrets/"+id+"/rollback", `{"version":2}`); code != http.StatusNotFound {
		t.Fatalf("rollback to a destroyed version: %d", code)
	}
	_, out = call(t, h, admin, "GET", "/secrets/"+id+"/versions", "")
	if len(out["versions"].([]interface{})) != 3 {
		t.Fatalf("versions: %v", out)
	}

	// KV v2: read a version, delete is recoverable, a write brings it back.
	call(t, h, admin, "POST", "/v1/kv/data/app/cfg", `{"data":{"n":"1"}}`)
	call(t, h, admin, "POST", "/v1/kv/data/app/cfg", `{"data":{"n":"2"}}`)
	if code, out := call(t, h, admin, "GET", "/v1/kv/data/app/cfg?version=1", ""); code != http.StatusOK || !strings.Contains(fmt.Sprint(out), "n:1") {
		t.Fatalf("kv version read: %d %v", code, out)
	}
	if code, _ := call(t, h, admin, "DELETE", "/v1/kv/data/app/cfg", ""); code != http.StatusNoContent {
		t.Fatalf("kv delete: %d", code)
	}
	if code, _ := call(t, h, admin, "GET", "/v1/kv/data/app/cfg", ""); code != http.StatusNotFound {
		t.Fatalf("kv read after delete: %d", code)
	}
	if _, out := call(t, h, admin, "GET", "/v1/kv/metadata/app/cfg", ""); out["data"].(map[string]interface{})["deletion_time"] == "" {
		t.Fatalf("kv metadata lacks deletion_time: %v", out)
	}
	if code, out := call(t, h, admin, "POST", "/v1/kv/data/app/cfg", `{"data":{"n":"3"}}`); code != http.StatusOK || out["data"].(map[string]interface{})["version"] != float64(3) {
		t.Fatalf("kv write after delete: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Event.Details["restored"] != true {
		t.Fatalf("kv write did not record the restore: %v", ev.Event.Details)
	}
}

func TestMounts(t *testing.T) { h, svc, _, rec := newRecordedHandler(t); runMounts(t, h, svc, rec) }
func TestDefaultDeny(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runDefaultDeny(t, h, svc, rec)
}
func TestGroupRules(t *testing.T) { h, svc, _, rec := newRecordedHandler(t); runGroups(t, h, svc, rec) }
func TestVersionCap(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runVersionCap(t, h, svc, rec)
}
func TestRetention(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	runRetention(t, h, svc, rec)
}

// Two mounts are two namespaces; "secret" is the root one.
func runMounts(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	admin := tenantAdmin("t1")
	write := func(url, v string) {
		t.Helper()
		if code, out := call(t, h, admin, "POST", url, `{"data":{"v":"`+v+`"}}`); code != http.StatusOK {
			t.Fatalf("write %s: %d %v", url, code, out)
		}
	}
	read := func(url string) (int, string) {
		code, out := call(t, h, admin, "GET", url, "")
		return code, fmt.Sprint(out["data"])
	}
	write("/v1/team-a/data/db", "a")
	write("/v1/team-b/data/db", "b")
	write("/v1/secret/data/db", "root")
	for url, want := range map[string]string{"/v1/team-a/data/db": "v:a", "/v1/team-b/data/db": "v:b", "/v1/secret/data/db": "v:root", "/v1/secret/data/team-a/db": "v:a"} {
		if code, got := read(url); code != http.StatusOK || !strings.Contains(got, want) {
			t.Fatalf("%s = %d %s, want %s", url, code, got, want)
		}
	}
	if code, _ := read("/v1/team-c/data/db"); code != http.StatusNotFound {
		t.Fatalf("an unwritten mount answered: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Details["mount"] != "team-c" || ev.Event.Details["path"] != "db" {
		t.Fatalf("event %v", ev.Event.Details)
	}
	// The mount is part of the path the access rules match on.
	call(t, h, admin, "POST", "/secrets/access/rules", `{"path":"/team-a/*","subject_type":"user","subject_id":"someone-else","capabilities":["value"]}`)
	if code, _ := read("/v1/team-a/data/db"); code != http.StatusForbidden {
		t.Fatalf("rule on /team-a/* did not cover the mount: %d", code)
	}
	if code, _ := read("/v1/team-b/data/db"); code != http.StatusOK {
		t.Fatalf("rule on /team-a/* covered team-b: %d", code)
	}
}

func putSettings(t *testing.T, h *Handler, who *pkgauth.Claims, body string) (int, map[string]interface{}) {
	t.Helper()
	return call(t, h, who, "PUT", "/secrets/settings", body)
}

// Under default-deny a path no allow rule covers is refused, for everyone.
func runDefaultDeny(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	admin := user("t1", "admin", "tenant-admin", "*")
	covered := mustCreate(t, h, admin, "covered", "/ops")
	bare := mustCreate(t, h, admin, "bare", "")
	call(t, h, admin, "POST", "/secrets/access/rules", `{"path":"/ops/*","subject_type":"user","subject_id":"admin","capabilities":["read","value","write","delete"]}`)

	for _, bad := range []string{`{"max_versions":-1}`, `{"max_versions":1001}`, `{"deleted_retention_days":-1}`, `{"deleted_retention_days":4000}`} {
		if code, _ := putSettings(t, h, admin, bad); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", bad, code)
		}
	}
	if code, _ := putSettings(t, h, user("t1", "w", "ops", "kms.read", "kms.write"), `{"default_deny":true}`); code != http.StatusForbidden {
		t.Fatalf("kms.write changed settings: %d", code)
	}
	refused(t, rec, "settings_updated", "permission_denied")

	if code, out := putSettings(t, h, admin, `{"default_deny":true}`); code != http.StatusOK || out["settings"].(map[string]interface{})["default_deny"] != true {
		t.Fatalf("enable: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Action != "settings_updated" || ev.Event.Details["default_deny"] != true || fmt.Sprint(ev.Event.Details["previous"]) == "" {
		t.Fatalf("settings event %+v", ev.Event.Details)
	}
	if code, _ := call(t, h, admin, "GET", "/secrets/"+bare+"/value", ""); code != http.StatusForbidden {
		t.Fatalf("uncovered secret readable under default-deny: %d", code)
	}
	refused(t, rec, "value_read", reasonNoRule)
	if code, _ := call(t, h, admin, "POST", "/secrets", `{"name":"new","secret_type":"token","value":"x"}`); code != http.StatusForbidden {
		t.Fatalf("create on an uncovered path: %d", code)
	}
	if code, _ := call(t, h, admin, "GET", "/secrets/"+covered+"/value", ""); code != http.StatusOK {
		t.Fatalf("covered secret: %d", code)
	}
	_, out := call(t, h, admin, "GET", "/secrets", "")
	if items := out["items"].([]interface{}); len(items) != 1 || items[0].(map[string]interface{})["name"] != "covered" || items[0].(map[string]interface{})["restricted"] != true {
		t.Fatalf("list under default-deny: %v", out)
	}
	// Rules can still be managed, so the tenant is never locked out.
	if code, _ := call(t, h, admin, "POST", "/secrets/access/rules", `{"path":"/bare","subject_type":"user","subject_id":"admin","capabilities":["value"]}`); code != http.StatusCreated {
		t.Fatal("rule under default-deny")
	}
	if code, _ := call(t, h, admin, "GET", "/secrets/"+bare+"/value", ""); code != http.StatusOK {
		t.Fatalf("newly covered secret: %d", code)
	}
	if code, _ := putSettings(t, h, admin, `{"default_deny":false}`); code != http.StatusOK {
		t.Fatal("disable")
	}
}

// memberships stands in for keycore's access groups.
type memberships struct {
	of  map[string][]string
	err error
}

func (m *memberships) GroupsOf(_ context.Context, _ string, userID string) ([]string, error) {
	return m.of[userID], m.err
}

// A group rule names the members keycore reports. When membership cannot be
// read, a group rule never allows and a deny group rule is never skipped.
func runGroups(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	groups := &memberships{of: map[string][]string{"alice": {"grp_fin"}}}
	h.groups = groups
	alice := user("t1", "alice", "analyst", "*")
	bob := user("t1", "bob", "analyst", "*")
	id := mustCreate(t, h, alice, "ledger", "/finance")
	other := mustCreate(t, h, alice, "notes", "/misc")
	call(t, h, alice, "POST", "/secrets/access/rules", `{"path":"/finance/*","subject_type":"group","subject_id":"grp_fin","capabilities":["read","value"]}`)

	if code, _ := call(t, h, alice, "GET", "/secrets/"+id+"/value", ""); code != http.StatusOK {
		t.Fatalf("group member: %d", code)
	}
	if code, _ := call(t, h, bob, "GET", "/secrets/"+id+"/value", ""); code != http.StatusForbidden {
		t.Fatalf("non-member: %d", code)
	}
	refused(t, rec, "value_read", reasonNotInRule)

	groups.err = fmt.Errorf("keycore unreachable")
	groups.of = nil
	if code, _ := call(t, h, alice, "GET", "/secrets/"+id+"/value", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("unknown membership allowed: %d", code)
	}
	refused(t, rec, "value_read", reasonGroupsUnavailable)
	// A path no group rule covers does not need the lookup.
	if code, _ := call(t, h, alice, "GET", "/secrets/"+other+"/value", ""); code != http.StatusOK {
		t.Fatalf("unrelated secret needed groups: %d", code)
	}
	// A deny group rule with unknown membership refuses too.
	call(t, h, alice, "POST", "/secrets/access/rules", `{"path":"/misc/*","subject_type":"group","subject_id":"grp_out","capabilities":["value"],"effect":"deny"}`)
	if code, _ := call(t, h, alice, "GET", "/secrets/"+other+"/value", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("deny group rule skipped: %d", code)
	}
	groups.err, groups.of = nil, map[string][]string{"alice": {"grp_out"}}
	if code, _ := call(t, h, alice, "GET", "/secrets/"+other+"/value", ""); code != http.StatusForbidden {
		t.Fatalf("deny group rule: %d", code)
	}
	refused(t, rec, "value_read", reasonRuleDenied)
	// Without a group source, a group rule refuses rather than opens.
	h.groups = nil
	if code, _ := call(t, h, alice, "GET", "/secrets/"+id+"/value", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("no group source: %d", code)
	}
}

// The cap keeps the newest versions and removes the rest at each write.
func runVersionCap(t *testing.T, h *Handler, _ *Service, rec *routetest.Recorder) {
	admin := tenantAdmin("t1")
	id := mustCreate(t, h, admin, "capped", "")
	rotate := func(v string) {
		t.Helper()
		if code, out := call(t, h, admin, "POST", "/secrets/"+id+"/rotate", `{"value":"`+v+`"}`); code != http.StatusOK {
			t.Fatalf("rotate: %d %v", code, out)
		}
	}
	rotate("two")
	rotate("three") // three versions, no cap yet
	if code, _ := putSettings(t, h, admin, `{"max_versions":2}`); code != http.StatusOK {
		t.Fatal("set cap")
	}
	rotate("four")
	if ev := rec.Last(t); ev.Action != "rotated" || ev.Event.Details["versions_pruned"] != 2 {
		t.Fatalf("rotate event %v", ev.Event.Details)
	}
	_, out := call(t, h, admin, "GET", "/secrets/"+id+"/versions", "")
	if got := fmt.Sprint(out["versions"]); len(out["versions"].([]interface{})) != 2 || !strings.Contains(got, "version:4") || !strings.Contains(got, "version:3") {
		t.Fatalf("versions after cap: %s", got)
	}
	if code, _ := call(t, h, admin, "GET", "/secrets/"+id+"/value?version=2", ""); code != http.StatusNotFound {
		t.Fatalf("pruned version readable: %d", code)
	}
	if code, out := call(t, h, admin, "POST", "/secrets/"+id+"/rollback", `{"version":3}`); code != http.StatusOK || out["secret"].(map[string]interface{})["current_version"] != float64(5) {
		t.Fatalf("rollback under cap: %d %v", code, out)
	}
	if code, out := call(t, h, admin, "GET", "/secrets/"+id+"/value", ""); code != http.StatusOK || out["value"] != "three" {
		t.Fatalf("value after rollback: %d %v", code, out)
	}
	_, out = call(t, h, admin, "GET", "/secrets/"+id+"/audit", "")
	if !strings.Contains(fmt.Sprint(out["entries"]), "versions_pruned") {
		t.Fatalf("change history lacks the prune: %v", out)
	}
	putSettings(t, h, admin, `{"max_versions":0}`)
}

// A deleted secret is destroyed once its tenant's retention period has
// passed, by the primary only, and each purge is audited.
func runRetention(t *testing.T, h *Handler, svc *Service, rec *routetest.Recorder) {
	admin := tenantAdmin("t1")
	gone := mustCreate(t, h, admin, "gone", "")
	kept := mustCreate(t, h, admin, "kept", "")
	live := mustCreate(t, h, admin, "live", "")
	for _, id := range []string{gone, kept} {
		if code, _ := call(t, h, admin, "DELETE", "/secrets/"+id, ""); code != http.StatusOK {
			t.Fatal("delete")
		}
	}
	ctx := context.Background()
	now := time.Now().UTC()
	// No retention period: nothing is purged however old the delete.
	if n := h.purgeExpired(ctx, now.AddDate(1, 0, 0)); n != 0 {
		t.Fatalf("purged %d with no retention period", n)
	}
	if code, _ := putSettings(t, h, admin, `{"deleted_retention_days":7}`); code != http.StatusOK {
		t.Fatal("set retention")
	}
	if n := h.purgeExpired(ctx, now.AddDate(0, 0, 6)); n != 0 {
		t.Fatalf("purged %d before the period passed", n)
	}
	// Restoring one before the period ends keeps it.
	if code, _ := call(t, h, admin, "POST", "/secrets/"+kept+"/restore", ""); code != http.StatusOK {
		t.Fatal("restore")
	}

	// A cluster member never runs the sweep.
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	n := h.purgeExpired(ctx, now.AddDate(0, 0, 8))
	clusterstate.SetDefault(nil)
	if n != 0 {
		t.Fatalf("a member purged %d secrets", n)
	}
	if _, err := svc.GetSecret(ctx, "t1", gone); err != nil {
		t.Fatalf("a member destroyed the secret: %v", err)
	}

	rec.Reset()
	if n := h.purgeExpired(ctx, now.AddDate(0, 0, 8)); n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	ev := rec.Last(t)
	if ev.Action != "retention_purged" || ev.Event.TargetID != gone || ev.Event.ActorID != retentionActor || ev.Event.Result != "success" ||
		ev.Event.Details["retention_days"] != 7 || ev.Event.Details["deleted_by"] != "u-t1" {
		t.Fatalf("purge event %+v", ev)
	}
	if _, err := svc.GetSecret(ctx, "t1", gone); err == nil {
		t.Fatal("secret survived its retention period")
	}
	for _, id := range []string{kept, live} {
		if code, _ := call(t, h, admin, "GET", "/secrets/"+id+"/value", ""); code != http.StatusOK {
			t.Fatalf("an active secret was purged: %d", code)
		}
	}
	putSettings(t, h, admin, `{"deleted_retention_days":0}`)
}

// Migration 005 on real Postgres, from a database as 7.29.0 left it: a
// secret written under a non-root Vault mount is renamed to <mount>/<path>
// with a change-history entry, a name that is already taken is left alone,
// and the value_hash column is gone.
func TestMigration005Postgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	db, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.SQL().Conn(ctx) // one connection, so search_path holds
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	file := func(path string) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		exec(string(raw)) // one statement batch, as pkg/db runs a migration
	}
	exec(`DROP SCHEMA IF EXISTS mig005 CASCADE`)
	exec(`CREATE SCHEMA mig005`)
	defer conn.ExecContext(ctx, `DROP SCHEMA IF EXISTS mig005 CASCADE`) //nolint:errcheck
	exec(`SET search_path TO mig005`)
	for _, f := range []string{"001_initial.sql", "002_audit_log.sql", "003_mek_state.sql", "004_access_rules_soft_delete.sql"} {
		file("migrations/" + f)
	}
	seed := func(id, name, metadata string) {
		exec(`INSERT INTO secrets (id, tenant_id, name, secret_type, metadata, created_by) VALUES ($1,'t1',$2,'api_key',$3,'u')`, id, name, metadata)
		exec(`INSERT INTO secret_values (tenant_id, secret_id, version, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash) VALUES ('t1',$1,1,'\x01','\x02','\x03','\x04','\xdeadbeef')`, id)
	}
	seed("s_kv", "app/cfg", `{"vault_compat":true,"mount":"kv"}`)        // renamed to kv/app/cfg
	seed("s_root", "app/root", `{"vault_compat":true,"mount":"secret"}`) // root mount: unchanged
	seed("s_ui", "stripe-live", `{"source":"dashboard"}`)                // not a KV secret: unchanged
	seed("s_clash", "db", `{"vault_compat":true,"mount":"team"}`)        // target name taken: unchanged
	seed("s_taken", "team/db", `{"source":"dashboard"}`)
	seed("s_done", "kv/already", `{"vault_compat":true,"mount":"kv"}`) // already carries its mount

	file("migrations/005_settings_mount_drop_hash.sql")

	names := map[string]string{}
	rows, err := conn.QueryContext(ctx, `SELECT id, name FROM secrets`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, name string
		_ = rows.Scan(&id, &name)
		names[id] = name
	}
	rows.Close() //nolint:errcheck
	want := map[string]string{"s_kv": "kv/app/cfg", "s_root": "app/root", "s_ui": "stripe-live", "s_clash": "db", "s_taken": "team/db", "s_done": "kv/already"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("names after migration:\n got %v\nwant %v", names, want)
	}
	var renames int
	var detail string
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*), MAX(detail) FROM secret_audit_log WHERE action = 'renamed'`).Scan(&renames, &detail); err != nil || renames != 1 || !strings.Contains(detail, "app/cfg -> kv/app/cfg") {
		t.Fatalf("rename history: %d %q %v", renames, detail, err)
	}
	var hashColumns, values int
	_ = conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'mig005' AND table_name = 'secret_values' AND column_name = 'value_hash'`).Scan(&hashColumns)
	_ = conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_values`).Scan(&values)
	if hashColumns != 0 || values != 6 {
		t.Fatalf("value_hash columns %d (want 0), value rows %d (want 6)", hashColumns, values)
	}
	// Applying it again changes nothing.
	file("migrations/005_settings_mount_drop_hash.sql")
}
