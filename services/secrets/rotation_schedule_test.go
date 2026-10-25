package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route/routetest"
)

type stubAuthority struct {
	answer authority.Answer
	err    error
}

func (a stubAuthority) Authority(_ context.Context, _, _ string, perms []string) (authority.Answer, error) {
	out := a.answer
	if out.Missing == nil {
		out.Missing = []string{}
	}
	return out, a.err
}

func scheduleCall(t *testing.T, h *Handler, claims *pkgauth.Claims, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAs(h, claims, httptest.NewRequest(method, path+"?tenant_id=t1", bytes.NewReader([]byte(body))))
}

func generatedSSHKey(t *testing.T, h *Handler) Secret {
	t.Helper()
	rr := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPost, "/secrets/generate/ssh_key", `{"tenant_id":"t1","name":"deploy-key"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("generate: %d %s", rr.Code, rr.Body)
	}
	var out struct {
		Secret Secret `json:"secret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out.Secret
}

// publicMatches says whether the stored public key is the public half of the
// stored private key: a rotation that changed one and not the other fails.
func publicMatches(t *testing.T, svc *Service, id string) (string, bool) {
	t.Helper()
	val, err := svc.GetSecretValue(context.Background(), "t1", id, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(val.Value))
	if err != nil {
		t.Fatalf("stored value is not a private key: %v", err)
	}
	s, err := svc.GetSecret(context.Background(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := s.Metadata["public_key"].(string)
	return val.Value, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) == strings.TrimSpace(pub)
}

func TestGeneratedSecretRotatesOnSchedule(t *testing.T) {
	h, svc, _, rec := newRecordedHandler(t)
	h.authority = stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}}
	key := generatedSSHKey(t, h)
	before, ok := publicMatches(t, svc, key.ID)
	if !ok {
		t.Fatal("generated key's public half does not match")
	}

	// A secret whose value came from outside cannot have a schedule.
	plain := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPost, "/secrets", `{"tenant_id":"t1","name":"db-pass","secret_type":"password","value":"x"}`)
	var created struct {
		Secret Secret `json:"secret"`
	}
	_ = json.Unmarshal(plain.Body.Bytes(), &created)
	if rr := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPut, "/secrets/rotation-schedules/"+created.Secret.ID, `{"interval_hours":24}`); rr.Code != http.StatusConflict {
		t.Fatalf("schedule on an outside value: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != reasonNotGenerated {
		t.Fatalf("refusal audited as %+v", ev)
	}

	rr := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPut, "/secrets/rotation-schedules/"+key.ID, `{"interval_hours":24}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body)
	}
	var saved struct {
		Schedule SecretRotationSchedule `json:"schedule"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &saved)
	if saved.Schedule.AuthorizedBy != "u-t1" || saved.Schedule.NextRunAt == nil || saved.Schedule.SecretPath == "" {
		t.Fatalf("saved %+v", saved.Schedule)
	}

	rr = scheduleCall(t, h, tenantAdmin("t1"), http.MethodPost, "/secrets/rotation-schedules/"+key.ID+"/run", ``)
	if rr.Code != http.StatusOK {
		t.Fatalf("run: %d %s", rr.Code, rr.Body)
	}
	after, ok := publicMatches(t, svc, key.ID)
	if after == before || !ok {
		t.Fatal("the run did not write fresh, matching material")
	}
	s, _ := svc.GetSecret(context.Background(), "t1", key.ID)
	if s.CurrentVersion != 2 {
		t.Fatalf("version %d after one rotation", s.CurrentVersion)
	}
	var run *struct{ result, version any }
	for _, e := range rec.Events() {
		if e.Action == "rotation_schedule_run" {
			run = &struct{ result, version any }{e.Event.Result, e.Event.Details["new_version"]}
		}
	}
	if run == nil || run.result != "success" || run.version != 2 {
		t.Fatalf("run event %+v", run)
	}

	// The tick runs what is due.
	r, _ := svc.store.GetRotationSchedule(context.Background(), "t1", key.ID)
	past := time.Now().UTC().Add(-time.Minute)
	r.NextRunAt = &past
	_ = svc.store.PutRotationSchedule(context.Background(), r)
	if n := h.rotateDue(context.Background(), time.Now().UTC()); n != 1 {
		t.Fatalf("due runs: %d", n)
	}
	if s, _ := svc.GetSecret(context.Background(), "t1", key.ID); s.CurrentVersion != 3 {
		t.Fatalf("tick did not rotate: v%d", s.CurrentVersion)
	}
}

// Before each run: the saver must be active with secrets.write, allowed by
// the vault's access rules to write the path, and the secret must exist.
// Otherwise the schedule pauses, the refusal is audited and nothing changes.
func TestSecretRotationScheduleNeedsTheSaversAuthority(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, a authority.Checker) (*Handler, *Service, Secret) {
		t.Helper()
		h, svc, _, _ := newRecordedHandler(t)
		h.authority = stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}}
		key := generatedSSHKey(t, h)
		if rr := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPut, "/secrets/rotation-schedules/"+key.ID, `{"interval_hours":1}`); rr.Code != http.StatusOK {
			t.Fatalf("save: %d %s", rr.Code, rr.Body)
		}
		h.authority = a
		r, _ := svc.store.GetRotationSchedule(ctx, "t1", key.ID)
		past := time.Now().UTC().Add(-time.Minute)
		r.NextRunAt = &past
		_ = svc.store.PutRotationSchedule(ctx, r)
		return h, svc, key
	}

	t.Run("authority revoked", func(t *testing.T) {
		h, svc, key := setup(t, stubAuthority{answer: authority.Answer{Active: true, Missing: []string{permWrite}}})
		runAndExpect(t, h, svc, key, authority.ReasonRevoked, true)
	})
	t.Run("auth unreachable: postponed, not paused", func(t *testing.T) {
		h, svc, key := setup(t, stubAuthority{err: errAuthDown})
		runAndExpect(t, h, svc, key, authority.ReasonUnknown, false)
	})
	t.Run("an access rule no longer lets the saver write the path", func(t *testing.T) {
		h, svc, key := setup(t, stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}})
		if err := svc.store.CreateAccessRule(ctx, AccessRule{ID: "r1", TenantID: "t1", Path: key.Path, SubjectType: subjectUser,
			SubjectID: "u-t1", Capabilities: []string{capWrite}, Effect: effectDeny, CreatedBy: "sec"}); err != nil {
			t.Fatal(err)
		}
		runAndExpect(t, h, svc, key, reasonRuleDenied, true)
	})
	t.Run("the secret was deleted", func(t *testing.T) {
		h, svc, key := setup(t, stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}})
		if err := svc.DeleteSecret(ctx, "t1", key.ID, "u-t1"); err != nil {
			t.Fatal(err)
		}
		runAndExpect(t, h, svc, key, authority.ReasonRevoked, true)
	})
}

var errAuthDown = &authDown{}

type authDown struct{}

func (*authDown) Error() string { return "auth unreachable" }

func runAndExpect(t *testing.T, h *Handler, svc *Service, key Secret, reason string, paused bool) {
	t.Helper()
	ctx := context.Background()
	rec := h.audit.(*routetest.Recorder)
	h.rotateDue(ctx, time.Now().UTC())
	s, _ := svc.store.GetRotationSchedule(ctx, "t1", key.ID)
	if s.LastResult != "refused" || (s.PausedReason != "") != paused {
		t.Fatalf("schedule after refusal: %+v", s)
	}
	if cur, err := svc.store.GetSecret(ctx, "t1", key.ID); err == nil && cur.CurrentVersion != 1 {
		t.Fatalf("refused run rotated: v%d", cur.CurrentVersion)
	}
	ev := rec.Last(t)
	if ev.Action != "rotation_schedule_run" || ev.Event.Result != "refused" || ev.Event.Details["reason"] != reason {
		t.Fatalf("refusal audited as %+v", ev)
	}
}

// The list shows only schedules on secrets the caller may read.
func TestRotationScheduleListFollowsReadRules(t *testing.T) {
	h, svc, _, _ := newRecordedHandler(t)
	h.authority = stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}}
	key := generatedSSHKey(t, h)
	if rr := scheduleCall(t, h, tenantAdmin("t1"), http.MethodPut, "/secrets/rotation-schedules/"+key.ID, `{"interval_hours":24}`); rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body)
	}
	if err := svc.store.CreateAccessRule(context.Background(), AccessRule{ID: "r1", TenantID: "t1", Path: key.Path, SubjectType: subjectUser,
		SubjectID: "u-reader", Capabilities: []string{capRead}, Effect: effectDeny, CreatedBy: "sec"}); err != nil {
		t.Fatal(err)
	}
	list := func(claims *pkgauth.Claims) int {
		rr := scheduleCall(t, h, claims, http.MethodGet, "/secrets/rotation-schedules", ``)
		var out struct {
			Items []SecretRotationSchedule `json:"items"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("list: %d %s", rr.Code, rr.Body)
		}
		return len(out.Items)
	}
	reader := &pkgauth.Claims{UserID: "u-reader", TenantID: "t1", Role: "auditor", Permissions: []string{permRead}}
	if n := list(tenantAdmin("t1")); n != 1 {
		t.Fatalf("admin sees %d", n)
	}
	if n := list(reader); n != 0 {
		t.Fatalf("a caller denied read sees %d schedules", n)
	}
}
