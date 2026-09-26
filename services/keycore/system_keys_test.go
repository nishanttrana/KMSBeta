package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/route/routetest"
)

type subjectRecorder struct {
	mu       sync.Mutex
	subjects []string
}

func (r *subjectRecorder) Publish(_ context.Context, subject string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subjects = append(r.subjects, subject)
	return nil
}

func (r *subjectRecorder) count(subject string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

func newSystemKeyTestService(t *testing.T) (*Service, *SQLStore, *subjectRecorder) {
	t.Helper()
	store := newStoreForTest(t)
	rec := &subjectRecorder{}
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), rec, metering.NewMeter(0, time.Hour),
		[]byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	return svc, store, rec
}

func TestEnsureSystemKeyIsIdempotentAndServiceBound(t *testing.T) {
	svc, _, rec := newSystemKeyTestService(t)
	first, err := svc.EnsureSystemKey(serviceCtx("kms-secrets"), "secrets-mek")
	if err != nil || !first.Created || first.KeyID == "" || first.TenantID != "root" || first.Version != 1 {
		t.Fatalf("first ensure: %+v %v", first, err)
	}
	again, err := svc.EnsureSystemKey(serviceCtx("kms-secrets"), "secrets-mek")
	if err != nil || again.Created || again.KeyID != first.KeyID {
		t.Fatalf("second ensure is not idempotent: %+v %v", again, err)
	}
	other, err := svc.EnsureSystemKey(serviceCtx("kms-cloud"), "secrets-mek")
	if err != nil || other.KeyID == first.KeyID {
		t.Fatalf("services share a system key: %+v %v", other, err)
	}
	if rec.count("audit.key.system_key_created") != 2 {
		t.Fatalf("system_key_created events: %v", rec.subjects)
	}
	if _, err := svc.EnsureSystemKey(context.Background(), "secrets-mek"); !errors.Is(err, errServiceIdentityRequired) {
		t.Fatalf("non-service caller: %v", err)
	}
}

// Every path that would leave a platform service unable to derive its
// master key is refused and audited; rotation stays allowed.
func TestSystemKeyIsProtectedFromDestruction(t *testing.T) {
	svc, store, rec := newSystemKeyTestService(t)
	sk, err := svc.EnsureSystemKey(serviceCtx("kms-secrets"), "secrets-mek")
	if err != nil {
		t.Fatal(err)
	}
	ctx, tenant, id := context.Background(), sk.TenantID, sk.KeyID
	refusals := map[string]error{
		"disable":          svc.SetKeyStatus(ctx, tenant, id, "disabled"),
		"compromised":      svc.SetKeyStatus(ctx, tenant, id, "compromised"),
		"allow export":     svc.SetExportAllowed(ctx, tenant, id, true),
		"delete version":   store.DeleteVersion(ctx, tenant, id, 1),
		"hard delete":      store.HardDeleteKey(ctx, tenant, id),
		"schedule destroy": store.ScheduleDestroy(ctx, tenant, id, time.Now()),
	}
	_, markErr := store.MarkKeyDestroyed(ctx, tenant, id, time.Now())
	refusals["destroy now"] = markErr
	if _, err := svc.ScheduleKeyDestroy(ctx, tenant, id, 7, "cleanup", "u1", "u1@example.test", "10.0.0.1"); err != nil {
		refusals["schedule destroy (service)"] = err
	} else {
		t.Error("schedule destroy (service): allowed")
	}
	for op, err := range refusals {
		if !errors.Is(err, errSystemKeyProtected) {
			t.Errorf("%s: %v, want errSystemKeyProtected", op, err)
		}
	}
	if n := rec.count("audit.key.system_key_change_refused"); n < len(refusals) {
		t.Errorf("%d refusal events for %d refusals", n, len(refusals))
	}
	// The purge sweep skips a system key that somehow reached destroy-pending.
	if _, err := store.db.SQL().Exec(`UPDATE keys SET status='destroy-pending', destroy_date=CURRENT_TIMESTAMP WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PurgeDueDestroyed(ctx, tenant, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("purge sweep aborted: %v", err)
	}
	if _, err := store.db.SQL().Exec(`UPDATE keys SET status='active', destroy_date=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetVersion(ctx, tenant, id, 1); err != nil {
		t.Fatalf("version 1 gone after refusals: %v", err)
	}
	// Rotation and deactivation keep derivation working, so they're allowed.
	if _, err := svc.RotateKey(adminCtx(), tenant, id, "scheduled", ""); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := svc.SetKeyStatus(ctx, tenant, id, "deactivated"); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := svc.ServiceDerive(serviceCtx("kms-secrets"), id, ServiceDeriveRequest{TenantID: tenant, Purpose: "secrets-mek", Version: 1}); err != nil {
		t.Fatalf("derive after rotation: %v", err)
	}
}

func TestSystemKeyRouteIsServiceOnlyAndAudited(t *testing.T) {
	svc, _, _ := newSystemKeyTestService(t)
	h := NewHandler(svc)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	call := func(c *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/system-keys/ensure", strings.NewReader(`{"purpose":"secrets-mek"}`))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	admin := &pkgauth.Claims{UserID: "admin", TenantID: "root", Role: "admin", Permissions: []string{"*"}}
	if w := call(admin); w.Code != http.StatusForbidden {
		t.Fatalf("admin ensured a system key: %d %s", w.Code, w.Body)
	}
	if e := rec.Last(t); e.Action != "system_key_ensure" || e.Event.Result != "refused" || e.Event.Details["reason"] != "service_identity_required" {
		t.Fatalf("refusal event %+v", e)
	}
	secrets := &pkgauth.Claims{ClientID: "kms-secrets", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	secrets.Subject = "kms-secrets" // service JWTs carry sub = client id
	w := call(secrets)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"created":true`) {
		t.Fatalf("service ensure: %d %s", w.Code, w.Body)
	}
	if e := rec.Last(t); e.Event.Result != "success" || e.Event.ActorType != "service" || e.Event.TargetID == "" {
		t.Fatalf("success event %+v", e)
	}
}
