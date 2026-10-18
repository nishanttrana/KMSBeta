package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func seedCert(t *testing.T, store *SQLStore, tenant, id, caID, status string, notAfter time.Time, created time.Time) {
	t.Helper()
	err := store.CreateCertificate(context.Background(), Certificate{
		ID: id, TenantID: tenant, CAID: caID, SerialNumber: id, SubjectCN: id,
		CertType: "tls-server", Algorithm: "ECDSA-P256", Protocol: "rest", CertClass: "classical",
		CertPEM: "pem", Status: status, NotBefore: created, NotAfter: notAfter,
		CreatedAt: created, UpdatedAt: created,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The summary counts every certificate, past the store's 500-row page, and
// "expiring" leaves out revoked, expired and (by policy) external ones.
func TestCertSummaryCountsWholeSetWithSweepRule(t *testing.T) {
	svc, store := newCertsService(t)
	now := time.Now().UTC()
	// 520 active certificates expiring in 60 days: more than one page.
	for i := 0; i < 520; i++ {
		seedCert(t, store, "t1", fmt.Sprintf("far-%03d", i), "ca1", CertStatusActive, now.Add(60*24*time.Hour), now.Add(-time.Duration(i)*time.Minute))
	}
	seedCert(t, store, "t1", "soon", "ca1", CertStatusActive, now.Add(3*24*time.Hour), now)
	seedCert(t, store, "t1", "month", "ca1", CertStatusActive, now.Add(20*24*time.Hour), now)
	seedCert(t, store, "t1", "ext", "external-ca", CertStatusActive, now.Add(10*24*time.Hour), now)
	seedCert(t, store, "t1", "revoked", "ca1", CertStatusRevoked, now.Add(5*24*time.Hour), now)
	seedCert(t, store, "t1", "lapsed", "ca1", CertStatusActive, now.Add(-time.Hour), now.Add(-48*time.Hour))
	seedCert(t, store, "t2", "other", "ca1", CertStatusActive, now.Add(time.Hour), now)

	sum, err := svc.CertSummary(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 525 || sum.Active != 523 || sum.Revoked != 1 || sum.Expired != 1 {
		t.Fatalf("counts over the whole set: %+v", sum)
	}
	// Default policy: 30 days, external included.
	if sum.Expiring != 3 || sum.ExpiringWeek != 1 || sum.AlertDays != defaultCertExpiryAlertDays {
		t.Fatalf("expiring with external included: %+v", sum)
	}
	if _, err := svc.UpsertCertExpiryAlertPolicy(context.Background(), UpsertCertExpiryAlertPolicyRequest{TenantID: "t1", DaysBefore: 30, IncludeExternal: false, UpdatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	sum, _ = svc.CertSummary(context.Background(), "t1")
	if sum.Expiring != 2 || sum.IncludeExternal {
		t.Fatalf("expiring with external excluded: %+v", sum)
	}
}

// allCertificates reaches past the first page; a single call does not.
func TestAllCertificatesPagesPastTheStoreCap(t *testing.T) {
	svc, store := newCertsService(t)
	now := time.Now().UTC()
	for i := 0; i < 610; i++ {
		seedCert(t, store, "t1", fmt.Sprintf("c-%03d", i), "ca1", CertStatusActive, now.Add(time.Hour), now.Add(-time.Duration(i)*time.Minute))
	}
	all, err := svc.allCertificates(context.Background(), "t1", CertStatusActive, "")
	if err != nil || len(all) != 610 {
		t.Fatalf("allCertificates: %d %v", len(all), err)
	}
}

// No caller asks the store for more rows than one call returns: such a
// request used to come back with 100 rows and no error.
func TestNoCertificateListPastTheStoreCap(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	call := regexp.MustCompile(`ListCertificates\([^)]*,\s*(\d+)\s*,\s*[^)]*\)`)
	for _, f := range files {
		if regexp.MustCompile(`_test\.go$`).MatchString(f) {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllSubmatch(src, -1) {
			if n, _ := strconv.Atoi(string(m[1])); n > certPageSize {
				t.Errorf("%s: %s asks for %d rows; use allCertificates", f, m[0], n)
			}
		}
	}
}

func summaryRouter(svc *Service, rec *routetest.Recorder) *route.Router {
	k := route.New("cert", rec, log.New(io.Discard, "", 0))
	NewHandler(svc).RegisterSummaryRoutes(k)
	return k
}

func TestCertSummaryRouteRefusalsAudited(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, summaryRouter(svc, rec), rec)
}

// Reading the summary is audited as audit.certs.summary_read with its counts.
func TestCertSummaryRouteAudited(t *testing.T) {
	svc, store := newCertsService(t)
	now := time.Now().UTC()
	seedCert(t, store, "t1", "soon", "ca1", CertStatusActive, now.Add(2*24*time.Hour), now)
	rec := &routetest.Recorder{}
	router := summaryRouter(svc, rec)
	req := httptest.NewRequest(http.MethodGet, "/certs/summary?tenant_id=t1", http.NoBody)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "viewer"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var out struct {
		Summary CertSummary `json:"summary"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || out.Summary.Total != 1 || out.Summary.Expiring != 1 {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	last := rec.Last(t)
	if last.Action != "summary_read" || last.Event.Result != "success" || fmt.Sprint(last.Event.Details["expiring"]) != "1" {
		t.Fatalf("summary read must be audited with its counts: %+v", last)
	}
}
