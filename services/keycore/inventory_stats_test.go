package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// Every count on Key inventory equals the number of keys its drill-down
// lists, and deleted keys count nowhere.
func TestKeyStatsCountTheKeysTheyList(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	ctx := context.Background()
	db := svc.store.(*SQLStore).db.SQL()
	now := time.Now().UTC()
	for i, k := range []struct {
		alg, status string
		age         time.Duration
	}{
		{"AES-256", "active", time.Hour},
		{"AES-256", "active", 3 * time.Hour},
		{"AES-256", "disabled", 40 * 24 * time.Hour},
		{"RSA-3072", "active", 2 * time.Hour},
		{"RSA-3072", "deleted", time.Hour}, // counted nowhere
	} {
		key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k" + string(rune('a'+i)), Algorithm: k.alg,
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "owner-1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE keys SET status=$1, created_at=$2 WHERE tenant_id='t1' AND id=$3`, k.status, now.Add(-k.age), key.ID); err != nil {
			t.Fatal(err)
		}
	}

	get := func(path string, q url.Values, out any) {
		t.Helper()
		w := callStats(h, path, q, visAuditor)
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), out) != nil {
			t.Fatalf("%s %v: %d %s", path, q, w.Code, w.Body)
		}
	}
	count := func(q url.Values) int {
		t.Helper()
		var body struct {
			Items   []map[string]any `json:"items"`
			HasMore bool             `json:"has_more"`
		}
		get("/inventory/stats/keys", q, &body)
		if body.HasMore {
			t.Fatalf("%v: more than one page", q)
		}
		return len(body.Items)
	}
	for _, from := range []time.Time{now.Add(-24 * time.Hour), now.Add(-365 * 24 * time.Hour), {}} {
		q := url.Values{}
		if !from.IsZero() {
			q.Set("from", from.Format(time.RFC3339))
		}
		var body struct {
			Stats KeyStats `json:"stats"`
		}
		get("/inventory/stats", q, &body)
		st := body.Stats
		if st.Total != 4 || count(url.Values{}) != 4 {
			t.Fatalf("total %d", st.Total)
		}
		for _, s := range st.ByState {
			if got := count(url.Values{"state": {s.Key}}); got != s.Count {
				t.Fatalf("state %s: chart %d, list %d", s.Key, s.Count, got)
			}
		}
		for _, a := range st.ByAlgorithm {
			if got := count(url.Values{"algorithm": {a.Key}}); got != a.Count {
				t.Fatalf("algorithm %s: chart %d, list %d", a.Key, a.Count, got)
			}
		}
		win := url.Values{"from": {st.From.Format(time.RFC3339Nano)}, "to": {st.To.Format(time.RFC3339Nano)}}
		if got := count(win); got != st.Created {
			t.Fatalf("created: chart %d, list %d", st.Created, got)
		}
		sum := 0
		for _, p := range st.Series {
			sum += p.Count
			end := p.Start.Add(time.Duration(st.BucketSeconds) * time.Second).Add(-time.Microsecond)
			b := url.Values{"from": {maxT(p.Start, st.From).Format(time.RFC3339Nano)}, "to": {minT(end, st.To).Format(time.RFC3339Nano)}}
			if got := count(b); got != p.Count {
				t.Fatalf("bucket %v: chart %d, list %d", p.Start, p.Count, got)
			}
		}
		if sum != st.Created {
			t.Fatalf("series %d, created %d", sum, st.Created)
		}
	}
	var day struct {
		Stats KeyStats `json:"stats"`
	}
	get("/inventory/stats", url.Values{"from": {now.Add(-24 * time.Hour).Format(time.RFC3339)}}, &day)
	if day.Stats.Created != 3 || day.Stats.ByState[0] != (KeyStatCount{"active", 3}) || day.Stats.ByAlgorithm[0] != (KeyStatCount{"AES-256", 3}) {
		t.Fatalf("day %+v", day.Stats)
	}
}

func TestKeyStatsNeedInventoryPermissionAndAValidWindow(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	router := h.inventoryRouter(rec)
	for path, action := range map[string]string{"/inventory/stats": "inventory_stats_read", "/inventory/stats/keys": "inventory_stats_keys_read"} {
		if w := callStats(router, path, nil, visAlice); w.Code != http.StatusForbidden {
			t.Fatalf("%s without key.inventory.read: %d", path, w.Code)
		}
		if w := callStats(router, path, url.Values{"from": {"yesterday"}}, visAuditor); w.Code != http.StatusBadRequest {
			t.Fatalf("%s bad window: %d", path, w.Code)
		}
		if ev := rec.Last(t); ev.Action != action || ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
			t.Fatalf("%s refusal audited as %+v", path, ev)
		}
		if w := callStats(router, path, nil, visAuditor); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Action != action || ev.Event.Result != "success" {
			t.Fatalf("%s read audited as %+v", path, ev)
		}
	}
}

func callStats(h http.Handler, path string, q url.Values, claims *pkgauth.Claims) *httptest.ResponseRecorder {
	if q == nil {
		q = url.Values{}
	}
	q.Set("tenant_id", "t1")
	req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func maxT(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minT(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
