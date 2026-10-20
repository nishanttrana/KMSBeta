package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// AllCertificates pages through GET /certs at its 500-row maximum: one
// request for more came back with 100 rows and no error (13.24.0-beta).
func TestAllCertificatesPagesPastTheEndpointCap(t *testing.T) {
	const total = 620
	var offsets []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit > 500 {
			t.Errorf("asked for %d rows; GET /certs answers at most 500", limit)
		}
		offsets = append(offsets, offset)
		items := []map[string]string{}
		for i := offset; i < total && i < offset+limit; i++ {
			items = append(items, map[string]string{"id": "c" + strconv.Itoa(i)})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	}))
	defer srv.Close()
	got, err := NewHTTPCertsClient(srv.URL, 5*time.Second).AllCertificates(context.Background(), "t1")
	if err != nil || len(got) != total {
		t.Fatalf("got %d certificates, err %v; want %d", len(got), err, total)
	}
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 500 {
		t.Fatalf("offsets %v, want [0 500]", offsets)
	}
}
