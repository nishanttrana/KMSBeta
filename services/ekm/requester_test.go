package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

// Who asks for a TDE key operation is the verified caller. The requester is
// what a key-access decision records and what an approval is asked in the
// name of; until 13.0.0-beta it was whatever requester_id the body carried.
func TestTDEKeyRequesterIsTheVerifiedCaller(t *testing.T) {
	h, svc, _, _ := newEKMHandler(t)
	keyID, dbID := newEKMKeyForGate(t, svc)

	var asked []map[string]any
	keyAccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		asked = append(asked, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"action":"allow","decision_id":"kad_1"}}`))
	}))
	defer keyAccess.Close()
	svc.SetKeyAccess(pkgkeyaccess.Deployed(pkgkeyaccess.NewHTTPClient(keyAccess.URL, 5*time.Second)))

	plain := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/ekm/tde/keys/" + keyID + "/wrap", map[string]any{"plaintext": plain, "database_id": dbID}},
		{"/ekm/tde/keys/" + keyID + "/rotate", map[string]any{}},
	} {
		tc.body["tenant_id"], tc.body["requester_id"], tc.body["requester_email"] = "tenant-ka", "somebody-else", "else@example.com"
		raw, _ := json.Marshal(tc.body)
		req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer jwt:tenant-ka:admin")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code >= 300 {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body)
		}
		if len(asked) == 0 {
			t.Fatalf("%s: no key-access decision was asked for", tc.path)
		}
		last := asked[len(asked)-1]
		if last["requester_id"] != "u-admin" || (last["requester_email"] != nil && last["requester_email"] != "") {
			t.Fatalf("%s: the decision was asked for %v / %v, want the caller u-admin and no stated email", tc.path, last["requester_id"], last["requester_email"])
		}
	}
}
