package config

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"vecta-kms/pkg/clientip"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterstate"
)

// audited collects member-side audit events as "action reason actor".
var audited []string

type seenRequest struct {
	method, path, auth, node, cred, claims, body, client string
}

func newTestForwarder(t *testing.T, service string, st clusterstate.State) (*clusterForwarder, *[]string) {
	t.Helper()
	local := []string{}
	f := &clusterForwarder{
		service: service,
		state:   func(*http.Request) clusterstate.State { return st },
		parser: func(raw string) (*pkgauth.Claims, error) {
			if raw == "good" {
				return &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "alice"}, nil
			}
			return nil, errors.New("bad token")
		},
		client: func(s clusterstate.State) *http.Client {
			return clusterstate.PinnedHTTPClient(s.PrimaryFingerprint, 5*time.Second)
		},
		emit: func(_ context.Context, action string, evt pkgaudit.Event) {
			audited = append(audited, strings.Join(strings.Fields(action+" "+evt.ErrorMessage+" "+evt.ActorID), " "))
		},
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			local = append(local, r.Method+" "+r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}),
	}
	return f, &local
}

func TestClusterForwarding(t *testing.T) {
	audited = nil
	var seen []seenRequest
	primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, seenRequest{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get(HeaderClusterNode), r.Header.Get(HeaderClusterCredential), r.Header.Get(HeaderForwardClaims), string(b), r.Header.Get(HeaderClusterClientIP)})
		w.Header().Set("X-From", "primary")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer primary.Close()
	sum := sha256.Sum256(primary.Certificate().Raw)
	member := clusterstate.State{NodeID: "node-2", Role: "follower", PrimaryNodeID: "node-1", PrimaryURL: primary.URL, PrimaryFingerprint: hex.EncodeToString(sum[:]), ForwardCredential: "cred-123"}

	f, local := newTestForwarder(t, "kms-keycore", member)
	call := func(method, path, bearer, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		req.Header.Set(HeaderClusterCredential, "spoofed") // a client must not inject cluster headers
		req.Header.Set(HeaderClusterClientIP, "203.0.113.9")
		req.Header.Set(clientip.Header, "203.0.113.9, 198.51.100.7") // what the caller wrote, then what this member's edge saw
		rr := httptest.NewRecorder()
		f.ServeHTTP(rr, req)
		return rr
	}

	// Reads and crypto operations run on the member.
	call("GET", "/keys", "good", "")
	call("POST", "/keys/k1/encrypt", "good", `{"plaintext":"x"}`)
	if len(*local) != 2 || len(seen) != 0 {
		t.Fatalf("reads and crypto must run locally: local=%v forwarded=%d", *local, len(seen))
	}

	// A lifecycle write goes to the primary with the member's identity.
	rr := call("POST", "/keys?tenant_id=t1", "good", `{"name":"k"}`)
	if rr.Code != http.StatusCreated || rr.Header().Get(HeaderForwardedTo) != "node-1" || rr.Header().Get("X-From") != "primary" {
		t.Fatalf("forwarded response must come back unchanged: %d %v", rr.Code, rr.Header())
	}
	got := seen[0]
	if got.path != "/cluster/forward/kms-keycore/keys?tenant_id=t1" || got.body != `{"name":"k"}` || got.method != "POST" {
		t.Fatalf("forwarded request: %+v", got)
	}
	if got.auth != "" || got.node != "node-2" || got.cred != "cred-123" {
		t.Fatalf("the user token must not travel; the member credential must replace any client header: %+v", got)
	}
	if got.client != "198.51.100.7" {
		t.Fatalf("the primary must be told the address this member's edge saw, not one the caller wrote: %q", got.client)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(got.claims)
	var claims pkgauth.Claims
	_ = json.Unmarshal(raw, &claims)
	if claims.UserID != "alice" || claims.TenantID != "t1" {
		t.Fatalf("the verified identity must travel as claims: %+v", claims)
	}

	// An invalid token is refused on the member; nothing reaches the primary.
	if rr := call("DELETE", "/keys/k1", "forged", ""); rr.Code != http.StatusUnauthorized || len(seen) != 1 {
		t.Fatalf("an invalid token must be refused before forwarding: %d", rr.Code)
	}

	// A wrong pin fails closed.
	badPin := member
	badPin.PrimaryFingerprint = strings.Repeat("00", 32)
	fb, _ := newTestForwarder(t, "kms-keycore", badPin)
	rr = httptest.NewRecorder()
	fb.ServeHTTP(rr, httptest.NewRequest("POST", "/keys", strings.NewReader("{}")))
	if rr.Code != http.StatusBadGateway || len(seen) != 1 {
		t.Fatalf("a primary with the wrong certificate must not receive the write: %d", rr.Code)
	}

	// A service that cannot be forwarded refuses writes instead of diverging.
	fu, localU := newTestForwarder(t, "kms-unknown", member)
	rr = httptest.NewRecorder()
	fu.ServeHTTP(rr, httptest.NewRequest("POST", "/things", strings.NewReader("{}")))
	if rr.Code != http.StatusConflict || len(*localU) != 0 {
		t.Fatalf("an unforwardable write must be refused: %d", rr.Code)
	}

	// Every forward and every refusal is audited on the member.
	want := []string{
		"cluster_write_forwarded alice",
		"cluster_write_refused invalid_token",
		"cluster_write_refused primary_unreachable",
		"cluster_write_refused primary_write_required",
	}
	if strings.Join(audited, "|") != strings.Join(want, "|") {
		t.Fatalf("member audit events:\n got %q\nwant %q", audited, want)
	}

	// Standalone nodes are untouched.
	fs, localS := newTestForwarder(t, "kms-keycore", clusterstate.State{})
	fs.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/keys", strings.NewReader("{}")))
	if len(*localS) != 1 {
		t.Fatal("a standalone node must handle writes itself")
	}
}

// A fenced former primary and a primary past its lease refuse lifecycle
// writes (audited) and still serve crypto and reads; a primary within its
// lease writes.
func TestFencedOrLeaselessPrimaryRefusesWrites(t *testing.T) {
	for _, c := range []struct {
		st     clusterstate.State
		reason string
	}{
		{clusterstate.State{NodeID: "node-1", Role: clusterstate.RoleFenced, Epoch: 2}, "node_fenced"},
		{clusterstate.State{NodeID: "node-1", Role: clusterstate.RolePrimary, WritableUntil: time.Now().Add(-time.Second)}, "primary_lease_lost"},
		{clusterstate.State{NodeID: "node-1", Role: clusterstate.RolePrimary, WritableUntil: time.Now().Add(time.Minute)}, ""},
	} {
		audited = nil
		f, local := newTestForwarder(t, "kms-keycore", c.st)
		do := func(method, path string) int {
			rr := httptest.NewRecorder()
			f.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader("{}")))
			return rr.Code
		}
		write := do(http.MethodPost, "/keys")
		crypto := do(http.MethodPost, "/keys/k1/encrypt")
		read := do(http.MethodGet, "/keys")
		if c.reason == "" {
			if write != 200 || len(*local) != 3 {
				t.Fatalf("leased primary: write %d, local %v", write, *local)
			}
			continue
		}
		if write != http.StatusServiceUnavailable || crypto != 200 || read != 200 || len(*local) != 2 {
			t.Fatalf("%s: write %d crypto %d read %d local %v", c.reason, write, crypto, read, *local)
		}
		if len(audited) != 1 || audited[0] != "cluster_write_refused "+c.reason {
			t.Fatalf("%s: audit %v", c.reason, audited)
		}
	}
}
