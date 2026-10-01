package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

const (
	testCommit = "0123456789abcdef0123456789abcdef01234567"
	testAKIA   = "AKIAABCDEFGHIJKLMNOP"
	testHex    = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

// repoArchive is a tar.gz as `git archive` (and every hosting API) writes
// it: a pax header naming the commit, then the tree under one folder.
func repoArchive(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	files := []struct{ name, body string }{
		{"deploy/id_rsa", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))},
		{"certs/server.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t, time.Now().Add(90*24*time.Hour))}))},
		{"config/.env.production", "REGION=eu\nAWS_ACCESS_KEY_ID=" + testAKIA + "\nAPI_TOKEN=" + testHex + "\n"},
		// Not this project's keys: dependencies, lock files and a digest
		// that no name calls a secret.
		{"node_modules/dep/key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))},
		{"yarn.lock", "checksum " + testHex + "\n"},
		{"build/manifest.json", `{"sha256": "` + testHex + `"}`},
		{"README.md", "API_TOKEN=" + testHex},
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": testCommit}}); err != nil {
		t.Fatal(err)
	}
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "app-0123456/", Mode: 0o755})
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "app-0123456/" + f.name, Mode: 0o644, Size: int64(len(f.body))})
		_, _ = tw.Write([]byte(f.body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// hostingServer stands in for a hosting service's HTTPS API. It records each
// request's escaped path and Authorization header.
type hostingServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newHostingServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *hostingServer {
	h := &hostingServer{}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.seen = append(h.seen, r.URL.RequestURI()+" | "+r.Header.Get("Authorization"))
		h.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hostingServer) requests() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.seen...)
}

func (h *hostingServer) hostport() string { return strings.TrimPrefix(h.URL, "https://") }

type stubConnections map[string]ResolvedConnection

func (s stubConnections) Resolve(_ context.Context, _, id string) (ResolvedConnection, error) {
	c, ok := s[id]
	if !ok {
		return ResolvedConnection{}, errors.New("compliance HTTP 404 not_found: connection not found")
	}
	return c, nil
}

func trust(t *testing.T, svc *Service, servers ...*hostingServer) {
	t.Helper()
	svc.repoRoots = x509.NewCertPool()
	for _, s := range servers {
		svc.repoRoots.AddCert(s.Certificate())
	}
}

func TestNormalizeRepository(t *testing.T) {
	for in, want := range map[string]Repository{
		"https://github.com/Acme/App.git":                      {URL: "https://github.com/Acme/App", Provider: "github"},
		" https://GitLab.com/group/sub/project/ ":              {URL: "https://gitlab.com/group/sub/project", Provider: "gitlab"},
		"https://bitbucket.org/team/repo":                      {URL: "https://bitbucket.org/team/repo", Provider: "bitbucket"},
		"https://codeberg.org/forgejo/docs":                    {URL: "https://codeberg.org/forgejo/docs", Provider: "gitea"},
		"https://git.example.com:8443/platform/kms":            {URL: "https://git.example.com:8443/platform/kms", Provider: "gitlab"},
		"https://10.4.0.12/ops/secrets-in-here":                {URL: "https://10.4.0.12/ops/secrets-in-here", Provider: "gitlab"},
		"https://github.example.com/acme/app#ignored-provider": {},
	} {
		got, err := normalizeRepository(in, "", "gitlab")
		if want.URL == "" {
			if !errors.Is(err, errInvalidRepo) {
				t.Errorf("%q accepted: %+v %v", in, got, err)
			}
			continue
		}
		if err != nil || got.URL != want.URL || got.Provider != want.Provider {
			t.Errorf("normalizeRepository(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "github.com/acme/app", "http://github.com/acme/app", "git@github.com:acme/app.git", "ssh://git@github.com/acme/app",
		"https://alice:ghp_token@github.com/acme/app", "https://ghp_token@github.com/acme/app", "https://github.com/acme/app?ref=main",
		"https://github.com/acme", "https://github.com/acme/app/tree/main", "https://github.com/acme/../app", "https://github.com/acme/ap p",
		"https://127.0.0.1/acme/app", "https://localhost/acme/app", "https://169.254.169.254/acme/app", "https://[::1]/acme/app",
	} {
		if r, err := normalizeRepository(in, "", "github"); !errors.Is(err, errInvalidRepo) {
			t.Errorf("%q accepted: %+v %v", in, r, err)
		}
	}
	// A credential in the URL is refused without repeating it.
	if _, err := normalizeRepository("https://alice:ghp_token@github.com/acme/app", "", ""); err == nil || strings.Contains(err.Error(), "ghp_token") {
		t.Errorf("credential URL: %v", err)
	}
	if _, err := normalizeRepository("https://keycore/acme/app", "", "gitlab"); !errors.Is(err, errPlatformTarget) {
		t.Errorf("platform host: %v", err)
	}
	if _, err := normalizeRepository("https://git.example.com/acme/app", "", ""); !errors.Is(err, errInvalidRepo) {
		t.Errorf("unknown host without a provider: %v", err)
	}
	for ref, ok := range map[string]bool{"main": true, "release/2.4": true, "v1.0.0": true, testCommit: true, "a..b": false, "-x": false, "feature branch": false, "x;rm": false} {
		if _, err := normalizeRepository("https://github.com/acme/app", ref, ""); (err == nil) != ok {
			t.Errorf("ref %q: %v", ref, err)
		}
	}
}

// Each hosting API is asked for its archive at its own URL, with its own
// authorization scheme, and the files are inventoried from the stream.
func TestGitScanReadsEachHostingAPI(t *testing.T) {
	archive := repoArchive(t)
	cases := []struct {
		provider, path, ref, username string
		want                          []string // request-uri | Authorization
	}{
		{"github", "acme/app", "main", "", []string{"/api/v3/repos/acme/app/tarball/main | Bearer s3cret-token"}},
		{"github", "acme/app", "", "", []string{"/api/v3/repos/acme/app/tarball | Bearer s3cret-token"}},
		{"gitlab", "acme/platform/app", "release/2.4", "", []string{"/api/v4/projects/acme%2Fplatform%2Fapp/repository/archive.tar.gz?sha=release%2F2.4 | Bearer s3cret-token"}},
		{"bitbucket", "acme/app", "", "alice", []string{"/acme/app/get/HEAD.tar.gz | Basic YWxpY2U6czNjcmV0LXRva2Vu"}},
		{"gitea", "acme/app", "", "", []string{"/api/v1/repos/acme/app | token s3cret-token", "/api/v1/repos/acme/app/archive/trunk.tar.gz | token s3cret-token"}},
	}
	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.ref, func(t *testing.T) {
			svc, _, _ := newDiscoveryService(t)
			srv := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/repos/acme/app" {
					_, _ = w.Write([]byte(`{"default_branch":"trunk"}`))
					return
				}
				_, _ = w.Write(archive)
			})
			trust(t, svc, srv)
			host, _, _ := strings.Cut(srv.hostport(), ":")
			svc.conns = stubConnections{"conn1": {Type: "git", Endpoint: host, Fields: map[string]string{"token": "s3cret-token", "username": tc.username}}}
			repo := Repository{ID: "repo_1", TenantID: "t1", URL: "https://" + srv.hostport() + "/" + tc.path, Ref: tc.ref, Provider: tc.provider, ConnectionID: "conn1"}
			if err := svc.store.CreateRepository(context.Background(), repo); err != nil {
				t.Fatal(err)
			}
			assets, stats, err := svc.scanGit(context.Background(), "t1", "scan_1")
			if err != nil {
				t.Fatal(err)
			}
			if got := srv.requests(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("requests\n got %q\nwant %q", got, tc.want)
			}
			var got []string
			for _, a := range assets {
				got = append(got, a.AssetType+"|"+a.Algorithm+"|"+a.Classification+"|"+strings.TrimPrefix(a.Location, repo.label()+"/"))
				if a.Source != "git" || a.Metadata["commit"] != testCommit || a.Metadata["repository"] != repo.URL {
					t.Fatalf("asset %+v", a)
				}
			}
			sort.Strings(got)
			want := []string{
				"certificate|ECDSA-P256|quantum_vulnerable|certs/server.crt:1",
				"cloud_access_key||exposed|config/.env.production:2",
				"hex_secret||exposed|config/.env.production:3",
				"private_key_material|RSA-2048|exposed|deploy/id_rsa:1",
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("assets\n got %q\nwant %q", got, want)
			}
			// id_rsa, server.crt, .env.production and manifest.json are
			// parsed; the dependency, the lock file and the README are not.
			if stats["git_files"] != 4 || stats["git_repositories"] != 1 {
				t.Fatalf("stats %+v", stats)
			}
			raw, _ := json.Marshal(assets)
			if s := string(raw); strings.Contains(s, testAKIA) || strings.Contains(s, testHex) || strings.Contains(s, "s3cret-token") || strings.Contains(s, "BEGIN") {
				t.Fatalf("a secret reached the assets: %s", s)
			}
		})
	}
}

// A token goes only to the host its connection names, and never follows a
// redirect to another host.
func TestGitTokenStaysOnItsHost(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	archive := repoArchive(t)
	download := newHostingServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	api := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, download.URL+"/codeload/acme/app", http.StatusFound)
	})
	trust(t, svc, api, download)
	host, _, _ := strings.Cut(api.hostport(), ":")
	repo := Repository{ID: "r1", TenantID: "t1", URL: "https://" + api.hostport() + "/acme/app", Ref: "main", Provider: "github", ConnectionID: "c1"}
	_ = svc.store.CreateRepository(ctx, repo)

	svc.conns = stubConnections{"c1": {Type: "git", Endpoint: host, Fields: map[string]string{"token": "s3cret-token"}}}
	if assets, _, err := svc.scanGit(ctx, "t1", "s"); err != nil || len(assets) != 4 {
		t.Fatalf("redirected archive: %d assets, %v", len(assets), err)
	}
	if got := download.requests(); len(got) != 1 || got[0] != "/codeload/acme/app | " {
		t.Fatalf("download host saw %q", got)
	}
	if got := api.requests(); len(got) != 1 || !strings.HasSuffix(got[0], "Bearer s3cret-token") {
		t.Fatalf("API host saw %q", got)
	}

	// A connection for another host, or of another type, is not used and
	// nothing is requested.
	for name, conn := range map[string]ResolvedConnection{
		"other host": {Type: "git", Endpoint: "github.com", Fields: map[string]string{"token": "s3cret-token"}},
		"other type": {Type: "slack", Endpoint: host, Fields: map[string]string{"webhook_url": "https://hooks.example/x"}},
	} {
		svc.conns = stubConnections{"c1": conn}
		before := len(api.requests())
		_, _, err := svc.scanGit(ctx, "t1", "s")
		if err == nil || !strings.Contains(err.Error(), errConnectionUnfit.Error()) || len(api.requests()) != before {
			t.Fatalf("%s: err %v, requests %d -> %d", name, err, before, len(api.requests()))
		}
		if strings.Contains(err.Error(), "s3cret-token") || strings.Contains(err.Error(), "hooks.example") {
			t.Fatalf("%s: credential in the error: %v", name, err)
		}
	}
	// The connection was deleted: the repository fails, by name.
	svc.conns = stubConnections{}
	if _, _, err := svc.scanGit(ctx, "t1", "s"); err == nil || !strings.Contains(err.Error(), "connection c1") {
		t.Fatalf("missing connection: %v", err)
	}
}

// A hosting API's refusal is reported in words the operator can act on,
// without its body; a public repository sends no credential.
func TestGitScanReportsRefusals(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	status := http.StatusNotFound
	srv := newHostingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"internal detail the operator should not need"}`))
	})
	trust(t, svc, srv)
	_ = svc.store.CreateRepository(ctx, Repository{ID: "r1", TenantID: "t1", URL: "https://" + srv.hostport() + "/acme/app", Provider: "gitlab"})
	for code, want := range map[int]string{http.StatusNotFound: "a private repository needs a Git connection", http.StatusUnauthorized: "access denied", http.StatusTooManyRequests: "rate limiting", http.StatusBadGateway: "HTTP 502"} {
		status = code
		assets, _, err := svc.scanGit(ctx, "t1", "s")
		if err == nil || len(assets) != 0 || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "internal detail") {
			t.Fatalf("HTTP %d: %d assets, %v", code, len(assets), err)
		}
	}
	for _, r := range srv.requests() {
		if !strings.HasSuffix(r, " | ") {
			t.Fatalf("a public repository sent a credential: %q", r)
		}
	}
	if _, _, err := svc.scanGit(ctx, "t2", "s"); !errors.Is(err, errScanNotConfigured) {
		t.Fatalf("tenant with no repositories: %v", err)
	}
}

// An archive larger than the cap stops the scan of that repository with
// what was found so far; a stream that isn't an archive is an error.
func TestGitArchiveLimits(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	repo := Repository{TenantID: "t1", URL: "https://git.example.com/acme/app", Provider: "gitlab"}
	archive := repoArchive(t)
	old := maxRepoBytes
	maxRepoBytes = 4096
	res, err := svc.scanArchive(repo, "s", bytes.NewReader(archive), 0)
	maxRepoBytes = old
	if !errors.Is(err, errRepoTooLarge) || res.files == 0 || res.files >= 4 {
		t.Fatalf("over the cap: %d files, %v", res.files, err)
	}
	if _, err := svc.scanArchive(repo, "s", strings.NewReader("<html>sign in</html>"), 0); err == nil {
		t.Fatal("an HTML page read as an archive")
	}
	if _, err := svc.scanArchive(repo, "s", bytes.NewReader(archive[:len(archive)/2]), 0); err == nil {
		t.Fatal("a truncated archive read as complete")
	}
	if res, err := svc.scanArchive(repo, "", bytes.NewReader(archive), 1); err != nil || res.files != 1 || res.commit != testCommit {
		t.Fatalf("test read: %+v %v", res, err)
	}
}

// Repository routes: each refusal is audited with its reason, a credential
// in a URL is never copied to the audit, and a test that can't read the
// repository fails.
func TestRepositoryRoutesAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	svc.conns = stubConnections{
		"gh":    {Type: "git", Endpoint: "github.com", Fields: map[string]string{"token": "s3cret-token"}},
		"slack": {Type: "slack", Endpoint: "hooks.slack.com"},
	}
	post := func(who *pkgauth.Claims, body string) *httptest.ResponseRecorder {
		return serveAs(h, who, http.MethodPost, "/discovery/repositories", body)
	}
	if rr := post(testReadonly, `{"url":"https://github.com/acme/app"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("add as discovery.read: %d", rr.Code)
	}
	expectAudit(t, rec, "repository_add", route.ResultRefused, route.ReasonPermissionDenied)

	for body, reason := range map[string]string{
		`{"url":"http://github.com/acme/app"}`:                          "invalid_repository",
		`{"url":"https://alice:ghp_token@github.com/acme/app"}`:         "invalid_repository",
		`{"url":"https://127.0.0.1/acme/app","provider":"gitlab"}`:      "invalid_repository",
		`{"url":"https://keycore/acme/app","provider":"gitlab"}`:        "platform_target",
		`{"url":"https://gitlab.com/acme/app","connection_id":"gh"}`:    "connection_unfit",
		`{"url":"https://github.com/acme/app","connection_id":"slack"}`: "connection_unfit",
	} {
		if rr := post(testWriter, body); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body)
		}
		ev := expectAudit(t, rec, "repository_add", route.ResultRefused, reason)
		if raw, _ := json.Marshal(ev); strings.Contains(string(raw), "ghp_token") || strings.Contains(string(raw), "s3cret-token") {
			t.Fatalf("credential in the audit event: %s", raw)
		}
	}
	if rr := post(testWriter, `{"url":"https://github.com/acme/app","connection_id":"gone"}`); rr.Code != http.StatusBadGateway {
		t.Fatalf("missing connection: %d %s", rr.Code, rr.Body)
	}

	rr := post(testWriter, `{"url":"https://github.com/Acme/App.git","ref":"main","connection_id":"gh"}`)
	var created struct{ Repository Repository }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if rr.Code != http.StatusCreated || created.Repository.URL != "https://github.com/Acme/App" || created.Repository.Provider != "github" || created.Repository.CreatedBy != "w" {
		t.Fatalf("add: %d %s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), "s3cret-token") {
		t.Fatal("token in the response")
	}
	expectAudit(t, rec, "repository_add", route.ResultSuccess, "")
	if rr := post(testWriter, `{"url":"https://github.com/Acme/App","ref":"main"}`); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rr.Code)
	}
	expectAudit(t, rec, "repository_add", route.ResultRefused, "repository_exists")

	if rr := serveAs(h, testReadonly, http.MethodGet, "/discovery/repositories", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), created.Repository.ID) || strings.Contains(rr.Body.String(), "s3cret-token") {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	if src, _ := svc.Sources(context.Background(), "t1"); src[3].ID != "git" || !src[3].Configured || src[3].Detail["private"] != 1 {
		t.Fatalf("git source: %+v", src[3])
	}

	// The test can't reach github.com through the test dial guard's
	// certificate pool: it fails, and says so.
	svc.repoRoots = x509.NewCertPool()
	path := "/discovery/repositories/" + created.Repository.ID
	if rr := serveAs(h, testWriter, http.MethodPost, path+"/test", ""); rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "repository_unreachable") {
		t.Fatalf("test of an unreadable repository: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Action != "repository_test" || ev.Event.Result == route.ResultSuccess {
		t.Fatalf("failed test audited as %s %s", ev.Action, ev.Event.Result)
	}
	other := &pkgauth.Claims{UserID: "o", TenantID: "t2", Permissions: []string{"discovery.write"}}
	if rr := serveAs(h, other, http.MethodDelete, path, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("remove another tenant's repository: %d", rr.Code)
	}
	if rr := serveAs(h, testWriter, http.MethodDelete, path, ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body)
	}
	expectAudit(t, rec, "repository_remove", route.ResultSuccess, "")
}

// The test route reads a real archive through the repository's connection.
func TestRepositoryTestReadsTheArchive(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	archive := repoArchive(t)
	srv := newHostingServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	trust(t, svc, srv)
	_ = svc.store.CreateRepository(context.Background(), Repository{ID: "r1", TenantID: "t1", URL: "https://" + srv.hostport() + "/acme/app", Provider: "gitlab"})
	rec := &routetest.Recorder{}
	rr := serveAs(NewHandler(svc, rec, nil), testWriter, http.MethodPost, "/discovery/repositories/r1/test", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), testCommit) {
		t.Fatalf("test: %d %s", rr.Code, rr.Body)
	}
	if ev := expectAudit(t, rec, "repository_test", route.ResultSuccess, ""); ev.Details["commit"] != testCommit {
		t.Fatalf("details %+v", ev.Details)
	}
	if _, n, _ := svc.FindAssets(context.Background(), "t1", 10, 0, AssetFilter{Source: "git"}); n != 0 {
		t.Fatalf("a test stored %d assets", n)
	}
}

// Opt-in check against the real hosting services' public APIs
// (VECTA_TEST_LIVE_GIT=1; needs the internet): the URL each provider is
// asked for answers with an archive this scanner reads.
func TestLivePublicRepositories(t *testing.T) {
	if os.Getenv("VECTA_TEST_LIVE_GIT") == "" {
		t.Skip("set VECTA_TEST_LIVE_GIT=1 to scan real public repositories")
	}
	svc, _, _ := newDiscoveryService(t)
	svc.targetGuard = newTargetGuard
	for _, raw := range strings.Fields(defaultString(os.Getenv("VECTA_TEST_LIVE_GIT_URLS"), "https://github.com/octocat/Hello-World https://gitlab.com/gitlab-org/gitlab-test https://codeberg.org/forgejo/governance")) {
		u, _ := url.Parse(raw)
		r, err := normalizeRepository(raw, "", "")
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		r.TenantID = "t1"
		res, err := svc.scanRepository(context.Background(), svc.repoClient(svc.targetGuard(context.Background())), r, "s", 0)
		t.Logf("%s (%s): %d files parsed, %d assets, commit %q, err %v", u.Host, r.Provider, res.files, len(res.assets), res.commit, err)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
