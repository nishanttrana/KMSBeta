package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Git repositories: the "git" scan source (7.20.0-beta). A tenant adds a
// repository by URL. The scan asks the hosting service's API for an archive
// of one ref over HTTPS, reads it as a stream and scans each file in memory
// with the code scan's parser (material.go). Nothing is written to disk and
// no git program runs, so the only cryptography is this service's own TLS
// and the scan behaves the same in every FIPS mode.
//
// A private repository names a sealed git connection in compliance
// (docs/SECURITY/CONNECTIONS.md). Discovery opens it for each scan and sends
// its token only to the host the connection names; it stores no credential
// and refuses a URL that carries one. Every request goes through the scan's
// dial guard (targets.go): reserved and platform addresses are refused after
// DNS resolution, on redirects too.
//
// The scan reads the files at the ref's latest commit. It does not read
// history: a secret removed in a later commit is not found.

const (
	maxReposPerTenant = 100
	repoFetchTimeout  = 5 * time.Minute
	maxRepoEntries    = 50000 // archive entries visited
	repoWorkers       = 4
)

// maxRepoBytes caps the decompressed bytes read from one archive, so a
// crafted archive can't hold the scan for long (a variable so a test can
// lower it).
var maxRepoBytes int64 = 512 << 20

var (
	errInvalidRepo      = errors.New("invalid repository")
	errRepoExists       = errors.New("repository already added")
	errRepoLimit        = fmt.Errorf("at most %d repositories per tenant", maxReposPerTenant)
	errConnectionUnfit  = errors.New("connection can't be used for this repository")
	errRepoTooLarge     = errors.New("repository is larger than the scan limit")
	errConnectionsUnset = errors.New("no connection client: private repositories are unavailable")

	// gitHosts: hosting services recognised by host name. Any other host
	// states its provider.
	gitHosts = map[string]string{"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket", "codeberg.org": "gitea", "gitea.com": "gitea"}

	gitProviders = map[string]bool{"github": true, "gitlab": true, "bitbucket": true, "gitea": true}

	reRepoSegment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._~-]*$`)
	reRepoRef     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,199}$`)
)

// normalizeRepository checks a repository URL, ref and provider and returns
// them in stored form: https://host[:port]/path, without ".git".
func normalizeRepository(rawURL, ref, provider string) (Repository, error) {
	bad := func(msg string) (Repository, error) { return Repository{}, fmt.Errorf("%w: %s", errInvalidRepo, msg) }
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return bad("enter the repository's https URL, such as https://github.com/acme/app")
	}
	if u.Scheme != "https" {
		return bad("the URL must start with https://")
	}
	if u.User != nil {
		return bad("remove the user name or token from the URL; a private repository uses a Git connection")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return bad("the URL must not have a query or fragment")
	}
	port := 443
	if p := u.Port(); p != "" {
		if port = atoi(p); fmt.Sprint(port) != p {
			return bad("bad port")
		}
	}
	host, err := normalizeTarget(u.Hostname(), port)
	if errors.Is(err, errPlatformTarget) {
		return Repository{}, err
	} else if err != nil || strings.Contains(host, "/") {
		return bad("host must be a public or private DNS name or address, not a loopback, link-local or reserved one")
	}
	segs := strings.Split(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
	for _, s := range segs {
		if !reRepoSegment.MatchString(s) {
			return bad("the path must name a repository, such as /acme/app")
		}
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if known, ok := gitHosts[host]; ok {
		provider = known
	}
	if !gitProviders[provider] {
		return bad("choose the hosting type for " + host + ": github, gitlab, bitbucket or gitea")
	}
	if len(segs) < 2 || (provider != "gitlab" && len(segs) != 2) {
		return bad("the path must be /owner/repository")
	}
	ref = strings.TrimSpace(ref)
	if ref != "" && (!reRepoRef.MatchString(ref) || strings.Contains(ref, "..")) {
		return bad("the branch, tag or commit has characters a ref can't have")
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != 443 {
		hostport = net.JoinHostPort(host, fmt.Sprint(port))
	}
	return Repository{URL: "https://" + hostport + "/" + strings.Join(segs, "/"), Ref: ref, Provider: provider}, nil
}

func (r Repository) parsed() (host, hostport, repoPath string) {
	u, err := neturl.Parse(r.URL)
	if err != nil {
		return "", "", ""
	}
	return u.Hostname(), u.Host, strings.Trim(u.Path, "/")
}

// label names the repository in asset locations: host/path, with @ref when
// the repository is pinned to one.
func (r Repository) label() string {
	_, hostport, p := r.parsed()
	if r.Ref != "" {
		return hostport + "/" + p + "@" + r.Ref
	}
	return hostport + "/" + p
}

// archiveURL is the hosting API's tar.gz of ref ("" asks for the default
// branch where the API can).
func (r Repository) archiveURL(ref string) string {
	host, hostport, p := r.parsed()
	esc := func(s string) string { return strings.ReplaceAll(neturl.PathEscape(s), "%2F", "/") }
	switch r.Provider {
	case "github":
		api := "https://" + hostport + "/api/v3" // GitHub Enterprise Server
		if host == "github.com" {
			api = "https://api.github.com"
		}
		u := api + "/repos/" + p + "/tarball"
		if ref != "" {
			u += "/" + esc(ref)
		}
		return u
	case "gitlab":
		u := "https://" + hostport + "/api/v4/projects/" + neturl.PathEscape(p) + "/repository/archive.tar.gz"
		if ref != "" {
			u += "?sha=" + neturl.QueryEscape(ref)
		}
		return u
	case "bitbucket":
		return "https://" + hostport + "/" + p + "/get/" + esc(defaultString(ref, "HEAD")) + ".tar.gz"
	default: // gitea, forgejo
		return "https://" + hostport + "/api/v1/repos/" + p + "/archive/" + esc(ref) + ".tar.gz"
	}
}

// repoCredential is an opened git connection, held for one scan.
type repoCredential struct{ username, token string }

func (c repoCredential) authorize(req *http.Request, provider string) {
	switch {
	case c.token == "":
	case c.username != "":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.token)))
	case provider == "gitea":
		req.Header.Set("Authorization", "token "+c.token)
	default:
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// credential opens the repository's connection. The connection must be a
// git connection for the repository's own host: a token is never sent to a
// host its connection doesn't name.
func (s *Service) credential(ctx context.Context, r Repository) (repoCredential, error) {
	if r.ConnectionID == "" {
		return repoCredential{}, nil
	}
	if s.conns == nil {
		return repoCredential{}, errConnectionsUnset
	}
	conn, err := s.conns.Resolve(ctx, r.TenantID, r.ConnectionID)
	if err != nil {
		return repoCredential{}, fmt.Errorf("connection %s: %w", r.ConnectionID, err)
	}
	host, _, _ := r.parsed()
	if conn.Type != "git" {
		return repoCredential{}, fmt.Errorf("%w: %s is a %s connection, not git", errConnectionUnfit, r.ConnectionID, conn.Type)
	}
	if !strings.EqualFold(conn.Endpoint, host) {
		return repoCredential{}, fmt.Errorf("%w: its token is for %s, not %s", errConnectionUnfit, conn.Endpoint, host)
	}
	return repoCredential{username: conn.Fields["username"], token: conn.Fields["token"]}, nil
}

// repoClient is the HTTPS client for one scan's repository downloads.
func (s *Service) repoClient(guard dialControl) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if s.repoRoots != nil {
		cfg.RootCAs = s.repoRoots
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, Control: guard}).DialContext,
			TLSClientConfig:       cfg,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			ForceAttemptHTTP2:     true,
			Proxy:                 nil, // a proxy would bypass the dial guard
		},
		// A hosting API redirects an archive to its download host. The
		// redirect stays on HTTPS and behind the dial guard, and the token
		// does not follow it to another host.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-HTTPS address refused")
			}
			if req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

// repoError turns a hosting API's answer into what the operator can act on.
// It never includes the response body or a header.
func repoError(status int, private bool) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		if private {
			return fmt.Errorf("access denied (HTTP %d): check the connection's token and its read access to the repository", status)
		}
		return fmt.Errorf("access denied (HTTP %d): a private repository needs a Git connection", status)
	case http.StatusNotFound:
		if private {
			return errors.New("repository or ref not found, or the token can't read it")
		}
		return errors.New("repository or ref not found; a private repository needs a Git connection")
	case http.StatusTooManyRequests:
		return errors.New("the hosting service is rate limiting requests; try later or use a connection")
	}
	return fmt.Errorf("the hosting service answered HTTP %d", status)
}

func (s *Service) repoGet(ctx context.Context, client *http.Client, r Repository, cred repoCredential, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VectaKMS-Discovery")
	if r.Provider == "github" {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	cred.authorize(req, r.Provider)
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL adds nothing the repository label doesn't say
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close() //nolint:errcheck
		return nil, repoError(resp.StatusCode, r.ConnectionID != "")
	}
	return resp, nil
}

// openArchive requests the repository's archive and returns its body.
func (s *Service) openArchive(ctx context.Context, client *http.Client, r Repository) (io.ReadCloser, error) {
	cred, err := s.credential(ctx, r)
	if err != nil {
		return nil, err
	}
	ref := r.Ref
	if ref == "" && r.Provider == "gitea" {
		// Gitea's archive route needs a ref; ask for the default branch.
		_, hostport, p := r.parsed()
		resp, err := s.repoGet(ctx, client, r, cred, "https://"+hostport+"/api/v1/repos/"+p)
		if err != nil {
			return nil, err
		}
		var info struct {
			DefaultBranch string `json:"default_branch"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info)
		resp.Body.Close() //nolint:errcheck
		if err != nil || !reRepoRef.MatchString(info.DefaultBranch) {
			return nil, errors.New("the hosting service did not name a default branch; set the branch")
		}
		ref = info.DefaultBranch
	}
	resp, err := s.repoGet(ctx, client, r, cred, r.archiveURL(ref))
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// repoSkipDirs: dependency and build output, not the tenant's own code.
var repoSkipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "bin": true, "dist": true}

type repoScan struct {
	assets []CryptoAsset
	files  int    // files read and parsed
	commit string // the archive's commit, when it says
}

// scanArchive reads a tar.gz stream and inventories each source, config,
// key or certificate file. limit caps how many files are parsed (0: no cap).
func (s *Service) scanArchive(r Repository, scanID string, body io.Reader, limit int) (repoScan, error) {
	var out repoScan
	gz, err := gzip.NewReader(body)
	if err != nil {
		return out, errors.New("the hosting service did not return a gzip archive")
	}
	defer gz.Close() //nolint:errcheck
	counted := &io.LimitedReader{R: gz, N: maxRepoBytes + 1}
	tr := tar.NewReader(counted)
	label := r.label()
	for entries := 0; ; entries++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if counted.N <= 0 || entries >= maxRepoEntries {
			return out, errRepoTooLarge
		}
		if err != nil {
			return out, errors.New("the archive ended early or is damaged")
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			out.commit = h.PAXRecords["comment"] // git archive records the commit here
			continue
		}
		// The first path element is the archive's own folder (repo-commit).
		_, rel, ok := strings.Cut(path.Clean(h.Name), "/")
		if h.Typeflag != tar.TypeReg || !ok || h.Size <= 0 || h.Size > maxUploadBytes || !codeScanFile(path.Base(rel)) || skippedPath(rel) {
			continue
		}
		raw := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, raw); err != nil {
			if counted.N <= 0 {
				return out, errRepoTooLarge
			}
			return out, errors.New("the archive ended early or is damaged")
		}
		out.files++
		for _, a := range s.materialAssets(r.TenantID, scanID, "git", label+"/"+rel, findMaterial(rel, raw)) {
			a.Metadata["repository"], a.Metadata["path"] = r.URL, rel
			if r.Ref != "" {
				a.Metadata["ref"] = r.Ref
			}
			if out.commit != "" {
				a.Metadata["commit"] = out.commit
			}
			out.assets = append(out.assets, a)
		}
		if limit > 0 && out.files >= limit {
			break
		}
	}
	return out, nil
}

func skippedPath(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if repoSkipDirs[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

func (s *Service) scanRepository(ctx context.Context, client *http.Client, r Repository, scanID string, limit int) (repoScan, error) {
	ctx, cancel := context.WithTimeout(ctx, repoFetchTimeout)
	defer cancel()
	body, err := s.openArchive(ctx, client, r)
	if err != nil {
		return repoScan{}, err
	}
	defer body.Close() //nolint:errcheck
	return s.scanArchive(r, scanID, body, limit)
}

// scanGit scans every repository the tenant added. A repository that fails
// is an error naming it; the others are still scanned.
func (s *Service) scanGit(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, map[string]interface{}, error) {
	repos, err := s.store.ListRepositories(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("read repositories: %w", err)
	}
	if len(repos) == 0 {
		return nil, nil, fmt.Errorf("%w: add a repository in Crypto Discovery", errScanNotConfigured)
	}
	client := s.repoClient(s.targetGuard(ctx))
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		assets []CryptoAsset
		failed []string
		files  int
	)
	jobs := make(chan Repository)
	for i := 0; i < min(repoWorkers, len(repos)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				res, err := s.scanRepository(ctx, client, r, scanID, 0)
				mu.Lock()
				assets = append(assets, res.assets...)
				files += res.files
				if err != nil {
					failed = append(failed, r.label()+": "+err.Error())
				}
				mu.Unlock()
			}
		}()
	}
	for _, r := range repos {
		jobs <- r
	}
	close(jobs)
	wg.Wait()
	stats := map[string]interface{}{"git_repositories": len(repos), "git_files": files}
	if len(failed) > 0 {
		sort.Strings(failed)
		return assets, stats, fmt.Errorf("%d of %d repositories failed: %s", len(failed), len(repos), strings.Join(failed, "; "))
	}
	return assets, stats, nil
}

// ---- managing repositories ----

func (s *Service) AddRepository(ctx context.Context, tenantID, rawURL, ref, provider, connectionID, actor string) (Repository, error) {
	r, err := normalizeRepository(rawURL, ref, provider)
	if err != nil {
		return Repository{}, err
	}
	r.ID, r.TenantID, r.ConnectionID, r.CreatedBy = newID("repo"), tenantID, strings.TrimSpace(connectionID), actor
	existing, err := s.store.ListRepositories(ctx, tenantID)
	if err != nil {
		return Repository{}, err
	}
	if len(existing) >= maxReposPerTenant {
		return Repository{}, errRepoLimit
	}
	for _, e := range existing {
		if e.URL == r.URL && e.Ref == r.Ref {
			return Repository{}, errRepoExists
		}
	}
	// Opening the connection now proves it exists, is a git connection and
	// is for this host, before a scan depends on it.
	if _, err := s.credential(ctx, r); err != nil {
		return Repository{}, err
	}
	if err := s.store.CreateRepository(ctx, r); err != nil {
		return Repository{}, err
	}
	r.CreatedAt = s.now()
	return r, nil
}

func (s *Service) ListRepositories(ctx context.Context, tenantID string) ([]Repository, error) {
	return s.store.ListRepositories(ctx, tenantID)
}

func (s *Service) repository(ctx context.Context, tenantID, id string) (Repository, error) {
	items, err := s.store.ListRepositories(ctx, tenantID)
	if err != nil {
		return Repository{}, err
	}
	for _, r := range items {
		if r.ID == id {
			return r, nil
		}
	}
	return Repository{}, errNotFound
}

func (s *Service) RemoveRepository(ctx context.Context, tenantID, id string) (Repository, error) {
	r, err := s.repository(ctx, tenantID, id)
	if err != nil {
		return Repository{}, err
	}
	return r, s.store.DeleteRepository(ctx, tenantID, id)
}

// TestRepository downloads the start of the repository's archive and reads
// it far enough to prove the URL, the ref and the token work together. It
// stores nothing.
func (s *Service) TestRepository(ctx context.Context, tenantID, id string) (Repository, repoScan, error) {
	r, err := s.repository(ctx, tenantID, id)
	if err != nil {
		return Repository{}, repoScan{}, err
	}
	res, err := s.scanRepository(ctx, s.repoClient(s.targetGuard(ctx)), r, "", 1)
	return r, res, err
}
