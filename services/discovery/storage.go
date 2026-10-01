package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
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

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Object storage: the "storage" scan source (7.34.0-beta). A tenant adds a
// bucket (S3 or any service that speaks its API: MinIO, Ceph, Cloudflare R2,
// Google Cloud Storage with HMAC keys) or an Azure Blob container. The scan
// lists the objects under the prefix over HTTPS, reads each source, config,
// key or certificate file in memory and inventories it with the same parser
// as the code, git and upload sources (material.go). Nothing is written to
// disk. The only cryptography is this service's TLS and, for S3, the
// request signature (HMAC-SHA256 from pkg/crypto), so the scan behaves the
// same in every FIPS mode.
//
// A private bucket names a sealed connection in compliance
// (docs/SECURITY/CONNECTIONS.md): type s3 (access key) or azure_blob (a SAS
// token with read and list). Discovery opens it for each scan, uses it only
// against the host the connection names, stores no credential, and follows
// no redirect. Every request goes through the scan's dial guard
// (targets.go).
//
// The scan reads the current version of each object. It does not read
// object versions, archives inside the bucket, or objects in an archive
// storage class.

const (
	maxBucketsPerTenant = 100
	bucketFetchTimeout  = 8 * time.Minute
	bucketPageSize      = 1000
	bucketWorkers       = 8
	azureAPIVersion     = "2021-08-06"
)

// Caps on one bucket, so a large one can't hold the scan (variables so a
// test can lower them).
var (
	maxBucketObjects       = 100000    // objects listed
	maxBucketBytes   int64 = 512 << 20 // bytes read
)

var (
	errInvalidBucket  = errors.New("invalid bucket")
	errBucketExists   = errors.New("bucket already added")
	errBucketLimit    = fmt.Errorf("at most %d buckets per tenant", maxBucketsPerTenant)
	errBucketTooLarge = errors.New("the bucket has more objects or bytes than the scan limit; narrow it with a prefix")

	bucketProviders = map[string]string{"s3": "s3", "azure": "azure_blob"} // provider -> connection type

	reBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	reRegion     = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	reErrorCode  = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// normalizeBucket checks a bucket's fields and returns them in stored form:
// endpoint https://host[:port] with no path.
func normalizeBucket(provider, endpoint, name, prefix, region string) (Bucket, error) {
	bad := func(msg string) (Bucket, error) { return Bucket{}, fmt.Errorf("%w: %s", errInvalidBucket, msg) }
	provider = strings.ToLower(strings.TrimSpace(provider))
	if _, ok := bucketProviders[provider]; !ok {
		return bad("provider must be s3 or azure")
	}
	region = strings.ToLower(strings.TrimSpace(region))
	if provider == "azure" {
		region = ""
	} else if region == "" {
		region = "us-east-1"
	} else if !reRegion.MatchString(region) {
		return bad("the region has characters a region name can't have")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" && provider == "s3" {
		endpoint = "https://s3." + region + ".amazonaws.com"
	}
	u, err := neturl.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return bad("enter the storage service's https address, such as https://s3.eu-west-1.amazonaws.com or https://account.blob.core.windows.net")
	}
	if u.Scheme != "https" {
		return bad("the endpoint must start with https://")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return bad("remove the credential or query from the endpoint; a private bucket uses a connection")
	}
	if strings.Trim(u.Path, "/") != "" {
		return bad("the endpoint is the service's address only; put the bucket and prefix in their own fields")
	}
	port := 443
	if p := u.Port(); p != "" {
		if port = atoi(p); fmt.Sprint(port) != p {
			return bad("bad port")
		}
	}
	host, err := normalizeTarget(u.Hostname(), port)
	if errors.Is(err, errPlatformTarget) {
		return Bucket{}, err
	} else if err != nil || strings.Contains(host, "/") {
		return bad("host must be a public or private DNS name or address, not a loopback, link-local or reserved one")
	}
	if name = strings.TrimSpace(name); !reBucketName.MatchString(name) {
		return bad("the bucket or container name is 3 to 63 lower-case letters, digits, dots, hyphens or underscores")
	}
	prefix = strings.TrimLeft(strings.TrimSpace(prefix), "/")
	if len(prefix) > 512 || strings.ContainsFunc(prefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return bad("the prefix is at most 512 printable characters")
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != 443 {
		hostport = net.JoinHostPort(host, fmt.Sprint(port))
	}
	return Bucket{Provider: provider, Endpoint: "https://" + hostport, Name: name, Prefix: prefix, Region: region}, nil
}

func (b Bucket) host() string {
	u, err := neturl.Parse(b.Endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// label names the bucket in asset locations: host/bucket.
func (b Bucket) label() string {
	return strings.TrimPrefix(b.Endpoint, "https://") + "/" + b.Name
}

// bucketCredential is an opened s3 or azure_blob connection, held for one
// scan.
type bucketCredential struct {
	accessKey, secretKey string        // s3
	sas                  neturl.Values // azure
}

// bucketCredential opens the bucket's connection. It must be of the
// provider's type and for the bucket's own host: a credential is never sent
// to a host its connection doesn't name.
func (s *Service) bucketCredential(ctx context.Context, b Bucket) (bucketCredential, error) {
	if b.ConnectionID == "" {
		return bucketCredential{}, nil
	}
	if s.conns == nil {
		return bucketCredential{}, errConnectionsUnset
	}
	conn, err := s.conns.Resolve(ctx, b.TenantID, b.ConnectionID)
	if err != nil {
		return bucketCredential{}, fmt.Errorf("connection %s: %w", b.ConnectionID, err)
	}
	if want := bucketProviders[b.Provider]; conn.Type != want {
		return bucketCredential{}, fmt.Errorf("%w: %s is a %s connection, not %s", errConnectionUnfit, b.ConnectionID, conn.Type, want)
	}
	if !strings.EqualFold(conn.Endpoint, b.host()) {
		return bucketCredential{}, fmt.Errorf("%w: its credential is for %s, not %s", errConnectionUnfit, conn.Endpoint, b.host())
	}
	if b.Provider == "azure" {
		sas, err := neturl.ParseQuery(strings.TrimPrefix(strings.TrimSpace(conn.Fields["sas_token"]), "?"))
		if err != nil || sas.Get("sig") == "" {
			return bucketCredential{}, fmt.Errorf("%w: its SAS token is not a signed query string", errConnectionUnfit)
		}
		return bucketCredential{sas: sas}, nil
	}
	cred := bucketCredential{accessKey: strings.TrimSpace(conn.Fields["access_key_id"]), secretKey: strings.TrimSpace(conn.Fields["secret_access_key"])}
	// An HMAC key under 112 bits is not approved, and panics in FIPS-only mode.
	if cred.accessKey == "" || len("AWS4"+cred.secretKey) < 14 {
		return bucketCredential{}, fmt.Errorf("%w: its access key is missing or its secret key is too short to sign with", errConnectionUnfit)
	}
	return cred, nil
}

// awsEscape percent-encodes s as request signing requires: every byte but
// the unreserved characters, and "/" when it separates path segments.
func awsEscape(s string, keepSlash bool) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~', c == '/' && keepSlash:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

// canonicalQuery encodes q sorted by name, as the signature covers it.
func canonicalQuery(q neturl.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, awsEscape(k, false)+"="+awsEscape(v, false))
		}
	}
	return strings.Join(parts, "&")
}

// emptySHA256 is the payload hash of a request with no body.
var emptySHA256 = hex.EncodeToString(pkgcrypto.SHA256(nil))

// signV4 signs a bodyless GET with AWS Signature Version 4 for service s3.
// The request's path and query must already be in canonical encoding.
func signV4(req *http.Request, cred bucketCredential, region string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	const signed = "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), req.URL.RawQuery,
		"host:" + req.URL.Host + "\nx-amz-content-sha256:" + emptySHA256 + "\nx-amz-date:" + stamp + "\n",
		signed, emptySHA256,
	}, "\n")
	scope := date + "/" + region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(pkgcrypto.SHA256([]byte(canonical)))
	key := []byte("AWS4" + cred.secretKey)
	for _, part := range []string{date, region, "s3", "aws4_request"} {
		key = pkgcrypto.HMACSHA256(key, []byte(part))
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cred.accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(pkgcrypto.HMACSHA256(key, []byte(toSign))))
}

// storageClient is the HTTPS client for one scan's bucket reads. It follows
// no redirect: a signature is for one host, and a SAS token is in the URL.
func (s *Service) storageClient(guard dialControl) *http.Client {
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
			MaxIdleConnsPerHost:   bucketWorkers,
			ForceAttemptHTTP2:     true,
			Proxy:                 nil, // a proxy would bypass the dial guard
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// storageError turns a storage service's answer into what the operator can
// act on. Of the response it keeps only the service's error code.
func storageError(resp *http.Response, private bool) error {
	var e struct {
		Code string `xml:"Code"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = xml.Unmarshal(raw, &e)
	code := ""
	if reErrorCode.MatchString(e.Code) {
		code = " (" + e.Code + ")"
	}
	switch status := resp.StatusCode; {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		if private {
			return fmt.Errorf("access denied%s: check the connection's credential and that it may list and read this bucket", code)
		}
		return fmt.Errorf("access denied%s: a private bucket needs a connection", code)
	case status == http.StatusNotFound:
		return fmt.Errorf("bucket or object not found%s", code)
	case status >= 300 && status < 400:
		return fmt.Errorf("the bucket is served from another address%s: use its own region's endpoint", code)
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return fmt.Errorf("the storage service is limiting requests%s; try later", code)
	default:
		return fmt.Errorf("the storage service answered HTTP %d%s", status, code)
	}
}

// bucketGet sends one authorized GET for the bucket. key "" is the listing.
func (s *Service) bucketGet(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, key string, q neturl.Values) (*http.Response, error) {
	if q == nil {
		q = neturl.Values{}
	}
	for k, v := range cred.sas {
		q[k] = v
	}
	target := b.Endpoint + "/" + awsEscape(b.Name, false)
	if key != "" {
		target += "/" + awsEscape(key, true)
	}
	if enc := canonicalQuery(q); enc != "" {
		target += "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("the object's name can't be put in a request")
	}
	req.Header.Set("User-Agent", "VectaKMS-Discovery")
	switch {
	case b.Provider == "azure":
		req.Header.Set("x-ms-version", azureAPIVersion)
	case cred.accessKey != "":
		signV4(req, cred, b.Region, s.now())
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL can carry a SAS token
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close() //nolint:errcheck
		return nil, storageError(resp, b.ConnectionID != "")
	}
	return resp, nil
}

type bucketObject struct {
	key  string
	size int64
}

// listPage reads one page of the bucket's listing after token ("" starts)
// and returns the token for the next page ("" when the listing is complete).
func (s *Service) listPage(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, token string) ([]bucketObject, string, error) {
	q := neturl.Values{}
	if b.Provider == "azure" {
		q.Set("restype", "container")
		q.Set("comp", "list")
		q.Set("maxresults", fmt.Sprint(bucketPageSize))
		if token != "" {
			q.Set("marker", token)
		}
	} else {
		q.Set("list-type", "2")
		q.Set("max-keys", fmt.Sprint(bucketPageSize))
		if token != "" {
			q.Set("continuation-token", token)
		}
	}
	if b.Prefix != "" {
		q.Set("prefix", b.Prefix)
	}
	resp, err := s.bucketGet(ctx, client, b, cred, "", q)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var page struct {
		// S3 ListObjectsV2
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		// Azure List Blobs
		Blobs []struct {
			Name string `xml:"Name"`
			Size int64  `xml:"Properties>Content-Length"`
		} `xml:"Blobs>Blob"`
		NextMarker string `xml:"NextMarker"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page); err != nil {
		return nil, "", errors.New("the storage service did not return a listing")
	}
	out := make([]bucketObject, 0, len(page.Contents)+len(page.Blobs))
	for _, o := range page.Contents {
		out = append(out, bucketObject{o.Key, o.Size})
	}
	for _, o := range page.Blobs {
		out = append(out, bucketObject{o.Name, o.Size})
	}
	next := page.NextMarker
	if b.Provider != "azure" {
		if next = page.NextContinuationToken; page.IsTruncated && next == "" {
			return nil, "", errors.New("the storage service's listing is incomplete and names no next page")
		}
	}
	return out, next, nil
}

// readObject downloads one object of at most maxUploadBytes.
func (s *Service) readObject(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, key string) ([]byte, error) {
	resp, err := s.bucketGet(ctx, client, b, cred, key, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUploadBytes+1))
	if err != nil {
		return nil, errors.New("the download ended early")
	}
	if len(raw) > maxUploadBytes {
		return nil, errors.New("the object is larger than its listing said")
	}
	return raw, nil
}

type bucketScan struct {
	assets     []CryptoAsset
	objects    int // objects listed
	files      int // objects read and parsed
	unreadable []string
}

// scannable: an object the parser reads, by the same rules as a repository
// file (name, size, not under a dependency or build folder).
func scannable(o bucketObject) bool {
	return o.size > 0 && o.size <= maxUploadBytes && !strings.HasSuffix(o.key, "/") && codeScanFile(path.Base(o.key)) && !skippedPath(o.key)
}

// scanBucket lists the bucket and inventories each scannable object. With
// probe set it reads only the first page and at most one object, to prove
// the endpoint, the bucket and the credential work together. An object that
// can't be read is named in the error; the others are still scanned.
func (s *Service) scanBucket(ctx context.Context, client *http.Client, b Bucket, scanID string, probe bool) (bucketScan, error) {
	ctx, cancel := context.WithTimeout(ctx, bucketFetchTimeout)
	defer cancel()
	var out bucketScan
	cred, err := s.bucketCredential(ctx, b)
	if err != nil {
		return out, err
	}
	var (
		mu    sync.Mutex
		bytes int64
		label = b.label()
	)
	for token := ""; ; {
		page, next, err := s.listPage(ctx, client, b, cred, token)
		if err != nil {
			return out, err
		}
		out.objects += len(page)
		if out.objects > maxBucketObjects {
			return out, errBucketTooLarge
		}
		var todo []bucketObject
		for _, o := range page {
			if !scannable(o) {
				continue
			}
			if bytes += o.size; bytes > maxBucketBytes {
				return out, errBucketTooLarge
			}
			if todo = append(todo, o); probe {
				break
			}
		}
		jobs := make(chan bucketObject)
		var wg sync.WaitGroup
		for i := 0; i < min(bucketWorkers, len(todo)); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for o := range jobs {
					raw, err := s.readObject(ctx, client, b, cred, o.key)
					var found []CryptoAsset
					if err == nil {
						found = s.materialAssets(b.TenantID, scanID, "storage", label+"/"+o.key, findMaterial(o.key, raw))
						for _, a := range found {
							a.Metadata["endpoint"], a.Metadata["bucket"], a.Metadata["key"], a.Metadata["provider"] = b.Endpoint, b.Name, o.key, b.Provider
						}
					}
					mu.Lock()
					if err != nil {
						out.unreadable = append(out.unreadable, o.key+": "+err.Error())
					} else {
						out.files++
						out.assets = append(out.assets, found...)
					}
					mu.Unlock()
				}
			}()
		}
		for _, o := range todo {
			jobs <- o
		}
		close(jobs)
		wg.Wait()
		if token = next; token == "" || probe {
			break
		}
	}
	if n := len(out.unreadable); n > 0 {
		sort.Strings(out.unreadable)
		return out, fmt.Errorf("%d objects could not be read, the first: %s", n, out.unreadable[0])
	}
	return out, nil
}

// scanStorage scans every bucket the tenant added. A bucket that fails is an
// error naming it; the others are still scanned.
func (s *Service) scanStorage(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, map[string]interface{}, error) {
	buckets, err := s.store.ListBuckets(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("read buckets: %w", err)
	}
	if len(buckets) == 0 {
		return nil, nil, fmt.Errorf("%w: add a bucket in Crypto Discovery", errScanNotConfigured)
	}
	client := s.storageClient(s.targetGuard(ctx))
	var (
		assets         []CryptoAsset
		failed         []string
		objects, files int
	)
	for _, b := range buckets {
		res, err := s.scanBucket(ctx, client, b, scanID, false)
		assets = append(assets, res.assets...)
		objects += res.objects
		files += res.files
		if err != nil {
			failed = append(failed, b.label()+": "+err.Error())
		}
	}
	stats := map[string]interface{}{"storage_buckets": len(buckets), "storage_objects": objects, "storage_files": files}
	if len(failed) > 0 {
		return assets, stats, fmt.Errorf("%d of %d buckets failed: %s", len(failed), len(buckets), strings.Join(failed, "; "))
	}
	return assets, stats, nil
}

// ---- managing buckets ----

type BucketInput struct {
	Provider     string `json:"provider"`
	Endpoint     string `json:"endpoint"`
	Name         string `json:"bucket"`
	Prefix       string `json:"prefix"`
	Region       string `json:"region"`
	ConnectionID string `json:"connection_id"`
}

func (s *Service) AddBucket(ctx context.Context, tenantID string, in BucketInput, actor string) (Bucket, error) {
	b, err := normalizeBucket(in.Provider, in.Endpoint, in.Name, in.Prefix, in.Region)
	if err != nil {
		return Bucket{}, err
	}
	b.ID, b.TenantID, b.ConnectionID, b.CreatedBy = newID("bucket"), tenantID, strings.TrimSpace(in.ConnectionID), actor
	existing, err := s.store.ListBuckets(ctx, tenantID)
	if err != nil {
		return Bucket{}, err
	}
	if len(existing) >= maxBucketsPerTenant {
		return Bucket{}, errBucketLimit
	}
	for _, e := range existing {
		if e.Endpoint == b.Endpoint && e.Name == b.Name && e.Prefix == b.Prefix {
			return Bucket{}, errBucketExists
		}
	}
	// Opening the connection now proves it exists, is of the provider's
	// type and is for this host, before a scan depends on it.
	if _, err := s.bucketCredential(ctx, b); err != nil {
		return Bucket{}, err
	}
	if err := s.store.CreateBucket(ctx, b); err != nil {
		return Bucket{}, err
	}
	b.CreatedAt = s.now()
	return b, nil
}

func (s *Service) ListBuckets(ctx context.Context, tenantID string) ([]Bucket, error) {
	return s.store.ListBuckets(ctx, tenantID)
}

func (s *Service) bucket(ctx context.Context, tenantID, id string) (Bucket, error) {
	items, err := s.store.ListBuckets(ctx, tenantID)
	if err != nil {
		return Bucket{}, err
	}
	for _, b := range items {
		if b.ID == id {
			return b, nil
		}
	}
	return Bucket{}, errNotFound
}

func (s *Service) RemoveBucket(ctx context.Context, tenantID, id string) (Bucket, error) {
	b, err := s.bucket(ctx, tenantID, id)
	if err != nil {
		return Bucket{}, err
	}
	return b, s.store.DeleteBucket(ctx, tenantID, id)
}

// TestBucket lists the first page of the bucket and reads one object with
// its connection. It stores nothing.
func (s *Service) TestBucket(ctx context.Context, tenantID, id string) (Bucket, bucketScan, error) {
	b, err := s.bucket(ctx, tenantID, id)
	if err != nil {
		return Bucket{}, bucketScan{}, err
	}
	res, err := s.scanBucket(ctx, s.storageClient(s.targetGuard(ctx)), b, "", true)
	return b, res, err
}
