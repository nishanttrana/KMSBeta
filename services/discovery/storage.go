package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
// object versions or objects in an archive storage class.

const (
	maxBucketsPerTenant = 100
	bucketFetchTimeout  = 8 * time.Minute
	bucketPageSize      = 1000
	bucketWorkers       = 8
	azureAPIVersion     = "2021-08-06"
)

// What one run reads of one bucket, so a large one can't hold the scan
// (variables so a test can lower them). Beyond it the bucket continues with
// the next scan (scanBucket).
var (
	maxBucketObjects       = 100000    // objects listed
	maxBucketBytes   int64 = 512 << 20 // bytes read
)

var (
	errInvalidBucket = errors.New("invalid bucket")
	errBucketExists  = errors.New("bucket already added")
	errBucketLimit   = fmt.Errorf("at most %d buckets per tenant", maxBucketsPerTenant)

	bucketProviders = map[string]string{"s3": "s3", "azure": "azure_blob", "gcs": "gcs"} // provider -> connection type

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
		return bad("provider must be s3, azure or gcs")
	}
	region = strings.ToLower(strings.TrimSpace(region))
	if provider != "s3" {
		region = ""
	} else if region == "" {
		region = "us-east-1"
	} else if !reRegion.MatchString(region) {
		return bad("the region has characters a region name can't have")
	}
	endpoint = strings.TrimSpace(endpoint)
	switch {
	case endpoint == "" && provider == "s3":
		endpoint = "https://s3." + region + ".amazonaws.com"
	case endpoint == "" && provider == "gcs":
		endpoint = "https://storage.googleapis.com"
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
	code := errorCode(resp)
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

// bucketGet sends one authorized GET for the bucket. key "" is the listing;
// first > 0 asks for only that many bytes from the start of an object.
func (s *Service) bucketGet(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, key string, q neturl.Values, first int) (*http.Response, error) {
	if q == nil {
		q = neturl.Values{}
	}
	for k, v := range cred.sas {
		q[k] = v
	}
	target := b.Endpoint + "/" + awsEscape(b.Name, false)
	if b.Provider == "gcs" {
		// The JSON API names an object as one path segment.
		target = b.Endpoint + "/storage/v1/b/" + awsEscape(b.Name, false) + "/o"
		if key != "" {
			target += "/" + awsEscape(key, false)
			q.Set("alt", "media")
		}
	} else if key != "" {
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
	if first > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", first-1))
	}
	if b.Provider == "azure" {
		req.Header.Set("x-ms-version", azureAPIVersion)
	}
	switch {
	case cred.bearer != "":
		req.Header.Set("Authorization", "Bearer "+cred.bearer)
	case cred.accountKey != nil:
		signSharedKey(req, cred, s.now())
	case b.Provider == "s3" && cred.accessKey != "":
		signV4(req, cred, b.Region, "s3", nil, s.now())
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL can carry a SAS token
		}
		return nil, err
	}
	// 206: the range asked for. A service that ignores Range answers 200
	// with the whole object, which the caller's limit still bounds.
	if resp.StatusCode != http.StatusOK && !(first > 0 && resp.StatusCode == http.StatusPartialContent) {
		defer resp.Body.Close() //nolint:errcheck
		return nil, storageError(resp, b.ConnectionID != "")
	}
	return resp, nil
}

type bucketObject struct {
	key      string
	size     int64
	etag     string    // "" when the service names none
	modified string    // the listing's last-modified time, as the service wrote it
	listed   time.Time // the service's own clock when it listed the object
}

// A service that names no ETag (8.1.0-beta). Until now its objects were
// read again in full on every scan. The listing's last-modified time and
// size now stand in for the ETag, under two conditions that answer why that
// was first rejected (two writes with one timestamp and one length, where
// what is missed is a replaced key):
//
//   - The time is trusted only once it is modifiedSettle old by the
//     service's own clock (the Date of the listing response). A write after
//     the scan read the object then carries a later time. A younger object
//     gets no token and is read again next scan.
//   - A token is trusted for modifiedTrust from when the object was read.
//     After that it is read again whatever the listing says, which bounds
//     how long a write that kept the old time and length (a copy that
//     preserves times, on a gateway over a file system) can go unseen.
//
// A listing with neither an ETag nor a time and a Date is read in full, as
// before.
const (
	modifiedSettle = 2 * time.Minute
	modifiedTrust  = 7 * 24 * time.Hour
	modifiedMark   = "~lm~"
)

// token is what says the object has not changed: its ETag, or the
// last-modified stand-in, or "" when nothing can be trusted.
func (o bucketObject) token() string {
	if o.etag != "" {
		return o.etag
	}
	at := parseListingTime(o.modified)
	if at.IsZero() || o.listed.IsZero() || o.listed.Sub(at) < modifiedSettle {
		return ""
	}
	return fmt.Sprintf("%s%s~%d", modifiedMark, at.UTC().Format(time.RFC3339Nano), o.size)
}

// recorded is the token as stored when the object is read at now: a
// stand-in also carries when it was read.
func (o bucketObject) recorded(now time.Time) string {
	t := o.token()
	if strings.HasPrefix(t, modifiedMark) {
		t += fmt.Sprintf("~%d", now.Unix())
	}
	return t
}

// unchangedSince reports whether stored (the token recorded at the last
// read) says the object listed now is the one that was read.
func (o bucketObject) unchangedSince(stored string, now time.Time) bool {
	t := o.token()
	if t == "" || stored == "" {
		return false
	}
	if !strings.HasPrefix(t, modifiedMark) {
		return stored == t
	}
	read, ok := strings.CutPrefix(stored, t+"~")
	if !ok || atoi(read) <= 0 {
		return false
	}
	at := time.Unix(int64(atoi(read)), 0)
	return !now.Before(at) && now.Sub(at) < modifiedTrust
}

// parseListingTime reads a listing's time: RFC 3339 (S3, Google) or the
// HTTP date Azure writes.
func parseListingTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}
	if t, err := http.ParseTime(v); err == nil {
		return t
	}
	return time.Time{}
}

// listedAt is the service's clock on a listing response.
func listedAt(resp *http.Response) time.Time {
	t, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return time.Time{}
	}
	return t
}

// listPage reads one page of the bucket's listing from cursor ("" starts)
// and returns the cursor of the next page ("" when the listing is complete).
// An S3 cursor is the last key listed (start-after), which stays valid
// between scans; an Azure cursor is the service's marker.
func (s *Service) listPage(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, cursor string) ([]bucketObject, string, error) {
	if b.Provider == "gcs" {
		return s.listGCS(ctx, client, b, cred, cursor)
	}
	q := neturl.Values{}
	if b.Provider == "azure" {
		q.Set("restype", "container")
		q.Set("comp", "list")
		q.Set("maxresults", fmt.Sprint(bucketPageSize))
		if cursor != "" {
			q.Set("marker", cursor)
		}
	} else {
		q.Set("list-type", "2")
		q.Set("max-keys", fmt.Sprint(bucketPageSize))
		if cursor != "" {
			q.Set("start-after", cursor)
		}
	}
	if b.Prefix != "" {
		q.Set("prefix", b.Prefix)
	}
	resp, err := s.bucketGet(ctx, client, b, cred, "", q, 0)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var page struct {
		// S3 ListObjectsV2
		Contents []struct {
			Key      string `xml:"Key"`
			Size     int64  `xml:"Size"`
			ETag     string `xml:"ETag"`
			Modified string `xml:"LastModified"`
		} `xml:"Contents"`
		IsTruncated bool `xml:"IsTruncated"`
		// Azure List Blobs
		Blobs []struct {
			Name     string `xml:"Name"`
			Size     int64  `xml:"Properties>Content-Length"`
			ETag     string `xml:"Properties>Etag"`
			Modified string `xml:"Properties>Last-Modified"`
		} `xml:"Blobs>Blob"`
		NextMarker string `xml:"NextMarker"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page); err != nil {
		return nil, "", errors.New("the storage service did not return a listing")
	}
	out := make([]bucketObject, 0, len(page.Contents)+len(page.Blobs))
	at := listedAt(resp)
	for _, o := range page.Contents {
		out = append(out, bucketObject{o.Key, o.Size, strings.Trim(o.ETag, `"`), o.Modified, at})
	}
	for _, o := range page.Blobs {
		out = append(out, bucketObject{o.Name, o.Size, strings.Trim(o.ETag, `"`), o.Modified, at})
	}
	if b.Provider == "azure" {
		return out, page.NextMarker, nil
	}
	if !page.IsTruncated {
		return out, "", nil
	}
	if len(out) == 0 {
		return nil, "", errors.New("the storage service's listing is incomplete and names no next page")
	}
	return out, out[len(out)-1].key, nil
}

// listGCS reads one page of a bucket's listing from Google's JSON API. Its
// cursor is the service's page token.
func (s *Service) listGCS(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, cursor string) ([]bucketObject, string, error) {
	q := neturl.Values{"maxResults": {fmt.Sprint(bucketPageSize)}, "fields": {"items(name,size,etag,updated),nextPageToken"}}
	if cursor != "" {
		q.Set("pageToken", cursor)
	}
	if b.Prefix != "" {
		q.Set("prefix", b.Prefix)
	}
	resp, err := s.bucketGet(ctx, client, b, cred, "", q, 0)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var page struct {
		Items []struct {
			Name     string `json:"name"`
			Size     string `json:"size"`
			ETag     string `json:"etag"`
			Modified string `json:"updated"`
		} `json:"items"`
		Next string `json:"nextPageToken"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil || !json.Valid(raw) || json.Unmarshal(raw, &page) != nil {
		return nil, "", errors.New("the storage service did not return a listing")
	}
	out := make([]bucketObject, 0, len(page.Items))
	for _, o := range page.Items {
		out = append(out, bucketObject{o.Name, int64(atoi(o.Size)), o.ETag, o.Modified, listedAt(resp)})
	}
	return out, page.Next, nil
}

// readObject downloads an object of at most limit bytes. first > 0 reads
// only the object's first bytes.
func (s *Service) readObject(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, key string, limit int64, first int) ([]byte, error) {
	resp, err := s.bucketGet(ctx, client, b, cred, key, nil, first)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if first > 0 {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(first)))
		if err != nil {
			return nil, errors.New("the download ended early")
		}
		return raw, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("the download ended early")
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("the object is larger than its listing said")
	}
	return raw, nil
}

type bucketScan struct {
	assets     []CryptoAsset
	objects    int  // objects listed in this run
	files      int  // objects read and parsed
	sniffed    int  // objects whose first bytes a deep scan read
	unchanged  int  // objects not read: the same ETag as when last read
	kept       int  // assets of unchanged objects, marked seen
	partial    bool // the run stopped at a budget; the next scan continues
	unreadable []string
}

// scannable: an object the parser reads, by the same rules as a repository
// file (name, size, not under a dependency or build folder).
func scannable(o bucketObject) bool {
	return fileSizeOK(o.key, o.size) && !strings.HasSuffix(o.key, "/") && codeScanFile(path.Base(o.key)) && !skippedPath(o.key)
}

// sniffable: an object a deep scan looks into because its name says
// nothing: any other object small enough to hold, outside dependency and
// build folders.
func sniffable(o bucketObject) bool {
	return o.size > 0 && o.size <= maxArchiveBytes && !strings.HasSuffix(o.key, "/") && !skippedPath(o.key)
}

// headOnlyExt: formats that are compressed or encoded throughout, so key
// text can't be read out of their middle: images, audio, video, fonts,
// columnar data and compressed files the scan does not open. A deep scan
// still reads their first kilobyte, which is where a keystore, an archive
// or a key given one of these names shows itself.
var headOnlyExt = exts(".jpg .jpeg .png .gif .webp .bmp .ico .tif .tiff .heic .mp3 .mp4 .m4a .mov .avi .mkv .webm .wav .flac .ogg " +
	".woff .woff2 .ttf .otf .eot .parquet .orc .avro .bz2 .xz .zst .7z .rar")

// readWhole: an object a deep scan reads in full (8.1.0-beta): up to the
// size of any file the parser holds, and not a headOnlyExt format. Until
// now a deep scan judged every object by its first kilobyte, so a key or
// token further in (a certificate after its text dump, a key in the middle
// of a notes or log file) was missed.
func readWhole(o bucketObject) bool {
	return o.size <= maxUploadBytes && !headOnlyExt[strings.ToLower(path.Ext(o.key))]
}

// sniffCost is what a deep scan reads of an object to decide.
func sniffCost(o bucketObject) int64 {
	if readWhole(o) {
		return o.size
	}
	return sniffBytes
}

// worthParsing: content read whole by a deep scan that the parser should
// see: text (it may hold a key, a token or a secret on any line), or
// binary with a key marker anywhere in it.
func worthParsing(raw []byte) bool {
	if looksLikeKeyMaterial(raw[:min(len(raw), sniffBytes)]) || !bytes.Contains(raw[:min(len(raw), 8192)], []byte{0}) {
		return true
	}
	for _, m := range keyMarkers {
		if bytes.Contains(raw, m) {
			return true
		}
	}
	return false
}

// bucketJob is one object to read; sniff: a deep scan's object, kept only
// if its content holds key material.
type bucketJob struct {
	bucketObject
	sniff bool
}

// fetchObject reads the object a job names. A sniffed object that holds
// nothing of interest returns nil. A deep scan reads a small object whole
// and a larger one only if its first kilobyte is a keystore, an archive or
// a key.
func (s *Service) fetchObject(ctx context.Context, client *http.Client, b Bucket, cred bucketCredential, j bucketJob) ([]byte, error) {
	limit := int64(maxUploadBytes)
	if !j.sniff {
		if archiveName(j.key) {
			limit = maxArchiveBytes
		}
		return s.readObject(ctx, client, b, cred, j.key, limit, 0)
	}
	if readWhole(j.bucketObject) {
		raw, err := s.readObject(ctx, client, b, cred, j.key, limit, 0)
		if err != nil || !worthParsing(raw) {
			return nil, err
		}
		return raw, nil
	}
	head, err := s.readObject(ctx, client, b, cred, j.key, 0, sniffBytes)
	if err != nil || !looksLikeKeyMaterial(head) {
		return nil, err
	}
	if j.size <= int64(len(head)) {
		return head, nil
	}
	if archiveKind(head) != "" {
		limit = maxArchiveBytes
	}
	if j.size > limit {
		return nil, nil // key material by its first bytes, but too large to hold
	}
	return s.readObject(ctx, client, b, cred, j.key, limit, 0)
}

// One run's budget for one bucket (variables so a test can lower them). A
// bucket larger than a run can cover is read over several scans: each run
// continues where the last stopped, and the pass is complete when the
// listing ends.
var bucketRunBudget = 6 * time.Minute

// scanRules is recorded with each object read. Raise it when the parser
// learns something new, so unchanged objects are read again.
const scanRules = 3

// scanBucket reads the bucket from where its last run stopped, through
// guard (and, with a connection, only to addresses its credential may go): it lists the
// objects, skips those whose ETag (or, without one, last-modified time and
// size) says they have not changed since they were read (their assets are
// marked seen), and inventories the rest. A run stops
// at its budget of objects, bytes or time and records where; the next
// continues from there. With probe set it reads only the first page and at
// most one object and records nothing, to prove the endpoint, the bucket
// and the credential work together. An object that can't be read is named
// in the error and tried again next time; the others are still scanned.
func (s *Service) scanBucket(ctx context.Context, guard dialControl, b Bucket, scanID string, probe bool) (bucketScan, error) {
	ctx, cancel := context.WithTimeout(ctx, bucketFetchTimeout)
	defer cancel()
	var out bucketScan
	cred, err := s.bucketCredential(ctx, b)
	if err != nil {
		return out, err
	}
	// Its own client: a connection opened without a credential is never
	// reused for a request that carries one.
	if b.ConnectionID != "" {
		guard = credentialGuard(guard, cred.approved)
	}
	client := s.storageClient(guard)
	if err := s.authorize(ctx, client, b, &cred); err != nil {
		return out, err
	}
	started := s.now()
	known := map[string]BucketObject{}
	if !probe {
		if known, err = s.store.BucketObjects(ctx, b.TenantID, b.ID); err != nil {
			return out, fmt.Errorf("read scan state: %w", err)
		}
		if b.Cursor == "" {
			b.PassStartedAt, b.PassObjects = started, 0
		}
	}
	var (
		mu    sync.Mutex
		bytes int64
		label = b.label()
		wall  = time.Now()
	)
	finish := func(complete bool) error {
		if probe {
			return nil
		}
		b.ScannedAt = s.now()
		if complete {
			// Objects read in an earlier pass and not listed in this one
			// are gone.
			if err := s.store.PruneBucketObjects(ctx, b.TenantID, b.ID, b.PassStartedAt); err != nil {
				return err
			}
			b.LastPassStartedAt, b.LastPassAt, b.LastPassObjects = b.PassStartedAt, b.ScannedAt, b.PassObjects
			b.Cursor, b.PassObjects, b.PassStartedAt = "", 0, time.Time{}
		}
		return s.store.SaveBucketProgress(ctx, b)
	}
	for cursor := b.Cursor; ; {
		if out.objects > 0 && (out.objects >= maxBucketObjects || bytes >= maxBucketBytes || time.Since(wall) > bucketRunBudget) {
			out.partial = true
			break
		}
		page, next, err := s.listPage(ctx, client, b, cred, cursor)
		if err != nil {
			_ = finish(false)
			return out, err
		}
		var (
			todo []bucketJob
			rows []BucketObject
			cut  bool // the byte budget ended inside this page
		)
		for _, o := range page {
			j := bucketJob{bucketObject: o, sniff: !scannable(o)}
			cost := o.size
			if j.sniff {
				if !b.Deep || probe || !sniffable(o) {
					continue
				}
				cost = sniffCost(o)
			}
			if old, ok := known[o.key]; ok && !probe && old.Rules == scanRules && o.unchangedSince(old.ETag, s.now()) {
				n, err := s.store.TouchAssets(ctx, b.TenantID, old.AssetIDs, scanID, s.now())
				if err != nil {
					return out, fmt.Errorf("mark unchanged assets seen: %w", err)
				}
				// Skipped only if every asset found in it is still in the
				// inventory; one that is not (removed, or never stored
				// because the scan stopped first) is found by reading again.
				if n == len(old.AssetIDs) {
					out.unchanged++
					out.kept += n
					rows = append(rows, BucketObject{TenantID: b.TenantID, BucketID: b.ID, Key: o.key, ETag: old.ETag, Size: o.size, AssetIDs: old.AssetIDs, Rules: scanRules})
					continue
				}
			}
			if bytes+cost > maxBucketBytes && bytes > 0 {
				cut = true
				break
			}
			bytes += cost
			if todo = append(todo, j); probe {
				break
			}
		}
		jobs := make(chan bucketJob)
		var wg sync.WaitGroup
		for i := 0; i < min(bucketWorkers, len(todo)); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for o := range jobs {
					raw, err := s.fetchObject(ctx, client, b, cred, o)
					var found []CryptoAsset
					if err == nil && raw != nil {
						found, err = s.fileAssets(b.TenantID, scanID, "storage", label+"/"+o.key, o.key, raw)
						for _, a := range found {
							a.Metadata["endpoint"], a.Metadata["bucket"], a.Metadata["key"], a.Metadata["provider"] = b.Endpoint, b.Name, o.key, b.Provider
						}
					}
					mu.Lock()
					if o.sniff {
						out.sniffed++
					}
					if raw != nil {
						out.files++
						out.assets = append(out.assets, found...)
					}
					if err != nil {
						out.unreadable = append(out.unreadable, o.key+": "+err.Error())
					} else {
						ids := make([]string, 0, len(found))
						for _, a := range found {
							ids = append(ids, a.ID)
						}
						rows = append(rows, BucketObject{TenantID: b.TenantID, BucketID: b.ID, Key: o.key, ETag: o.recorded(s.now()), Size: o.size, AssetIDs: ids, Rules: scanRules})
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
		if probe {
			out.objects = len(page)
			break
		}
		if err := s.store.PutBucketObjects(ctx, rows, s.now()); err != nil {
			return out, fmt.Errorf("record scan state: %w", err)
		}
		if cut {
			// This page is listed again next run; what was read of it is
			// skipped by ETag.
			out.partial = true
			break
		}
		out.objects += len(page)
		b.PassObjects += len(page)
		b.Cursor = next
		if cursor = next; cursor == "" {
			break
		}
	}
	if err := finish(!out.partial && !probe); err != nil {
		return out, fmt.Errorf("record scan progress: %w", err)
	}
	if n := len(out.unreadable); n > 0 {
		sort.Strings(out.unreadable)
		return out, fmt.Errorf("%d objects could not be read, the first: %s", n, out.unreadable[0])
	}
	return out, nil
}

// scanStorage scans every bucket the tenant added, the one scanned longest
// ago first. A bucket that fails is an error naming it; the others are still
// scanned. A bucket too large for one run is not an error: it continues
// with the next scan.
func (s *Service) scanStorage(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, map[string]interface{}, error) {
	buckets, err := s.store.ListBuckets(ctx, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("read buckets: %w", err)
	}
	if len(buckets) == 0 {
		return nil, nil, fmt.Errorf("%w: add a bucket in Crypto Discovery", errScanNotConfigured)
	}
	sort.SliceStable(buckets, func(i, j int) bool { return buckets[i].ScannedAt.Before(buckets[j].ScannedAt) })
	guard := s.targetGuard(ctx)
	var (
		assets []CryptoAsset
		failed []string
		total  bucketScan
		inPass int
	)
	for _, b := range buckets {
		res, err := s.scanBucket(ctx, guard, b, scanID, false)
		assets = append(assets, res.assets...)
		total.objects += res.objects
		total.files += res.files
		total.sniffed += res.sniffed
		total.unchanged += res.unchanged
		total.kept += res.kept
		if res.partial {
			inPass++
		}
		if err != nil {
			failed = append(failed, b.label()+": "+err.Error())
		}
	}
	stats := map[string]interface{}{
		"storage_buckets": len(buckets), "storage_objects": total.objects, "storage_files": total.files, "storage_sniffed": total.sniffed,
		"storage_unchanged": total.unchanged, "storage_assets_unchanged": total.kept, "storage_buckets_continuing": inPass,
	}
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
	Deep         bool   `json:"deep"`
}

func (s *Service) AddBucket(ctx context.Context, tenantID string, in BucketInput, actor string) (Bucket, error) {
	b, err := normalizeBucket(in.Provider, in.Endpoint, in.Name, in.Prefix, in.Region)
	if err != nil {
		return Bucket{}, err
	}
	b.ID, b.TenantID, b.ConnectionID, b.CreatedBy, b.Deep = newID("bucket"), tenantID, strings.TrimSpace(in.ConnectionID), actor, in.Deep
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
	if err := s.store.DeleteBucket(ctx, tenantID, id); err != nil {
		return b, err
	}
	// Its scan state goes with it; its assets stay until removed or stale.
	return b, s.store.PruneBucketObjects(ctx, tenantID, id, time.Time{})
}

// storageStaleBefore: a storage asset last seen before this was not found
// by a complete pass of any bucket. Zero while a bucket has yet to complete
// its first pass: until then nothing can be called missing.
func (s *Service) storageStaleBefore(ctx context.Context, tenantID string) (time.Time, error) {
	buckets, err := s.store.ListBuckets(ctx, tenantID)
	if err != nil {
		return time.Time{}, err
	}
	var oldest time.Time
	for _, b := range buckets {
		if b.LastPassStartedAt.IsZero() {
			return time.Time{}, nil
		}
		if oldest.IsZero() || b.LastPassStartedAt.Before(oldest) {
			oldest = b.LastPassStartedAt
		}
	}
	return oldest, nil
}

// TestBucket lists the first page of the bucket and reads one object with
// its connection. It stores nothing.
func (s *Service) TestBucket(ctx context.Context, tenantID, id string) (Bucket, bucketScan, error) {
	b, err := s.bucket(ctx, tenantID, id)
	if err != nil {
		return Bucket{}, bucketScan{}, err
	}
	res, err := s.scanBucket(ctx, s.targetGuard(ctx), b, "", true)
	return b, res, err
}
