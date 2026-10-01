package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

const (
	testS3Key    = "AKIDSCANNER0000000001"
	testS3Secret = "s3cret/access+key=for-the-scanner"
	testSASSig   = "c2lnbmF0dXJl+/Zm9yLXRoZS1zY2FubmVy="
)

// bucketObjects is a bucket's content: key material under ordinary names,
// names that need escaping, and objects the scan must leave alone.
func bucketObjects(t *testing.T) map[string]string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
	return map[string]string{
		"app/deploy keys/id_rsa":       priv,
		"app/certs/server.crt":         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t, time.Now().Add(90*24*time.Hour))})),
		"app/config/prod+eu=1/.env":    "REGION=eu\nAWS_ACCESS_KEY_ID=" + testAKIA + "\nAPI_TOKEN=" + testHex + "\n",
		"app/données/état.yaml":        "name: état\n",
		"app/node_modules/dep/key.pem": priv,               // a dependency
		"app/logo.png":                 "\x89PNG not code", // not a scanned file type
		"app/empty.yaml":               "",
		"app/folder/":                  "",
		"other/id_rsa":                 priv, // outside the prefix
	}
}

var wantBucketAssets = []string{
	"certificate|ECDSA-P256|quantum_vulnerable|app/certs/server.crt:1",
	"cloud_access_key||exposed|app/config/prod+eu=1/.env:2",
	"hex_secret||exposed|app/config/prod+eu=1/.env:3",
	"private_key_material|RSA-2048|exposed|app/deploy keys/id_rsa:1",
}

func writeXML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header + body))
}

func xmlText(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

// page returns the keys under prefix after the key named by token, three
// at a time, and the token for the next page.
func page(objects map[string]string, prefix, token string) (keys []string, next string) {
	for k := range objects {
		if strings.HasPrefix(k, prefix) && k > token {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > 3 {
		keys, next = keys[:3], keys[2]
	}
	return keys, next
}

// sdkAuthorization signs the request a server received with the AWS SDK's
// own signer: the reference this service's signV4 must agree with.
func sdkAuthorization(t *testing.T, r *http.Request, region string) string {
	t.Helper()
	u, err := url.Parse("https://" + r.Host + r.RequestURI)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "unsigned"
	}
	ref := &http.Request{Method: r.Method, URL: u, Host: r.Host, Header: http.Header{}}
	ref.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
	err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: testS3Key, SecretAccessKey: testS3Secret}, ref,
		r.Header.Get("X-Amz-Content-Sha256"), "s3", region, at, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err != nil {
		t.Fatal(err)
	}
	return ref.Header.Get("Authorization")
}

// newS3Server speaks the two S3 calls the scan makes (ListObjectsV2 and
// GetObject, path style). With signed set it refuses a request whose
// signature differs from the AWS SDK's for the same request.
func newS3Server(t *testing.T, objects map[string]string, signed bool) *hostingServer {
	return newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if signed && r.Header.Get("Authorization") != sdkAuthorization(t, r, "eu-west-1") {
			writeXML(w, http.StatusForbidden, `<Error><Code>SignatureDoesNotMatch</Code><Message>internal detail the operator should not need</Message></Error>`)
			return
		}
		bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if bucket != "acme-artifacts" {
			writeXML(w, http.StatusNotFound, `<Error><Code>NoSuchBucket</Code></Error>`)
			return
		}
		if key != "" {
			body, ok := objects[key]
			if !ok {
				writeXML(w, http.StatusNotFound, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}
		q := r.URL.Query()
		if q.Get("list-type") != "2" {
			writeXML(w, http.StatusBadRequest, `<Error><Code>InvalidArgument</Code></Error>`)
			return
		}
		keys, next := page(objects, q.Get("prefix"), q.Get("continuation-token"))
		out := `<ListBucketResult><IsTruncated>` + strconv.FormatBool(next != "") + `</IsTruncated>`
		for _, k := range keys {
			out += `<Contents><Key>` + xmlText(k) + `</Key><Size>` + strconv.Itoa(len(objects[k])) + `</Size></Contents>`
		}
		if next != "" {
			out += `<NextContinuationToken>` + xmlText(next) + `</NextContinuationToken>`
		}
		writeXML(w, http.StatusOK, out+`</ListBucketResult>`)
	})
}

// newAzureServer speaks List Blobs and Get Blob for one container, and
// refuses a request without the SAS signature or the API version.
func newAzureServer(t *testing.T, objects map[string]string) *hostingServer {
	return newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("sig") != testSASSig || q.Get("sv") == "" || r.Header.Get("x-ms-version") == "" {
			writeXML(w, http.StatusForbidden, `<Error><Code>AuthenticationFailed</Code><Message>Signature did not match. String to sign used was internal detail</Message></Error>`)
			return
		}
		container, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if container != "acme-artifacts" {
			writeXML(w, http.StatusNotFound, `<Error><Code>ContainerNotFound</Code></Error>`)
			return
		}
		if key != "" {
			body, ok := objects[key]
			if !ok {
				writeXML(w, http.StatusNotFound, `<Error><Code>BlobNotFound</Code></Error>`)
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}
		if q.Get("restype") != "container" || q.Get("comp") != "list" {
			writeXML(w, http.StatusBadRequest, `<Error><Code>InvalidQueryParameterValue</Code></Error>`)
			return
		}
		keys, next := page(objects, q.Get("prefix"), q.Get("marker"))
		out := `<EnumerationResults><Blobs>`
		for _, k := range keys {
			out += `<Blob><Name>` + xmlText(k) + `</Name><Properties><Content-Length>` + strconv.Itoa(len(objects[k])) + `</Content-Length></Properties></Blob>`
		}
		writeXML(w, http.StatusOK, out+`</Blobs><NextMarker>`+xmlText(next)+`</NextMarker></EnumerationResults>`)
	})
}

func s3Connection(host string) ResolvedConnection {
	return ResolvedConnection{Type: "s3", Endpoint: host, Fields: map[string]string{"access_key_id": testS3Key, "secret_access_key": testS3Secret}}
}

func azureConnection(host string) ResolvedConnection {
	return ResolvedConnection{Type: "azure_blob", Endpoint: host, Fields: map[string]string{"sas_token": "?sv=2022-11-02&sp=rl&sr=c&sig=" + url.QueryEscape(testSASSig)}}
}

func srvHost(s *hostingServer) string {
	host, _, _ := strings.Cut(s.hostport(), ":")
	return host
}

func assetLines(assets []CryptoAsset, label string) []string {
	var got []string
	for _, a := range assets {
		got = append(got, a.AssetType+"|"+a.Algorithm+"|"+a.Classification+"|"+strings.TrimPrefix(a.Location, label+"/"))
	}
	sort.Strings(got)
	return got
}

func TestNormalizeBucket(t *testing.T) {
	for _, c := range []struct {
		provider, endpoint, name, prefix, region string
		want                                     Bucket
	}{
		{"s3", "", "acme-artifacts", "", "eu-west-1", Bucket{Provider: "s3", Endpoint: "https://s3.eu-west-1.amazonaws.com", Name: "acme-artifacts", Region: "eu-west-1"}},
		{"S3", " https://MinIO.corp.example:9000/ ", "builds", "/releases/2026/", "", Bucket{Provider: "s3", Endpoint: "https://minio.corp.example:9000", Name: "builds", Prefix: "releases/2026/", Region: "us-east-1"}},
		{"s3", "https://storage.googleapis.com:443", "acme_logs.eu", "", "auto", Bucket{Provider: "s3", Endpoint: "https://storage.googleapis.com", Name: "acme_logs.eu", Region: "auto"}},
		{"s3", "https://10.4.0.20", "ceph", "", "", Bucket{Provider: "s3", Endpoint: "https://10.4.0.20", Name: "ceph", Region: "us-east-1"}},
		{"azure", "https://acme.blob.core.windows.net", "configs", "prod/", "ignored", Bucket{Provider: "azure", Endpoint: "https://acme.blob.core.windows.net", Name: "configs", Prefix: "prod/"}},
	} {
		got, err := normalizeBucket(c.provider, c.endpoint, c.name, c.prefix, c.region)
		if err != nil || got != c.want {
			t.Errorf("normalizeBucket(%q, %q, %q) = %+v, %v; want %+v", c.provider, c.endpoint, c.name, got, err, c.want)
		}
	}
	for _, c := range [][5]string{
		{"gcs", "https://storage.googleapis.com", "acme", "", ""},                     // unknown provider
		{"azure", "", "configs", "", ""},                                              // no endpoint to default to
		{"s3", "http://minio.corp.example", "builds", "", ""},                         // not https
		{"s3", "https://AKID:secret@minio.corp.example", "builds", "", ""},            // credential in the endpoint
		{"azure", "https://acme.blob.core.windows.net?sv=1&sig=x", "configs", "", ""}, // SAS in the endpoint
		{"s3", "https://minio.corp.example/builds", "builds", "", ""},                 // bucket in the endpoint
		{"s3", "https://127.0.0.1", "builds", "", ""},                                 // loopback
		{"s3", "https://169.254.169.254", "builds", "", ""},                           // instance metadata
		{"s3", "", "Builds", "", ""},                                                  // upper case
		{"s3", "", "ab", "", ""},                                                      // too short
		{"s3", "", "builds/../etc", "", ""},
		{"s3", "", "builds", "a\x00b", ""},
		{"s3", "", "builds", "", "eu west"},
	} {
		if got, err := normalizeBucket(c[0], c[1], c[2], c[3], c[4]); !errors.Is(err, errInvalidBucket) {
			t.Errorf("%q accepted: %+v %v", c, got, err)
		}
	}
	if _, err := normalizeBucket("s3", "https://keycore:8010", "builds", "", ""); !errors.Is(err, errPlatformTarget) {
		t.Errorf("a platform host as a bucket endpoint: %v", err)
	}
}

// This service's request signature is the AWS SDK's for the same request,
// for names and tokens that need every kind of escaping.
func TestSignV4MatchesTheAWSSDK(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	at := time.Date(2026, 10, 1, 12, 30, 45, 0, time.UTC)
	svc.now = func() time.Time { return at }
	cred := bucketCredential{accessKey: testS3Key, secretKey: testS3Secret}
	var got []string
	srv := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"), sdkAuthorization(t, r, "eu-west-1"))
		w.WriteHeader(http.StatusNoContent)
	})
	trust(t, svc, srv)
	b := Bucket{Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Region: "eu-west-1", ConnectionID: "c"}
	client := svc.storageClient(nil)
	for _, c := range []struct {
		key string
		q   url.Values
	}{
		{"", url.Values{"list-type": {"2"}, "prefix": {"app/deploy keys/é+=&?"}, "continuation-token": {"1/abc+def==/~x y"}, "max-keys": {"1000"}}},
		{"plain/path.yaml", nil},
		{"app/deploy keys/id_rsa", nil},
		{"a+b=c&d@e:f,g;h$i!j*k'(l)/état #1?.env", nil},
		{"trailing/space .pem", nil},
	} {
		// 204 is not a success for the scan; only the signature matters here.
		_, _ = svc.bucketGet(context.Background(), client, b, cred, c.key, c.q)
	}
	if len(got) != 10 {
		t.Fatalf("%d requests reached the server", len(got)/2)
	}
	for i := 0; i < len(got); i += 2 {
		if got[i] == "" || got[i] != got[i+1] {
			t.Errorf("request %d\n signed %q\n    SDK %q", i/2, got[i], got[i+1])
		}
	}
}

// A bucket is listed page by page and each scannable object is read and
// inventoried: through S3 with a signature the server checks against the
// AWS SDK's, and through Azure Blob with a SAS token.
func TestStorageScanReadsS3AndAzure(t *testing.T) {
	objects := bucketObjects(t)
	for _, provider := range []string{"s3", "azure"} {
		t.Run(provider, func(t *testing.T) {
			svc, _, _ := newDiscoveryService(t)
			ctx := context.Background()
			var srv *hostingServer
			var conn ResolvedConnection
			if provider == "s3" {
				srv = newS3Server(t, objects, true)
				conn = s3Connection(srvHost(srv))
			} else {
				srv = newAzureServer(t, objects)
				conn = azureConnection(srvHost(srv))
			}
			trust(t, svc, srv)
			svc.conns = stubConnections{"c1": conn}
			b := Bucket{ID: "b1", TenantID: "t1", Provider: provider, Endpoint: srv.URL, Name: "acme-artifacts", Prefix: "app/", Region: "eu-west-1", ConnectionID: "c1"}
			if err := svc.store.CreateBucket(ctx, b); err != nil {
				t.Fatal(err)
			}
			assets, stats, err := svc.scanStorage(ctx, "t1", "scan_1")
			if err != nil {
				t.Fatal(err)
			}
			if got := assetLines(assets, b.label()); !reflect.DeepEqual(got, wantBucketAssets) {
				t.Fatalf("assets\n got %q\nwant %q", got, wantBucketAssets)
			}
			for _, a := range assets {
				if a.Source != "storage" || a.Metadata["bucket"] != "acme-artifacts" || a.Metadata["endpoint"] != srv.URL || a.Metadata["provider"] != provider ||
					!strings.HasPrefix(fmt.Sprint(a.Metadata["key"]), "app/") || assetClass(a) != a.Classification {
					t.Fatalf("asset %+v", a)
				}
			}
			// Eight objects are under the prefix; id_rsa, server.crt, .env
			// and état.yaml are read. The dependency, the image, the empty
			// file and the folder marker are not.
			if stats["storage_buckets"] != 1 || stats["storage_objects"] != 8 || stats["storage_files"] != 4 {
				t.Fatalf("stats %+v", stats)
			}
			lists, gets := 0, 0
			for _, r := range srv.requests() {
				uri, _, _ := strings.Cut(r, " | ")
				if p, _, _ := strings.Cut(uri, "?"); p == "/acme-artifacts" {
					lists++
				} else {
					gets++
				}
				if strings.Contains(uri, "node_modules") || strings.Contains(uri, "logo.png") || strings.Contains(uri, "/other/") {
					t.Fatalf("read an object the scan should leave alone: %s", uri)
				}
			}
			if lists != 3 || gets != 4 {
				t.Fatalf("%d listings and %d reads, want 3 and 4: %q", lists, gets, srv.requests())
			}
			raw, _ := json.Marshal(assets)
			for _, secret := range []string{testAKIA, testHex, testS3Secret, testSASSig, url.QueryEscape(testSASSig), "BEGIN"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("a secret reached the assets: %s", raw)
				}
			}
			// The whole scan: the source is recorded and its secrets raise
			// the incident event once.
			scan, err := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"storage"}})
			if err != nil {
				t.Fatal(err)
			}
			if done := finishScan(t, svc, scan); done.Status != "completed" || extractInt(done.Stats["storage_assets"]) != 4 {
				t.Fatalf("scan %s %+v", done.Status, done.Stats)
			}
			if _, n, _ := svc.FindAssets(ctx, "t1", 10, 0, AssetFilter{Source: "storage", Classes: []string{"exposed"}}); n != 3 {
				t.Fatalf("%d exposed storage assets, want 3", n)
			}
		})
	}
}

// A public bucket is read with no credential.
func TestStoragePublicBucketSendsNoCredential(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	srv := newS3Server(t, bucketObjects(t), false)
	trust(t, svc, srv)
	_ = svc.store.CreateBucket(context.Background(), Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Region: "us-east-1"})
	assets, _, err := svc.scanStorage(context.Background(), "t1", "s")
	if err != nil || len(assets) != 5 { // the four under app/ and other/id_rsa
		t.Fatalf("%d assets, %v", len(assets), err)
	}
	for _, r := range srv.requests() {
		if !strings.HasSuffix(r, " | ") {
			t.Fatalf("a public bucket sent a credential: %q", r)
		}
	}
}

// A credential goes only to the host its connection names, in a connection
// of the provider's type, and never follows a redirect.
func TestStorageCredentialStaysOnItsHost(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	objects := bucketObjects(t)
	elsewhere := newS3Server(t, objects, false)
	redirecting := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
	trust(t, svc, redirecting, elsewhere)
	host := srvHost(redirecting)
	_ = svc.store.CreateBucket(ctx, Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: redirecting.URL, Name: "acme-artifacts", Region: "eu-west-1", ConnectionID: "c1"})

	svc.conns = stubConnections{"c1": s3Connection(host)}
	assets, _, err := svc.scanStorage(ctx, "t1", "s")
	if err == nil || len(assets) != 0 || !strings.Contains(err.Error(), "another address") {
		t.Fatalf("redirected listing: %d assets, %v", len(assets), err)
	}
	if got := elsewhere.requests(); len(got) != 0 {
		t.Fatalf("the redirect was followed: %q", got)
	}

	for name, conn := range map[string]ResolvedConnection{
		"other host":     s3Connection("s3.amazonaws.com"),
		"other provider": azureConnection(host),
		"other type":     {Type: "git", Endpoint: host, Fields: map[string]string{"token": "s3cret-token"}},
		"short secret":   {Type: "s3", Endpoint: host, Fields: map[string]string{"access_key_id": testS3Key, "secret_access_key": "tiny"}},
	} {
		svc.conns = stubConnections{"c1": conn}
		before := len(redirecting.requests())
		_, _, err := svc.scanStorage(ctx, "t1", "s")
		if err == nil || !strings.Contains(err.Error(), errConnectionUnfit.Error()) || len(redirecting.requests()) != before {
			t.Fatalf("%s: err %v, requests %d -> %d", name, err, before, len(redirecting.requests()))
		}
		for _, secret := range []string{testS3Secret, testSASSig, "s3cret-token", "tiny"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: credential in the error: %v", name, err)
			}
		}
	}
	svc.conns = stubConnections{}
	if _, _, err := svc.scanStorage(ctx, "t1", "s"); err == nil || !strings.Contains(err.Error(), "connection c1") {
		t.Fatalf("missing connection: %v", err)
	}
	if _, _, err := svc.scanStorage(ctx, "t2", "s"); !errors.Is(err, errScanNotConfigured) {
		t.Fatalf("tenant with no buckets: %v", err)
	}
}

// A storage service's refusal is reported with its error code and nothing
// else of its answer, and a SAS token never reaches an error.
func TestStorageScanReportsRefusals(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	objects := bucketObjects(t)

	s3 := newS3Server(t, objects, true)
	azure := newAzureServer(t, objects)
	trust(t, svc, s3, azure)
	wrong := s3Connection(srvHost(s3))
	wrong.Fields["secret_access_key"] = "not-the-right-secret-key"
	badSAS := azureConnection(srvHost(azure))
	badSAS.Fields["sas_token"] = "sv=2022-11-02&sig=d3Jvbmctc2lnbmF0dXJl"
	svc.conns = stubConnections{"s3": wrong, "az": badSAS}
	_ = svc.store.CreateBucket(ctx, Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: s3.URL, Name: "acme-artifacts", Region: "eu-west-1", ConnectionID: "s3"})
	_ = svc.store.CreateBucket(ctx, Bucket{ID: "b2", TenantID: "t1", Provider: "azure", Endpoint: azure.URL, Name: "acme-artifacts", ConnectionID: "az"})
	_ = svc.store.CreateBucket(ctx, Bucket{ID: "b3", TenantID: "t1", Provider: "s3", Endpoint: s3.URL, Name: "no-such-bucket", Region: "eu-west-1"})
	assets, _, err := svc.scanStorage(ctx, "t1", "s")
	if err == nil || len(assets) != 0 {
		t.Fatalf("%d assets, %v", len(assets), err)
	}
	for _, want := range []string{"3 of 3 buckets failed", "access denied (SignatureDoesNotMatch): check the connection's credential", "access denied (AuthenticationFailed)", "a private bucket needs a connection"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	for _, leak := range []string{"internal detail", "String to sign", "d3Jvbmctc2lnbmF0dXJl", "not-the-right-secret-key", "sig="} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error carries %q: %v", leak, err)
		}
	}

	// A server that can't be reached: the error names no URL, so no SAS.
	azure.Close()
	svc.conns = stubConnections{"az": azureConnection(srvHost(azure))}
	_, err = svc.scanBucket(ctx, svc.storageClient(nil), Bucket{TenantID: "t1", Provider: "azure", Endpoint: azure.URL, Name: "acme-artifacts", ConnectionID: "az"}, "s", false)
	if err == nil || strings.Contains(err.Error(), "sig") || strings.Contains(err.Error(), "c2lnbmF0dXJl") {
		t.Fatalf("unreachable server: %v", err)
	}
}

// A bucket over the caps stops with what was found so far, and an object
// that can't be read is named while the others are still scanned.
func TestStorageLimitsAndUnreadableObjects(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	objects := bucketObjects(t)
	srv := newS3Server(t, objects, false)
	trust(t, svc, srv)
	b := Bucket{TenantID: "t1", Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Prefix: "app/", Region: "us-east-1"}
	client := svc.storageClient(nil)

	oldObjects, oldBytes := maxBucketObjects, maxBucketBytes
	defer func() { maxBucketObjects, maxBucketBytes = oldObjects, oldBytes }()
	maxBucketObjects = 5
	if res, err := svc.scanBucket(ctx, client, b, "s", false); !errors.Is(err, errBucketTooLarge) || res.files == 0 || res.files >= 4 {
		t.Fatalf("over the object cap: %d files, %v", res.files, err)
	}
	maxBucketObjects, maxBucketBytes = oldObjects, 600
	if res, err := svc.scanBucket(ctx, client, b, "s", false); !errors.Is(err, errBucketTooLarge) || res.files >= 4 {
		t.Fatalf("over the byte cap: %d files, %v", res.files, err)
	}
	maxBucketBytes = oldBytes

	// Listed, then gone before it is read.
	listed := map[string]string{}
	for k, v := range objects {
		listed[k] = v
	}
	vanishing := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/id_rsa") {
			writeXML(w, http.StatusNotFound, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		srv.Config.Handler.ServeHTTP(w, r)
	})
	trust(t, svc, srv, vanishing)
	b.Endpoint = vanishing.URL
	res, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false)
	if err == nil || !strings.Contains(err.Error(), "1 objects could not be read, the first: app/deploy keys/id_rsa: bucket or object not found (NoSuchKey)") {
		t.Fatalf("unreadable object: %v", err)
	}
	if res.files != 3 || len(res.assets) != 3 {
		t.Fatalf("%d files, %d assets after one unreadable object", res.files, len(res.assets))
	}

	// Not a listing at all.
	html := newHostingServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>sign in")) })
	trust(t, svc, html)
	b.Endpoint = html.URL
	if _, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false); err == nil || !strings.Contains(err.Error(), "did not return a listing") {
		t.Fatalf("an HTML page read as a listing: %v", err)
	}
}

// Bucket routes: each refusal is audited with its reason, a credential in
// an endpoint is never copied to the audit, and a test that can't read the
// bucket fails.
func TestBucketRoutesAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	srv := newS3Server(t, bucketObjects(t), true)
	trust(t, svc, srv)
	svc.conns = stubConnections{
		"aws":   s3Connection("s3.eu-west-1.amazonaws.com"),
		"azure": azureConnection("acme.blob.core.windows.net"),
		"git":   {Type: "git", Endpoint: "s3.eu-west-1.amazonaws.com", Fields: map[string]string{"token": "s3cret-token"}},
	}
	post := func(who *pkgauth.Claims, body string) *httptest.ResponseRecorder {
		return serveAs(h, who, http.MethodPost, "/discovery/buckets", body)
	}
	if rr := post(testReadonly, `{"provider":"s3","bucket":"acme-artifacts"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("add as discovery.read: %d", rr.Code)
	}
	expectAudit(t, rec, "bucket_add", route.ResultRefused, route.ReasonPermissionDenied)

	for body, reason := range map[string]string{
		`{"provider":"gcs","bucket":"acme-artifacts"}`:                                                              "invalid_bucket",
		`{"provider":"s3","endpoint":"http://minio.corp.example","bucket":"builds"}`:                                "invalid_bucket",
		`{"provider":"s3","endpoint":"https://AKID:wJalrSecret@minio.corp.example","bucket":"builds"}`:              "invalid_bucket",
		`{"provider":"azure","endpoint":"https://acme.blob.core.windows.net?sv=1&sig=c2FzLXNlY3JldA","bucket":"c"}`: "invalid_bucket",
		`{"provider":"s3","endpoint":"https://127.0.0.1","bucket":"builds"}`:                                        "invalid_bucket",
		`{"provider":"s3","endpoint":"https://keycore:8010","bucket":"builds"}`:                                     "platform_target",
		`{"provider":"s3","region":"us-west-2","bucket":"acme-artifacts","connection_id":"aws"}`:                    "connection_unfit", // another host
		`{"provider":"s3","region":"eu-west-1","bucket":"acme-artifacts","connection_id":"git"}`:                    "connection_unfit",
		`{"provider":"s3","region":"eu-west-1","bucket":"acme-artifacts","connection_id":"azure"}`:                  "connection_unfit",
	} {
		if rr := post(testWriter, body); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body)
		}
		ev := expectAudit(t, rec, "bucket_add", route.ResultRefused, reason)
		raw, _ := json.Marshal(ev)
		for _, secret := range []string{"wJalrSecret", "c2FzLXNlY3JldA", testS3Secret, testSASSig, "s3cret-token"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("credential in the audit event: %s", raw)
			}
		}
	}
	if rr := post(testWriter, `{"provider":"s3","bucket":"acme-artifacts","connection_id":"gone"}`); rr.Code != http.StatusBadGateway {
		t.Fatalf("missing connection: %d %s", rr.Code, rr.Body)
	}

	rr := post(testWriter, `{"provider":"s3","region":"eu-west-1","bucket":"acme-artifacts","prefix":"/app/","connection_id":"aws"}`)
	var created struct{ Bucket Bucket }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if b := created.Bucket; rr.Code != http.StatusCreated || b.Endpoint != "https://s3.eu-west-1.amazonaws.com" || b.Prefix != "app/" || b.CreatedBy != "w" || b.ConnectionID != "aws" {
		t.Fatalf("add: %d %s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), testS3Secret) {
		t.Fatal("secret key in the response")
	}
	expectAudit(t, rec, "bucket_add", route.ResultSuccess, "")
	if rr := post(testWriter, `{"provider":"s3","region":"eu-west-1","bucket":"acme-artifacts","prefix":"app/"}`); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rr.Code)
	}
	expectAudit(t, rec, "bucket_add", route.ResultRefused, "bucket_exists")

	if rr := serveAs(h, testReadonly, http.MethodGet, "/discovery/buckets", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), created.Bucket.ID) || strings.Contains(rr.Body.String(), testS3Secret) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	expectAudit(t, rec, "buckets_list", route.ResultSuccess, "")
	src, _ := svc.Sources(context.Background(), "t1")
	if s := src[4]; s.ID != "storage" || !s.Configured || s.Detail["buckets"] != 1 || s.Detail["private"] != 1 {
		t.Fatalf("storage source: %+v", s)
	}

	// The test pool doesn't trust the real service's certificate: the test
	// fails, and says so.
	path := "/discovery/buckets/" + created.Bucket.ID
	if rr := serveAs(h, testWriter, http.MethodPost, path+"/test", ""); rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "bucket_unreachable") {
		t.Fatalf("test of an unreadable bucket: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Action != "bucket_test" || ev.Event.Result == route.ResultSuccess {
		t.Fatalf("failed test audited as %s %s", ev.Action, ev.Event.Result)
	}
	other := &pkgauth.Claims{UserID: "o", TenantID: "t2", Permissions: []string{"discovery.write"}}
	if rr := serveAs(h, other, http.MethodDelete, path, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("remove another tenant's bucket: %d", rr.Code)
	}
	if rr := serveAs(h, testWriter, http.MethodDelete, path, ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body)
	}
	expectAudit(t, rec, "bucket_remove", route.ResultSuccess, "")

	// A bucket that can be read: the test lists it and reads one object,
	// and stores nothing.
	svc.conns = stubConnections{"c1": s3Connection(srvHost(srv))}
	_ = svc.store.CreateBucket(context.Background(), Bucket{ID: "b9", TenantID: "t1", Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Prefix: "app/", Region: "eu-west-1", ConnectionID: "c1"})
	rr = serveAs(h, testWriter, http.MethodPost, "/discovery/buckets/b9/test", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"objects_listed":3`) || !strings.Contains(rr.Body.String(), `"objects_read":1`) {
		t.Fatalf("test: %d %s", rr.Code, rr.Body)
	}
	if ev := expectAudit(t, rec, "bucket_test", route.ResultSuccess, ""); ev.Details["objects_read"] != 1 {
		t.Fatalf("details %+v", ev.Details)
	}
	if _, n, _ := svc.FindAssets(context.Background(), "t1", 10, 0, AssetFilter{Source: "storage"}); n != 0 {
		t.Fatalf("a test stored %d assets", n)
	}
}

// The per-tenant limit is refused and audited.
func TestBucketLimit(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	for i := 0; i < maxBucketsPerTenant; i++ {
		b := Bucket{ID: fmt.Sprintf("b%d", i), TenantID: "t1", Provider: "s3", Endpoint: "https://s3.us-east-1.amazonaws.com", Name: fmt.Sprintf("bucket-%d", i), Region: "us-east-1"}
		if err := svc.store.CreateBucket(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	if rr := serveAs(h, testWriter, http.MethodPost, "/discovery/buckets", `{"provider":"s3","bucket":"one-more"}`); rr.Code != http.StatusConflict {
		t.Fatalf("bucket %d: %d %s", maxBucketsPerTenant+1, rr.Code, rr.Body)
	}
	expectAudit(t, rec, "bucket_add", route.ResultRefused, "bucket_limit")
	// Another tenant has its own count.
	other := &pkgauth.Claims{UserID: "o", TenantID: "t2", Permissions: []string{"discovery.write"}}
	if rr := serveAs(h, other, http.MethodPost, "/discovery/buckets", `{"provider":"s3","bucket":"one-more"}`); rr.Code != http.StatusCreated {
		t.Fatalf("another tenant's first bucket: %d %s", rr.Code, rr.Body)
	}
}

// Opt-in check against a real storage service (needs one running): the
// bucket is listed and read through its real API with a real signature or
// SAS token. For S3 set VECTA_TEST_S3_ENDPOINT, VECTA_TEST_S3_BUCKET,
// VECTA_TEST_S3_ACCESS_KEY, VECTA_TEST_S3_SECRET_KEY and optionally
// VECTA_TEST_S3_REGION and VECTA_TEST_S3_PREFIX (no access key: a public
// bucket, read with no credential); for Azure Blob VECTA_TEST_AZURE_ENDPOINT,
// VECTA_TEST_AZURE_CONTAINER and VECTA_TEST_AZURE_SAS. VECTA_TEST_STORAGE_CA
// names a PEM file to trust for a private endpoint, and
// VECTA_TEST_STORAGE_MIN_ASSETS the least number of assets to expect.
func TestLiveObjectStorage(t *testing.T) {
	type live struct {
		b    Bucket
		conn ResolvedConnection
	}
	var cases []live
	host := func(endpoint string) string { u, _ := url.Parse(endpoint); return u.Hostname() }
	if ep := os.Getenv("VECTA_TEST_S3_ENDPOINT"); ep != "" {
		conn := ResolvedConnection{Type: "s3", Endpoint: host(ep), Fields: map[string]string{"access_key_id": os.Getenv("VECTA_TEST_S3_ACCESS_KEY"), "secret_access_key": os.Getenv("VECTA_TEST_S3_SECRET_KEY")}}
		b := Bucket{Provider: "s3", Endpoint: ep, Name: os.Getenv("VECTA_TEST_S3_BUCKET"), Prefix: os.Getenv("VECTA_TEST_S3_PREFIX"), Region: defaultString(os.Getenv("VECTA_TEST_S3_REGION"), "us-east-1")}
		if conn.Fields["access_key_id"] != "" {
			b.ConnectionID = "live"
		}
		cases = append(cases, live{b, conn})
	}
	if ep := os.Getenv("VECTA_TEST_AZURE_ENDPOINT"); ep != "" {
		conn := ResolvedConnection{Type: "azure_blob", Endpoint: host(ep), Fields: map[string]string{"sas_token": os.Getenv("VECTA_TEST_AZURE_SAS")}}
		cases = append(cases, live{Bucket{Provider: "azure", Endpoint: ep, Name: os.Getenv("VECTA_TEST_AZURE_CONTAINER"), ConnectionID: "live"}, conn})
	}
	if len(cases) == 0 {
		t.Skip("set VECTA_TEST_S3_ENDPOINT or VECTA_TEST_AZURE_ENDPOINT to scan a real storage service")
	}
	svc, _, _ := newDiscoveryService(t)
	if ca := os.Getenv("VECTA_TEST_STORAGE_CA"); ca != "" {
		raw, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		svc.repoRoots = x509.NewCertPool()
		if !svc.repoRoots.AppendCertsFromPEM(raw) {
			t.Fatalf("%s holds no certificate", ca)
		}
	}
	least, _ := strconv.Atoi(os.Getenv("VECTA_TEST_STORAGE_MIN_ASSETS"))
	for _, c := range cases {
		c.b.TenantID = "t1"
		svc.conns = stubConnections{"live": c.conn}
		res, err := svc.scanBucket(context.Background(), svc.storageClient(nil), c.b, "s", false)
		t.Logf("%s %s: %d objects listed, %d read, %d assets %q, err %v", c.b.Provider, c.b.label(), res.objects, res.files, len(res.assets), assetLines(res.assets, c.b.label()), err)
		if err != nil || len(res.assets) < least {
			t.Errorf("%s: %d assets (want at least %d), %v", c.b.label(), len(res.assets), least, err)
		}
		if c.b.ConnectionID == "" {
			continue
		}
		// A wrong credential is refused by the real service.
		for k := range c.conn.Fields {
			if k == "secret_access_key" {
				c.conn.Fields[k] += "x"
			} else if k == "sas_token" {
				c.conn.Fields[k] = strings.Replace(c.conn.Fields[k], "sig=", "sig=AAAA", 1)
			}
		}
		if _, err := svc.scanBucket(context.Background(), svc.storageClient(nil), c.b, "s", false); err == nil || !strings.Contains(err.Error(), "access denied") {
			t.Errorf("%s with a wrong credential: %v", c.b.label(), err)
		}
	}
}
