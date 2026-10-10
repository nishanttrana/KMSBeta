package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	testTempKey    = "ASIATEMPORARY0000001"
	testTempSecret = "temp/secret+from=sts-for-one-scan"
	testTempToken  = "FwoGZXIvYXdzEJr//session+token/for=the+role=="
	testEntraToken = "entra.access.token-for-storage"
	testGoogleTok  = "ya29.google-access-token-for-storage"
)

// sdkSigned signs the request a server received with the AWS SDK's signer,
// for the credentials and service given.
func sdkSigned(t *testing.T, r *http.Request, creds aws.Credentials, service, region string) string {
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
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, ref, r.Header.Get("X-Amz-Content-Sha256"), service, region, at, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }); err != nil {
		t.Fatal(err)
	}
	return ref.Header.Get("Authorization")
}

// With a role, the stored key signs one AssumeRole call to STS and the
// bucket is read with the temporary credentials, session token included.
func TestS3AssumesItsRole(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	objects := bucketObjects(t)
	base := aws.Credentials{AccessKeyID: testS3Key, SecretAccessKey: testS3Secret}
	temp := aws.Credentials{AccessKeyID: testTempKey, SecretAccessKey: testTempSecret, SessionToken: testTempToken}
	refuse := false
	var stsQuery url.Values
	sts := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != sdkSigned(t, r, base, "sts", "eu-west-1") {
			writeXML(w, http.StatusForbidden, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>internal detail</Message></Error></ErrorResponse>`)
			return
		}
		if refuse {
			writeXML(w, http.StatusForbidden, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User arn:aws:iam::1:user/x is not authorized to perform sts:AssumeRole (internal detail)</Message></Error></ErrorResponse>`)
			return
		}
		stsQuery = r.URL.Query()
		writeXML(w, http.StatusOK, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>`+testTempKey+`</AccessKeyId><SecretAccessKey>`+testTempSecret+`</SecretAccessKey><SessionToken>`+xmlText(testTempToken)+`</SessionToken></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	})
	inner := newS3Server(t, objects, false)
	s3 := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Only the temporary credentials open the bucket.
		if r.Header.Get("X-Amz-Security-Token") != testTempToken || r.Header.Get("Authorization") != sdkSigned(t, r, temp, "s3", "eu-west-1") {
			writeXML(w, http.StatusForbidden, `<Error><Code>InvalidAccessKeyId</Code></Error>`)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	})
	trust(t, svc, sts, s3, inner)
	svc.stsURL = sts.URL + "/%s"
	conn := s3Connection(srvHost(s3))
	conn.Fields["role_arn"], conn.Fields["external_id"] = "arn:aws:iam::123456789012:role/kms/scanner", "vecta-discovery"
	svc.conns = stubConnections{"c1": conn}
	b := Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: s3.URL, Name: "acme-artifacts", Prefix: "app/", Region: "eu-west-1", ConnectionID: "c1"}
	res, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := assetLines(res.assets, b.label()); !reflect.DeepEqual(got, wantBucketAssets) {
		t.Fatalf("assets\n got %q\nwant %q", got, wantBucketAssets)
	}
	if stsQuery.Get("Action") != "AssumeRole" || stsQuery.Get("RoleArn") != conn.Fields["role_arn"] || stsQuery.Get("ExternalId") != "vecta-discovery" || stsQuery.Get("DurationSeconds") != "900" {
		t.Fatalf("STS was asked %v", stsQuery)
	}
	// One call, signed for the sts service with the stored key.
	if n := len(sts.requests()); n != 1 || !strings.Contains(sts.requests()[0], "Credential="+testS3Key+"/20") || !strings.Contains(sts.requests()[0], "/eu-west-1/sts/aws4_request") {
		t.Fatalf("STS requests: %d %q", n, sts.requests())
	}
	raw, _ := json.Marshal(res.assets)
	for _, secret := range []string{testTempSecret, testTempToken, testS3Secret} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("a credential reached the assets")
		}
	}

	// STS refuses: its code is reported, nothing else, and the bucket is
	// never asked.
	refuse = true
	before := len(s3.requests())
	_, err = svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false)
	if err == nil || !strings.Contains(err.Error(), "AWS STS refused to assume the role (AccessDenied): HTTP 403") || strings.Contains(err.Error(), "internal detail") || strings.Contains(err.Error(), "arn:aws:iam::1") || len(s3.requests()) != before {
		t.Fatalf("refused role: %v (%d bucket requests)", err, len(s3.requests())-before)
	}
	// A role that is not an ARN is refused before any request.
	conn.Fields["role_arn"] = "scanner"
	if _, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false); err == nil || !strings.Contains(err.Error(), errConnectionUnfit.Error()) {
		t.Fatalf("bad role: %v", err)
	}
}

// sharedKeyOf computes an Azure Shared Key authorization for a received
// request with the standard library, separately from the service's code.
func sharedKeyOf(r *http.Request, account string, key []byte) string {
	u, _ := url.Parse("https://" + r.Host + r.RequestURI)
	resource := "/" + account + u.EscapedPath()
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		resource += "\n" + strings.ToLower(k) + ":" + strings.Join(q[k], ",")
	}
	lines := []string{"GET", "", "", "", "", "", "", "", "", "", "", r.Header.Get("Range"),
		"x-ms-date:" + r.Header.Get("x-ms-date"), "x-ms-version:" + r.Header.Get("x-ms-version"), resource}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Join(lines, "\n")))
	return "SharedKey " + account + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// An Azure container is read with the account's Shared Key (every request
// signed, ranged reads included) or with an Entra ID application's token.
func TestAzureSharedKeyAndEntraID(t *testing.T) {
	objects := bucketObjects(t)
	objects["app/backups/store.dat"] = string(jksBytes) // found by a ranged read
	accountKey := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	want := append([]string{"keystore||exposed|app/backups/store.dat"}, wantBucketAssets...)
	sort.Strings(want)

	listing := func(w http.ResponseWriter, r *http.Request) {
		container, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		q := r.URL.Query()
		switch {
		case container != "acme-artifacts":
			writeXML(w, http.StatusNotFound, `<Error><Code>ContainerNotFound</Code></Error>`)
		case key != "":
			http.ServeContent(w, r, "", time.Time{}, strings.NewReader(objects[key]))
		default:
			keys, next := page(objects, q.Get("prefix"), q.Get("marker"))
			out := `<EnumerationResults><Blobs>`
			for _, k := range keys {
				out += `<Blob><Name>` + xmlText(k) + `</Name><Properties><Content-Length>` + strconv.Itoa(len(objects[k])) + `</Content-Length><Etag>` + etagOf(objects[k]) + `</Etag></Properties></Blob>`
			}
			writeXML(w, http.StatusOK, out+`</Blobs><NextMarker>`+xmlText(next)+`</NextMarker></EnumerationResults>`)
		}
	}

	t.Run("shared key", func(t *testing.T) {
		svc, _, _ := newDiscoveryService(t)
		srv := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("x-ms-date") == "" || r.Header.Get("Authorization") != sharedKeyOf(r, "acmestore", accountKey) {
				writeXML(w, http.StatusForbidden, `<Error><Code>AuthenticationFailed</Code><Message>The MAC signature found in the HTTP request is not the same as any computed signature. internal detail</Message></Error>`)
				return
			}
			listing(w, r)
		})
		trust(t, svc, srv)
		conn := ResolvedConnection{Type: "azure_blob", Endpoint: srvHost(srv), Fields: map[string]string{"account_key": base64.StdEncoding.EncodeToString(accountKey), "account_name": "acmestore"}}
		svc.conns = stubConnections{"c1": conn}
		b := Bucket{ID: "b1", TenantID: "t1", Provider: "azure", Endpoint: srv.URL, Name: "acme-artifacts", Prefix: "app/", ConnectionID: "c1", Deep: true}
		res, err := svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false)
		if err != nil {
			t.Fatal(err)
		}
		if got := assetLines(res.assets, b.label()); !reflect.DeepEqual(got, want) || res.sniffed == 0 {
			t.Fatalf("assets (%d sniffed)\n got %q\nwant %q", res.sniffed, got, want)
		}
		// The key itself is never sent, and a wrong one is refused with the
		// service's code only.
		for _, r := range srv.requests() {
			if strings.Contains(r, conn.Fields["account_key"]) {
				t.Fatal("the account key was sent")
			}
		}
		conn.Fields["account_key"] = base64.StdEncoding.EncodeToString([]byte("another-key-of-enough-length-0000"))
		_, err = svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false)
		if err == nil || !strings.Contains(err.Error(), "access denied (AuthenticationFailed)") || strings.Contains(err.Error(), "internal detail") {
			t.Fatalf("wrong key: %v", err)
		}
		// Without a name, and with an address that is not account.host, the
		// account can't be known.
		delete(conn.Fields, "account_name")
		if _, err := svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false); err == nil || !strings.Contains(err.Error(), "set account_name") {
			t.Fatalf("no account name: %v", err)
		}
	})

	t.Run("entra id", func(t *testing.T) {
		svc, _, _ := newDiscoveryService(t)
		var form url.Values
		reject := false
		login := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			form = r.PostForm
			if reject || r.URL.Path != "/acme.onmicrosoft.com/oauth2/v2.0/token" || r.PostForm.Get("client_secret") != "entra-client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. internal detail"}`))
				return
			}
			_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"` + testEntraToken + `"}`))
		})
		srv := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+testEntraToken || r.Header.Get("x-ms-version") == "" {
				writeXML(w, http.StatusUnauthorized, `<Error><Code>InvalidAuthenticationInfo</Code></Error>`)
				return
			}
			listing(w, r)
		})
		trust(t, svc, srv, login)
		svc.entraURL = login.URL
		svc.conns = stubConnections{"c1": {Type: "azure_blob", Endpoint: srvHost(srv), Fields: map[string]string{"azure_tenant_id": "acme.onmicrosoft.com", "client_id": "app-id", "client_secret": "entra-client-secret"}}}
		b := Bucket{ID: "b1", TenantID: "t1", Provider: "azure", Endpoint: srv.URL, Name: "acme-artifacts", Prefix: "app/", ConnectionID: "c1", Deep: true}
		res, err := svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false)
		if err != nil {
			t.Fatal(err)
		}
		if got := assetLines(res.assets, b.label()); !reflect.DeepEqual(got, want) {
			t.Fatalf("assets\n got %q\nwant %q", got, want)
		}
		if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != "app-id" || form.Get("scope") != "https://storage.azure.com/.default" || len(login.requests()) != 1 {
			t.Fatalf("token request %v (%d requests)", form, len(login.requests()))
		}
		// The client secret goes to the token endpoint only.
		for _, r := range srv.requests() {
			if strings.Contains(r, "entra-client-secret") {
				t.Fatal("the client secret was sent to the storage service")
			}
		}
		reject = true
		before := len(srv.requests())
		_, err = svc.scanBucket(context.Background(), svc.storageClient(nil), b, "s", false)
		if err == nil || !strings.Contains(err.Error(), "Entra ID refused the connection's credential (invalid_client): HTTP 401") || strings.Contains(err.Error(), "internal detail") || strings.Contains(err.Error(), "entra-client-secret") || len(srv.requests()) != before {
			t.Fatalf("refused application: %v", err)
		}
	})
}

// A Google bucket is read through the JSON API with a token obtained by a
// service account's signed assertion; a public one with no token at all.
func TestGCSServiceAccount(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return at }
	objects := bucketObjects(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "scan@acme.iam.gserviceaccount.com", "private_key_id": "kid-1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))})

	var claims map[string]interface{}
	var tokenURL string
	token := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		bad := func(why string) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + why + ` internal detail"}`))
		}
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 {
			bad("not an assertion")
			return
		}
		// Google verifies the assertion with the service account's public key.
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
			bad("bad signature")
			return
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(raw, &claims)
		if claims["aud"] != tokenURL || claims["iss"] != "scan@acme.iam.gserviceaccount.com" {
			bad("wrong audience or issuer")
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"` + testGoogleTok + `","expires_in":3599,"token_type":"Bearer"}`))
	})
	tokenURL = token.URL + "/token"
	private := true
	api := newHostingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if private && r.Header.Get("Authorization") != "Bearer "+testGoogleTok {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":403,"message":"scan@acme does not have storage.objects.list access (internal detail)","errors":[{"reason":"forbidden"}]}}`))
			return
		}
		// One path segment names the object: its slashes arrive escaped.
		const base = "/storage/v1/b/acme-artifacts/o"
		escaped := r.URL.EscapedPath()
		switch {
		case escaped == base:
			q := r.URL.Query()
			keys, next := page(objects, q.Get("prefix"), q.Get("pageToken"))
			type item struct {
				Name string `json:"name"`
				Size string `json:"size"`
				ETag string `json:"etag"`
			}
			out := struct {
				Items []item `json:"items"`
				Next  string `json:"nextPageToken,omitempty"`
			}{Next: next}
			for _, k := range keys {
				out.Items = append(out.Items, item{k, strconv.Itoa(len(objects[k])), etagOf(objects[k])})
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(escaped, base+"/") && !strings.Contains(strings.TrimPrefix(escaped, base+"/"), "/") && r.URL.Query().Get("alt") == "media":
			name, _ := url.PathUnescape(strings.TrimPrefix(escaped, base+"/"))
			http.ServeContent(w, r, "", time.Time{}, strings.NewReader(objects[name]))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"errors":[{"reason":"notFound"}]}}`))
		}
	})
	trust(t, svc, token, api)
	svc.googleURL = tokenURL
	svc.conns = stubConnections{"c1": {Type: "gcs", Endpoint: srvHost(api), Fields: map[string]string{"service_account_json": string(sa)}}}
	b := Bucket{ID: "b1", TenantID: "t1", Provider: "gcs", Endpoint: api.URL, Name: "acme-artifacts", Prefix: "app/", ConnectionID: "c1"}
	res, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := assetLines(res.assets, b.label()); !reflect.DeepEqual(got, wantBucketAssets) || res.objects != 8 {
		t.Fatalf("assets (%d objects)\n got %q\nwant %q", res.objects, got, wantBucketAssets)
	}
	if claims["scope"] != "https://www.googleapis.com/auth/devstorage.read_only" || claims["iat"] != float64(at.Unix()) || claims["exp"] != float64(at.Add(10*time.Minute).Unix()) || len(token.requests()) != 1 {
		t.Fatalf("assertion claims %v (%d token requests)", claims, len(token.requests()))
	}
	raw, _ := json.Marshal(res.assets)
	if strings.Contains(string(raw), testGoogleTok) || strings.Contains(string(raw), "BEGIN") {
		t.Fatal("a credential reached the assets")
	}

	// A public bucket: no connection, no token request.
	private = false
	pub := Bucket{ID: "b2", TenantID: "t1", Provider: "gcs", Endpoint: api.URL, Name: "acme-artifacts", Prefix: "app/"}
	if res, err := svc.scanBucket(ctx, svc.storageClient(nil), pub, "s", false); err != nil || len(res.assets) != 4 || len(token.requests()) != 1 {
		t.Fatalf("public bucket: %d assets, %v, %d token requests", len(res.assets), err, len(token.requests()))
	}
	private = true
	if _, err := svc.scanBucket(ctx, svc.storageClient(nil), pub, "s", false); err == nil || !strings.Contains(err.Error(), "access denied (forbidden): a private bucket needs a connection") || strings.Contains(err.Error(), "internal detail") {
		t.Fatalf("private bucket without a connection: %v", err)
	}

	// Google refuses the assertion (another project's key): its code only.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	o8, _ := x509.MarshalPKCS8PrivateKey(other)
	wrong, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "scan@acme.iam.gserviceaccount.com", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: o8}))})
	svc.conns = stubConnections{"c1": {Type: "gcs", Endpoint: srvHost(api), Fields: map[string]string{"service_account_json": string(wrong)}}}
	before := len(api.requests())
	_, err = svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false)
	if err == nil || !strings.Contains(err.Error(), "Google refused the connection's credential (invalid_grant): HTTP 400") || strings.Contains(err.Error(), "internal detail") || len(api.requests()) != before {
		t.Fatalf("refused assertion: %v", err)
	}
	// Not a service account key file at all.
	svc.conns = stubConnections{"c1": {Type: "gcs", Endpoint: srvHost(api), Fields: map[string]string{"service_account_json": `{"type":"authorized_user"}`}}}
	if _, err := svc.scanBucket(ctx, svc.storageClient(nil), b, "s", false); err == nil || !strings.Contains(err.Error(), errConnectionUnfit.Error()) {
		t.Fatalf("user key file: %v", err)
	}
}
