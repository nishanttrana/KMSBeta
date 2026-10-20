package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route/routetest"
)

// AWS KMS external key store: requests signed by the AWS SDK's SigV4 signer
// (service kms-xks-proxy), with the XKS proxy API v1 wire format.

// Appendix C's worked example.
func TestXKSCDIVMatchesTheSpecExample(t *testing.T) {
	h := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	aad := []byte("project=nile,department=marketing")
	meta := []byte("key_version=1")
	iv := h("1c ca e5 47 0f 39 70 02 54 77 90 31")
	ct := h("82 1c 64 2b 5b 71 78 33 67 de af 18")
	tag := h("bc 1c 4d da 77 07 d6 81 24 47 c5 95 5e 99 b2 61")
	if got := base64.StdEncoding.EncodeToString(xksCDIV(aad, meta, iv, ct, tag)); got != "qHA/ImC9h5HsLRXqCyPmWgYx7tzyoTplzILbP0fPXsc=" {
		t.Fatalf("CDIV %s", got)
	}
}

type xksFixture struct {
	h       *Handler
	svc     *Service
	keycore *fakeHYOKKeyCore
	pub     *nopHYOKPublisher
	rec     *routetest.Recorder
}

const (
	xksKey1    = "AKIAXKSONEEXAMPLE234567"
	xksSecret1 = "c2VjcmV0LW9uZS1mb3ItdGhlLXhrcy1wcm94eS10ZXN0"
	xksKey2    = "AKIAXKSTWOEXAMPLE234567"
	xksSecret2 = "c2VjcmV0LXR3by1mb3ItdGhlLXhrcy1wcm94eS10ZXN0"
)

func newXKSFixture(t *testing.T) *xksFixture {
	t.Helper()
	svc, _, keycore, _, _, pub := newHYOKService(t)
	keycore.Seed("tenant-a", "k-aes", "AES-256")
	keycore.Seed("tenant-a", "k-rsa", "RSA-2048")
	keycore.Seed("tenant-b", "k-b", "AES-256")
	svc.SetCredentials(&fakeCreds{byID: map[string]credstore.Credential{
		"pbconn_x1":   {ID: "pbconn_x1", Type: "aws_xks", Fields: map[string]string{"access_key_id": xksKey1, "secret_access_key": xksSecret1}},
		"pbconn_x2":   {ID: "pbconn_x2", Type: "aws_xks", Fields: map[string]string{"access_key_id": xksKey2, "secret_access_key": xksSecret2}},
		"pbconn_smtp": {ID: "pbconn_smtp", Type: "smtp", Fields: map[string]string{"host": "mail"}},
	}})
	if err := saveXKS(svc, "tenant-a", adminClaims(), AWSXKSMetadata{PathPrefix: "contoso/xks", CredentialIDs: []string{"pbconn_x1", "pbconn_x2"}, Keys: map[string]string{"xks-key-1": "k-aes"}}, false); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(svc, testJWTParser)
	rec := &routetest.Recorder{}
	h.MountKernel(rec, nil, "test")
	return &xksFixture{h: h, svc: svc, keycore: keycore, pub: pub, rec: rec}
}

func adminClaims() *pkgauth.Claims {
	return &pkgauth.Claims{TenantID: "tenant-a", UserID: "alice", Permissions: []string{"*"}}
}

func saveXKS(svc *Service, tenant string, claims *pkgauth.Claims, m AWSXKSMetadata, governance bool) error {
	raw, _ := json.Marshal(m)
	ctx := pkgauth.ContextWithClaims(context.Background(), claims)
	_, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: tenant, Protocol: ProtocolAWSXKS, Enabled: true, GovernanceRequired: governance, MetadataJSON: string(raw)})
	return err
}

// call signs as AWS KMS does, for the edge path, then serves the request as
// Envoy hands it on (prefix /svc/hyok rewritten to /).
func (f *xksFixture) call(t *testing.T, path string, body map[string]interface{}, keyID, secret string) (int, map[string]interface{}) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "https://kms.example.com/svc/hyok/xks/contoso/xks/kms/xks/v1/"+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if keyID != "" {
		sum := sha256.Sum256(raw)
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: keyID, SecretAccessKey: secret}, r, hex.EncodeToString(sum[:]), "kms-xks-proxy", "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/svc/hyok")
	r.RequestURI = r.URL.RequestURI()
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func meta(op string) map[string]interface{} {
	return map[string]interface{}{"kmsRequestId": "req-" + op, "kmsOperation": op, "awsPrincipalArn": "arn:aws:iam::123456789012:role/app", "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc"}
}

func dec(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAWSXKSEncryptsAndDecryptsAcrossRotation(t *testing.T) {
	f := newXKSFixture(t)
	code, health := f.call(t, "health", map[string]interface{}{"requestMetadata": map[string]string{"kmsRequestId": "h1", "kmsOperation": "KmsHealthCheck"}}, xksKey1, xksSecret1)
	if code != 200 || !strings.Contains(mustJSON(health), `"healthStatus":"ACTIVE"`) || health["xksProxyFleetSize"] != float64(1) {
		t.Fatalf("health %d %v", code, health)
	}
	code, md := f.call(t, "keys/xks-key-1/metadata", map[string]interface{}{"requestMetadata": meta("CreateKey")}, xksKey1, xksSecret1)
	if code != 200 || md["keySpec"] != "AES_256" || md["keyStatus"] != "ENABLED" || mustJSON(md["keyUsage"]) != `["ENCRYPT","DECRYPT"]` {
		t.Fatalf("metadata %d %v", code, md)
	}

	plain := bytes.Repeat([]byte{0x2a}, 32)
	aad := []byte("project=nile,department=marketing")
	code, enc := f.call(t, "keys/xks-key-1/encrypt", map[string]interface{}{
		"requestMetadata": meta("GenerateDataKey"), "plaintext": base64.StdEncoding.EncodeToString(plain),
		"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad), "encryptionAlgorithm": "AES_GCM",
		"ciphertextDataIntegrityValueAlgorithm": "SHA_256",
	}, xksKey1, xksSecret1)
	if code != 200 {
		t.Fatalf("encrypt %d %v", code, enc)
	}
	ct, md5, iv, tag := dec(t, enc["ciphertext"]), dec(t, enc["ciphertextMetadata"]), dec(t, enc["initializationVector"]), dec(t, enc["authenticationTag"])
	if len(ct) != len(plain) || len(iv) != 12 || len(tag) != 16 || len(md5) > 20 {
		t.Fatalf("sizes ct=%d iv=%d tag=%d meta=%d", len(ct), len(iv), len(tag), len(md5))
	}
	// AWS checks the CDIV itself, as Appendix C computes it.
	sum := sha256.Sum256(bytes.Join([][]byte{aad, md5, iv, ct, tag}, nil))
	if enc["ciphertextDataIntegrityValue"] != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("CDIV %v", enc["ciphertextDataIntegrityValue"])
	}
	// The wire value is AES-GCM under the key the KMS holds, over the AAD
	// the spec prescribes.
	direct, err := pkgcrypto.OpenDetached(f.keycore.current("tenant-a", "k-aes"), iv, append(append([]byte{}, ct...), tag...), xksAAD(aad, md5))
	if err != nil || !bytes.Equal(direct, plain) {
		t.Fatalf("output is not AES-GCM under the key: %v", err)
	}

	decryptBody := func(ct, tag, aad []byte) map[string]interface{} {
		return map[string]interface{}{
			"requestMetadata": meta("Decrypt"), "ciphertext": base64.StdEncoding.EncodeToString(ct), "ciphertextMetadata": enc["ciphertextMetadata"],
			"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad), "encryptionAlgorithm": "AES_GCM",
			"initializationVector": enc["initializationVector"], "authenticationTag": base64.StdEncoding.EncodeToString(tag),
		}
	}
	code, out := f.call(t, "keys/xks-key-1/decrypt", decryptBody(ct, tag, aad), xksKey1, xksSecret1)
	if code != 200 || out["plaintext"] != base64.StdEncoding.EncodeToString(plain) {
		t.Fatalf("decrypt %d %v", code, out)
	}

	// After rotation the old ciphertext still decrypts (its version rides in
	// ciphertextMetadata), with the second credential this time.
	f.keycore.Rotate("tenant-a", "k-aes")
	code, out = f.call(t, "keys/xks-key-1/decrypt", decryptBody(ct, tag, aad), xksKey2, xksSecret2)
	if code != 200 || out["plaintext"] != base64.StdEncoding.EncodeToString(plain) {
		t.Fatalf("decrypt after rotation %d %v", code, out)
	}
	code, enc2 := f.call(t, "keys/xks-key-1/encrypt", map[string]interface{}{"requestMetadata": meta("Encrypt"), "plaintext": base64.StdEncoding.EncodeToString(plain), "encryptionAlgorithm": "AES_GCM"}, xksKey1, xksSecret1)
	if code != 200 || enc2["ciphertextMetadata"] == enc["ciphertextMetadata"] {
		t.Fatalf("encrypt after rotation %d %v", code, enc2)
	}

	// Altered ciphertext, tag or AAD does not decrypt.
	badTag := append([]byte{}, tag...)
	badTag[0] ^= 1
	for name, body := range map[string]map[string]interface{}{
		"tag": decryptBody(ct, badTag, aad), "aad": decryptBody(ct, tag, []byte("other")), "no metadata": func() map[string]interface{} {
			b := decryptBody(ct, tag, aad)
			delete(b, "ciphertextMetadata")
			return b
		}(),
	} {
		code, out := f.call(t, "keys/xks-key-1/decrypt", body, xksKey1, xksSecret1)
		if code != 400 || out["errorName"] != "InvalidCiphertextException" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}

	if f.pub.Count("audit.hyok.aws_xks_request") < 4 {
		t.Fatalf("aws_xks_request events: %d", f.pub.Count("audit.hyok.aws_xks_request"))
	}
	var sawSuccess bool
	for _, e := range f.rec.Events() {
		if e.Action == "xks_request" && e.Event.Result == "success" && e.Event.TenantID == "tenant-a" && e.Event.ActorID == xksKey1 {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatalf("no xks_request success event for tenant-a by %s", xksKey1)
	}
	logs, _ := f.svc.store.ListRequestLogs(context.Background(), "tenant-a", ProtocolAWSXKS, 50, 0)
	for _, l := range logs {
		if strings.Contains(l.RequestJSON+l.ResponseJSON, base64.StdEncoding.EncodeToString(plain)) {
			t.Fatalf("the request log holds the plaintext: %+v", l)
		}
	}
}

func TestAWSXKSRefusesAndAuditsBadCalls(t *testing.T) {
	f := newXKSFixture(t)
	enc := map[string]interface{}{"requestMetadata": meta("Encrypt"), "plaintext": base64.StdEncoding.EncodeToString([]byte("data")), "encryptionAlgorithm": "AES_GCM"}
	refused := func(t *testing.T, code int, out map[string]interface{}, wantCode int, wantName string) {
		t.Helper()
		if code != wantCode || out["errorName"] != wantName {
			t.Fatalf("got %d %v, want %d %s", code, out, wantCode, wantName)
		}
		e := f.rec.Last(t)
		if e.Action != "xks_request" || e.Event.Result == "success" || e.Event.Details["reason"] != wantName {
			t.Fatalf("event %+v", e.Event)
		}
	}
	code, out := f.call(t, "keys/xks-key-1/encrypt", enc, "", "")
	refused(t, code, out, 401, "AuthenticationFailedException")
	code, out = f.call(t, "keys/xks-key-1/encrypt", enc, xksKey1, xksSecret2)
	refused(t, code, out, 401, "AuthenticationFailedException")
	code, out = f.call(t, "keys/xks-key-1/encrypt", enc, "AKIAUNKNOWNEXAMPLE2345", xksSecret1)
	refused(t, code, out, 401, "AuthenticationFailedException")
	code, out = f.call(t, "keys/unmapped/encrypt", enc, xksKey1, xksSecret1)
	refused(t, code, out, 404, "KeyNotFoundException")
	code, out = f.call(t, "keys/xks-key-1/sign", enc, xksKey1, xksSecret1)
	refused(t, code, out, 404, "InvalidUriPathException")
	bad := map[string]interface{}{"requestMetadata": meta("Encrypt"), "plaintext": base64.StdEncoding.EncodeToString([]byte("data")), "encryptionAlgorithm": "RSAES_OAEP_SHA_256"}
	code, out = f.call(t, "keys/xks-key-1/encrypt", bad, xksKey1, xksSecret1)
	refused(t, code, out, 400, "ValidationException")
	f.keycore.SetStatus("tenant-a", "k-aes", "disabled")
	code, out = f.call(t, "keys/xks-key-1/encrypt", enc, xksKey1, xksSecret1)
	refused(t, code, out, 400, "InvalidStateException")
	code, md := f.call(t, "keys/xks-key-1/metadata", map[string]interface{}{"requestMetadata": meta("DescribeKey")}, xksKey1, xksSecret1)
	if code != 200 || md["keyStatus"] != "DISABLED" {
		t.Fatalf("metadata of a disabled key %d %v", code, md)
	}

	// Another tenant's prefix, signed with this tenant's credential.
	r := httptest.NewRequest(http.MethodPost, "/xks/nobody/kms/xks/v1/health", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "InvalidUriPathException") {
		t.Fatalf("unknown prefix %d %s", w.Code, w.Body.String())
	}
}

func TestAWSXKSEndpointSettingsAreChecked(t *testing.T) {
	f := newXKSFixture(t)
	ok := AWSXKSMetadata{PathPrefix: "tenant-b-xks", CredentialIDs: []string{"pbconn_x1"}, Keys: map[string]string{"k": "k-b"}}
	bClaims := &pkgauth.Claims{TenantID: "tenant-b", UserID: "bob", Permissions: []string{"*"}}
	if err := saveXKS(f.svc, "tenant-b", bClaims, ok, false); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
	stored, _ := f.svc.store.GetEndpoint(context.Background(), "tenant-b", ProtocolAWSXKS)
	if stored.AuthMode != AuthModeSigV4 {
		t.Fatalf("auth mode %q", stored.AuthMode)
	}
	hyokOnly := &pkgauth.Claims{TenantID: "tenant-b", UserID: "carol", Permissions: []string{"hyok.write"}}
	for name, tc := range map[string]struct {
		claims     *pkgauth.Claims
		governance bool
		m          AWSXKSMetadata
	}{
		"approval":              {bClaims, true, ok},
		"no credential":         {bClaims, false, AWSXKSMetadata{PathPrefix: "p"}},
		"three credentials":     {bClaims, false, AWSXKSMetadata{PathPrefix: "p", CredentialIDs: []string{"pbconn_x1", "pbconn_x2", "pbconn_x1"}}},
		"same credential twice": {bClaims, false, AWSXKSMetadata{PathPrefix: "p", CredentialIDs: []string{"pbconn_x1", "pbconn_x1"}}},
		"wrong type":            {bClaims, false, AWSXKSMetadata{PathPrefix: "p", CredentialIDs: []string{"pbconn_smtp"}}},
		"missing credential":    {bClaims, false, AWSXKSMetadata{PathPrefix: "p", CredentialIDs: []string{"pbconn_gone"}}},
		"no connection.use":     {hyokOnly, false, ok},
		"bad prefix":            {bClaims, false, AWSXKSMetadata{PathPrefix: "a b", CredentialIDs: []string{"pbconn_x1"}}},
		"bad external key id":   {bClaims, false, AWSXKSMetadata{PathPrefix: "p", CredentialIDs: []string{"pbconn_x1"}, Keys: map[string]string{"a/b": "k-b"}}},
		"prefix in use":         {bClaims, false, AWSXKSMetadata{PathPrefix: "CONTOSO/xks", CredentialIDs: []string{"pbconn_x1"}}},
	} {
		before := f.pub.Count("audit.hyok.endpoint_refused")
		if err := saveXKS(f.svc, "tenant-b", tc.claims, tc.m, tc.governance); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if f.pub.Count("audit.hyok.endpoint_refused") != before+1 {
			t.Fatalf("%s: refusal not audited", name)
		}
	}
	if err := saveXKS(f.svc, "tenant-a", adminClaims(), AWSXKSMetadata{PathPrefix: "contoso/xks", CredentialIDs: []string{"pbconn_x1"}, Keys: map[string]string{"r": "k-rsa"}}, false); err == nil {
		t.Fatal("an RSA key accepted for XKS")
	}
}

// Only the credential store may ask which endpoints use a credential.
func TestXKSCredentialUsageOnlyForCompliance(t *testing.T) {
	f := newXKSFixture(t)
	ask := func(tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/hyok/credential-usage?tenant_id=tenant-a", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		return w
	}
	if w := ask("jwt:tenant-a:admin"); w.Code != http.StatusForbidden {
		t.Fatalf("a tenant administrator read credential usage: %d", w.Code)
	}
	if e := f.rec.Last(t); e.Action != "credential_usage_read" || e.Event.Result != "refused" {
		t.Fatalf("refusal event %+v", e.Event)
	}
}
