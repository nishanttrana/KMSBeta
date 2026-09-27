package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/oidc"
)

// Signing service against real Postgres (metadata_json is JSONB, which
// re-orders keys on storage; SQLite would hide that) with a keycore stand-in
// that does real ECDSA P-384 through pkg/crypto. Runs when
// VECTA_TEST_POSTGRES_DSN points at a disposable database.

type ecdsaKeycore struct {
	mu   sync.Mutex
	keys map[string]*pkgcrypto.KeyPair
}

func (k *ecdsaKeycore) key(t testing.TB, id string) *pkgcrypto.KeyPair {
	k.mu.Lock()
	defer k.mu.Unlock()
	if kp, ok := k.keys[id]; ok {
		return kp
	}
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	k.keys[id] = kp
	return kp
}

type keycoreForTest struct {
	t  testing.TB
	kc *ecdsaKeycore
}

func (f keycoreForTest) Sign(_ context.Context, keyID string, req KeyCoreSignRequest) (KeyCoreSignResponse, error) {
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		return KeyCoreSignResponse{}, err
	}
	sig, err := pkgcrypto.Sign(f.kc.key(f.t, keyID), data)
	if err != nil {
		return KeyCoreSignResponse{}, err
	}
	return KeyCoreSignResponse{SignatureB64: base64.StdEncoding.EncodeToString(sig), KeyID: keyID, Version: 1}, nil
}

func (f keycoreForTest) Verify(_ context.Context, keyID string, req KeyCoreVerifyRequest) (KeyCoreVerifyResponse, error) {
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	kp := f.kc.key(f.t, keyID)
	return KeyCoreVerifyResponse{Valid: pkgcrypto.Verify(kp.Algorithm, kp.Public, data, sig) == nil}, nil
}

type recordingPublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (p *recordingPublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.payloads = append(p.payloads, payload)
	return nil
}

// details returns the details of the last event published on subject.
func (p *recordingPublisher) details(t *testing.T, subject string) map[string]any {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.subjects) - 1; i >= 0; i-- {
		if p.subjects[i] != subject {
			continue
		}
		var ev struct {
			Details map[string]any `json:"details"`
		}
		if err := json.Unmarshal(p.payloads[i], &ev); err != nil {
			t.Fatal(err)
		}
		return ev.Details
	}
	t.Fatalf("no %s event published: %v", subject, p.subjects)
	return nil
}

func (p *recordingPublisher) count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type signingFixture struct {
	svc    *Service
	conn   *pkgdb.DB
	pub    *recordingPublisher
	issuer *ciIssuer
}

// ciIssuer is a real OIDC issuer over TLS (discovery + JWKS) that mints
// ES256 ID tokens, standing in for a CI provider such as GitHub Actions.
type ciIssuer struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
}

func newCIIssuer(t *testing.T) *ciIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ci := &ciIssuer{key: key}
	mux := http.NewServeMux()
	ci.srv = httptest.NewTLSServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": ci.srv.URL, "jwks_uri": ci.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b := func(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "EC", "crv": "P-256", "kid": "ci", "use": "sig",
			"x": b(key.PublicKey.X.FillBytes(make([]byte, 32))), "y": b(key.PublicKey.Y.FillBytes(make([]byte, 32)))}}})
	})
	t.Cleanup(ci.srv.Close)
	return ci
}

func (ci *ciIssuer) token(t *testing.T, key *ecdsa.PrivateKey, iss, sub, repo string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": iss, "sub": sub, "aud": "vecta-kms-signing",
		"repository": repo, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	tok.Header["kid"] = "ci"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database to run signing integration tests")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE signing_settings, signing_profiles, signing_records`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	pub := &recordingPublisher{}
	svc := NewService(NewSQLStore(conn), keycoreForTest{t: t, kc: &ecdsaKeycore{keys: map[string]*pkgcrypto.KeyPair{}}}, pub)
	ci := newCIIssuer(t)
	svc.oidc = &oidc.Verifier{HTTP: ci.srv.Client()}
	return signingFixture{svc: svc, conn: conn, pub: pub, issuer: ci}
}

// enable turns signing on for the tenant with one OIDC profile.
func (f signingFixture) enable(t *testing.T, tenant string) SigningProfile {
	t.Helper()
	ctx := context.Background()
	prof, err := f.svc.UpsertProfile(ctx, SigningProfile{
		TenantID: tenant, Name: "release", ArtifactType: "blob", KeyID: "key-release", IdentityMode: "oidc",
		AllowedOIDCIssuers: []string{f.issuer.srv.URL}, AllowedSubjectPatterns: []string{"repo:acme/*:ref:refs/tags/*"},
		AllowedRepositories: []string{"acme/*"}, AllowedWorkloadPatterns: []string{"spiffe://acme/ci/*"}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateSettings(ctx, SigningSettings{TenantID: tenant, Enabled: true, DefaultProfileID: prof.ID, AllowedIdentityModes: []string{"oidc", "workload"}}); err != nil {
		t.Fatal(err)
	}
	return prof
}

func (f signingFixture) validSignInput(t *testing.T, tenant string, payload []byte) SignArtifactInput {
	return SignArtifactInput{
		TenantID: tenant, ArtifactName: "vecta-cli-1.2.0.tar.gz", PayloadB64: base64.StdEncoding.EncodeToString(payload),
		IdentityMode: "oidc", RequestedBy: "ci",
		OIDCToken: f.issuer.token(t, f.issuer.key, f.issuer.srv.URL, "repo:acme/vecta-cli:ref:refs/tags/v1.2.0", "acme/vecta-cli"),
	}
}

func digestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sign then verify must succeed for the artifact that was signed, and fail for
// any other artifact.
func TestSignAndVerifyArtifactPostgres(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	f.enable(t, "t-sign")
	payload := []byte("release artifact bytes")
	res, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-sign", payload))
	if err != nil {
		t.Fatal(err)
	}
	rec := res.Record
	if rec.DigestSHA256 != digestHex(payload) || rec.SignatureB64 == "" || rec.TransparencyIndex != 1 {
		t.Fatalf("signing record: %+v", rec)
	}

	ok, err := f.svc.VerifyArtifact(ctx, VerifyArtifactInput{TenantID: "t-sign", RecordID: rec.ID})
	if err != nil || !ok.Valid {
		t.Fatalf("a freshly signed record must verify: %+v %v", ok, err)
	}
	match, err := f.svc.VerifyArtifact(ctx, VerifyArtifactInput{TenantID: "t-sign", RecordID: rec.ID, PayloadB64: base64.StdEncoding.EncodeToString(payload)})
	if err != nil || !match.Valid || !match.DigestMatch {
		t.Fatalf("the signed artifact must verify against its record: %+v %v", match, err)
	}
	other, err := f.svc.VerifyArtifact(ctx, VerifyArtifactInput{TenantID: "t-sign", RecordID: rec.ID, DigestSHA256: digestHex([]byte("a different artifact"))})
	if err != nil || other.Valid || other.DigestMatch {
		t.Fatalf("a different artifact must not verify against this record: %+v %v", other, err)
	}
	if f.pub.count("audit.signing.artifact_signed") != 1 || f.pub.count("audit.signing.artifact_verified") != 3 {
		t.Fatalf("sign and verify must be audited: %v", f.pub.subjects)
	}

	second, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-sign", []byte("next")))
	if err != nil || second.Record.TransparencyIndex != 2 {
		t.Fatalf("transparency index must increase: %+v %v", second.Record, err)
	}
}

// Tampering with a stored record (signature or signed envelope) must make
// verification fail.
func TestVerifyDetectsTamperedRecordPostgres(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	f.enable(t, "t-tamper")
	res, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-tamper", []byte("artifact")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.SQL().ExecContext(ctx,
		`UPDATE signing_records SET metadata_json = jsonb_set(metadata_json, '{envelope,digest_sha256}', to_jsonb($1::text)),
			digest_sha256 = $1 WHERE id = $2`, digestHex([]byte("evil")), res.Record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.SQL().ExecContext(ctx, `UPDATE signing_records SET metadata_json = metadata_json - 'envelope_b64' WHERE id = $1`, res.Record.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.VerifyArtifact(ctx, VerifyArtifactInput{TenantID: "t-tamper", RecordID: res.Record.ID})
	if err != nil || got.Valid {
		t.Fatalf("a record whose envelope was altered must not verify: %+v %v", got, err)
	}

	res2, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-tamper", []byte("artifact-2")))
	if err != nil {
		t.Fatal(err)
	}
	badSig := make([]byte, 96)
	if _, err := f.conn.SQL().ExecContext(ctx, `UPDATE signing_records SET signature_b64 = $1 WHERE id = $2`, base64.StdEncoding.EncodeToString(badSig), res2.Record.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.VerifyArtifact(ctx, VerifyArtifactInput{TenantID: "t-tamper", RecordID: res2.Record.ID}); err != nil || got.Valid {
		t.Fatalf("a replaced signature must not verify: %+v %v", got, err)
	}
}

// Every identity and policy gate refuses with its specific error code.
func TestSignArtifactPolicyGatesPostgres(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	payload := []byte("artifact")

	if _, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-gates", payload)); errCode(err) != "disabled" {
		t.Fatalf("signing must be refused while the tenant has it disabled, got %v", err)
	}
	prof := f.enable(t, "t-gates")

	ci := f.issuer
	forged, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]func(*SignArtifactInput){
		// Identity is only what a verified token proves; stating it is not enough.
		"oidc_issuer_denied": func(in *SignArtifactInput) {
			in.OIDCToken = ci.token(t, ci.key, "https://evil.example", "repo:acme/vecta-cli:ref:refs/tags/v1", "acme/vecta-cli")
		},
		"oidc_token_invalid": func(in *SignArtifactInput) {
			in.OIDCToken = ci.token(t, forged, ci.srv.URL, "repo:acme/vecta-cli:ref:refs/tags/v1", "acme/vecta-cli")
		},
		"oidc_token_required": func(in *SignArtifactInput) { in.OIDCToken = "" },
		"oidc_subject_denied": func(in *SignArtifactInput) {
			in.OIDCToken = ci.token(t, ci.key, ci.srv.URL, "repo:other/project:ref:main", "acme/vecta-cli")
		},
		"repository_denied": func(in *SignArtifactInput) {
			in.OIDCToken = ci.token(t, ci.key, ci.srv.URL, "repo:acme/vecta-cli:ref:refs/tags/v1", "other/project")
			in.Repository = "acme/vecta-cli"
		},
		"workload_identity_denied": func(in *SignArtifactInput) { in.IdentityMode = "workload" },
		"bad_request":              func(in *SignArtifactInput) { in.PayloadB64 = "%%%not-base64" },
	}
	for want, mutate := range cases {
		in := f.validSignInput(t, "t-gates", payload)
		mutate(&in)
		if _, err := f.svc.SignArtifact(ctx, in); errCode(err) != want {
			t.Fatalf("%s: got %v", want, err)
		}
	}

	if _, err := f.svc.UpdateSettings(ctx, SigningSettings{TenantID: "t-gates", Enabled: true, DefaultProfileID: prof.ID, AllowedIdentityModes: []string{"workload"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-gates", payload)); errCode(err) != "identity_mode_denied" {
		t.Fatalf("an identity mode the tenant disallows must be refused, got %v", err)
	}

	prof.Enabled = false
	if _, err := f.svc.UpsertProfile(ctx, prof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateSettings(ctx, SigningSettings{TenantID: "t-gates", Enabled: true, DefaultProfileID: prof.ID, AllowedIdentityModes: []string{"oidc"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignArtifact(ctx, f.validSignInput(t, "t-gates", payload)); errCode(err) != "disabled" {
		t.Fatalf("a disabled profile must refuse signing, got %v", err)
	}
	if f.pub.count("audit.signing.artifact_signed") != 0 {
		t.Fatal("refused signing requests must not be recorded as signed")
	}
}

func errCode(err error) string {
	var se serviceError
	if errors.As(err, &se) {
		return se.Code
	}
	if err != nil {
		return "unexpected:" + err.Error()
	}
	return ""
}

var _ = http.StatusOK
