package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	pkgauth "vecta-kms/pkg/auth"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

type nopHYOKPublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (p *nopHYOKPublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.payloads = append(p.payloads, payload)
	return nil
}

// Last returns the data of the newest event on subject, or nil.
func (p *nopHYOKPublisher) Last(subject string) map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return lastEventData(p.subjects, p.payloads, subject)
}

func (p *nopHYOKPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, s := range p.subjects {
		if s == subject {
			total++
		}
	}
	return total
}

// fakeHYOKKeyCore answers in keycore's response shapes: GET /keys/{id}
// carries no public key (GET /keys/{id}/public-key does), and WrapAs /
// UnwrapAs do the named algorithm on key material it holds, so a test uses
// what was produced.
type fakeHYOKKeyCore struct {
	mu       sync.Mutex
	keys     map[string]map[string]interface{}
	material map[string][]byte
	calls    []string
}

var (
	testRSAKey     *rsa.PrivateKey
	testRSAKeyOnce sync.Once
)

func newFakeHYOKKeyCore() *fakeHYOKKeyCore {
	return &fakeHYOKKeyCore{
		keys:     map[string]map[string]interface{}{},
		material: map[string][]byte{},
	}
}

func (f *fakeHYOKKeyCore) Seed(tenantID string, keyID string, algorithm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if algorithm == "" {
		algorithm = "AES-256"
	}
	f.keys[tenantID+":"+keyID] = map[string]interface{}{
		"id":              keyID,
		"algorithm":       algorithm,
		"status":          "active",
		"current_version": 1,
	}
	m := make([]byte, 32)
	_, _ = rand.Read(m)
	f.material[tenantID+":"+keyID] = m
}

// SetStatus changes a seeded key's lifecycle status.
func (f *fakeHYOKKeyCore) SetStatus(tenantID, keyID, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[tenantID+":"+keyID]["status"] = status
}

func getTestRSAKey() *rsa.PrivateKey {
	testRSAKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testRSAKey = k
	})
	return testRSAKey
}

func getTestRSAPublicPEM() string {
	raw, _ := x509.MarshalPKIXPublicKey(&getTestRSAKey().PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
}

func (f *fakeHYOKKeyCore) GetKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "GET /keys/"+keyID)
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, keycoreError{Status: 404, Code: "not_found", Message: "key not found"}
	}
	out := map[string]interface{}{}
	for kk, vv := range k {
		out[kk] = vv
	}
	return out, nil
}

func (f *fakeHYOKKeyCore) PublicKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	k, err := f.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	alg := firstString(k["algorithm"])
	if !strings.Contains(strings.ToUpper(alg), "RSA") {
		return nil, keycoreError{Status: 409, Code: "not_asymmetric", Message: "key has no public part"}
	}
	return map[string]interface{}{"key_id": keyID, "version": 1, "algorithm": alg, "format": "spki-pem", "public_key_pem": getTestRSAPublicPEM()}, nil
}

func (f *fakeHYOKKeyCore) WrapAs(ctx context.Context, tenantID string, keyID string, plaintextB64 string, alg string, _ string) (map[string]interface{}, error) {
	k, err := f.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	plain, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, keycoreError{Status: 400, Code: "bad_request", Message: "plaintext must be base64"}
	}
	var out []byte
	if strings.Contains(strings.ToUpper(firstString(k["algorithm"])), "RSA") {
		out, err = pkgcrypto.JWAWrapRSA(alg, &getTestRSAKey().PublicKey, plain)
	} else {
		f.mu.Lock()
		m := f.material[tenantID+":"+keyID]
		f.mu.Unlock()
		out, err = pkgcrypto.JWAWrapAES(alg, m, plain)
	}
	if err != nil {
		return nil, keycoreError{Status: 400, Code: "encrypt_failed", Message: err.Error()}
	}
	return map[string]interface{}{"key_id": keyID, "version": 1, "ciphertext": base64.StdEncoding.EncodeToString(out), "iv": ""}, nil
}

func (f *fakeHYOKKeyCore) UnwrapAs(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, alg string) (map[string]interface{}, error) {
	k, err := f.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, keycoreError{Status: 400, Code: "bad_request", Message: "ciphertext must be base64"}
	}
	var out []byte
	if strings.Contains(strings.ToUpper(firstString(k["algorithm"])), "RSA") {
		out, err = pkgcrypto.JWAUnwrapRSA(alg, getTestRSAKey(), wrapped)
	} else {
		f.mu.Lock()
		m := f.material[tenantID+":"+keyID]
		f.mu.Unlock()
		out, err = pkgcrypto.JWAUnwrapAES(alg, m, wrapped)
	}
	if err != nil {
		return nil, keycoreError{Status: 400, Code: "decrypt_failed", Message: "the wrapped key does not open under this key version"}
	}
	return map[string]interface{}{"key_id": keyID, "version": 1, "plaintext": base64.StdEncoding.EncodeToString(out)}, nil
}

func (f *fakeHYOKKeyCore) Encrypt(_ context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, _ string) (map[string]interface{}, error) {
	if _, err := f.GetKey(context.Background(), tenantID, keyID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(ivB64) == "" {
		ivB64 = "aXYxMjM0NTY3ODkw"
	}
	return map[string]interface{}{
		"key_id":     keyID,
		"version":    1,
		"ciphertext": "enc:" + plaintextB64,
		"iv":         ivB64,
	}, nil
}

func (f *fakeHYOKKeyCore) Decrypt(_ context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	if _, err := f.GetKey(context.Background(), tenantID, keyID); err != nil {
		return nil, err
	}
	plain := strings.TrimSpace(ciphertextB64)
	if raw, err := base64.StdEncoding.DecodeString(plain); err == nil {
		decoded := string(raw)
		decoded = strings.TrimPrefix(decoded, "enc:")
		decoded = strings.TrimPrefix(decoded, "wrap:")
		plain = decoded
	} else {
		plain = strings.TrimPrefix(plain, "enc:")
		plain = strings.TrimPrefix(plain, "wrap:")
	}
	return map[string]interface{}{
		"key_id":    keyID,
		"version":   1,
		"plaintext": plain,
		"iv":        ivB64,
	}, nil
}

func (f *fakeHYOKKeyCore) Wrap(_ context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, _ string) (map[string]interface{}, error) {
	if _, err := f.GetKey(context.Background(), tenantID, keyID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(ivB64) == "" {
		ivB64 = "aXYxMjM0NTY3ODkw"
	}
	return map[string]interface{}{
		"key_id":     keyID,
		"version":    1,
		"ciphertext": "wrap:" + plaintextB64,
		"iv":         ivB64,
	}, nil
}

func (f *fakeHYOKKeyCore) Unwrap(_ context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	if _, err := f.GetKey(context.Background(), tenantID, keyID); err != nil {
		return nil, err
	}
	plain := strings.TrimPrefix(ciphertextB64, "wrap:")
	return map[string]interface{}{
		"key_id":    keyID,
		"version":   1,
		"plaintext": plain,
		"iv":        ivB64,
	}, nil
}

type fakeHYOKPolicy struct {
	decision string
	reason   string
	err      error
}

func (f *fakeHYOKPolicy) Evaluate(_ context.Context, _ PolicyEvaluateRequest) (PolicyEvaluateResponse, error) {
	if f.err != nil {
		return PolicyEvaluateResponse{}, f.err
	}
	if strings.TrimSpace(f.decision) == "" {
		return PolicyEvaluateResponse{Decision: "ALLOW"}, nil
	}
	return PolicyEvaluateResponse{Decision: f.decision, Reason: f.reason}, nil
}

type fakeHYOKGovernance struct {
	id     string
	err    error
	status map[string]GovernanceApprovalStatus
	asked  []GovernanceApprovalRequest
}

func (f *fakeHYOKGovernance) CreateKeyApproval(_ context.Context, req GovernanceApprovalRequest) (string, error) {
	f.asked = append(f.asked, req)
	if f.err != nil {
		return "", f.err
	}
	if strings.TrimSpace(f.id) == "" {
		f.id = "apr_test_1"
	}
	return f.id, nil
}

func (f *fakeHYOKGovernance) GetApprovalStatus(_ context.Context, _ string, id string) (GovernanceApprovalStatus, error) {
	if st, ok := f.status[id]; ok {
		return st, nil
	}
	return GovernanceApprovalStatus{Status: "pending"}, nil
}

func newHYOKService(t *testing.T) (*Service, *SQLStore, *fakeHYOKKeyCore, *fakeHYOKPolicy, *fakeHYOKGovernance, *nopHYOKPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createHYOKSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newFakeHYOKKeyCore()
	policy := &fakeHYOKPolicy{decision: "ALLOW"}
	governance := &fakeHYOKGovernance{id: "apr_test_1"}
	pub := &nopHYOKPublisher{}
	svc := NewService(store, keycore, policy, governance, pub)
	svc.SetKeyAccess(pkgkeyaccess.NotDeployed())
	return svc, store, keycore, policy, governance, pub
}

func newHYOKHandler(t *testing.T) (*Handler, *Service, *fakeHYOKKeyCore, *fakeHYOKPolicy, *fakeHYOKGovernance, *nopHYOKPublisher) {
	t.Helper()
	svc, _, keycore, policy, governance, pub := newHYOKService(t)
	return NewHandler(svc, testJWTParser), svc, keycore, policy, governance, pub
}

func createHYOKSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE hyok_endpoints (
			tenant_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			auth_mode TEXT NOT NULL DEFAULT 'mtls_or_jwt',
			policy_id TEXT NOT NULL DEFAULT '',
			governance_required BOOLEAN NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, protocol)
		);`,
		`CREATE TABLE hyok_requests (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			operation TEXT NOT NULL,
			key_id TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			auth_mode TEXT NOT NULL,
			auth_subject TEXT NOT NULL DEFAULT '',
			requester_id TEXT NOT NULL DEFAULT '',
			requester_email TEXT NOT NULL DEFAULT '',
			policy_decision TEXT NOT NULL DEFAULT '',
			governance_required BOOLEAN NOT NULL DEFAULT 0,
			approval_request_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			request_json TEXT NOT NULL DEFAULT '{}',
			response_json TEXT NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// testJWTParser verifies test tokens of the form "jwt:<tenant>:<role>".
func testJWTParser(tok string) (*pkgauth.Claims, error) {
	parts := strings.Split(tok, ":")
	if len(parts) != 3 || parts[0] != "jwt" {
		return nil, errors.New("invalid token")
	}
	return &pkgauth.Claims{TenantID: parts[1], Role: parts[2], UserID: "u-" + parts[2]}, nil
}
