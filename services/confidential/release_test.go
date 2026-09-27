package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// sealingReleaser stands in for keycore's HTTP endpoint (tested in keycore);
// it seals real bytes to the recipient so the test can prove who can open them.
type sealingReleaser struct {
	calls  int
	secret []byte
	err    error
}

func (r *sealingReleaser) AttestedRelease(_ context.Context, tenantID, keyID string, req keycoreReleaseRequest) (SealedKeyRelease, error) {
	r.calls++
	if r.err != nil {
		return SealedKeyRelease{}, r.err
	}
	der, _ := base64.StdEncoding.DecodeString(req.RecipientPublicKey)
	pub, err := pkgcrypto.ParseRecipientPublicKey(der)
	if err != nil {
		return SealedKeyRelease{}, err
	}
	aad := tenantID + "|" + keyID + "|" + req.ReleaseID
	w, n, c, err := pkgcrypto.SealToRecipient(pub, r.secret, []byte(aad))
	if err != nil {
		return SealedKeyRelease{}, err
	}
	b := base64.StdEncoding.EncodeToString
	return SealedKeyRelease{KeyID: keyID, Version: 1, SealAlgorithm: pkgcrypto.RecipientSealAlgorithm,
		WrappedKey: b(w), Nonce: b(n), Ciphertext: b(c), AAD: aad}, nil
}

// nitroDocument builds a real COSE_Sign1 Nitro attestation, signed by a test
// root the verifier trusts, committing to publicKey.
func nitroDocument(t *testing.T, publicKey []byte) (string, *x509.Certificate) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aws.nitro-enclaves"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "aws.nitro.leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	payload, _ := cbor.Marshal(map[string]any{
		"module_id": "i-enclave", "digest": "SHA384", "timestamp": time.Now().UTC().UnixMilli(),
		"certificate": leafDER, "cabundle": []any{rootDER}, "public_key": publicKey,
		"pcrs": map[any]any{0: []byte{0xaa, 0xbb}},
	})
	protected, _ := cbor.Marshal(map[int]any{1: -35})
	sigStructure, _ := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, sha384Sum(sigStructure))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := cbor.Marshal([]any{protected, map[any]any{}, payload, append(paddedBytes(r.Bytes(), 48), paddedBytes(s.Bytes(), 48)...)})
	return base64.StdEncoding.EncodeToString(doc), root
}

func recipientKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, der
}

type subjectLog struct{ subjects []string }

func (l *subjectLog) Publish(_ context.Context, subject string, _ []byte) error {
	l.subjects = append(l.subjects, subject)
	return nil
}

func (l *subjectLog) count(subject string) int {
	n := 0
	for _, s := range l.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

var releaseEvents = &subjectLog{}

func nitroService(t *testing.T, root *x509.Certificate, rel KeyReleaser) (*Service, *memStore) {
	pol := defaultAttestationPolicy("t1")
	pol.Enabled = true
	pol.RequiredMeasurements = map[string]string{"pcr0": "aabb"}
	store := &memStore{policy: pol}
	svc := NewService(store, releaseEvents, "node-1")
	svc.verifier = NewProviderVerifier()
	svc.verifier.awsRootCerts = x509.NewCertPool()
	svc.verifier.awsRootCerts.AddCert(root)
	svc.SetKeyReleaser(rel)
	return svc, store
}

// An allowed Nitro attestation whose signed public_key is the recipient key
// gets the key sealed to it: only the enclave's private key opens it.
func TestReleaseSealsKeyToAttestedEnclaveKey(t *testing.T) {
	enclave, der := recipientKey(t)
	doc, root := nitroDocument(t, der)
	rel := &sealingReleaser{secret: []byte("0123456789abcdef0123456789abcdef")}
	svc, store := nitroService(t, root, rel)
	out, err := svc.ReleaseKey(context.Background(), AttestedReleaseRequest{TenantID: "t1", KeyID: "k1",
		Provider: "aws_nitro_enclaves", AttestationDocument: doc, RecipientPublicKey: base64.StdEncoding.EncodeToString(der)})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Released || out.Release == nil || rel.calls != 1 {
		t.Fatalf("not released: %+v", out.Reasons)
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	got, err := pkgcrypto.OpenFromRecipient(enclave, dec(out.Release.WrappedKey), dec(out.Release.Nonce), dec(out.Release.Ciphertext), []byte(out.Release.AAD))
	if err != nil || string(got) != string(rel.secret) {
		t.Fatalf("enclave could not open its release: %v", err)
	}
	if releaseEvents.count("audit.confidential.key_released") == 0 {
		t.Fatal("release not audited")
	}
	if len(store.records) != 1 || !store.records[0].Released || store.records[0].RecipientKeyBinding != pkgcrypto.RecipientKeyBinding(der) {
		t.Fatalf("release not recorded: %+v", store.records)
	}
}

// Nothing is released when the evidence does not commit to the recipient key,
// when the verdict is not allow, or when keycore refuses; each is recorded.
func TestReleaseRefusedWithoutBindingAllowOrKeycore(t *testing.T) {
	_, der := recipientKey(t)
	_, otherDER := recipientKey(t)
	doc, root := nitroDocument(t, der)
	b64 := base64.StdEncoding.EncodeToString

	rel := &sealingReleaser{secret: []byte("k")}
	svc, store := nitroService(t, root, rel)
	out, err := svc.ReleaseKey(context.Background(), AttestedReleaseRequest{TenantID: "t1", KeyID: "k1",
		Provider: "aws_nitro_enclaves", AttestationDocument: doc, RecipientPublicKey: b64(otherDER)})
	if err != nil || out.Released || rel.calls != 0 {
		t.Fatalf("released to a key the evidence does not name: %+v %v", out, err)
	}

	store.policy.RequiredMeasurements = map[string]string{"pcr0": "ffff"}
	if out, _ := svc.ReleaseKey(context.Background(), AttestedReleaseRequest{TenantID: "t1", KeyID: "k1",
		Provider: "aws_nitro_enclaves", AttestationDocument: doc, RecipientPublicKey: b64(der)}); out.Released || rel.calls != 0 {
		t.Fatal("released on a deny verdict")
	}

	store.policy.RequiredMeasurements = map[string]string{"pcr0": "aabb"}
	rel.err = errors.New("export is disabled by key policy")
	out, _ = svc.ReleaseKey(context.Background(), AttestedReleaseRequest{TenantID: "t1", KeyID: "k1",
		Provider: "aws_nitro_enclaves", AttestationDocument: doc, RecipientPublicKey: b64(der)})
	if out.Released || rel.calls != 1 || out.Decision != "allow" {
		t.Fatalf("keycore refusal not honoured: %+v", out)
	}
	for _, r := range store.records {
		if r.Released {
			t.Fatal("a refused release was recorded as released")
		}
	}
	if len(store.records) != 3 || releaseEvents.count("audit.confidential.key_release_refused") < 3 {
		t.Fatalf("refusals not recorded or audited: %d", len(store.records))
	}
	if _, err := svc.ReleaseKey(context.Background(), AttestedReleaseRequest{TenantID: "t1", KeyID: "k1", Provider: "aws_nitro_enclaves", AttestationDocument: doc}); err == nil {
		t.Fatal("release without a recipient key accepted")
	}
}

// OIDC attestations bind the recipient key through their verified nonce.
func TestReleaseBindsOIDCAttestationThroughNonce(t *testing.T) {
	serverURL, fx := newOIDCTestVerifier(t, "azure")
	_, der := recipientKey(t)
	_, otherDER := recipientKey(t)
	pol := defaultAttestationPolicy("t1")
	pol.Enabled, pol.Provider = true, "azure_secure_key_release"
	pol.RequiredMeasurements, pol.RequireSecureBoot = map[string]string{}, false
	svc := NewService(&memStore{policy: pol}, nil, "node-1")
	svc.verifier = fx.verifier
	rel := &sealingReleaser{secret: []byte("k")}
	svc.SetKeyReleaser(rel)
	token := func(nonce string) string {
		return mustSignedJWT(t, fx.privateKey, fx.kid, map[string]any{"iss": serverURL, "aud": "kms-key-release",
			"sub": "spiffe://root/enclave", "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
			"x-ms-sgx-is-debuggable": false, "nonce": nonce})
	}
	req := func(tok string) AttestedReleaseRequest {
		return AttestedReleaseRequest{TenantID: "t1", KeyID: "k1", Provider: "azure_secure_key_release", AttestationDocument: tok,
			Audience: "kms-key-release", RecipientPublicKey: base64.StdEncoding.EncodeToString(der)}
	}
	if out, err := svc.ReleaseKey(context.Background(), req(token(pkgcrypto.RecipientKeyBinding(otherDER)))); err != nil || out.Released {
		t.Fatalf("released with a nonce for another key: %+v %v", out.Reasons, err)
	}
	out, err := svc.ReleaseKey(context.Background(), req(token(pkgcrypto.RecipientKeyBinding(der))))
	if err != nil || !out.Released {
		t.Fatalf("bound OIDC attestation not released: %+v %v", out.Reasons, err)
	}
}
