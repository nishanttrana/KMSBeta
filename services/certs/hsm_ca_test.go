package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"

	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
)

// hsmKeycore stands in for keycore's two HSM calls (generate an HSM key,
// sign a digest with it) and forwards them to a real hsm-connector on
// SoftHSM2, so every signature here is made by a real PKCS#11 HSM.
// keycore's own side (prehashed HSM signing) is tested in keycore.
type hsmKeycore struct {
	client *hsm.Client
	n      int
}

func (k *hsmKeycore) EnsureKey(context.Context, string, string, string, string) (string, error) {
	return "", errors.New("not used")
}
func (k *hsmKeycore) Sign(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (k *hsmKeycore) CreateHSMSigningKey(ctx context.Context, tenantID, algorithm, _ string) (string, []byte, error) {
	k.n++
	keyID := fmt.Sprintf("key_ca_%d", k.n)
	res, err := k.client.Generate(ctx, tenantID, hsm.KeyLabel(tenantID, keyID, 1), algorithm)
	return keyID, res.PublicKey, err
}
func (k *hsmKeycore) SignDigest(ctx context.Context, tenantID, keyID, hash string, digest []byte) ([]byte, error) {
	return k.client.Sign(ctx, tenantID, hsm.KeyLabel(tenantID, keyID, 1), hash, digest)
}

func certFromPEM(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A CA whose key lives in the HSM: the root and intermediate are signed in
// the HSM, certs stores no private key, and leaf certificates, CRLs and OCSP
// responses it signs all verify.
func TestHSMCAKeysSignInTheHSM(t *testing.T) {
	srv := softhsmtest.Start(t, "kms-keycore", "t-ca")
	svc, _ := newCertsService(t)
	svc.keycore = &hsmKeycore{client: hsm.New(srv.URL)}
	ctx := context.Background()

	root, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t-ca", Name: "HSM Root", CALevel: "root", Algorithm: "ECDSA-P384", KeyBackend: "hsm", Subject: "CN=HSM Root"})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := svc.store.GetCA(ctx, "t-ca", root.ID)
	if stored.KeyBackend != "hsm" || stored.SignerKeyVersion != signerVersionHSM || len(stored.SignerCiphertext) != 0 || stored.KeyRef == "" {
		t.Fatalf("stored CA: backend %q version %q ciphertext %d ref %q", stored.KeyBackend, stored.SignerKeyVersion, len(stored.SignerCiphertext), stored.KeyRef)
	}
	rootCert := certFromPEM(t, root.CertPEM)
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("root self-signature: %v", err)
	}
	inter, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t-ca", Name: "HSM Issuing", CALevel: "intermediate", ParentCAID: root.ID, Algorithm: "ECDSA-P256", KeyBackend: "hsm", Subject: "CN=HSM Issuing"})
	if err != nil {
		t.Fatal(err)
	}
	interCert := certFromPEM(t, inter.CertPEM)
	if err := interCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("intermediate signed by the HSM root: %v", err)
	}

	leaf, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "t-ca", CAID: inter.ID, SubjectCN: "api.t-ca.local",
		SANs: []string{"api.t-ca.local"}, CertType: "tls-server", Algorithm: "ECDSA-P256", ServerKeygen: true})
	if err != nil {
		t.Fatal(err)
	}
	leafCert := certFromPEM(t, leaf.CertPEM)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(rootCert)
	inters.AddCert(interCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "api.t-ca.local"}); err != nil {
		t.Fatalf("leaf chain: %v", err)
	}

	crlPEM, _, err := svc.GenerateCRL(ctx, "t-ca", inter.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(crlPEM))
	crl, err := x509.ParseRevocationList(b.Bytes)
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(interCert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}

	reqDER, err := ocsp.CreateRequest(leafCert, interCert, &ocsp.RequestOptions{Hash: crypto.SHA256}) // SHA-1 CertIDs are refused in strict mode
	if err != nil {
		t.Fatal(err)
	}
	respDER, _, _, _, err := svc.CheckOCSPDER(ctx, "t-ca", reqDER)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := ocsp.ParseResponseForCert(respDER, leafCert, interCert); err != nil || resp.Status != ocsp.Good {
		t.Fatalf("OCSP response signed by the HSM CA: %v", err)
	}

	// RSA can't be an HSM CA key; nor can a CA be put in the HSM without keycore.
	if _, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t-ca", Name: "rsa", CALevel: "root", Algorithm: "RSA-3072", KeyBackend: "hsm"}); !errors.Is(err, errHSMCAAlgorithm) {
		t.Fatalf("RSA HSM CA: %v", err)
	}
	svc.keycore = NoopKeyCoreSigner{}
	if _, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t-ca", Name: "nokeycore", CALevel: "root", Algorithm: "ECDSA-P256", KeyBackend: "hsm"}); err == nil || !strings.Contains(err.Error(), "keycore") {
		t.Fatalf("without keycore: %v", err)
	}
}
