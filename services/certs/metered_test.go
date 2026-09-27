package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A certificate signed with a local CA key is a metered operation (its
// audit.cert.issued carries metered_op and duration_ms). An HSM-held CA
// signs in keycore, which meters it, so the issuance is not metered twice
// (TestHSMCAKeysSignInTheHSM covers that path's signer).
func TestLocalCertificateSigningMetered(t *testing.T) {
	svc, _ := newCertsService(t)
	pub := &subjectRecorder{}
	svc.SetPublisher(pub)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t4", Name: "root", CALevel: "root", Algorithm: "ECDSA-P384", KeyBackend: "software", Subject: "CN=Root"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "t4", CAID: ca.ID, SubjectCN: "svc.local", CertType: "tls-server", Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	d := pub.last(t, "audit.cert.issued")
	if d["metered_op"] != "cert_issue" {
		t.Fatalf("issued event not metered: %+v", d)
	}
	if _, ok := d["duration_ms"].(float64); !ok {
		t.Fatalf("no duration_ms: %+v", d)
	}
	if signsLocally(&hsmSigner{}) {
		t.Fatal("an HSM/keycore signer must not be metered here")
	}
}

// A signature the CA could not make is audited as <op>_failed with the
// error, and metered only when the key is local.
func TestCertSigningFailureAuditedAndMetered(t *testing.T) {
	svc, _ := newCertsService(t)
	pub := &subjectRecorder{}
	svc.SetPublisher(pub)
	ctx := context.Background()
	svc.signingFailed(ctx, true, "ocsp_sign", "t4", time.Now(), errors.New("signer unavailable"))
	d := pub.last(t, "audit.cert.ocsp_sign_failed")
	if d["result"] != "failure" || d["error"] != "signer unavailable" || d["metered_op"] != "ocsp_sign" {
		t.Fatalf("local signing failure: %+v", d)
	}
	svc.signingFailed(ctx, false, "cert_issue", "t4", time.Now(), errors.New("keycore refused"))
	if d := pub.last(t, "audit.cert.cert_issue_failed"); d["metered_op"] != nil || d["result"] != "failure" {
		t.Fatalf("keycore-signed failure must be audited, not metered: %+v", d)
	}
}
