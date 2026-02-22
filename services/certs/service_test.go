package main

import (
	"context"
	"strings"
	"testing"
)

func TestCAHierarchyIssueRevokeAndOCSP(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()

	root, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t1",
		Name:       "root-ca",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root CA,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	intermediate, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t1",
		Name:       "int-ca",
		ParentCAID: root.ID,
		CALevel:    "intermediate",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Intermediate CA,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}

	issued, keyPEM, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     "t1",
		CAID:         intermediate.ID,
		SubjectCN:    "api.vecta.local",
		SANs:         []string{"api.vecta.local", "10.20.30.40"},
		CertType:     "tls-server",
		Algorithm:    "ECDSA-P256",
		ServerKeygen: true,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.ID == "" || !strings.Contains(issued.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected issued cert: %+v", issued)
	}
	if !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatalf("expected private key pem")
	}

	if err := svc.RevokeCertificate(ctx, RevokeCertificateRequest{
		TenantID: "t1",
		CertID:   issued.ID,
		Reason:   "key_compromise",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	status, reason, _, err := svc.CheckOCSP(ctx, "t1", issued.ID, "")
	if err != nil {
		t.Fatalf("ocsp: %v", err)
	}
	if status != "revoked" || reason == "" {
		t.Fatalf("expected revoked status, got status=%s reason=%s", status, reason)
	}
}

func TestDeleteCertificate(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "td",
		Name:       "root-ca",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root CA,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	issued, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "td",
		CAID:      ca.ID,
		SubjectCN: "delete-me.vecta.local",
		CertType:  "tls-server",
		Algorithm: "ECDSA-P256",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := svc.DeleteCertificate(ctx, "td", issued.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := svc.GetCertificate(ctx, "td", issued.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if strings.ToLower(got.Status) != CertStatusDeleted {
		t.Fatalf("expected deleted status, got %+v", got)
	}
}

func TestStatefulOTSBudget(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:          "t2",
		Name:              "xmss-ca",
		CALevel:           "root",
		Algorithm:         "XMSS",
		KeyBackend:        "software",
		Subject:           "CN=XMSS Root",
		OTSMax:            2,
		OTSAlertThreshold: 1,
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
			TenantID:  "t2",
			CAID:      ca.ID,
			SubjectCN: "host-" + string(rune('a'+i)),
			CertType:  "device",
			Algorithm: "XMSS",
		})
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	_, _, err = svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "t2",
		CAID:      ca.ID,
		SubjectCN: "host-overflow",
		CertType:  "device",
		Algorithm: "XMSS",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ots") {
		t.Fatalf("expected ots exhaustion error, got %v", err)
	}
	status, err := svc.GetOTSStatus(ctx, "t2", ca.ID)
	if err != nil {
		t.Fatalf("ots status: %v", err)
	}
	if !status.Alert || status.Remaining != 0 {
		t.Fatalf("expected alert at zero remaining: %+v", status)
	}
}

func TestPQCReadinessAndMigration(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t3",
		Name:       "root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	classical, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "t3",
		CAID:      ca.ID,
		SubjectCN: "legacy-app",
		CertType:  "tls-server",
		Algorithm: "ECDSA-P256",
	})
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := svc.MigrateToPQC(ctx, MigrateToPQCRequest{
		TenantID:        "t3",
		CertID:          classical.ID,
		TargetAlgorithm: "ML-DSA-65",
	})
	if err != nil {
		t.Fatal(err)
	}
	if migrated.CertClass != "pqc" {
		t.Fatalf("expected pqc class after migration, got %s", migrated.CertClass)
	}
	readiness, err := svc.GetPQCReadiness(ctx, "t3")
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Total < 2 || readiness.PQC < 1 || readiness.Classical < 1 {
		t.Fatalf("unexpected readiness summary: %+v", readiness)
	}
}

func TestACMEFlow(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t4",
		Name:       "acme-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=ACME Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	acct, err := svc.AcmeNewAccount(ctx, ACMENewAccountRequest{TenantID: "t4", Email: "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	order, err := svc.AcmeNewOrder(ctx, ACMENewOrderRequest{
		TenantID:  "t4",
		AccountID: acct.ID,
		CAID:      ca.ID,
		SubjectCN: "acme.vecta.local",
		SANs:      []string{"acme.vecta.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AcmeRespondChallenge(ctx, "t4", order.ID, order.ChallengeID, true); err != nil {
		t.Fatal(err)
	}
	cert, _, err := svc.AcmeFinalize(ctx, ACMEFinalizeRequest{
		TenantID: "t4",
		OrderID:  order.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.ID == "" {
		t.Fatalf("expected certificate id")
	}
}

func TestProtocolConfigCanDisableACME(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	_, err := svc.UpsertProtocolConfig(ctx, UpsertProtocolConfigRequest{
		TenantID:   "t5",
		Protocol:   "acme",
		Enabled:    false,
		ConfigJSON: `{"rfc":"8555"}`,
		UpdatedBy:  "test",
	})
	if err != nil {
		t.Fatalf("upsert protocol config: %v", err)
	}
	_, err = svc.AcmeNewAccount(ctx, ACMENewAccountRequest{
		TenantID: "t5",
		Email:    "ops@example.com",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "disabled") {
		t.Fatalf("expected acme disabled error, got %v", err)
	}
}

func TestUploadThirdPartyCertificate(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()

	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t6",
		Name:       "upload-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Upload Root",
	})
	if err != nil {
		t.Fatalf("create root ca: %v", err)
	}
	issued, keyPEM, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     "t6",
		CAID:         ca.ID,
		SubjectCN:    "upload.example.local",
		SANs:         []string{"upload.example.local"},
		CertType:     "tls-server",
		Algorithm:    "ECDSA-P256",
		ServerKeygen: true,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	out, err := svc.UploadThirdPartyCertificate(ctx, UploadThirdPartyCertificateRequest{
		TenantID:       "t6",
		Purpose:        "KMS Web Interface (HTTPS:443)",
		CertificatePEM: issued.CertPEM,
		PrivateKeyPEM:  keyPEM,
		SetActive:      true,
		EnableOCSP:     true,
		AutoRenewACME:  false,
		UpdatedBy:      "test",
	})
	if err != nil {
		t.Fatalf("upload third-party cert: %v", err)
	}
	if out.ID == "" || out.Protocol != "upload-3p" || out.CertPEM == "" {
		t.Fatalf("unexpected upload output: %+v", out)
	}
}

func TestCMPv2PolicyEnforcement(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "tcp",
		Name:       "cmp-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=CMP Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpsertProtocolConfig(ctx, UpsertProtocolConfigRequest{
		TenantID: "tcp",
		Protocol: "cmpv2",
		Enabled:  true,
		ConfigJSON: `{
			"rfc":"4210",
			"enterprise_pki":true,
			"message_types":["ir","kur"],
			"require_message_protection":true,
			"require_transaction_id":true,
			"default_validity_days":365
		}`,
		UpdatedBy: "test",
	})
	if err != nil {
		t.Fatalf("upsert cmp config: %v", err)
	}
	_, _, err = svc.CMPv2Request(ctx, CMPv2RequestMessage{
		TenantID:    "tcp",
		CAID:        ca.ID,
		MessageType: "ir",
		PayloadJSON: `{"subject_cn":"cmp-pol.local","cert_type":"tls-client"}`,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "protection") {
		t.Fatalf("expected protection policy error, got %v", err)
	}
	_, _, err = svc.CMPv2Request(ctx, CMPv2RequestMessage{
		TenantID:      "tcp",
		CAID:          ca.ID,
		MessageType:   "ir",
		TransactionID: "txn-1",
		Protected:     true,
		ProtectionAlg: "pbm-sha256",
		PayloadJSON:   `{"subject_cn":"cmp-pol.local","cert_type":"tls-client"}`,
	})
	if err != nil {
		t.Fatalf("cmpv2 request with policy-compliant fields failed: %v", err)
	}
}

func TestSCEPChallengePolicyEnforcement(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "tscp",
		Name:       "scep-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=SCEP Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpsertProtocolConfig(ctx, UpsertProtocolConfigRequest{
		TenantID: "tscp",
		Protocol: "scep",
		Enabled:  true,
		ConfigJSON: `{
			"rfc":"8894",
			"challenge_password_required":true,
			"challenge_password":"secret-pass",
			"allow_renewal":true,
			"default_validity_days":365
		}`,
		UpdatedBy: "test",
	})
	if err != nil {
		t.Fatalf("upsert scep config: %v", err)
	}
	_, _, err = svc.SCEPPKIOperation(ctx, SCEPPKIOperationRequest{
		TenantID:      "tscp",
		CAID:          ca.ID,
		CSRPem:        "-----BEGIN CERTIFICATE REQUEST-----\nMIIBXTCB...dummy\n-----END CERTIFICATE REQUEST-----",
		TransactionID: "txn-1",
		MessageType:   "pkcsreq",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "challenge_password") {
		t.Fatalf("expected scep challenge policy error, got %v", err)
	}
}
