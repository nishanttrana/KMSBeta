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
	if _, err := svc.GetCertificate(ctx, "td", issued.ID); err == nil {
		t.Fatalf("expected not found after hard delete")
	}
	deleted, err := svc.ListCertificates(ctx, "td", CertStatusDeleted, "", 50, 0)
	if err != nil {
		t.Fatalf("list deleted: %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected empty list after hard delete, got %+v", deleted)
	}
}

func TestDeleteInternalMTLSCertificateBlocked(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "timtls",
		Name:       "runtime-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Runtime Root,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	issued, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "timtls",
		CAID:      ca.ID,
		SubjectCN: "kms-envoy",
		CertType:  "tls-client",
		Algorithm: "ECDSA-P384",
		CertClass: "internal-mtls",
		Protocol:  "internal-mtls",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	err = svc.DeleteCertificate(ctx, "timtls", issued.ID)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "internal-mtls") {
		t.Fatalf("expected internal-mtls delete block, got %v", err)
	}
	got, err := svc.GetCertificate(ctx, "timtls", issued.ID)
	if err != nil {
		t.Fatalf("get after failed delete: %v", err)
	}
	if strings.ToLower(got.Status) == CertStatusDeleted {
		t.Fatalf("internal-mtls certificate must not be marked deleted")
	}
}

func TestDeleteCARequiresNoChildrenAndNoCertificates(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	root, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "tca-del",
		Name:       "root-ca",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root CA,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	leaf, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "tca-del",
		Name:       "leaf-ca",
		ParentCAID: root.ID,
		CALevel:    "intermediate",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Leaf CA,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	if err := svc.DeleteCA(ctx, "tca-del", root.ID, false); err == nil || !strings.Contains(strings.ToLower(err.Error()), "child") {
		t.Fatalf("expected child CA delete block, got %v", err)
	}

	issued, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "tca-del",
		CAID:      leaf.ID,
		SubjectCN: "svc.ca-delete.local",
		CertType:  "tls-server",
		Algorithm: "ECDSA-P256",
	})
	if err != nil {
		t.Fatalf("issue leaf cert: %v", err)
	}
	if err := svc.DeleteCA(ctx, "tca-del", leaf.ID, false); err == nil || !strings.Contains(strings.ToLower(err.Error()), "issued certificate") {
		t.Fatalf("expected issued certificate delete block, got %v", err)
	}
	if err := svc.DeleteCertificate(ctx, "tca-del", issued.ID); err != nil {
		t.Fatalf("delete cert: %v", err)
	}
	if err := svc.DeleteCA(ctx, "tca-del", leaf.ID, false); err != nil {
		t.Fatalf("delete leaf ca: %v", err)
	}
	if _, err := svc.store.GetCA(ctx, "tca-del", leaf.ID); err == nil {
		t.Fatalf("expected deleted CA to be removed")
	}
}

func TestDeleteRuntimeRootCABlocked(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	tenant := "t-runtime-del"
	runtimeName := svc.runtimeRootCAName(ctx, tenant)
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   tenant,
		Name:       runtimeName,
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Runtime Root,O=Vecta",
	})
	if err != nil {
		t.Fatalf("create runtime root: %v", err)
	}
	if err := svc.DeleteCA(ctx, tenant, ca.ID, false); err == nil || !strings.Contains(strings.ToLower(err.Error()), "runtime root") {
		t.Fatalf("expected runtime root delete block, got %v", err)
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

func TestRuntimeMTLSTenantDefaultRootAutoCreated(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()

	cas, err := svc.ListCAs(ctx, "trt-default")
	if err != nil {
		t.Fatalf("list cas: %v", err)
	}
	found := false
	for _, ca := range cas {
		if strings.EqualFold(strings.TrimSpace(ca.Name), "vecta-runtime-root") && strings.EqualFold(strings.TrimSpace(ca.CALevel), "root") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected default runtime root CA to be auto-created")
	}
}

func TestRuntimeMTLSTenantCustomRootAutoCreated(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()

	_, err := svc.UpsertProtocolConfig(ctx, UpsertProtocolConfigRequest{
		TenantID:   "trt-custom",
		Protocol:   "runtime-mtls",
		Enabled:    true,
		ConfigJSON: `{"mode":"custom","runtime_root_ca_name":"tenant-runtime-root"}`,
		UpdatedBy:  "test",
	})
	if err != nil {
		t.Fatalf("upsert runtime-mtls config: %v", err)
	}

	cas, err := svc.ListCAs(ctx, "trt-custom")
	if err != nil {
		t.Fatalf("list cas: %v", err)
	}
	customFound := false
	defaultFound := false
	for _, ca := range cas {
		name := strings.ToLower(strings.TrimSpace(ca.Name))
		switch name {
		case "tenant-runtime-root":
			customFound = true
		case "vecta-runtime-root":
			defaultFound = true
		}
	}
	if !customFound {
		t.Fatalf("expected custom runtime root CA to be auto-created")
	}
	if defaultFound {
		t.Fatalf("did not expect default runtime root when custom mode is active")
	}
}

func TestIssueInternalMTLSUsesTenantRuntimeRootWhenCAIDMissing(t *testing.T) {
	svc, store := newCertsService(t)
	ctx := context.Background()

	_, err := svc.UpsertProtocolConfig(ctx, UpsertProtocolConfigRequest{
		TenantID:   "trt-issue",
		Protocol:   "runtime-mtls",
		Enabled:    true,
		ConfigJSON: `{"mode":"custom","runtime_root_ca_name":"issuer-runtime-root"}`,
		UpdatedBy:  "test",
	})
	if err != nil {
		t.Fatalf("upsert runtime-mtls config: %v", err)
	}

	issued, _, err := svc.IssueInternalMTLS(ctx, "auth", InternalMTLSRequest{
		TenantID: "trt-issue",
		CAID:     "",
	})
	if err != nil {
		t.Fatalf("issue internal mtls: %v", err)
	}
	ca, err := store.GetCA(ctx, "trt-issue", issued.CAID)
	if err != nil {
		t.Fatalf("get issuing ca: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(ca.Name), "issuer-runtime-root") {
		t.Fatalf("expected issuer-runtime-root, got %s", ca.Name)
	}
}
