package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFieldEncryptionLeaseAndReceiptWrapperAuthEnforced(t *testing.T) {
	svc, store, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-auth"

	_, err := svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID:                tenantID,
		LocalCryptoAllowed:      true,
		CacheEnabled:            true,
		CacheTTLSeconds:         600,
		LeaseMaxOps:             100,
		MaxCachedKeys:           4,
		RequireSignedNonce:      true,
		AntiReplayWindowSeconds: 600,
		RequireMTLS:             true,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	reg, signPriv := registerWrapperForAuthTest(t, svc, tenantID, "wrapper-auth-1", "app-auth-1", "aa11bb22cc33")
	if strings.TrimSpace(reg.AuthProfile.Token) == "" {
		t.Fatal("expected auth_profile token")
	}

	leaseNonce := "lease-nonce-1"
	leaseTS := time.Now().UTC().Format(time.RFC3339)
	leaseSig := signWrapperPayload(
		"lease",
		tenantID,
		reg.Wrapper.WrapperID,
		"key-1",
		"encrypt",
		leaseNonce,
		leaseTS,
		signPriv,
	)

	_, err = svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-1",
		Operation:    "encrypt",
		Nonce:        leaseNonce,
		Timestamp:    leaseTS,
		SignatureB64: leaseSig,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	expectServiceErrCode(t, err, "auth_required")

	_, err = svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-1",
		Operation:    "encrypt",
		Nonce:        "lease-nonce-2",
		Timestamp:    leaseTS,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, "key-1", "encrypt", "lease-nonce-2", leaseTS, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: "mismatch-fingerprint",
	})
	expectServiceErrCode(t, err, "access_denied")

	lease, err := svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-1",
		Operation:    "encrypt",
		Nonce:        "lease-nonce-3",
		Timestamp:    leaseTS,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, "key-1", "encrypt", "lease-nonce-3", leaseTS, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("issue lease with wrapper auth: %v", err)
	}
	if strings.TrimSpace(lease.LeaseID) == "" {
		t.Fatal("lease_id is empty")
	}

	renewTS := time.Now().UTC().Format(time.RFC3339)
	renewed, err := svc.RenewFieldEncryptionLease(ctx, tenantID, lease.LeaseID, FieldEncryptionLeaseRequest{
		WrapperID:    lease.WrapperID,
		KeyID:        lease.KeyID,
		Operation:    lease.Operation,
		Nonce:        "lease-renew-nonce-1",
		Timestamp:    renewTS,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, lease.KeyID, lease.Operation, "lease-renew-nonce-1", renewTS, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("renew lease with wrapper auth: %v", err)
	}
	if strings.TrimSpace(renewed.LeaseID) == "" || strings.EqualFold(strings.TrimSpace(renewed.LeaseID), strings.TrimSpace(lease.LeaseID)) {
		t.Fatalf("expected new lease id after renewal, got old=%q new=%q", lease.LeaseID, renewed.LeaseID)
	}
	oldLease, err := store.GetFieldEncryptionLease(ctx, tenantID, lease.LeaseID)
	if err != nil {
		t.Fatalf("load old lease after renewal: %v", err)
	}
	if !oldLease.Revoked {
		t.Fatalf("expected old lease to be revoked after renewal: %+v", oldLease)
	}

	receiptTS := time.Now().UTC().Format(time.RFC3339)
	receiptNonce := "receipt-nonce-1"
	receiptSig := signWrapperPayload(
		"receipt",
		tenantID,
		reg.Wrapper.WrapperID,
		renewed.LeaseID+"|"+renewed.KeyID,
		renewed.Operation+"|1",
		receiptNonce,
		receiptTS,
		signPriv,
	)

	_, err = svc.SubmitFieldEncryptionUsageReceipt(ctx, FieldEncryptionReceiptRequest{
		TenantID:     tenantID,
		LeaseID:      renewed.LeaseID,
		WrapperID:    renewed.WrapperID,
		KeyID:        renewed.KeyID,
		Operation:    renewed.Operation,
		OpCount:      1,
		Nonce:        receiptNonce,
		Timestamp:    receiptTS,
		SignatureB64: receiptSig,
		ClientStatus: "ok",
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	expectServiceErrCode(t, err, "auth_required")

	receipt, err := svc.SubmitFieldEncryptionUsageReceipt(ctx, FieldEncryptionReceiptRequest{
		TenantID:     tenantID,
		LeaseID:      renewed.LeaseID,
		WrapperID:    renewed.WrapperID,
		KeyID:        renewed.KeyID,
		Operation:    renewed.Operation,
		OpCount:      1,
		Nonce:        "receipt-nonce-2",
		Timestamp:    receiptTS,
		SignatureB64: signWrapperPayload("receipt", tenantID, reg.Wrapper.WrapperID, renewed.LeaseID+"|"+renewed.KeyID, renewed.Operation+"|1", "receipt-nonce-2", receiptTS, signPriv),
		ClientStatus: "ok",
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("submit receipt with wrapper auth: %v", err)
	}
	if !receipt.Accepted {
		t.Fatalf("expected accepted receipt, got: %+v", receipt)
	}
}

func registerWrapperForAuthTest(t *testing.T, svc *Service, tenantID string, wrapperID string, appID string, certFP string) (FieldEncryptionWrapperRegistrationResult, ed25519.PrivateKey) {
	t.Helper()
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	curve := ecdh.X25519()
	encPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}
	initOut, err := svc.InitFieldEncryptionWrapperRegistration(context.Background(), FieldEncryptionRegisterInitRequest{
		TenantID:            tenantID,
		WrapperID:           wrapperID,
		AppID:               appID,
		DisplayName:         wrapperID,
		SigningPublicKeyB64: base64.StdEncoding.EncodeToString(signPub),
		EncryptionPublicKey: base64.StdEncoding.EncodeToString(encPriv.PublicKey().Bytes()),
		Transport:           "mtls+jwt",
		Metadata:            map[string]string{"attested": "true"},
	})
	if err != nil {
		t.Fatalf("InitFieldEncryptionWrapperRegistration: %v", err)
	}
	challengeRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(firstString(initOut["challenge_b64"])))
	if err != nil || len(challengeRaw) == 0 {
		t.Fatalf("invalid challenge payload: %v", err)
	}
	sig := ed25519.Sign(signPriv, challengeRaw)
	reg, err := svc.CompleteFieldEncryptionWrapperRegistration(context.Background(), FieldEncryptionRegisterCompleteRequest{
		TenantID:           tenantID,
		ChallengeID:        strings.TrimSpace(firstString(initOut["challenge_id"])),
		WrapperID:          wrapperID,
		SignatureB64:       base64.StdEncoding.EncodeToString(sig),
		CertFingerprint:    strings.ToLower(strings.TrimSpace(certFP)),
		GovernanceApproved: true,
		ApprovedBy:         "test-governance",
	})
	if err != nil {
		t.Fatalf("CompleteFieldEncryptionWrapperRegistration: %v", err)
	}
	return reg, signPriv
}

func signWrapperPayload(mode string, tenantID string, wrapperID string, left string, right string, nonce string, ts string, signPriv ed25519.PrivateKey) string {
	payload := strings.Join([]string{
		mode,
		strings.TrimSpace(tenantID),
		strings.TrimSpace(wrapperID),
		strings.TrimSpace(left),
		strings.TrimSpace(right),
		strings.TrimSpace(nonce),
		strings.TrimSpace(ts),
	}, "|")
	sig := ed25519.Sign(signPriv, []byte(payload))
	return base64.StdEncoding.EncodeToString(sig)
}

func expectServiceErrCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected service error code %q, got nil", want)
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected service error code %q, got non-service error: %v", want, err)
	}
	if strings.TrimSpace(svcErr.Code) != strings.TrimSpace(want) {
		t.Fatalf("expected service error code %q, got %q (%v)", want, svcErr.Code, err)
	}
}

func TestFieldEncryptionTPMAttestationEnforcement(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-attest"
	wrapperID := "wrapper-attested-1"
	appID := "app-attested-1"

	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(sign): %v", err)
	}
	curve := ecdh.X25519()
	encPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}
	akPub, akPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey(ak): %v", err)
	}
	akDER, err := x509.MarshalPKIXPublicKey(akPub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	akPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: akDER}))
	akSum := sha256.Sum256(akDER)
	akFP := hex.EncodeToString(akSum[:])

	_, err = svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID:                       tenantID,
		RequireTPMAttestation:          true,
		AttestedWrapperOnly:            true,
		RequireNonExportableWrapperKey: true,
		AttestationAKAllowlist:         []string{akFP},
		AttestationAllowedPCRs: map[string][]string{
			"0": []string{"abc123"},
			"7": []string{"def456"},
		},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	initOut, err := svc.InitFieldEncryptionWrapperRegistration(ctx, FieldEncryptionRegisterInitRequest{
		TenantID:            tenantID,
		WrapperID:           wrapperID,
		AppID:               appID,
		DisplayName:         wrapperID,
		SigningPublicKeyB64: base64.StdEncoding.EncodeToString(signPub),
		EncryptionPublicKey: base64.StdEncoding.EncodeToString(encPriv.PublicKey().Bytes()),
		Transport:           "mtls+jwt",
		Metadata:            map[string]string{"source": "test"},
	})
	if err != nil {
		t.Fatalf("init registration: %v", err)
	}
	challengeID := strings.TrimSpace(firstString(initOut["challenge_id"]))
	challengeB64 := strings.TrimSpace(firstString(initOut["challenge_b64"]))
	challengeNonce := strings.TrimSpace(firstString(initOut["nonce"]))
	challengeRaw, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil || len(challengeRaw) == 0 {
		t.Fatalf("decode challenge: %v", err)
	}
	challengeSig := base64.StdEncoding.EncodeToString(ed25519.Sign(signPriv, challengeRaw))

	_, err = svc.CompleteFieldEncryptionWrapperRegistration(ctx, FieldEncryptionRegisterCompleteRequest{
		TenantID:           tenantID,
		ChallengeID:        challengeID,
		WrapperID:          wrapperID,
		SignatureB64:       challengeSig,
		GovernanceApproved: true,
		ApprovedBy:         "attest-test",
	})
	expectServiceErrCode(t, err, "policy_denied")

	badEvidenceRaw, badSignatureB64 := signedAttestationPayload(t, akPriv, map[string]interface{}{
		"tenant_id":          tenantID,
		"wrapper_id":         wrapperID,
		"app_id":             appID,
		"challenge_id":       challengeID,
		"nonce":              challengeNonce,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"ak_fingerprint":     akFP,
		"non_exportable_key": false,
		"pcrs":               map[string]string{"0": "abc123", "7": "def456"},
	})
	_, err = svc.CompleteFieldEncryptionWrapperRegistration(ctx, FieldEncryptionRegisterCompleteRequest{
		TenantID:                tenantID,
		ChallengeID:             challengeID,
		WrapperID:               wrapperID,
		SignatureB64:            challengeSig,
		GovernanceApproved:      true,
		ApprovedBy:              "attest-test",
		AttestationEvidenceB64:  base64.StdEncoding.EncodeToString(badEvidenceRaw),
		AttestationSignatureB64: badSignatureB64,
		AttestationPublicKeyPEM: akPEM,
	})
	expectServiceErrCode(t, err, "policy_denied")

	goodEvidenceRaw, goodSignatureB64 := signedAttestationPayload(t, akPriv, map[string]interface{}{
		"tenant_id":          tenantID,
		"wrapper_id":         wrapperID,
		"app_id":             appID,
		"challenge_id":       challengeID,
		"nonce":              challengeNonce,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"ak_fingerprint":     akFP,
		"non_exportable_key": true,
		"pcrs":               map[string]string{"0": "abc123", "7": "def456"},
	})
	out, err := svc.CompleteFieldEncryptionWrapperRegistration(ctx, FieldEncryptionRegisterCompleteRequest{
		TenantID:                tenantID,
		ChallengeID:             challengeID,
		WrapperID:               wrapperID,
		SignatureB64:            challengeSig,
		GovernanceApproved:      true,
		ApprovedBy:              "attest-test",
		AttestationEvidenceB64:  base64.StdEncoding.EncodeToString(goodEvidenceRaw),
		AttestationSignatureB64: goodSignatureB64,
		AttestationPublicKeyPEM: akPEM,
	})
	if err != nil {
		t.Fatalf("complete registration with attestation: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(out.Wrapper.Metadata["attestation_verified"]), "true") {
		t.Fatalf("expected attestation_verified metadata, got: %+v", out.Wrapper.Metadata)
	}
	if !strings.EqualFold(strings.TrimSpace(out.Wrapper.Metadata["non_exportable_key_asserted"]), "true") {
		t.Fatalf("expected non_exportable_key_asserted metadata, got: %+v", out.Wrapper.Metadata)
	}
}

func TestFieldEncryptionMissingReceiptReconciliation(t *testing.T) {
	svc, store, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-reconcile"

	_, err := svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID:                       tenantID,
		LocalCryptoAllowed:             true,
		CacheEnabled:                   true,
		CacheTTLSeconds:                300,
		LeaseMaxOps:                    100,
		MaxCachedKeys:                  4,
		RequireSignedNonce:             true,
		AntiReplayWindowSeconds:        600,
		ReceiptReconciliationEnabled:   true,
		ReceiptHeartbeatSec:            1,
		ReceiptMissingGraceSec:         1,
		RequireRegisteredWrapper:       true,
		RequireTPMAttestation:          false,
		RequireNonExportableWrapperKey: false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	reg, signPriv := registerWrapperForAuthTest(t, svc, tenantID, "wrapper-reconcile-1", "app-reconcile-1", "ff11ee22dd33")
	leaseTS := time.Now().UTC().Format(time.RFC3339)
	lease, err := svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-1",
		Operation:    "encrypt",
		Nonce:        "lease-reconcile-1",
		Timestamp:    leaseTS,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, "key-1", "encrypt", "lease-reconcile-1", leaseTS, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}

	origNow := svc.now
	svc.now = func() time.Time { return time.Now().UTC().Add(10 * time.Minute) }
	t.Cleanup(func() { svc.now = origNow })

	scanned, revoked, err := svc.ReconcileMissingFieldEncryptionReceipts(ctx, 200)
	if err != nil {
		t.Fatalf("reconcile missing receipts: %v", err)
	}
	if scanned == 0 {
		t.Fatalf("expected reconciler to scan leases")
	}
	if revoked == 0 {
		t.Fatalf("expected reconciler to revoke stale lease")
	}
	updated, err := store.GetFieldEncryptionLease(ctx, tenantID, lease.LeaseID)
	if err != nil {
		t.Fatalf("get lease after reconcile: %v", err)
	}
	if !updated.Revoked {
		t.Fatalf("expected lease revoked by reconciler, got: %+v", updated)
	}
}

func TestFieldEncryptionLeaseRequiresExportableKey(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-exportable"

	_, err := svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID:                tenantID,
		LocalCryptoAllowed:      true,
		CacheEnabled:            true,
		CacheTTLSeconds:         300,
		LeaseMaxOps:             100,
		MaxCachedKeys:           4,
		RequireSignedNonce:      true,
		AntiReplayWindowSeconds: 600,
		RequireMTLS:             false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	reg, signPriv := registerWrapperForAuthTest(t, svc, tenantID, "wrapper-export-1", "app-export-1", "deafbeef0011")
	ts := time.Now().UTC().Format(time.RFC3339)

	_, err = svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-no-export",
		Operation:    "encrypt",
		Nonce:        "lease-no-export-1",
		Timestamp:    ts,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, "key-no-export", "encrypt", "lease-no-export-1", ts, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	expectServiceErrCode(t, err, "policy_denied")

	lease, err := svc.IssueFieldEncryptionLease(ctx, FieldEncryptionLeaseRequest{
		TenantID:     tenantID,
		WrapperID:    reg.Wrapper.WrapperID,
		KeyID:        "key-1",
		Operation:    "encrypt",
		Nonce:        "lease-export-1",
		Timestamp:    ts,
		SignatureB64: signWrapperPayload("lease", tenantID, reg.Wrapper.WrapperID, "key-1", "encrypt", "lease-export-1", ts, signPriv),
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("IssueFieldEncryptionLease(exportable): %v", err)
	}
	if strings.TrimSpace(lease.LeaseID) == "" {
		t.Fatalf("expected lease id for exportable key")
	}
}

func signedAttestationPayload(t *testing.T, signer ed25519.PrivateKey, payload map[string]interface{}) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal attestation payload: %v", err)
	}
	sig := ed25519.Sign(signer, raw)
	return raw, base64.StdEncoding.EncodeToString(sig)
}
