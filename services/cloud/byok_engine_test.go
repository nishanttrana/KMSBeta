package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"vecta-kms/pkg/credstore"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

// setCred puts a credential in the test store.
func setCred(svc *Service, id, typ string, fields map[string]string) {
	tc := svc.creds.(*testCredentials)
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.creds[id] = credstore.Credential{ID: id, Type: typ, Fields: fields}
}

func awsAccount(t *testing.T, svc *Service, tenant, endpoint string) CloudAccount {
	t.Helper()
	// 40 characters, as AWS issues them: SigV4 keys HMAC with "AWS4"+secret,
	// and strict FIPS mode refuses HMAC keys under 112 bits.
	setCred(svc, "cred-aws-double", "aws", map[string]string{"access_key_id": "AKIATEST", "secret_access_key": "test-only-0000000000000000000000000000000", "region": "us-east-1", "endpoint_url": endpoint})
	acct, err := svc.RegisterAccount(attachCtx(tenant), RegisterCloudAccountRequest{TenantID: tenant, Provider: ProviderAWS, Name: "aws-" + tenant, DefaultRegion: "us-east-1", ConnectionID: "cred-aws-double"})
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

func byokReason(err error) string {
	var r *byokRefusal
	if errors.As(err, &r) {
		return r.reason
	}
	var kc *keycoreError
	if errors.As(err, &kc) {
		return kc.Code
	}
	return ""
}

func stepNames(run BYOKRun) []string {
	out := []string{}
	for _, s := range run.Steps {
		out = append(out, s.Name+":"+s.Status)
	}
	return out
}

// The whole lifecycle against AWS KMS's protocol: the material the cloud
// unwraps is the KMS key version's, rotation brings the next version in as
// new material and makes it current, reimport renews the expiry of the same
// material, revoke deletes it in the cloud (encrypt stops working) and
// restore brings it back from the KMS.
func TestBYOKLifecycleAWS(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()

	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", Alias: "orders-db", ValidityDays: 90})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if run.Status != "succeeded" || len(run.Steps) != 6 || key.Source != SourceKMS || key.KeySpec != SpecAES256 || key.Alias != "alias/orders-db" {
		t.Fatalf("create run %v key %+v", stepNames(run), key)
	}
	cloudKey := d.keys[key.CloudKeyID]
	if got, want := cloudKey.material[cloudKey.current], kc.material("t1", "key-1", 1); string(got) != string(want) {
		t.Fatal("the cloud holds different material than KMS version 1")
	}
	if key.ExpiresAt == nil || cloudKey.validTo == nil {
		t.Fatal("expiry not set")
	}
	detail, _ := svc.GetBYOK(ctx, "t1", key.ID)
	if len(detail.Materials) != 1 || detail.Materials[0].KMSVersion != 1 || detail.Materials[0].KCV != kcvOf(kc.material("t1", "key-1", 1)) || len(detail.Runs) != 1 {
		t.Fatalf("custody %+v runs %d", detail.Materials, len(detail.Runs))
	}

	// Rotate: KMS version 2 becomes the cloud's current material.
	run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{})
	if err != nil {
		t.Fatalf("rotate: %v %v", err, stepNames(run))
	}
	if got := cloudKey.material[cloudKey.current]; string(got) != string(kc.material("t1", "key-1", 2)) {
		t.Fatal("after rotation the cloud's current material is not KMS version 2")
	}
	detail, _ = svc.GetBYOK(ctx, "t1", key.ID)
	states := map[int]string{}
	for _, m := range detail.Materials {
		states[m.KMSVersion] = m.State
	}
	if states[1] != MaterialPrevious || states[2] != MaterialCurrent {
		t.Fatalf("custody after rotate %v", states)
	}

	// Reimport renews the same material; different material is refused by
	// the cloud, so this proves the engine wrapped version 2 again.
	if run, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpReimport, "alice", BYOKOperationRequest{ValidityDays: 30}); err != nil {
		t.Fatalf("reimport: %v %v", err, stepNames(run))
	}

	// Revoke: the material is deleted in the cloud and encryption stops.
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatalf("revoke: %v %v", err, stepNames(run))
	}
	if key.MaterialState != MaterialRevoked || cloudKey.state != "PendingImport" {
		t.Fatalf("after revoke: %s / %s", key.MaterialState, cloudKey.state)
	}
	if run, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpVerify, "alice", BYOKOperationRequest{}); err == nil {
		t.Fatalf("a revoked key verified: %v", stepNames(run))
	}

	// Restore re-imports version 2 from the KMS.
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil {
		t.Fatalf("restore: %v %v", err, stepNames(run))
	}
	if key.MaterialState != MaterialCurrent || string(cloudKey.material[cloudKey.current]) != string(kc.material("t1", "key-1", 2)) {
		t.Fatal("restore did not bring version 2 back")
	}
	if run, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpVerify, "alice", BYOKOperationRequest{}); err != nil || run.Steps[0].Status != "succeeded" {
		t.Fatalf("verify after restore: %v %v", err, stepNames(run))
	}
	runs, _ := svc.byokStore.ListBYOKRuns(ctx, "t1", key.ID, 50)
	if len(runs) != 7 {
		t.Fatalf("%d runs recorded, want 7", len(runs))
	}
}

// Refusals happen before anything reaches the cloud, with their reasons.
func TestBYOKRefusals(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "t1", endpoint)
	ctx := context.Background()

	kc.Seed("t1", "fixed", "AES-256")
	kc.keys["t1/fixed"].exportOK = false
	if _, _, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "fixed"}); byokReason(err) != "key_not_exportable" {
		t.Fatalf("non-exportable key: %v", err)
	}
	kc.Seed("t1", "des", "3DES-168")
	if _, _, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "des"}); byokReason(err) != "spec_not_supported" {
		t.Fatalf("3DES key: %v", err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	if _, _, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", ValidityDays: 400}); byokReason(err) != "bad_request" {
		t.Fatalf("400-day validity: %v", err)
	}
	if len(d.calls) != 0 {
		t.Fatalf("refused requests reached the cloud: %v", d.calls)
	}

	// keycore refuses mid-run (here: the key's version is an HSM key made
	// without cloud import): the cloud key stays, waiting for material.
	kc.refuse["key-1"] = &keycoreError{Status: http.StatusConflict, Code: "key_not_extractable", Message: "never leaves the HSM"}
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if byokReason(err) != "key_not_extractable" || run.Status != "failed" || key.MaterialState != MaterialFailed {
		t.Fatalf("mid-run refusal: %v %v %+v", err, stepNames(run), key)
	}
	// Once fixed, the pending key is imported with reimport.
	delete(kc.refuse, "key-1")
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpReimport, "alice", BYOKOperationRequest{}); err != nil || key.MaterialState != MaterialCurrent {
		t.Fatalf("import into the pending key: %v %v", err, stepNames(run))
	}

	// Alibaba can't take new material on a key: rotate is refused.
	if _, _, err := svc.RunBYOK(ctx, "t1", "missing", OpRotate, "alice", BYOKOperationRequest{}); byokReason(err) != "not_found" {
		t.Fatalf("missing key: %v", err)
	}
}

// Key access deployed but unreachable: no material leaves, the refusal is
// a 424 key_access_unavailable and audited (until 6.10.0-beta the error
// was turned into an allow).
func TestBYOKKeyAccessUnavailableRefuses(t *testing.T) {
	svc, _, kc, pub := newCloudService(t)
	d, endpoint := newAWSKMSDouble(t)
	acct := awsAccount(t, svc, "tenant-ka", endpoint)
	kc.Seed("tenant-ka", "key-ka", "AES-256")
	svc.SetKeyAccess(unreachableKeyAccess(t))
	_, _, err := svc.CreateBYOK(context.Background(), "tenant-ka", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-ka"})
	if httpStatusForErr(err) != http.StatusFailedDependency || serviceCode(err, "") != pkgkeyaccess.ReasonUnavailable {
		t.Fatalf("%v, want 424 key_access_unavailable", err)
	}
	if ev := pub.Last("audit.cloud.key_access_denied"); ev["result"] != "refused" || ev["reason"] != pkgkeyaccess.ReasonUnavailable {
		t.Fatalf("refusal event %+v", ev)
	}
	if len(d.calls) != 0 {
		t.Fatalf("the cloud was called: %v", d.calls)
	}
}
