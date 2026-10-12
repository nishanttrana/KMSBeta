package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/fips/fipstest"
)

// TestLiveCloudBYOK runs cloud BYOK against real cloud accounts
// (docs/SECURITY/CLOUD_BYOK_LIVE_VERIFICATION.md). It is skipped unless a
// cloud's settings are in the environment; scripts/verify-byok-live.sh runs
// it from a file of them, and the "Cloud BYOK — live verification" workflow
// from repository secrets.
//
// For each cloud it registers the account, checks that a wrong credential
// is refused, imports a fresh AES-256 key (the cloud's own import protocol,
// wrapped by the same pkg/crypto code keycore uses), reads the custody
// record, uses the key in the cloud through the console, rotates, revokes
// (the key must then stop working), restores, and finally schedules the
// cloud key for deletion. The key material is random and made for the run.
//
// It logs step names, counts and the cloud's own error text, never a
// credential.
//
//	AWS KMS:      VECTA_TEST_BYOK_AWS_ACCESS_KEY, _SECRET_KEY, _REGION
//	              (_SESSION_TOKEN, _ROLE_ARN, _EXTERNAL_ID optional)
//	Google Cloud: VECTA_TEST_BYOK_GCP_SERVICE_ACCOUNT_FILE (path of the JSON
//	              key file), _PROJECT, _LOCATION, _KEY_RING
//	Azure:        VECTA_TEST_BYOK_AZURE_VAULT_URL (a Managed HSM: Key Vault
//	              takes no AES key), _TENANT_ID, _CLIENT_ID, _CLIENT_SECRET
//	OCI Vault:    VECTA_TEST_BYOK_OCI_TENANCY, _USER, _FINGERPRINT,
//	              _PRIVATE_KEY_FILE, _REGION, _COMPARTMENT,
//	              _MANAGEMENT_ENDPOINT, _CRYPTO_ENDPOINT
//	Alibaba:      VECTA_TEST_BYOK_ALIBABA_ACCESS_KEY, _SECRET_KEY, _REGION
type liveCloud struct {
	name     string
	provider string
	fields   map[string]string
	region   string
	// wrong returns the credential altered so the cloud must refuse it.
	wrong func(map[string]string) map[string]string
	// reimport: renewing the same material is part of this cloud's protocol.
	reimport bool
	// versioned: deletion is per key version (Google Cloud).
	versioned bool
	// left says what the cloud keeps after the run.
	left string
}

func liveClouds(t *testing.T) []liveCloud {
	env := func(name string) string { return strings.TrimSpace(os.Getenv("VECTA_TEST_BYOK_" + name)) }
	file := func(name string) string {
		raw, err := os.ReadFile(env(name))
		if err != nil {
			t.Fatalf("VECTA_TEST_BYOK_%s: the file cannot be read", name)
		}
		return string(raw)
	}
	alter := func(field string) func(map[string]string) map[string]string {
		return func(f map[string]string) map[string]string {
			// The same length and alphabet, so the request is well formed
			// and only the cloud can tell it is wrong.
			b := []byte(f[field])
			for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
			if string(b) == f[field] {
				b = append(b[1:], b[0]+1)
			}
			f[field] = string(b)
			return f
		}
	}
	var out []liveCloud
	if env("AWS_ACCESS_KEY") != "" {
		out = append(out, liveCloud{name: "AWS KMS", provider: ProviderAWS, region: env("AWS_REGION"), reimport: true,
			fields: map[string]string{"access_key_id": env("AWS_ACCESS_KEY"), "secret_access_key": env("AWS_SECRET_KEY"), "session_token": env("AWS_SESSION_TOKEN"),
				"region": env("AWS_REGION"), "role_arn": env("AWS_ROLE_ARN"), "external_id": env("AWS_EXTERNAL_ID")},
			wrong: alter("secret_access_key"),
			left:  "the key, pending deletion for 7 days (AWS's shortest wait)"})
	}
	if env("GCP_SERVICE_ACCOUNT_FILE") != "" {
		out = append(out, liveCloud{name: "Google Cloud KMS", provider: ProviderGCP, region: env("GCP_LOCATION"), versioned: true,
			fields: map[string]string{"service_account_json": file("GCP_SERVICE_ACCOUNT_FILE"), "project_id": env("GCP_PROJECT"), "location": env("GCP_LOCATION"), "key_ring": env("GCP_KEY_RING")},
			// Another key under the same name: Google must refuse the signature.
			wrong: func(f map[string]string) map[string]string {
				var sa map[string]interface{}
				if json.Unmarshal([]byte(f["service_account_json"]), &sa) != nil {
					t.Fatal("VECTA_TEST_BYOK_GCP_SERVICE_ACCOUNT_FILE is not a JSON key file")
				}
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				der, _ := x509.MarshalPKCS8PrivateKey(key)
				sa["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
				raw, _ := json.Marshal(sa)
				f["service_account_json"] = string(raw)
				return f
			},
			left: "the key ring, the key and its import jobs (Google deletes none of them); the key's versions are scheduled for destruction"})
	}
	if env("AZURE_VAULT_URL") != "" {
		out = append(out, liveCloud{name: "Azure Managed HSM", provider: ProviderAzure,
			fields: map[string]string{"vault_url": env("AZURE_VAULT_URL"), "tenant_id": env("AZURE_TENANT_ID"), "client_id": env("AZURE_CLIENT_ID"), "client_secret": env("AZURE_CLIENT_SECRET")},
			wrong:  alter("client_secret"),
			left:   "the key, soft-deleted until the vault's retention period ends"})
	}
	if env("OCI_TENANCY") != "" {
		out = append(out, liveCloud{name: "OCI Vault", provider: ProviderOCI, region: env("OCI_REGION"),
			fields: map[string]string{"tenancy_ocid": env("OCI_TENANCY"), "user_ocid": env("OCI_USER"), "fingerprint": env("OCI_FINGERPRINT"), "private_key_pem": file("OCI_PRIVATE_KEY_FILE"),
				"region": env("OCI_REGION"), "compartment_id": env("OCI_COMPARTMENT"), "management_endpoint": env("OCI_MANAGEMENT_ENDPOINT"), "crypto_endpoint": env("OCI_CRYPTO_ENDPOINT")},
			// A fingerprint that names no key of the user.
			wrong: alter("fingerprint"),
			left:  "the key, pending deletion for 7 days (OCI's shortest wait)"})
	}
	if env("ALIBABA_ACCESS_KEY") != "" {
		out = append(out, liveCloud{name: "Alibaba Cloud KMS", provider: ProviderAlibaba, region: env("ALIBABA_REGION"),
			fields: map[string]string{"access_key_id": env("ALIBABA_ACCESS_KEY"), "access_key_secret": env("ALIBABA_SECRET_KEY"), "region": env("ALIBABA_REGION")},
			wrong:  alter("access_key_secret"),
			left:   "the key, pending deletion for 7 days (Alibaba's shortest wait)"})
	}
	for i := range out {
		for k, v := range out[i].fields {
			if v == "" {
				delete(out[i].fields, k)
			}
		}
	}
	return out
}

func TestLiveCloudBYOK(t *testing.T) {
	clouds := liveClouds(t)
	if len(clouds) == 0 {
		t.Skip("set a cloud's VECTA_TEST_BYOK_* settings to run BYOK against a real account (scripts/verify-byok-live.sh)")
	}
	for _, c := range clouds {
		c := c
		t.Run(c.name, func(t *testing.T) { liveBYOK(t, c) })
	}
}

func liveBYOK(t *testing.T, c liveCloud) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	svc, _, kc, _ := newCloudService(t)
	caps := svc.byokProviders[c.provider].Capabilities()
	console, _ := svc.consoleProviderFor(c.provider)
	has := func(op string) bool { _, ok := console.Console()[op]; return ok }
	rt, _ := consoleRouter(svc)

	account := func(id string, fields map[string]string) CloudAccount {
		setCred(svc, id, c.provider, fields)
		acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: c.provider, Name: id, DefaultRegion: c.region, ConnectionID: id})
		if err != nil {
			t.Fatalf("register the account: %v", err)
		}
		return acct
	}
	acct := account("live", c.fields)
	op := func(acct CloudAccount, name, key, version string, params map[string]string) (int, consoleOut) {
		return runOp(t, rt, rw, name, map[string]interface{}{"account_id": acct.ID, "key": key, "version": version, "params": params})
	}

	// The account answers, and a wrong credential does not.
	if code, out := op(acct, "list-keys", "", "", nil); code != 200 {
		t.Fatalf("list keys with the credential given: HTTP %d %s: %s", code, out.Error.Code, out.Error.Message)
	}
	t.Logf("%s: the account lists its keys", c.name)
	if c.wrong != nil {
		altered := map[string]string{}
		for k, v := range c.fields {
			altered[k] = v
		}
		if code, out := op(account("live-wrong", c.wrong(altered)), "list-keys", "", "", nil); code == 200 {
			t.Fatalf("%s answered a credential that was altered", c.name)
		} else {
			t.Logf("%s: an altered credential is refused (HTTP %d %s)", c.name, code, out.Error.Code)
		}
	}

	// Import.
	kc.Seed("t1", "key-live", "AES-256")
	req := CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-live", Alias: "vecta-live-" + time.Now().UTC().Format("20060102-150405"),
		Description: "Vecta KMS BYOK live verification; safe to delete"}
	if caps.Expiry {
		req.ValidityDays = 2 // the material expires by itself if the clean-up below cannot run
	}
	run, key, err := svc.CreateBYOK(ctx, "t1", "live-check", req)
	t.Cleanup(func() {
		liveCleanup(t, svc, c, key, func(version string) (int, consoleOut) {
			return op(acct, "schedule-key-deletion", key.CloudKeyID, version, map[string]string{"pending_days": "7"})
		})
	})
	if err != nil || run.Status != "succeeded" {
		t.Fatalf("import: %v; steps %v", err, stepNames(run))
	}
	t.Logf("%s: imported; steps %v", c.name, stepNames(run))
	detail, err := svc.GetBYOK(ctx, "t1", key.ID)
	if err != nil || len(detail.Materials) != 1 || detail.Materials[0].KMSVersion != 1 || detail.Materials[0].KCV != kcvOf(kc.material("t1", "key-live", 1)) {
		t.Fatalf("custody after import: %+v %v", detail.Materials, err)
	}
	if caps.Expiry && key.ExpiresAt == nil {
		t.Fatal("an expiry was asked for and none is recorded")
	}

	// The key works in the cloud, asked through the console.
	if code, out := op(acct, "describe-key", key.CloudKeyID, "", nil); code != 200 {
		t.Fatalf("describe: HTTP %d %s: %s", code, out.Error.Code, out.Error.Message)
	}
	roundTrip := func(when string) {
		if !has("encrypt") || !has("decrypt") {
			return
		}
		version := ""
		if c.provider == ProviderAzure { // Azure addresses a key version
			version = key.CurrentMatID
		}
		code, out := op(acct, "encrypt", key.CloudKeyID, version, map[string]string{"plaintext_b64": b64s("vecta live check")})
		if code != 200 {
			t.Fatalf("encrypt %s: HTTP %d %s: %s", when, code, out.Error.Code, out.Error.Message)
		}
		var enc map[string]interface{}
		_ = json.Unmarshal(out.Result, &enc)
		params := map[string]string{}
		for _, name := range []string{"ciphertext_b64", "iv_b64", "tag_b64"} { // iv and tag: Azure AES-GCM
			if v := anyToString(enc[name]); v != "" {
				params[name] = v
			}
		}
		if code, out = op(acct, "decrypt", key.CloudKeyID, version, params); code != 200 || !strings.Contains(string(out.Result), "vecta live check") {
			t.Fatalf("decrypt %s: HTTP %d %s: %s", when, code, out.Error.Code, out.Error.Message)
		}
		t.Logf("%s: the cloud encrypts and decrypts with the key %s", c.name, when)
	}
	roundTrip("after the import")
	if has("tag-key") && has("list-tags") && has("untag-key") {
		if code, out := op(acct, "tag-key", key.CloudKeyID, "", map[string]string{"tag_key": "vecta-live", "tag_value": "check"}); code != 200 {
			t.Fatalf("tag: HTTP %d %s: %s", code, out.Error.Code, out.Error.Message)
		}
		if _, out := op(acct, "list-tags", key.CloudKeyID, "", nil); !strings.Contains(string(out.Result), "vecta-live") {
			t.Fatal("the tag just set is not listed")
		}
		if code, out := op(acct, "untag-key", key.CloudKeyID, "", map[string]string{"tag_key": "vecta-live"}); code != 200 {
			t.Fatalf("untag: HTTP %d %s: %s", code, out.Error.Code, out.Error.Message)
		}
		t.Logf("%s: a tag is set, listed and removed", c.name)
	}

	step := func(operation string, in BYOKOperationRequest) BYOKRun {
		t.Helper()
		run, k, err := svc.RunBYOK(ctx, "t1", key.ID, operation, "live-check", in)
		if err != nil {
			t.Fatalf("%s: %v; steps %v", operation, err, stepNames(run))
		}
		key = k
		t.Logf("%s: %s; steps %v", c.name, operation, stepNames(run))
		return run
	}
	if caps.Verify {
		step(OpVerify, BYOKOperationRequest{})
	}
	if caps.Rotate {
		step(OpRotate, BYOKOperationRequest{ValidityDays: req.ValidityDays})
		detail, _ = svc.GetBYOK(ctx, "t1", key.ID)
		current := 0
		for _, m := range detail.Materials {
			if m.State == MaterialCurrent {
				current = m.KMSVersion
			}
		}
		if current != 2 {
			t.Fatalf("after rotation the current material is KMS version %d, not 2", current)
		}
		roundTrip("after the rotation")
	} else if _, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "live-check", BYOKOperationRequest{}); byokReason(err) != "operation_not_supported" {
		t.Fatalf("this cloud takes no new material, and rotate was not refused: %v", err)
	}
	if c.reimport {
		step(OpReimport, BYOKOperationRequest{ValidityDays: req.ValidityDays})
	}
	if caps.Revoke {
		step(OpRevoke, BYOKOperationRequest{Reason: "live verification"})
		if caps.Verify {
			if run, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpVerify, "live-check", BYOKOperationRequest{}); err == nil {
				t.Fatalf("the key still works in the cloud after its material was revoked: %v", stepNames(run))
			}
			t.Logf("%s: the revoked key no longer works in the cloud", c.name)
		}
		step(OpRestore, BYOKOperationRequest{})
		if caps.Verify {
			step(OpVerify, BYOKOperationRequest{})
		}
	}
}

// liveCleanup schedules the cloud key for deletion and says what the cloud
// keeps. A failure here fails the run: a key left behind costs money.
func liveCleanup(t *testing.T, svc *Service, c liveCloud, key BYOKKey, schedule func(version string) (int, consoleOut)) {
	if key.CloudKeyID == "" {
		return
	}
	versions := []string{""}
	if c.versioned {
		versions = nil
		detail, _ := svc.GetBYOK(context.Background(), "t1", key.ID)
		for _, m := range detail.Materials {
			if m.CloudMaterialID != "" {
				versions = append(versions, m.CloudMaterialID)
			}
		}
	}
	for _, v := range versions {
		if code, out := schedule(v); code != 200 {
			t.Errorf("CLEAN UP BY HAND: %s key %s was not scheduled for deletion (HTTP %d %s: %s)", c.name, key.CloudKeyID, code, out.Error.Code, out.Error.Message)
			return
		}
	}
	t.Logf("%s: clean-up done. Left in the account: %s", c.name, c.left)
}

// The live run's own steps, proved on the protocol doubles: without this a
// mistake in the sequence would first show on a real account, as a key left
// behind. The doubles do not check request signatures, so the
// altered-credential step is the one part only a real cloud exercises.
func TestLiveFlowRunsOnTheDoubles(t *testing.T) {
	t.Run("AWS", func(t *testing.T) {
		d, endpoint := newAWSKMSDouble(t)
		// In a subtest of its own, so its clean-up has run when this one looks.
		t.Run("run", func(t *testing.T) {
			liveBYOK(t, liveCloud{name: "AWS double", provider: ProviderAWS, region: "us-east-1", reimport: true,
				fields: map[string]string{"access_key_id": "AKIATEST", "secret_access_key": "test-only-0000000000000000000000000000000", "region": "us-east-1", "endpoint_url": endpoint}})
		})
		if len(d.keys) != 1 {
			t.Fatalf("the run made %d keys", len(d.keys))
		}
		for id, k := range d.keys {
			if k.state != "PendingDeletion" {
				t.Errorf("the run left key %s in state %s, not pending deletion", id, k.state)
			}
		}
	})
	t.Run("Alibaba", func(t *testing.T) {
		fipstest.SkipIfStrict(t, "Alibaba's HMAC-SHA1 request signing")
		d, endpoint := newAlibabaDouble(t)
		t.Run("run", func(t *testing.T) {
			liveBYOK(t, liveCloud{name: "Alibaba double", provider: ProviderAlibaba, region: "cn-hangzhou",
				fields: map[string]string{"access_key_id": "LTAItest", "access_key_secret": "test-only-000000000000000000000000", "region": "cn-hangzhou", "endpoint_url": endpoint}})
		})
		if len(d.state) != 1 {
			t.Fatalf("the run made %d keys", len(d.state))
		}
		for id, state := range d.state {
			if state != "PendingDeletion" {
				t.Errorf("the run left key %s in state %s, not pending deletion", id, state)
			}
		}
	})
}
