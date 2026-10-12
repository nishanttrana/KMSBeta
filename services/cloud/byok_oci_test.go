package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// ociVaultDouble serves the OCI Vault management and crypto APIs import
// uses. Requests must carry an OCI request signature; the vault's wrapping
// key unwraps RSA_OAEP_SHA256 material.
type ociVaultDouble struct {
	mu       sync.Mutex
	wrap     *rsa.PrivateKey
	keys     map[string]*ociDoubleKey
	versions map[string][]byte
}

type ociDoubleKey struct {
	current string
	enabled bool
	state   string // "" or PENDING_DELETION
	tags    map[string]string
}

func (d *ociVaultDouble) key(id string) map[string]interface{} {
	k := d.keys[id]
	state := "ENABLED"
	if !k.enabled {
		state = "DISABLED"
	}
	if k.state != "" {
		state = k.state
	}
	return map[string]interface{}{"id": id, "compartmentId": "ocid1.compartment.test", "currentKeyVersion": k.current, "displayName": "k",
		"keyShape": map[string]interface{}{"algorithm": "AES", "length": 32}, "lifecycleState": state,
		"timeCreated": time.Now().UTC().Format(time.RFC3339), "vaultId": "ocid1.vault.test", "freeformTags": k.tags}
}

func (d *ociVaultDouble) unwrap(w http.ResponseWriter, body map[string]interface{}) []byte {
	wk := body["wrappedImportKey"].(map[string]interface{})
	if wk["wrappingAlgorithm"] != "RSA_OAEP_SHA256" {
		writeJSONT(w, 400, map[string]string{"code": "InvalidParameter", "message": "wrapping algorithm"})
		return nil
	}
	m, err := pkgcrypto.UnwrapCloudImport(d.wrap, must(base64.StdEncoding.DecodeString(wk["keyMaterial"].(string))), pkgcrypto.CloudWrapRSAOAEPSHA256)
	if err != nil {
		writeJSONT(w, 400, map[string]string{"code": "InvalidParameter", "message": err.Error()})
		return nil
	}
	return m
}

func (d *ociVaultDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		writeJSONT(w, 401, map[string]string{"code": "NotAuthenticated"})
		return
	}
	var body map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&body)
	p := strings.TrimPrefix(r.URL.Path, "/20180608")
	now := time.Now().UTC().Format(time.RFC3339)
	switch {
	case r.Method == http.MethodGet && p == "/wrappingKeys":
		der, _ := x509.MarshalPKIXPublicKey(&d.wrap.PublicKey)
		writeJSONT(w, 200, map[string]interface{}{"id": "ocid1.wrapkey.test", "compartmentId": "ocid1.compartment.test", "lifecycleState": "ACTIVE",
			"publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "timeCreated": now, "vaultId": "ocid1.vault.test"})
	case r.Method == http.MethodPost && p == "/keys/import":
		m := d.unwrap(w, body)
		if m == nil {
			return
		}
		id := fmt.Sprintf("ocid1.key.test.%d", len(d.keys)+1)
		d.keys[id] = &ociDoubleKey{current: id + ".v1", enabled: true}
		d.versions[id+".v1"] = m
		writeJSONT(w, 200, d.key(id))
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/keyVersions/import"):
		id := strings.Split(p, "/")[2]
		m := d.unwrap(w, body)
		if m == nil {
			return
		}
		v := fmt.Sprintf("%s.v%d", id, len(d.versions)+1)
		d.versions[v], d.keys[id].current = m, v
		writeJSONT(w, 200, map[string]interface{}{"id": v, "keyId": id, "compartmentId": "ocid1.compartment.test", "timeCreated": now, "vaultId": "ocid1.vault.test"})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/actions/disable"), r.Method == http.MethodPost && strings.HasSuffix(p, "/actions/enable"):
		id := strings.Split(p, "/")[2]
		d.keys[id].enabled = strings.HasSuffix(p, "enable")
		writeJSONT(w, 200, d.key(id))
	case r.Method == http.MethodGet && p == "/keys":
		list := []map[string]interface{}{}
		for id := range d.keys {
			list = append(list, map[string]interface{}{"id": id, "compartmentId": r.URL.Query().Get("compartmentId"), "displayName": "k", "lifecycleState": "ENABLED", "timeCreated": now, "vaultId": "ocid1.vault.test"})
		}
		writeJSONT(w, 200, list)
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/keyVersions"):
		id := strings.Split(p, "/")[2]
		list := []map[string]interface{}{}
		for v := range d.versions {
			if strings.HasPrefix(v, id+".") {
				list = append(list, map[string]interface{}{"id": v, "keyId": id, "compartmentId": "ocid1.compartment.test", "timeCreated": now, "vaultId": "ocid1.vault.test"})
			}
		}
		writeJSONT(w, 200, list)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/actions/scheduleDeletion"):
		id := strings.Split(p, "/")[2]
		d.keys[id].state = "PENDING_DELETION"
		writeJSONT(w, 200, d.key(id))
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/actions/cancelDeletion"):
		id := strings.Split(p, "/")[2]
		d.keys[id].state = ""
		writeJSONT(w, 200, d.key(id))
	case r.Method == http.MethodPut && strings.HasPrefix(p, "/keys/"):
		id := strings.TrimPrefix(p, "/keys/")
		tags := map[string]string{}
		for k, v := range body["freeformTags"].(map[string]interface{}) {
			tags[k] = v.(string)
		}
		d.keys[id].tags = tags
		writeJSONT(w, 200, d.key(id))
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/keys/"):
		writeJSONT(w, 200, d.key(strings.TrimPrefix(p, "/keys/")))
	case r.Method == http.MethodPost && (p == "/encrypt" || p == "/decrypt"):
		k := d.keys[body["keyId"].(string)]
		if k == nil || !k.enabled {
			writeJSONT(w, 409, map[string]string{"code": "IncorrectState", "message": "key disabled"})
			return
		}
		m := d.versions[k.current]
		if p == "/encrypt" {
			pt := must(base64.StdEncoding.DecodeString(body["plaintext"].(string)))
			writeJSONT(w, 200, map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(gcmSeal(m, pt)), "keyId": body["keyId"].(string)})
			return
		}
		pt, err := gcmOpen(m, must(base64.StdEncoding.DecodeString(body["ciphertext"].(string))))
		if err != nil {
			writeJSONT(w, 400, map[string]string{"code": "InvalidParameter"})
			return
		}
		writeJSONT(w, 200, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
	default:
		writeJSONT(w, 404, map[string]string{"code": "NotFound", "message": r.Method + " " + p})
	}
}

func TestBYOKOCIVault(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d := &ociVaultDouble{wrap: must(rsa.GenerateKey(pkgcrypto.Reader, 3072)), keys: map[string]*ociDoubleKey{}, versions: map[string][]byte{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	signer := must(rsa.GenerateKey(pkgcrypto.Reader, 2048))
	signerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer)}))
	setCred(svc, "cred-oci-double", "oci", map[string]string{"tenancy_ocid": "ocid1.tenancy.test", "user_ocid": "ocid1.user.test", "fingerprint": "aa:bb",
		"private_key_pem": signerPEM, "region": "eu-frankfurt-1", "compartment_id": "ocid1.compartment.test",
		"management_endpoint": srv.URL, "crypto_endpoint": srv.URL})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderOCI, Name: "oci", DefaultRegion: "eu-frankfurt-1", ConnectionID: "cred-oci-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if string(d.versions[key.CurrentMatID]) != string(kc.material("t1", "key-1", 1)) {
		t.Fatal("OCI holds different material than KMS version 1")
	}
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{}); err != nil || string(d.versions[key.CurrentMatID]) != string(kc.material("t1", "key-1", 2)) {
		t.Fatalf("rotate: %v %v", err, stepNames(run))
	}
	if _, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil || d.keys[key.CloudKeyID].enabled {
		t.Fatalf("revoke (disable): %v", err)
	}
	if run, _, err = svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil || !d.keys[key.CloudKeyID].enabled {
		t.Fatalf("restore (enable): %v %v", err, stepNames(run))
	}
}

// The console over OCI's signed REST API: tags, versions, scheduled
// deletion and its cancellation.
func TestConsoleOCI(t *testing.T) {
	svc, _, kc, _ := newCloudService(t)
	d := &ociVaultDouble{wrap: must(rsa.GenerateKey(pkgcrypto.Reader, 3072)), keys: map[string]*ociDoubleKey{}, versions: map[string][]byte{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	signer := must(rsa.GenerateKey(pkgcrypto.Reader, 2048))
	setCred(svc, "cred-oci-double", "oci", map[string]string{"tenancy_ocid": "ocid1.tenancy.test", "user_ocid": "ocid1.user.test", "fingerprint": "aa:bb",
		"private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer)})), "region": "eu-frankfurt-1",
		"compartment_id": "ocid1.compartment.test", "management_endpoint": srv.URL, "crypto_endpoint": srv.URL})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderOCI, Name: "oci", ConnectionID: "cred-oci-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	_, k, err := svc.CreateBYOK(context.Background(), "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"})
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := consoleRouter(svc)
	op := func(name string, params map[string]string) (int, consoleOut) {
		return runOp(t, rt, rw, name, map[string]interface{}{"account_id": acct.ID, "key": k.CloudKeyID, "params": params})
	}
	if code, out := op("list-keys", nil); code != 200 || !strings.Contains(string(out.Result), k.CloudKeyID) {
		t.Fatalf("list-keys %d %+v", code, out)
	}
	if code, out := op("list-versions", nil); code != 200 || !strings.Contains(string(out.Result), k.CurrentMatID) {
		t.Fatalf("list-versions %d %+v", code, out)
	}
	if code, out := op("tag-key", map[string]string{"tag_key": "team", "tag_value": "payments"}); code != 200 || d.keys[k.CloudKeyID].tags["team"] != "payments" {
		t.Fatalf("tag %d %+v", code, out)
	}
	if code, out := op("schedule-key-deletion", map[string]string{"pending_days": "7"}); code != 200 || d.keys[k.CloudKeyID].state != "PENDING_DELETION" {
		t.Fatalf("schedule %d %+v", code, out)
	}
	if code, _ := op("cancel-key-deletion", nil); code != 200 || d.keys[k.CloudKeyID].state != "" {
		t.Fatal("not cancelled")
	}
	if code, _ := op("create-alias", map[string]string{"alias": "x"}); code != http.StatusConflict {
		t.Fatalf("OCI has no aliases: %d", code)
	}
}
