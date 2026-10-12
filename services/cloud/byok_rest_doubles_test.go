package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
)

// Protocol doubles for the REST clouds. Each unwraps what it receives with
// the private half of the wrapping key it handed out, with that cloud's
// scheme, so a passing test proves the cloud would get the KMS's material.

// The doubles' own encryption, with module-generated nonces (strict FIPS
// mode refuses caller nonces).
func gcmSeal(key, pt []byte) []byte {
	g := must(cipher.NewGCMWithRandomNonce(must(aes.NewCipher(key))))
	return g.Seal(nil, nil, pt, nil)
}

func gcmOpen(key, blob []byte) ([]byte, error) {
	if len(key) == 0 || len(blob) < 28 {
		return nil, fmt.Errorf("short")
	}
	g := must(cipher.NewGCMWithRandomNonce(must(aes.NewCipher(key))))
	return g.Open(nil, nil, blob, nil)
}

func writeJSONT(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- Azure Key Vault ----

type azureDouble struct {
	mu       sync.Mutex
	url      string
	keks     map[string]*rsa.PrivateKey
	versions map[string][]azureVersion // key name → versions
	tags     map[string]map[string]interface{}
	deleted  map[string][]azureVersion // soft-deleted keys
}

type azureVersion struct {
	id       string
	material []byte
	enabled  bool
}

func newAzureDouble(t *testing.T) *azureDouble {
	d := &azureDouble{keks: map[string]*rsa.PrivateKey{}, versions: map[string][]azureVersion{}, tags: map[string]map[string]interface{}{}, deleted: map[string][]azureVersion{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	d.url = srv.URL
	return d
}

func (d *azureDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer azure-test-token" || r.URL.Query().Get("api-version") == "" {
		writeJSONT(w, 401, map[string]interface{}{"error": map[string]string{"code": "Unauthorized"}})
		return
	}
	var body map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&body)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // keys, name, [version|create], [op]
	if len(parts) == 1 && r.Method == http.MethodGet {
		list := []map[string]interface{}{}
		for n := range d.versions {
			list = append(list, map[string]interface{}{"kid": d.url + "/keys/" + n})
		}
		writeJSONT(w, 200, map[string]interface{}{"value": list})
		return
	}
	name := parts[1]
	if parts[0] == "deletedkeys" {
		d.versions[name] = d.deleted[name]
		delete(d.deleted, name)
		writeJSONT(w, 200, map[string]interface{}{"key": map[string]interface{}{"kid": d.url + "/keys/" + name}})
		return
	}
	if r.Method == http.MethodPatch && len(parts) == 2 {
		vs := d.versions[name]
		if attrs, ok := body["attributes"].(map[string]interface{}); ok {
			vs[len(vs)-1].enabled = attrs["enabled"].(bool)
		}
		if tags, ok := body["tags"].(map[string]interface{}); ok {
			d.tags[name] = tags
		}
		writeJSONT(w, 200, map[string]interface{}{"key": map[string]interface{}{"kid": d.url + "/keys/" + name}, "tags": d.tags[name]})
		return
	}
	if r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "versions" {
		list := []map[string]interface{}{}
		for _, v := range d.versions[name] {
			list = append(list, map[string]interface{}{"kid": d.url + "/keys/" + name + "/" + v.id, "attributes": map[string]bool{"enabled": v.enabled}})
		}
		writeJSONT(w, 200, map[string]interface{}{"value": list})
		return
	}
	if r.Method == http.MethodDelete && d.versions[name] != nil {
		d.deleted[name] = d.versions[name]
		delete(d.versions, name)
		writeJSONT(w, 200, map[string]interface{}{"recoveryId": d.url + "/deletedkeys/" + name, "scheduledPurgeDate": 1900000000})
		return
	}
	b64 := base64.RawURLEncoding
	switch {
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "create":
		priv := must(rsa.GenerateKey(pkgcrypto.Reader, 3072))
		d.keks[name] = priv
		n, e := pkgcrypto.RSAPublicComponents(&priv.PublicKey)
		writeJSONT(w, 200, map[string]interface{}{"key": map[string]interface{}{"kid": d.url + "/keys/" + name + "/kekv1", "kty": "RSA-HSM", "n": b64.EncodeToString(n), "e": b64.EncodeToString(e), "key_ops": []string{"import"}}})
	case r.Method == http.MethodPut && len(parts) == 2:
		key := body["key"].(map[string]interface{})
		blob := must(b64.DecodeString(key["key_hsm"].(string)))
		var transfer struct {
			Header     map[string]string `json:"header"`
			Ciphertext string            `json:"ciphertext"`
		}
		_ = json.Unmarshal(blob, &transfer)
		kekName := strings.Split(strings.TrimPrefix(transfer.Header["kid"], d.url+"/keys/"), "/")[0]
		kek := d.keks[kekName]
		if kek == nil || transfer.Header["enc"] != "CKM_RSA_AES_KEY_WRAP" || transfer.Header["alg"] != "dir" {
			writeJSONT(w, 400, map[string]interface{}{"error": map[string]string{"code": "BadParameter", "message": "bad transfer blob header"}})
			return
		}
		material, err := pkgcrypto.UnwrapCloudImport(kek, must(b64.DecodeString(transfer.Ciphertext)), pkgcrypto.CloudWrapRSAAESKWPSHA1)
		if err != nil {
			writeJSONT(w, 400, map[string]interface{}{"error": map[string]string{"code": "BadParameter", "message": err.Error()}})
			return
		}
		v := azureVersion{id: fmt.Sprintf("ver%d", len(d.versions[name])+1), material: material, enabled: true}
		d.versions[name] = append(d.versions[name], v)
		writeJSONT(w, 200, map[string]interface{}{"key": map[string]interface{}{"kid": d.url + "/keys/" + name + "/" + v.id}, "attributes": map[string]interface{}{"enabled": true}})
	case r.Method == http.MethodPatch && len(parts) == 3:
		for i := range d.versions[name] {
			if d.versions[name][i].id == parts[2] {
				d.versions[name][i].enabled = body["attributes"].(map[string]interface{})["enabled"].(bool)
			}
		}
		writeJSONT(w, 200, map[string]interface{}{})
	case r.Method == http.MethodGet && len(parts) == 2:
		vs := d.versions[name]
		last := vs[len(vs)-1]
		writeJSONT(w, 200, map[string]interface{}{"key": map[string]interface{}{"kid": d.url + "/keys/" + name + "/" + last.id, "kty": "oct-HSM"},
			"attributes": map[string]interface{}{"enabled": last.enabled}, "tags": d.tags[name]})
	case r.Method == http.MethodPost && len(parts) == 4:
		var v *azureVersion
		for i := range d.versions[name] {
			if d.versions[name][i].id == parts[2] {
				v = &d.versions[name][i]
			}
		}
		if v == nil || !v.enabled {
			writeJSONT(w, 403, map[string]interface{}{"error": map[string]string{"code": "Forbidden", "message": "key version disabled"}})
			return
		}
		in := must(b64.DecodeString(body["value"].(string)))
		var out []byte
		var err error
		if parts[3] == "wrapkey" || parts[3] == "encrypt" {
			out = gcmSeal(v.material, in)
		} else {
			out, err = gcmOpen(v.material, in)
		}
		if err != nil {
			writeJSONT(w, 400, map[string]interface{}{"error": map[string]string{"code": "BadParameter", "message": err.Error()}})
			return
		}
		writeJSONT(w, 200, map[string]interface{}{"value": b64.EncodeToString(out)})
	case r.Method == http.MethodDelete:
		delete(d.keks, name)
		writeJSONT(w, 200, map[string]interface{}{})
	default:
		writeJSONT(w, 404, map[string]interface{}{"error": map[string]string{"code": "NotFound"}})
	}
}

func TestBYOKAzureTransferBlob(t *testing.T) {
	fipstest.SkipIfStrict(t, "CKM_RSA_AES_KEY_WRAP (SHA-1, KWP) done by the KMS rather than an HSM")
	svc, _, kc, _ := newCloudService(t)
	d := newAzureDouble(t)
	setCred(svc, "cred-azure-double", "azure", map[string]string{"vault_url": d.url, "access_token": "azure-test-token"})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAzure, Name: "kv", DefaultRegion: "eastus", ConnectionID: "cred-azure-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", Alias: "payments"})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if len(d.keks) != 0 {
		t.Fatal("the temporary key exchange key was not deleted")
	}
	if got := d.versions["payments"][0].material; string(got) != string(kc.material("t1", "key-1", 1)) {
		t.Fatal("Azure unwrapped different material than KMS version 1")
	}
	if run, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{}); err != nil || key.CurrentMatID != "ver2" {
		t.Fatalf("rotate: %v %v %s", err, stepNames(run), key.CurrentMatID)
	}
	if string(d.versions["payments"][1].material) != string(kc.material("t1", "key-1", 2)) {
		t.Fatal("rotation imported different material than KMS version 2")
	}
	if _, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil || d.versions["payments"][1].enabled {
		t.Fatalf("revoke (disable): %v", err)
	}
	if _, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil || !d.versions["payments"][1].enabled || len(d.versions["payments"]) != 2 {
		t.Fatalf("restore (re-enable, no new version): %v", err)
	}
}

// ---- Alibaba Cloud KMS ----

type alibabaDouble struct {
	mu       sync.Mutex
	wrap     *rsa.PrivateKey
	material map[string][]byte
	state    map[string]string
	aliases  map[string]string            // alias → key
	tags     map[string]map[string]string // key → tags
}

func newAlibabaDouble(t *testing.T) (*alibabaDouble, string) {
	d := &alibabaDouble{wrap: must(rsa.GenerateKey(pkgcrypto.Reader, 2048)), material: map[string][]byte{}, state: map[string]string{},
		aliases: map[string]string{}, tags: map[string]map[string]string{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return d, srv.URL
}

func (d *alibabaDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := r.URL.Query()
	if q.Get("SignatureMethod") != "HMAC-SHA1" || q.Get("Signature") == "" || q.Get("AccessKeyId") != "LTAItest" {
		writeJSONT(w, 400, map[string]string{"Code": "IncompleteSignature"})
		return
	}
	id := q.Get("KeyId")
	switch q.Get("Action") {
	case "CreateKey":
		id = fmt.Sprintf("key-%d", len(d.state)+1)
		d.state[id] = "PendingImport"
		writeJSONT(w, 200, map[string]interface{}{"KeyMetadata": map[string]string{"KeyId": id, "Arn": "acs:kms:cn-hangzhou:1:key/" + id, "KeyState": "PendingImport"}})
	case "GetParametersForImport":
		der, _ := x509.MarshalPKIXPublicKey(&d.wrap.PublicKey)
		writeJSONT(w, 200, map[string]string{"KeyId": id, "PublicKey": base64.StdEncoding.EncodeToString(der), "ImportToken": "tok", "TokenExpireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	case "ImportKeyMaterial":
		m, err := pkgcrypto.UnwrapCloudImport(d.wrap, must(base64.StdEncoding.DecodeString(q.Get("EncryptedKeyMaterial"))), pkgcrypto.CloudWrapRSAOAEPSHA256)
		if err != nil || q.Get("ImportToken") != "tok" {
			writeJSONT(w, 400, map[string]string{"Code": "InvalidParameter", "Message": fmt.Sprint(err)})
			return
		}
		d.material[id], d.state[id] = m, "Enabled"
		writeJSONT(w, 200, map[string]string{})
	case "CreateAlias":
		d.aliases[q.Get("AliasName")] = id
		writeJSONT(w, 200, map[string]string{})
	case "DeleteAlias":
		delete(d.aliases, q.Get("AliasName"))
		writeJSONT(w, 200, map[string]string{})
	case "ListAliasesByKeyId":
		list := []map[string]string{}
		for a, k := range d.aliases {
			if k == id {
				list = append(list, map[string]string{"AliasName": a, "KeyId": k})
			}
		}
		writeJSONT(w, 200, map[string]interface{}{"Aliases": map[string]interface{}{"Alias": list}})
	case "TagResource":
		var tags []map[string]string
		_ = json.Unmarshal([]byte(q.Get("Tags")), &tags)
		if d.tags[id] == nil {
			d.tags[id] = map[string]string{}
		}
		for _, t := range tags {
			d.tags[id][t["TagKey"]] = t["TagValue"]
		}
		writeJSONT(w, 200, map[string]string{})
	case "UntagResource":
		var keys []string
		_ = json.Unmarshal([]byte(q.Get("TagKeys")), &keys)
		for _, k := range keys {
			delete(d.tags[id], k)
		}
		writeJSONT(w, 200, map[string]string{})
	case "ListResourceTags":
		list := []map[string]string{}
		for k, v := range d.tags[id] {
			list = append(list, map[string]string{"TagKey": k, "TagValue": v})
		}
		writeJSONT(w, 200, map[string]interface{}{"Tags": map[string]interface{}{"Tag": list}})
	case "EnableKey", "DisableKey":
		d.state[id] = map[bool]string{true: "Enabled", false: "Disabled"}[q.Get("Action") == "EnableKey"]
		writeJSONT(w, 200, map[string]string{})
	case "DeleteKeyMaterial":
		delete(d.material, id)
		d.state[id] = "PendingImport"
		writeJSONT(w, 200, map[string]string{})
	case "DescribeKey":
		writeJSONT(w, 200, map[string]interface{}{"KeyMetadata": map[string]string{"KeyId": id, "KeyState": d.state[id]}})
	case "ListKeys":
		keys := []map[string]string{}
		for k := range d.state {
			keys = append(keys, map[string]string{"KeyId": k})
		}
		writeJSONT(w, 200, map[string]interface{}{"Keys": map[string]interface{}{"Key": keys}})
	case "ScheduleKeyDeletion":
		d.state[id] = "PendingDeletion"
		writeJSONT(w, 200, map[string]string{})
	case "Encrypt":
		m := d.material[id]
		if m == nil || d.state[id] != "Enabled" {
			writeJSONT(w, 400, map[string]string{"Code": "Forbidden.KeyNotEnabled"})
			return
		}
		// As Alibaba returns it: one base64 blob that names the key inside.
		writeJSONT(w, 200, map[string]string{"CiphertextBlob": base64.StdEncoding.EncodeToString(append([]byte(id+"."), gcmSeal(m, []byte(q.Get("Plaintext")))...))})
	case "Decrypt":
		blob, _ := base64.StdEncoding.DecodeString(q.Get("CiphertextBlob"))
		parts := bytes.SplitN(blob, []byte("."), 2)
		if len(parts) != 2 || d.material[string(parts[0])] == nil {
			writeJSONT(w, 400, map[string]string{"Code": "Forbidden.KeyNotEnabled"})
			return
		}
		pt, err := gcmOpen(d.material[string(parts[0])], parts[1])
		if err != nil {
			writeJSONT(w, 400, map[string]string{"Code": "InvalidParameter"})
			return
		}
		writeJSONT(w, 200, map[string]string{"Plaintext": string(pt)})
	default:
		writeJSONT(w, 400, map[string]string{"Code": "UnsupportedOperation"})
	}
}

func TestBYOKAlibaba(t *testing.T) {
	fipstest.SkipIfStrict(t, "Alibaba's HMAC-SHA1 request signing")
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAlibabaDouble(t)
	setCred(svc, "cred-ali-double", "alibaba", map[string]string{"access_key_id": "LTAItest", "access_key_secret": "test-only", "region": "cn-hangzhou", "endpoint_url": endpoint})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAlibaba, Name: "ali", DefaultRegion: "cn-hangzhou", ConnectionID: "cred-ali-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", ValidityDays: 30})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if string(d.material[key.CloudKeyID]) != string(kc.material("t1", "key-1", 1)) {
		t.Fatal("Alibaba unwrapped different material")
	}
	if _, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{}); byokReason(err) != "operation_not_supported" {
		t.Fatalf("rotate on Alibaba: %v", err)
	}
	if _, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); err != nil || d.material[key.CloudKeyID] != nil {
		t.Fatalf("revoke: %v", err)
	}
	if run, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpRestore, "alice", BYOKOperationRequest{}); err != nil || string(d.material[key.CloudKeyID]) != string(kc.material("t1", "key-1", 1)) {
		t.Fatalf("restore: %v %v", err, stepNames(run))
	}
}

// ---- Salesforce Shield ----

func selfSignedCert(t *testing.T) (*rsa.PrivateKey, string) {
	priv := must(rsa.GenerateKey(pkgcrypto.Reader, 2048))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BYOK_Cert"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBYOKSalesforceTenantSecret(t *testing.T) {
	fipstest.SkipIfStrict(t, "Salesforce's RSA-OAEP SHA-1 done by the KMS rather than an HSM")
	svc, _, kc, _ := newCloudService(t)
	certKey, certPEM := selfSignedCert(t)
	var mu sync.Mutex
	secrets := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer sf-test-token" || !strings.HasPrefix(r.URL.Path, "/services/data/v61.0/sobjects/TenantSecret") {
			writeJSONT(w, 401, []map[string]string{{"errorCode": "INVALID_SESSION_ID"}})
			return
		}
		if r.Method == http.MethodGet {
			writeJSONT(w, 200, map[string]string{"Status": "ACTIVE"})
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var in map[string]string
		_ = json.Unmarshal(raw, &in)
		secret, err := pkgcrypto.UnwrapCloudImport(certKey, must(base64.StdEncoding.DecodeString(in["SecretValue"])), pkgcrypto.CloudWrapRSAOAEPSHA1)
		if err != nil || in["SecretValueHash"] != base64.StdEncoding.EncodeToString(pkgcrypto.SHA256(secret)) || in["SecretValueCertificate"] != "BYOK_Cert" || in["Type"] != "Data" {
			writeJSONT(w, 400, []map[string]string{{"errorCode": "INVALID_FIELD", "message": fmt.Sprint(err)}})
			return
		}
		id := fmt.Sprintf("0Ax%03d", len(secrets)+1)
		secrets[id] = secret
		writeJSONT(w, 201, map[string]interface{}{"id": id, "success": true})
	}))
	t.Cleanup(srv.Close)
	setCred(svc, "cred-sf-double", "salesforce", map[string]string{"instance_url": srv.URL, "access_token": "sf-test-token"})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderSalesforce, Name: "org", ConnectionID: "cred-sf-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	ctx := context.Background()
	if _, _, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1"}); err == nil {
		t.Fatal("created without the BYOK certificate")
	}
	run, key, err := svc.CreateBYOK(ctx, "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", CertificateName: "BYOK_Cert", CertificatePEM: certPEM})
	if err != nil {
		t.Fatalf("create: %v %v", err, stepNames(run))
	}
	if string(secrets[key.CurrentMatID]) != string(kc.material("t1", "key-1", 1)) {
		t.Fatal("Salesforce got a different secret")
	}
	if _, key, err = svc.RunBYOK(ctx, "t1", key.ID, OpRotate, "alice", BYOKOperationRequest{}); err != nil || string(secrets[key.CurrentMatID]) != string(kc.material("t1", "key-1", 2)) {
		t.Fatalf("rotate: %v", err)
	}
	if _, _, err := svc.RunBYOK(ctx, "t1", key.ID, OpRevoke, "alice", BYOKOperationRequest{}); byokReason(err) != "operation_not_supported" {
		t.Fatalf("revoke on Salesforce: %v", err)
	}
}

// The console over Key Vault's REST API: tags, disable, soft delete and
// recovery, and an AES-GCM round trip with the version's material.
func TestConsoleAzure(t *testing.T) {
	fipstest.SkipIfStrict(t, "the import step's CKM_RSA_AES_KEY_WRAP (SHA-1) done by the KMS")
	svc, _, kc, _ := newCloudService(t)
	d := newAzureDouble(t)
	setCred(svc, "cred-azure-double", "azure", map[string]string{"vault_url": d.url, "access_token": "azure-test-token"})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAzure, Name: "kv", ConnectionID: "cred-azure-double"})
	if err != nil {
		t.Fatal(err)
	}
	kc.Seed("t1", "key-1", "AES-256")
	_, k, err := svc.CreateBYOK(context.Background(), "t1", "alice", CreateBYOKRequest{AccountID: acct.ID, KeyID: "key-1", Alias: "payments"})
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := consoleRouter(svc)
	op := func(name, version string, params map[string]string) (int, consoleOut) {
		return runOp(t, rt, rw, name, map[string]interface{}{"account_id": acct.ID, "key": k.CloudKeyID, "version": version, "params": params})
	}
	if code, out := op("tag-key", "", map[string]string{"tag_key": "team", "tag_value": "payments"}); code != 200 || !strings.HasPrefix(out.CLI, "az keyvault key") {
		t.Fatalf("tag %d %+v", code, out)
	}
	if _, out := op("list-tags", "", nil); !strings.Contains(string(out.Result), "payments") {
		t.Fatal("tag missing")
	}
	var enc struct {
		C string `json:"ciphertext_b64"`
	}
	_, out := op("encrypt", k.CurrentMatID, map[string]string{"plaintext_b64": b64s("hello azure")})
	_ = json.Unmarshal(out.Result, &enc)
	if _, out := op("decrypt", k.CurrentMatID, map[string]string{"ciphertext_b64": enc.C}); !strings.Contains(string(out.Result), "hello azure") {
		t.Fatalf("decrypt %s", out.Result)
	}
	if code, _ := op("disable-key", "", nil); code != 200 || d.versions["payments"][0].enabled {
		t.Fatal("not disabled")
	}
	if code, _ := op("schedule-key-deletion", "", nil); code != 200 || d.deleted["payments"] == nil {
		t.Fatal("not soft-deleted")
	}
	if code, _ := op("cancel-key-deletion", "", nil); code != 200 || d.versions["payments"] == nil {
		t.Fatal("not recovered")
	}
	if code, _ := op("put-key-policy", "", map[string]string{"policy": "{}"}); code != http.StatusConflict {
		t.Fatalf("Azure has no per-key policy: %d", code)
	}
}

// The console over Alibaba's signed RPC API: aliases, tags, disable.
func TestConsoleAlibaba(t *testing.T) {
	fipstest.SkipIfStrict(t, "Alibaba's HMAC-SHA1 request signing")
	svc, _, kc, _ := newCloudService(t)
	d, endpoint := newAlibabaDouble(t)
	setCred(svc, "cred-ali-double", "alibaba", map[string]string{"access_key_id": "LTAItest", "access_key_secret": "test-only", "region": "cn-hangzhou", "endpoint_url": endpoint})
	acct, err := svc.RegisterAccount(attachCtx("t1"), RegisterCloudAccountRequest{TenantID: "t1", Provider: ProviderAlibaba, Name: "ali", ConnectionID: "cred-ali-double"})
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
	if code, out := op("create-alias", map[string]string{"alias": "orders"}); code != 200 || d.aliases["alias/orders"] != k.CloudKeyID || !strings.HasPrefix(out.CLI, "aliyun kms ") {
		t.Fatalf("alias %d %+v", code, out)
	}
	if _, out := op("list-aliases", nil); !strings.Contains(string(out.Result), "alias/orders") {
		t.Fatal("alias missing")
	}
	op("tag-key", map[string]string{"tag_key": "team", "tag_value": "payments"})
	if _, out := op("list-tags", nil); !strings.Contains(string(out.Result), "payments") {
		t.Fatal("tag missing")
	}
	op("untag-key", map[string]string{"tag_key": "team"})
	if len(d.tags[k.CloudKeyID]) != 0 {
		t.Fatal("tag not removed")
	}
	op("disable-key", nil)
	if code, _ := op("encrypt", map[string]string{"plaintext_b64": b64s("x")}); code != http.StatusBadGateway {
		t.Fatalf("encrypt with a disabled key: %d", code)
	}
	op("enable-key", nil)
	if code, _ := op("encrypt", map[string]string{"plaintext_b64": base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})}); code != http.StatusBadRequest {
		t.Fatalf("binary plaintext to Alibaba: %d", code)
	}
}
