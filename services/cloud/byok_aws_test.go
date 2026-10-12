package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// awsKMSDouble speaks the AWS KMS JSON protocol (X-Amz-Target
// TrentService.*) for the operations BYOK uses. It does what AWS does with
// imported material: unwraps it with the private half of the wrapping key
// it handed out, refuses a reimport of different material, and encrypts
// with the current material, so a round trip proves the material arrived.
type awsKMSDouble struct {
	t      *testing.T
	mu     sync.Mutex
	wrap   *rsa.PrivateKey
	keys   map[string]*awsDoubleKey
	tokens map[string]bool
	// alias name → key ID
	aliases map[string]string
	calls  []string
}

type awsDoubleKey struct {
	spec, state, current, pending string
	material             map[string][]byte // key material ID → material
	validTo              *time.Time
	// Key management state the console reads and changes.
	policy   string
	grants   []map[string]interface{}
	tags     map[string]string
	rotation bool
	period   int
}

func newAWSKMSDouble(t *testing.T) (*awsKMSDouble, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(pkgcrypto.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	d := &awsKMSDouble{t: t, wrap: priv, keys: map[string]*awsDoubleKey{}, tokens: map[string]bool{}, aliases: map[string]string{}}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return d, srv.URL
}

func (d *awsKMSDouble) fail(w http.ResponseWriter, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func (d *awsKMSDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	raw, _ := io.ReadAll(r.Body)
	var in map[string]interface{}
	_ = json.Unmarshal(raw, &in)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, op)
	b64 := func(k string) []byte { return decodeB64(anyToString(in[k])) }
	keyID := defaultString(anyToString(in["KeyId"]), anyToString(in["TargetKeyId"]))
	if target, ok := d.aliases[keyID]; ok {
		keyID = target
	}
	key := d.keys[keyID]
	if key == nil && op != "CreateKey" && op != "ListKeys" && op != "DeleteAlias" && !(op == "ListAliases" && keyID == "") {
		d.fail(w, "NotFoundException", "no key "+anyToString(in["KeyId"]))
		return
	}
	out := map[string]interface{}{}
	switch op {
	case "CreateKey":
		if in["Origin"] != "EXTERNAL" {
			d.fail(w, "ValidationException", "the double only makes EXTERNAL keys")
			return
		}
		id := fmt.Sprintf("1234abcd-%04d", len(d.keys)+1)
		d.keys[id] = &awsDoubleKey{spec: anyToString(in["KeySpec"]), state: "PendingImport", material: map[string][]byte{}}
		out["KeyMetadata"] = map[string]interface{}{"KeyId": id, "Arn": "arn:aws:kms:us-east-1:111122223333:key/" + id, "KeyState": "PendingImport", "Origin": "EXTERNAL"}
	case "CreateAlias":
		d.aliases[anyToString(in["AliasName"])] = keyID
	case "DeleteAlias":
		delete(d.aliases, anyToString(in["AliasName"]))
	case "ListAliases":
		list := []map[string]string{}
		for a, k := range d.aliases {
			if keyID == "" || k == keyID {
				list = append(list, map[string]string{"AliasName": a, "TargetKeyId": k})
			}
		}
		out["Aliases"] = list
	case "ListKeys":
		list := []map[string]string{}
		for id := range d.keys {
			list = append(list, map[string]string{"KeyId": id, "KeyArn": "arn:aws:kms:us-east-1:111122223333:key/" + id})
		}
		out["Keys"] = list
	case "ListKeyRotations":
		list := []map[string]interface{}{}
		for id := range key.material {
			list = append(list, map[string]interface{}{"KeyId": keyID, "KeyMaterialId": id, "KeyMaterialState": map[bool]string{true: "CURRENT", false: "NON_CURRENT"}[id == key.current]})
		}
		out["Rotations"] = list
	case "EnableKey", "DisableKey":
		if key.state == "PendingDeletion" || key.state == "PendingImport" {
			d.fail(w, "KMSInvalidStateException", "key is "+key.state)
			return
		}
		key.state = map[bool]string{true: "Enabled", false: "Disabled"}[op == "EnableKey"]
	case "ScheduleKeyDeletion":
		days := int(in["PendingWindowInDays"].(float64))
		if days < 7 || days > 30 {
			d.fail(w, "ValidationException", "PendingWindowInDays must be 7-30")
			return
		}
		key.state = "PendingDeletion"
		out["KeyId"], out["KeyState"], out["DeletionDate"] = keyID, "PendingDeletion", float64(time.Now().Add(time.Duration(days)*24*time.Hour).Unix())
	case "CancelKeyDeletion":
		key.state = "Disabled"
		out["KeyId"] = keyID
	case "GetKeyRotationStatus":
		out["KeyRotationEnabled"], out["RotationPeriodInDays"] = key.rotation, key.period
	case "EnableKeyRotation":
		key.rotation, key.period = true, 365
		if v, ok := in["RotationPeriodInDays"].(float64); ok {
			key.period = int(v)
		}
	case "DisableKeyRotation":
		key.rotation = false
	case "GetKeyPolicy":
		out["Policy"], out["PolicyName"] = defaultString(key.policy, `{"Version":"2012-10-17","Statement":[]}`), "default"
	case "PutKeyPolicy":
		if !json.Valid([]byte(anyToString(in["Policy"]))) {
			d.fail(w, "MalformedPolicyDocumentException", "not JSON")
			return
		}
		key.policy = anyToString(in["Policy"])
	case "ListGrants":
		out["Grants"] = key.grants
	case "CreateGrant":
		id := fmt.Sprintf("grant-%d", len(key.grants)+1)
		key.grants = append(key.grants, map[string]interface{}{"GrantId": id, "GranteePrincipal": in["GranteePrincipal"], "Operations": in["Operations"]})
		out["GrantId"] = id
	case "RevokeGrant":
		kept := key.grants[:0]
		for _, g := range key.grants {
			if g["GrantId"] != in["GrantId"] {
				kept = append(kept, g)
			}
		}
		key.grants = kept
	case "ListResourceTags":
		list := []map[string]string{}
		for k, v := range key.tags {
			list = append(list, map[string]string{"TagKey": k, "TagValue": v})
		}
		out["Tags"] = list
	case "TagResource":
		if key.tags == nil {
			key.tags = map[string]string{}
		}
		for _, t := range in["Tags"].([]interface{}) {
			key.tags[anyToString(t.(map[string]interface{})["TagKey"])] = anyToString(t.(map[string]interface{})["TagValue"])
		}
	case "UntagResource":
		for _, k := range in["TagKeys"].([]interface{}) {
			delete(key.tags, anyToString(k))
		}
	case "GenerateMac", "VerifyMac":
		if key.state != "Enabled" {
			d.fail(w, "DisabledException", "key is "+key.state)
			return
		}
		mac := hmacSHA256(key.material[key.current], b64("Message"))
		if op == "GenerateMac" {
			out["Mac"], out["MacAlgorithm"] = mac, "HMAC_SHA_256"
		} else {
			out["MacValid"] = bytes.Equal(mac, b64("Mac"))
		}
	case "GetParametersForImport":
		der, _ := x509.MarshalPKIXPublicKey(&d.wrap.PublicKey)
		tok := fmt.Sprintf("token-%d", len(d.tokens)+1)
		d.tokens[tok] = true
		out["KeyId"], out["PublicKey"], out["ImportToken"] = in["KeyId"], der, []byte(tok)
		out["ParametersValidTo"] = float64(time.Now().Add(24 * time.Hour).Unix())
	case "ImportKeyMaterial":
		if !d.tokens[string(b64("ImportToken"))] {
			d.fail(w, "InvalidImportTokenException", "unknown import token")
			return
		}
		material, err := pkgcrypto.UnwrapCloudImport(d.wrap, b64("EncryptedKeyMaterial"), pkgcrypto.CloudWrapRSAOAEPSHA256)
		if err != nil {
			d.fail(w, "InvalidCiphertextException", err.Error())
			return
		}
		id := fmt.Sprintf("mat-%x", pkgcrypto.SHA256(material)[:6])
		if in["ImportType"] == "NEW_KEY_MATERIAL" {
			if key.current == "" {
				d.fail(w, "ValidationException", "NEW_KEY_MATERIAL needs existing material")
				return
			}
			key.pending = id
		} else if key.current != "" && key.material[key.current] != nil && key.current != id {
			d.fail(w, "IncorrectKeyMaterialException", "this is not the key's material")
			return
		} else {
			key.current = id
		}
		key.material[id] = material
		key.state = "Enabled"
		key.validTo = nil
		if in["ExpirationModel"] == "KEY_MATERIAL_EXPIRES" {
			t := time.Unix(int64(in["ValidTo"].(float64)), 0)
			key.validTo = &t
		}
		out["KeyId"], out["KeyMaterialId"] = in["KeyId"], id
	case "RotateKeyOnDemand":
		if key.pending == "" {
			d.fail(w, "ValidationException", "no new material to rotate to")
			return
		}
		key.current, key.pending = key.pending, ""
	case "DeleteImportedKeyMaterial":
		id := defaultString(anyToString(in["KeyMaterialId"]), key.current)
		delete(key.material, id)
		if id == key.current {
			key.state = "PendingImport"
		}
	case "DescribeKey":
		meta := map[string]interface{}{"KeyId": in["KeyId"], "KeyState": key.state, "Origin": "EXTERNAL", "CurrentKeyMaterialId": key.current}
		if key.validTo != nil {
			meta["ValidTo"] = float64(key.validTo.Unix())
		}
		out["KeyMetadata"] = meta
	case "Encrypt":
		if key.state == "Disabled" || key.state == "PendingDeletion" {
			d.fail(w, "DisabledException", "key is "+key.state)
			return
		}
		m := key.material[key.current]
		if m == nil {
			d.fail(w, "KMSInvalidStateException", "the key has no material")
			return
		}
		out["CiphertextBlob"] = append([]byte(key.current+"|"), gcmSeal(m, b64("Plaintext"))...)
	case "Decrypt":
		blob := b64("CiphertextBlob")
		i := bytes.IndexByte(blob, '|')
		m := key.material[string(blob[:i])]
		if m == nil {
			d.fail(w, "KMSInvalidStateException", "the material is gone")
			return
		}
		pt, err := gcmOpen(m, blob[i+1:])
		if err != nil {
			d.fail(w, "InvalidCiphertextException", err.Error())
			return
		}
		out["Plaintext"] = pt
	default:
		d.fail(w, "UnsupportedOperationException", op)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func decodeB64(s string) []byte {
	b, _ := decodeStd(s)
	return b
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
