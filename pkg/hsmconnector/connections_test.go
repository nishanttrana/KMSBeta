package hsmconnector

import (
	"context"
	"net/http"
	"testing"

	"vecta-kms/pkg/hsm"
)

// testCredentials: t1 has the HSM credential "cred-c" on token vecta-c;
// "cred-wrong-pin" names the same token with another PIN.
type testCredentials struct{}

func (testCredentials) LoadConnection(_ context.Context, tenant, id string) (TenantConfig, error) {
	pin := map[string]string{"cred-c": credPIN, "cred-wrong-pin": "000000"}[id]
	if tenant != "t1" || pin == "" {
		return TenantConfig{}, ErrConnectionNotFound
	}
	return FromCredential(tenant, id, map[string]string{"library_path": softhsmLib, "token_label": "vecta-c", "pin": pin, "vendor": "softhsm2"})
}

// A request naming an HSM credential runs on that credential's token, not
// on the tenant's profile, and a credential the tenant doesn't have is
// refused and audited.
func TestHSMCredentialSelectsTheToken(t *testing.T) {
	h, rec := newTestHandler(t)
	h.SetConnections(testCredentials{})
	keycore := service("kms-keycore")
	label := hsm.KeyLabel("t1", "key_on_cred", 1)
	code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256"})
	if code != http.StatusCreated {
		t.Fatalf("generate on the credential: %d %v", code, out)
	}
	id, _ := out["hsm"].(map[string]interface{})
	if id["token_label"] != "vecta-c" {
		t.Fatalf("the key was generated on %v, not the credential's token", id["token_label"])
	}
	if ev := rec.Last(t); ev.Event.Details["connection_id"] != "cred-c" || ev.Event.Details["hsm_token"] != "vecta-c" {
		t.Fatalf("audit: %+v", ev.Event.Details)
	}
	// The object is on vecta-c only: the profile's token doesn't have it.
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label}); code != http.StatusNotFound {
		t.Fatalf("the key is on the tenant profile's token too: %d", code)
	}
	if code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label}); code != http.StatusOK {
		t.Fatalf("inspect on the credential: %d %v", code, out)
	}
	// Encrypt on the credential, decrypt on the credential.
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/encrypt?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label, "plaintext_b64": b64s([]byte("on cred")), "aad_b64": ""})
	if code != http.StatusOK {
		t.Fatalf("encrypt: %d %v", code, out)
	}
	iv, ct := field(t, out, "iv_b64"), field(t, out, "ciphertext_b64")
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/decrypt?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label, "iv_b64": b64s(iv), "ciphertext_b64": b64s(ct), "aad_b64": ""})
	if code != http.StatusOK || string(field(t, out, "plaintext_b64")) != "on cred" {
		t.Fatalf("decrypt: %d %v", code, out)
	}

	// Another tenant can't use t1's credential; an unknown one is refused.
	for _, c := range []struct{ tenant, conn string }{{"t2", "cred-c"}, {"t1", "cred-none"}} {
		code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys?connection_id="+c.conn, map[string]string{"tenant_id": c.tenant, "label": hsm.KeyLabel(c.tenant, "k", 1), "algorithm": "AES-256"})
		if code != http.StatusConflict {
			t.Fatalf("%s using %s: %d", c.tenant, c.conn, code)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "hsm_connection_not_found" {
			t.Fatalf("refusal audit: %+v", ev.Event)
		}
	}
	// The token is logged in for the whole process, so a second credential
	// naming it must carry the same PIN: a wrong one doesn't ride the login.
	code, _ = call(t, h, keycore, http.MethodPost, "/hsm/keys?connection_id=cred-wrong-pin", map[string]string{"tenant_id": "t1", "label": hsm.KeyLabel("t1", "k2", 1), "algorithm": "AES-256"})
	if code != http.StatusConflict {
		t.Fatalf("a credential with the wrong PIN used the token: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "pin_mismatch" {
		t.Fatalf("PIN mismatch audit: %+v", ev.Event)
	}
	// The root of trust never goes on a credential.
	code, _ = call(t, h, keycore, http.MethodPost, "/hsm/tenant-key?connection_id=cred-c", map[string]string{"tenant_id": "t1"})
	if code != http.StatusConflict {
		t.Fatalf("tenant key on a credential: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "root_of_trust_is_the_profile" {
		t.Fatalf("tenant key refusal: %+v", ev.Event)
	}
	// Status reports the credential's token.
	code, out = call(t, h, keycore, http.MethodGet, "/hsm/status?tenant_id=t1&connection_id=cred-c", nil)
	st, _ := out["status"].(map[string]interface{})
	if code != http.StatusOK || st["connected"] != true || st["token_label"] != "vecta-c" {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/destroy?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label}); code != http.StatusOK {
		t.Fatalf("destroy: %d", code)
	}
	// Without a credential store, a credential request fails; it does not
	// fall back to the profile.
	bare, _ := newTestHandler(t)
	if code, _ := call(t, bare, keycore, http.MethodPost, "/hsm/keys?connection_id=cred-c", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256"}); code != http.StatusServiceUnavailable {
		t.Fatalf("no credential store: %d", code)
	}
}

// Imported AES material becomes a sensitive, never-extractable token
// object; the HSM says honestly that it was not generated there.
func TestImportedAESKeyIsNotExtractable(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	label := hsm.KeyLabel("t1", "key_imported", 1)
	material := []byte("0123456789abcdef0123456789abcdef")
	code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256", "material_b64": b64s(material)})
	if code != http.StatusCreated {
		t.Fatalf("import: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Action != "key_imported" || ev.Event.Result != "success" {
		t.Fatalf("audit: %+v", ev)
	}
	if kcv := field(t, out, "kcv_b64"); len(kcv) != 3 {
		t.Fatalf("kcv = %x", kcv)
	}
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label})
	objs, _ := objectsFrom(t, out)
	if code != http.StatusOK || len(objs) != 1 {
		t.Fatalf("inspect: %d %v", code, out)
	}
	o := objs[0]
	if !isTrue(o.Sensitive) || !isFalse(o.Extractable) || !isFalse(o.Local) || o.SizeBits != 256 {
		t.Fatalf("imported key attributes: sensitive=%v extractable=%v local=%v bits=%d", o.Sensitive, o.Extractable, o.Local, o.SizeBits)
	}
	// It encrypts like a generated key.
	if code, out := call(t, h, keycore, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t1", "label": label, "plaintext_b64": b64s([]byte("x")), "aad_b64": ""}); code != http.StatusOK {
		t.Fatalf("encrypt with the imported key: %d %v", code, out)
	}
	for name, body := range map[string]map[string]string{
		"wrong length": {"tenant_id": "t1", "label": hsm.KeyLabel("t1", "k3", 1), "algorithm": "AES-256", "material_b64": b64s(material[:16])},
		"not AES":      {"tenant_id": "t1", "label": hsm.KeyLabel("t1", "k4", 1), "algorithm": "RSA-2048", "material_b64": b64s(material)},
		"same label":   {"tenant_id": "t1", "label": label, "algorithm": "AES-256", "material_b64": b64s(material)},
	} {
		if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", body); code < 400 {
			t.Fatalf("%s: import accepted (%d)", name, code)
		}
	}
	// Only keycore imports; another tenant's label is refused.
	if code, _ := call(t, h, service("kms-governance"), http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": hsm.KeyLabel("t1", "k5", 1), "algorithm": "AES-256", "material_b64": b64s(material)}); code != http.StatusForbidden {
		t.Fatalf("governance imported a key: %d", code)
	}
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": hsm.KeyLabel("t2", "k6", 1), "algorithm": "AES-256", "material_b64": b64s(material)}); code != http.StatusForbidden {
		t.Fatalf("foreign label imported: %d", code)
	}
	call(t, h, keycore, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t1", "label": label})
}
