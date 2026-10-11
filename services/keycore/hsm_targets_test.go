package main

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/route/routetest"
)

// These tests run keycore against a real hsm-connector with two SoftHSM2
// tokens: "vecta-test" is every tenant's HSM profile, and
// softhsmtest.CredentialToken is what an HSM credential points at.

// testHSMCredentials is the credential store as keycore sees it.
type testHSMCredentials struct {
	creds     map[string]HSMCredential // by ID, all in one tenant
	tenant    string
	forbidden bool
	err       error
}

func (c *testHSMCredentials) List(_ context.Context, tenantID string) ([]HSMCredential, error) {
	switch {
	case c.err != nil:
		return nil, c.err
	case c.forbidden:
		return nil, errHSMCredentialForbidden
	case tenantID != c.tenant:
		return nil, nil
	}
	out := []HSMCredential{}
	for _, cr := range c.creds {
		out = append(out, cr)
	}
	return out, nil
}

func (c *testHSMCredentials) Get(_ context.Context, tenantID, id string) (HSMCredential, error) {
	switch {
	case c.err != nil:
		return HSMCredential{}, c.err
	case c.forbidden:
		return HSMCredential{}, errHSMCredentialForbidden
	}
	cr, ok := c.creds[id]
	if !ok || tenantID != c.tenant {
		return HSMCredential{}, errHSMCredentialNotFound
	}
	return cr, nil
}

const lunaHA = "pbconn_luna_ha"

// newHSMCredentialService: tenant has the HSM profile and one HSM
// credential, lunaHA, declared as an HA group.
func newHSMCredentialService(t *testing.T, tenant string) (*Service, *eventRecorder, *hsm.Client, *testHSMCredentials) {
	t.Helper()
	srv := softhsmtest.StartWith(t, "kms-keycore", softhsmtest.Connections{tenant: {lunaHA}}, tenant)
	rec := &eventRecorder{}
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), rec,
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	client := hsm.New(srv.URL)
	svc.SetHSMBackend(client)
	creds := &testHSMCredentials{tenant: tenant, creds: map[string]HSMCredential{
		lunaHA: {ID: lunaHA, Name: "Luna HA group", Type: hsmCredentialType, Attributes: map[string]string{"topology": "ha_group", "vendor": "thales"}},
	}}
	svc.SetHSMCredentials(creds)
	return svc, rec, client, creds
}

// A key created on an HSM credential is generated on that credential's
// token, records it, and every later operation goes back to it. The
// tenant's HSM profile never sees the key.
func TestHSMKeyOnACredential(t *testing.T) {
	svc, rec, client, creds := newHSMCredentialService(t, "c1")
	ctx := adminCtx()
	// HSM keys are off on the tenant's profile: a credential is its own
	// opt-in, and the profile stays refused.
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "c1", Name: "on-profile", Algorithm: "AES-256", HSM: true}); hsmRefusalReason(err) != "hsm_keys_disabled" {
		t.Fatalf("profile with HSM keys off: %v", err)
	}
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "c1", Name: "on-luna", Algorithm: "AES-256", Purpose: "encrypt", HSMConnectionID: lunaHA,
		Labels: map[string]string{"team": "payments", "hsm_connection": "pbconn_somewhere_else", "hsm": "no"}})
	if err != nil {
		t.Fatal(err)
	}
	if key.Labels[labelHSMConnection] != lunaHA || key.Labels[labelHSMConnectionName] != "Luna HA group" || key.Labels[labelHSMTopology] != "ha_group" ||
		key.Labels[labelHSM] != labelHSMResident || key.Labels[labelHSMToken] != softhsmtest.CredentialToken || key.Labels["team"] != "payments" || key.ExportAllowed {
		t.Fatalf("labels: %v", key.Labels)
	}
	ev := rec.find("audit.key.create")
	if d, _ := ev["details"].(map[string]any); d[labelHSMConnection] != lunaHA || d["hsm_token"] != softhsmtest.CredentialToken || d[labelHSMTopology] != "ha_group" {
		t.Fatalf("create audit: %+v", ev)
	}
	label := hsm.KeyLabel("c1", key.ID, 1)
	if _, _, err := client.Inspect(context.Background(), "c1", label); err != hsm.ErrNotFound {
		t.Fatalf("the key is on the tenant's HSM profile: %v", err)
	}
	if objs, id, err := client.On(lunaHA).Inspect(context.Background(), "c1", label); err != nil || len(objs) != 1 || id.TokenLabel != softhsmtest.CredentialToken {
		t.Fatalf("the key is not on the credential's token: %v %v %+v", err, objs, id)
	}

	enc, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "c1", PlaintextB64: b64([]byte("pan")), AADB64: b64([]byte("a"))})
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "c1", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64, AADB64: b64([]byte("a"))}); err != nil || dec.PlainB64 != b64([]byte("pan")) {
		t.Fatalf("decrypt on the credential: %v %+v", err, dec)
	}
	// Rotation generates the next version on the same HSM.
	v2, err := svc.RotateKey(ctx, "c1", key.ID, "scheduled", "deactivate")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.On(lunaHA).Inspect(context.Background(), "c1", v2.HSMLabel); err != nil {
		t.Fatalf("rotated version not on the credential's token: %v", err)
	}
	if rec.find("audit.key.hsm_device_changed") != nil {
		t.Fatal("rotation on the same HSM reported a device change")
	}
	check, err := svc.InspectHSMKey(ctx, "c1", key.ID)
	if err != nil || !check.SameDevice || len(check.Versions) != 2 || check.Current.TokenLabel != softhsmtest.CredentialToken {
		t.Fatalf("verify in HSM: %v %+v", err, check)
	}
	// A metadata update can neither move the key to another HSM nor hide
	// that it is in one.
	if err := svc.UpdateKey(ctx, "c1", key.ID, UpdateKeyRequest{Name: "renamed", Purpose: "encrypt", Labels: map[string]string{"team": "cards", "hsm_connection": "pbconn_attacker"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.GetKey(ctx, "c1", key.ID)
	if got.Labels[labelHSMConnection] != lunaHA || got.Labels[labelHSM] != labelHSMResident || got.Labels["team"] != "cards" || got.Name != "renamed" {
		t.Fatalf("labels after update: %v", got.Labels)
	}
	if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "c1", PlaintextB64: b64([]byte("still works"))}); err != nil {
		t.Fatalf("encrypt after the update: %v", err)
	}

	// The create, form and import dialogs are offered both HSMs.
	targets, err := svc.ListHSMTargets(ctx, "c1")
	if err != nil || targets.CredentialsState != "listed" || len(targets.Targets) != 2 {
		t.Fatalf("targets: %v %+v", err, targets)
	}
	profile, cred := targets.Targets[0], targets.Targets[1]
	if profile.Kind != "tenant_profile" || profile.Usable || !strings.Contains(profile.Reason, "HSM keys are off") || profile.Status.TokenLabel != "vecta-test" {
		t.Fatalf("profile target: %+v", profile)
	}
	if cred.ID != lunaHA || cred.Kind != "credential" || !cred.Usable || cred.Topology != "ha_group" || cred.Vendor != "thales" || cred.Status.TokenLabel != softhsmtest.CredentialToken || cred.Status.SerialNumber == "" {
		t.Fatalf("credential target: %+v", cred)
	}

	// Destroying the key removes both versions from the credential's token.
	if err := svc.DestroyKeyImmediately(ctx, "c1", key.ID, "test cleanup of an HSM credential key", "tester", "", ""); err != nil {
		t.Fatal(err)
	}
	if rec.find("audit.key.hsm_objects_destroyed") == nil {
		t.Fatal("HSM objects not removed")
	}
	for _, l := range []string{label, v2.HSMLabel} {
		if _, _, err := client.On(lunaHA).Inspect(context.Background(), "c1", l); err != hsm.ErrNotFound {
			t.Fatalf("%s is still on the credential's token: %v", l, err)
		}
	}
	_ = creds
}

// A credential the tenant doesn't have, one the caller may not use, and a
// deployment without a credential store are each refused and audited; no
// key is created and none falls back to the tenant's profile.
func TestHSMCredentialRefusals(t *testing.T) {
	svc, rec, _, creds := newHSMCredentialService(t, "c2")
	ctx := adminCtx()
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "c2", HSMKeysEnabled: true}); err != nil {
		t.Fatal(err)
	}
	create := func(conn string) error {
		_, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "c2", Name: "k", Algorithm: "AES-256", HSMConnectionID: conn})
		return err
	}
	want := func(step, reason string, err error) {
		t.Helper()
		if hsmRefusalReason(err) != reason {
			t.Fatalf("%s: %v, want %s", step, err, reason)
		}
		if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != reason {
			t.Fatalf("%s audit: %+v", step, d)
		}
	}
	want("unknown credential", "hsm_connection_not_found", create("pbconn_nope"))
	// The connector, too, refuses a credential it can't resolve.
	creds.creds["pbconn_ghost"] = HSMCredential{ID: "pbconn_ghost", Name: "ghost", Type: hsmCredentialType}
	if err := create("pbconn_ghost"); err == nil {
		t.Fatal("a credential the connector can't open created a key")
	}
	creds.forbidden = true
	want("caller without the use permission", "hsm_credential_not_permitted", create(lunaHA))
	if tg, _ := svc.ListHSMTargets(ctx, "c2"); tg.CredentialsState != "not_permitted" || len(tg.Targets) != 1 {
		t.Fatalf("targets without the use permission: %+v", tg)
	}
	creds.forbidden, creds.err = false, context.DeadlineExceeded
	want("credential store down", "hsm_credentials_unavailable", create(lunaHA))
	if tg, _ := svc.ListHSMTargets(ctx, "c2"); tg.CredentialsState != "unavailable" || tg.CredentialsError == "" {
		t.Fatalf("targets with the store down: %+v", tg)
	}
	svc.SetHSMCredentials(nil)
	want("no credential store", "hsm_credentials_not_deployed", create(lunaHA))
	if tg, _ := svc.ListHSMTargets(ctx, "c2"); tg.CredentialsState != "not_deployed" {
		t.Fatalf("targets without a store: %+v", tg)
	}
	keys, _ := svc.store.ListKeys(context.Background(), "c2", 10, 0)
	if len(keys) != 0 {
		t.Fatalf("a refused request created %d key(s)", len(keys))
	}
}

// Imported and formed AES keys can be placed in an HSM: keycore keeps no
// material, the HSM's own check value matches the material's, and the key
// says it was imported.
func TestImportAndFormIntoHSM(t *testing.T) {
	svc, rec, client, _ := newHSMCredentialService(t, "c3")
	ctx := adminCtx()
	raw := []byte("0123456789abcdef0123456789abcdef")
	wantKCV, _, err := computeKCVStrict("AES-256", raw)
	if err != nil {
		t.Fatal(err)
	}
	imp := ImportKeyRequest{MaterialB64: b64(raw), ImportMethod: "raw", ExpectedKCV: hex.EncodeToString(wantKCV)}
	imp.TenantID, imp.Name, imp.Algorithm, imp.Purpose, imp.HSMConnectionID = "c3", "imported", "AES-256", "encrypt", lunaHA
	key, err := svc.ImportKey(ctx, imp)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key.KCV) != hex.EncodeToString(wantKCV) || key.KCVAlgorithm != "aes-ecb-zero-hsm" || key.Labels[labelHSMOrigin] != "imported" ||
		key.Labels[labelHSMConnection] != lunaHA || key.ExportAllowed {
		t.Fatalf("imported key: kcv %x (%s) labels %v", key.KCV, key.KCVAlgorithm, key.Labels)
	}
	ver, _ := svc.store.GetVersion(context.Background(), "c3", key.ID, 1)
	if ver.Protection != protectionHSMResident || len(ver.EncryptedMaterial) != 0 || len(ver.WrappedDEK) != 0 {
		t.Fatalf("keycore kept the imported material: %+v", ver)
	}
	if d, _ := rec.find("audit.key.import")["details"].(map[string]any); d["hsm"] != true || d[labelHSMOrigin] != "imported" || d[labelHSMConnection] != lunaHA {
		t.Fatalf("import audit: %+v", rec.find("audit.key.import"))
	}
	// The HSM holds it sensitive and not extractable, and reports that it
	// was not generated there.
	objs, _, err := client.On(lunaHA).Inspect(context.Background(), "c3", ver.HSMLabel)
	if err != nil || len(objs) != 1 || objs[0].Local == nil || *objs[0].Local || objs[0].Extractable == nil || *objs[0].Extractable || objs[0].Sensitive == nil || !*objs[0].Sensitive {
		t.Fatalf("imported object: %v %+v", err, objs)
	}
	enc, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "c3", PlaintextB64: b64([]byte("data"))})
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "c3", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64}); err != nil || dec.PlainB64 != b64([]byte("data")) {
		t.Fatalf("decrypt with the imported key: %v", err)
	}

	// A wrong expected check value is refused before anything reaches the HSM.
	bad := imp
	bad.Name, bad.ExpectedKCV = "bad-kcv", "000000"
	if _, err := svc.ImportKey(ctx, bad); err == nil || !strings.Contains(err.Error(), "kcv mismatch") {
		t.Fatalf("wrong KCV: %v", err)
	}
	// Material with no HSM form (an HMAC key) can't be placed in one.
	rsa := ImportKeyRequest{ImportMethod: "raw", MaterialB64: b64(raw)}
	rsa.TenantID, rsa.Name, rsa.Algorithm, rsa.HSMConnectionID = "c3", "hmac", "HMAC-SHA256", lunaHA
	if _, err := svc.ImportKey(ctx, rsa); hsmRefusalReason(err) != "hsm_import_not_supported" {
		t.Fatalf("non-AES import into the HSM: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != "hsm_import_not_supported" {
		t.Fatalf("refusal audit: %+v", d)
	}

	// A key formed from components goes to the HSM the same way.
	a, b := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []byte("0123456789abcdef0123456789abcdef")
	form := FormKeyRequest{ComponentMode: "clear-user", Components: []FormKeyComponent{{MaterialB64: b64(a)}, {MaterialB64: b64(b)}}, Parity: "none"}
	form.TenantID, form.Name, form.Algorithm, form.Purpose, form.HSMConnectionID = "c3", "formed", "AES-256", "encrypt", lunaHA
	formed, _, err := svc.FormKey(ctx, form)
	if err != nil {
		t.Fatal(err)
	}
	combinedKCV, _, _ := computeKCVStrict("AES-256", xorComponents([][]byte{a, b}, 32))
	if hex.EncodeToString(formed.KCV) != hex.EncodeToString(combinedKCV) || formed.Labels[labelHSMConnection] != lunaHA || formed.Labels["formed_from_components"] != "true" {
		t.Fatalf("formed key: kcv %x want %x labels %v", formed.KCV, combinedKCV, formed.Labels)
	}
	if d, _ := rec.find("audit.key.form")["details"].(map[string]any); d["hsm"] != true || d[labelHSMConnection] != lunaHA {
		t.Fatalf("form audit: %+v", rec.find("audit.key.form"))
	}
	fv, _ := svc.store.GetVersion(context.Background(), "c3", formed.ID, 1)
	if len(fv.EncryptedMaterial) != 0 {
		t.Fatal("keycore kept the formed key's material")
	}
	// The same on the tenant's profile, once HSM keys are on there.
	onProfile := imp
	onProfile.Name, onProfile.HSMConnectionID, onProfile.HSM = "imported-profile", "", true
	if _, err := svc.ImportKey(ctx, onProfile); hsmRefusalReason(err) != "hsm_keys_disabled" {
		t.Fatalf("import to the profile with HSM keys off: %v", err)
	}
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "c3", HSMKeysEnabled: true}); err != nil {
		t.Fatal(err)
	}
	pk, err := svc.ImportKey(ctx, onProfile)
	if err != nil || pk.Labels[labelHSMConnection] != "" || pk.Labels[labelHSMToken] != "vecta-test" {
		t.Fatalf("import to the profile: %v %v", err, pk.Labels)
	}
	for _, k := range []Key{key, formed, pk} {
		if err := svc.DestroyKeyImmediately(ctx, "c3", k.ID, "test cleanup of imported HSM keys", "tester", "", ""); err != nil {
			t.Fatal(err)
		}
	}
}

// An imported RSA or ECDSA private key goes to the HSM too (8.2.0-beta):
// keycore keeps the public key and no private material, the HSM holds the
// private key non-extractable, and the key signs there. A public key, or a
// key the HSM path excludes, is refused and audited.
func TestImportPrivateKeyIntoHSM(t *testing.T) {
	svc, rec, client, _ := newHSMCredentialService(t, "c5")
	ctx := adminCtx()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemOf := func(k any) string {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	var made []Key
	for alg, c := range map[string]struct{ priv, pub any }{"ECDSA-P256": {ec, &ec.PublicKey}, "RSA-2048": {rsaKey, &rsaKey.PublicKey}} {
		imp := ImportKeyRequest{MaterialB64: pemOf(c.priv), ImportMethod: "pem"}
		imp.TenantID, imp.Name, imp.Purpose, imp.HSMConnectionID = "c5", "imported-"+alg, "sign", lunaHA
		key, err := svc.ImportKey(ctx, imp)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		made = append(made, key)
		wantPub, _ := x509.MarshalPKIXPublicKey(c.pub)
		sum := sha256.Sum256(wantPub)
		if key.KCVAlgorithm != "sha256-spki" || !bytes.Equal(key.KCV, sum[:3]) || key.Labels[labelHSMOrigin] != "imported" || key.Labels[labelHSMConnection] != lunaHA || key.ExportAllowed {
			t.Fatalf("%s key: kcv %x (%s) labels %v", alg, key.KCV, key.KCVAlgorithm, key.Labels)
		}
		ver, _ := svc.store.GetVersion(context.Background(), "c5", key.ID, 1)
		if ver.Protection != protectionHSMResident || len(ver.EncryptedMaterial) != 0 || len(ver.WrappedDEK) != 0 || !bytes.Equal(ver.PublicKey, wantPub) {
			t.Fatalf("%s version: protection %s, %d material bytes, public key matches %v", alg, ver.Protection, len(ver.EncryptedMaterial), bytes.Equal(ver.PublicKey, wantPub))
		}
		if d, _ := rec.find("audit.key.import")["details"].(map[string]any); d["hsm"] != true || d[labelHSMOrigin] != "imported" || d["key_id"] != key.ID {
			t.Fatalf("%s import audit: %+v", alg, d)
		}
		objs, _, err := client.On(lunaHA).Inspect(context.Background(), "c5", ver.HSMLabel)
		if err != nil || len(objs) != 2 {
			t.Fatalf("%s objects: %v %+v", alg, err, objs)
		}
		for _, o := range objs {
			if o.Class == "private_key" && (o.Extractable == nil || *o.Extractable || o.Sensitive == nil || !*o.Sensitive || o.Local == nil || *o.Local) {
				t.Fatalf("%s private key object: %+v", alg, o)
			}
		}
		// The HSM signs with it; the signature verifies under the public
		// key of the key that was imported.
		digest := sha256.Sum256([]byte("statement"))
		sig, err := client.On(lunaHA).Sign(context.Background(), "c5", ver.HSMLabel, "SHA-256", digest[:])
		if err != nil {
			t.Fatalf("%s sign in the HSM: %v", alg, err)
		}
		switch pub := c.pub.(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatalf("%s: signature does not verify", alg)
			}
		case *rsa.PublicKey:
			if err := rsa.VerifyPSS(pub, stdcrypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: 32}); err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
		}
	}

	pubDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	refused := map[string]string{"a public key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))}
	// Outside strict FIPS mode only: there the module won't make such a key.
	if small, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		refused["a 1024-bit RSA key"] = pemOf(small)
	}
	for name, material := range refused {
		imp := ImportKeyRequest{MaterialB64: material, ImportMethod: "pem"}
		imp.TenantID, imp.Name, imp.HSMConnectionID = "c5", "refused", lunaHA
		if _, err := svc.ImportKey(ctx, imp); hsmRefusalReason(err) != "hsm_import_not_supported" {
			t.Fatalf("%s into the HSM: %v", name, err)
		}
		if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != "hsm_import_not_supported" {
			t.Fatalf("%s refusal audit: %+v", name, d)
		}
	}
	for _, k := range made {
		if err := svc.DestroyKeyImmediately(ctx, "c5", k.ID, "test cleanup of imported HSM keys", "tester", "", ""); err != nil {
			t.Fatal(err)
		}
	}
}

// The credential store alone may ask where HSM credentials are used, and it
// is told about live keys only.
func TestHSMCredentialUsageIsForTheCredentialStore(t *testing.T) {
	svc, _, _, _ := newHSMCredentialService(t, "t1")
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "used", Algorithm: "AES-256", HSMConnectionID: lunaHA})
	if err != nil {
		t.Fatal(err)
	}
	gone, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "gone", Algorithm: "AES-256", HSMConnectionID: lunaHA})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroyKeyImmediately(ctx, "t1", gone.ID, "test: a destroyed key is not a user", "tester", "", ""); err != nil {
		t.Fatal(err)
	}
	h := &Handler{svc: svc}
	rec := &routetest.Recorder{}
	router := h.hsmRouter(rec)
	get := func(claims *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/keys/hsm/credential-usage?tenant_id=t1", nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	keycoreSvc := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: "kms-audit", Permissions: []string{"service.internal"}}
	for _, who := range []*pkgauth.Claims{admin, keycoreSvc} {
		if w := get(who); w.Code != http.StatusForbidden {
			t.Fatalf("%s%s read credential usage: %d", who.UserID, who.ClientID, w.Code)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "caller_not_allowed" {
			t.Fatalf("refusal audit: %+v", ev.Event)
		}
	}
	compliance := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}}
	w := get(compliance)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"label":"key used"`) || strings.Contains(w.Body.String(), "gone") || !strings.Contains(w.Body.String(), lunaHA) {
		t.Fatalf("usage: %d %s", w.Code, w.Body.String())
	}
	_ = svc.DestroyKeyImmediately(ctx, "t1", key.ID, "test cleanup of an HSM credential key", "tester", "", "")
}
