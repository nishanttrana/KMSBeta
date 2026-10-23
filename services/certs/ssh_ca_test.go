package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func testSSHPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func sshRouter(svc *Service, rec *routetest.Recorder) *route.Router {
	k := route.New("cert", rec, log.New(io.Discard, "", 0))
	NewHandler(svc).RegisterSSHRoutes(k)
	return k
}

var sshAdmin = &pkgauth.Claims{UserID: "u-ssh", TenantID: "t1", Role: "operator", Permissions: []string{"cert.ssh.read", "cert.ssh.write", "cert.ssh.sign"}}

func sshCall(t *testing.T, router http.Handler, claims *pkgauth.Claims, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path+"?tenant_id=t1", r)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestSSHRoutesRefusalsAudited(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, sshRouter(svc, rec), rec)
}

// A certificate from each CA algorithm verifies as OpenSSH checks it: the
// CA's signature, the principal, the validity window. RSA signs
// rsa-sha2-512, never SHA-1.
func TestSSHCACertificatesVerify(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()
	for _, alg := range []string{"ECDSA-P256", "ECDSA-P384", "RSA-3072", "ED25519"} {
		ca, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "ca-" + alg, Algorithm: alg, AllowedPrincipals: []string{"deploy", "web-*"},
			DefaultExtensions: []string{"permit-pty"}})
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		rec, line, err := svc.SignSSH(ctx, "t1", ca.ID, "u-ssh", SignSSHRequest{PublicKey: testSSHPublicKey(t), Principals: []string{"deploy", "web-01"}, ValidSeconds: 3600})
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		cert := parsed.(*ssh.Certificate)
		caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
		checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caPub.Marshal()) }}
		if _, err := checker.Authenticate(fakeConnMeta("web-01"), cert); err != nil {
			t.Fatalf("%s: OpenSSH-style check: %v", alg, err)
		}
		if _, err := checker.Authenticate(fakeConnMeta("root"), cert); err == nil {
			t.Fatalf("%s: a principal not in the certificate was accepted", alg)
		}
		if alg == "RSA-3072" && cert.Signature.Format != ssh.KeyAlgoRSASHA512 {
			t.Fatalf("RSA CA signed with %s", cert.Signature.Format)
		}
		if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok || cert.CertType != ssh.UserCert {
			t.Fatalf("%s: extensions %v type %d", alg, cert.Permissions.Extensions, cert.CertType)
		}
		if d := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; d != time.Hour+sshBackdate {
			t.Fatalf("%s: validity %v", alg, d)
		}
		if rec.KeyFingerprint != ssh.FingerprintSHA256(cert.Key) || rec.Serial == "" || rec.Serial == "0" {
			t.Fatalf("%s: record %+v", alg, rec)
		}
	}
}

type fakeConnMeta string

func (f fakeConnMeta) User() string        { return string(f) }
func (fakeConnMeta) SessionID() []byte     { return nil }
func (fakeConnMeta) ClientVersion() []byte { return nil }
func (fakeConnMeta) ServerVersion() []byte { return nil }
func (fakeConnMeta) RemoteAddr() net.Addr  { return nil }
func (fakeConnMeta) LocalAddr() net.Addr   { return nil }

// The CA's policy is enforced, and every refusal is audited with its
// reason: a principal it doesn't list, a type it doesn't sign, too long a
// validity, a weak or unusable key, a disabled CA.
func TestSSHSigningPolicyRefusals(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &routetest.Recorder{}
	router := sshRouter(svc, rec)
	w := sshCall(t, router, sshAdmin, http.MethodPost, "/certs/ssh/cas", map[string]any{
		"name": "ops", "allowed_principals": []string{"deploy", "web-*"}, "max_validity_seconds": 3600,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "ssh_ca_created" || ev.Event.Result != "success" || ev.Event.Details["fingerprint"] == "" {
		t.Fatalf("create audited: %+v", ev)
	}
	var created struct {
		SSHCA SSHCA `json:"ssh_ca"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	ca := created.SSHCA
	if ca.Algorithm != "ECDSA-P384" || len(ca.CertTypes) != 1 || ca.CertTypes[0] != "user" || strings.Contains(w.Body.String(), "signer") {
		t.Fatalf("created %+v", ca)
	}
	// A 1024-bit RSA public key (generating one is refused in FIPS "only"
	// mode, so it is a fixed key).
	weakPub := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDCJRjH4c0fmBfyeMZ+kXtt0Rc8BiHCQs088GVtPNbXYJ4W2MSCvCsdFgUxLoAAmT0OYuXo8UyiAamoeyb09CqqElNtIrs+gTlgQJZTpOKD5oq1i8URaq9FDS2a+p5OW0ojHFoTR/Psu89+VMSr57kx22MqRAzXrXWQlGdHD8ombQ== weak"
	sign := "/certs/ssh/cas/" + ca.ID + "/sign"
	good := testSSHPublicKey(t)
	for _, tc := range []struct {
		name   string
		body   map[string]any
		code   int
		reason string
	}{
		{"principal not listed", map[string]any{"public_key": good, "principals": []string{"root"}}, http.StatusForbidden, "principal_not_allowed"},
		{"wildcard principal", map[string]any{"public_key": good, "principals": []string{"web-*"}}, http.StatusBadRequest, "invalid_principal"},
		{"no principal", map[string]any{"public_key": good}, http.StatusBadRequest, "principals_required"},
		{"host certificate", map[string]any{"public_key": good, "principals": []string{"deploy"}, "cert_type": "host"}, http.StatusForbidden, "cert_type_not_allowed"},
		{"too long", map[string]any{"public_key": good, "principals": []string{"deploy"}, "valid_seconds": 7200}, http.StatusBadRequest, "validity_too_long"},
		{"weak RSA", map[string]any{"public_key": weakPub, "principals": []string{"deploy"}}, http.StatusBadRequest, "weak_public_key"},
		{"not a key", map[string]any{"public_key": "ssh-ed25519 AAAA-not-base64", "principals": []string{"deploy"}}, http.StatusBadRequest, "invalid_public_key"},
		{"the CA's key", map[string]any{"public_key": ca.PublicKey, "principals": []string{"deploy"}}, http.StatusBadRequest, "invalid_public_key"},
		{"unknown extension", map[string]any{"public_key": good, "principals": []string{"deploy"}, "extensions": []string{"permit-everything"}}, http.StatusBadRequest, "extension_not_allowed"},
		{"bad source address", map[string]any{"public_key": good, "principals": []string{"deploy"}, "source_address": []string{"anywhere"}}, http.StatusBadRequest, "invalid_option"},
		{"two-line force command", map[string]any{"public_key": good, "principals": []string{"deploy"}, "force_command": "ls\nrm -rf /"}, http.StatusBadRequest, "invalid_option"},
	} {
		w := sshCall(t, router, sshAdmin, http.MethodPost, sign, tc.body)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Action != "ssh_certificate_issued" || ev.Event.Result != "refused" || ev.Event.Details["reason"] != tc.reason {
			t.Fatalf("%s: refusal audited as %+v", tc.name, ev.Event)
		}
	}

	// Within the policy it signs, with the options asked for.
	w = sshCall(t, router, sshAdmin, http.MethodPost, sign, map[string]any{"public_key": good, "principals": []string{"web-07"},
		"force_command": "/usr/bin/backup", "source_address": []string{"10.0.0.0/8", "192.0.2.4"}, "key_id": "backup-job"})
	if w.Code != http.StatusCreated {
		t.Fatalf("sign: %d %s", w.Code, w.Body)
	}
	ev := rec.Last(t)
	if ev.Event.Result != "success" || ev.Event.Details["key_id"] != "backup-job" || ev.Event.Details["serial"] == "" {
		t.Fatalf("issue audited: %+v", ev.Event)
	}
	var issued struct {
		Certificate string `json:"certificate"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &issued)
	parsed, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(issued.Certificate))
	opts := parsed.(*ssh.Certificate).Permissions.CriticalOptions
	if opts["force-command"] != "/usr/bin/backup" || opts["source-address"] != "10.0.0.0/8,192.0.2.4" {
		t.Fatalf("options %v", opts)
	}

	// Only cert.ssh.sign signs.
	reader := &pkgauth.Claims{UserID: "u-r", TenantID: "t1", Permissions: []string{"cert.ssh.read"}}
	if w := sshCall(t, router, reader, http.MethodPost, sign, map[string]any{"public_key": good, "principals": []string{"deploy"}}); w.Code != http.StatusForbidden {
		t.Fatalf("a reader signed: %d", w.Code)
	}

	// A disabled CA signs nothing; a narrowed policy applies at once.
	if w := sshCall(t, router, sshAdmin, http.MethodPut, "/certs/ssh/cas/"+ca.ID, map[string]any{"allowed_principals": []string{"deploy"}}); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	if w := sshCall(t, router, sshAdmin, http.MethodPost, sign, map[string]any{"public_key": good, "principals": []string{"web-07"}}); w.Code != http.StatusForbidden {
		t.Fatalf("a principal removed from the policy was signed: %d", w.Code)
	}
	if w := sshCall(t, router, sshAdmin, http.MethodPut, "/certs/ssh/cas/"+ca.ID, map[string]any{"status": "disabled"}); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "ssh_ca_updated" || ev.Event.Details["status"] != "disabled" {
		t.Fatalf("disable audited: %+v", ev)
	}
	if w := sshCall(t, router, sshAdmin, http.MethodPost, sign, map[string]any{"public_key": good, "principals": []string{"deploy"}}); w.Code != http.StatusConflict {
		t.Fatalf("a disabled CA signed: %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "ca_disabled" {
		t.Fatalf("disabled refusal: %+v", ev.Event)
	}

	// Another tenant's CA is not found.
	other := &pkgauth.Claims{UserID: "u-x", TenantID: "t2", Permissions: []string{"cert.ssh.read", "cert.ssh.sign"}}
	req := httptest.NewRequest(http.MethodGet, "/certs/ssh/cas/"+ca.ID+"?tenant_id=t2", http.NoBody)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), other))
	ow := httptest.NewRecorder()
	router.ServeHTTP(ow, req)
	if ow.Code != http.StatusNotFound {
		t.Fatalf("another tenant read the CA: %d", ow.Code)
	}

	// Creating needs a policy and a valid name.
	for _, body := range []map[string]any{
		{"name": "no-policy"},
		{"name": "ops"},
		{"name": "bad-alg", "algorithm": "DSA", "allowed_principals": []string{"*"}},
		{"name": "too-long", "allowed_principals": []string{"*"}, "max_validity_seconds": 400 * 24 * 3600},
	} {
		if w := sshCall(t, router, sshAdmin, http.MethodPost, "/certs/ssh/cas", body); w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
			t.Fatalf("create %v: %d %s", body, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" {
			t.Fatalf("create %v not refused: %+v", body, ev.Event)
		}
	}
}

// A revoked certificate is in the CA's KRL by serial, and OpenSSH's own
// ssh-keygen reads the KRL and reports it revoked; the other certificate
// stays valid. Without ssh-keygen on the machine the OpenSSH check is
// skipped (CI runners have it).
func TestSSHKRLRevokesBySerial(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &routetest.Recorder{}
	router := sshRouter(svc, rec)
	ctx := context.Background()
	ca, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "krl", AllowedPrincipals: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	keep, keepLine, err := svc.SignSSH(ctx, "t1", ca.ID, "u-ssh", SignSSHRequest{PublicKey: testSSHPublicKey(t), Principals: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	drop, dropLine, err := svc.SignSSH(ctx, "t1", ca.ID, "u-ssh", SignSSHRequest{PublicKey: testSSHPublicKey(t), Principals: []string{"bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if w := sshCall(t, router, sshAdmin, http.MethodPost, "/certs/ssh/certificates/"+drop.ID+"/revoke", map[string]any{"reason": "laptop lost"}); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "ssh_certificate_revoked" || ev.Event.Details["serial"] != drop.Serial || ev.Event.Details["reason"] != "laptop lost" {
		t.Fatalf("revoke audited: %+v", ev)
	}
	if w := sshCall(t, router, sshAdmin, http.MethodPost, "/certs/ssh/certificates/"+drop.ID+"/revoke", map[string]any{}); w.Code != http.StatusConflict {
		t.Fatalf("second revoke: %d", w.Code)
	}
	w := sshCall(t, router, sshAdmin, http.MethodGet, "/certs/ssh/cas/"+ca.ID+"/krl", nil)
	if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("SSHKRL\n\x00")) {
		t.Fatalf("krl: %d %q", w.Code, w.Body.Bytes())
	}
	if ev := rec.Last(t); ev.Event.Details["revoked"] != 1 {
		t.Fatalf("krl audited: %+v", ev.Event)
	}
	listed := sshCall(t, router, sshAdmin, http.MethodGet, "/certs/ssh/cas/"+ca.ID+"/certificates", nil)
	if !strings.Contains(listed.Body.String(), keep.ID) || !strings.Contains(listed.Body.String(), `"revoke_reason":"laptop lost"`) {
		t.Fatalf("list: %s", listed.Body)
	}

	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed; the KRL format check needs OpenSSH")
	}
	dir := t.TempDir()
	krl := filepath.Join(dir, "ca.krl")
	_ = os.WriteFile(krl, w.Body.Bytes(), 0o600)
	query := func(line string) (string, error) {
		f := filepath.Join(dir, "c-cert.pub")
		_ = os.WriteFile(f, []byte(line+"\n"), 0o600)
		out, err := exec.Command(keygen, "-Q", "-f", krl, f).CombinedOutput()
		return string(out), err
	}
	if out, err := query(dropLine); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("OpenSSH doesn't see the revoked certificate in the KRL: %v %s", err, out)
	}
	if out, err := query(keepLine); err != nil || !strings.Contains(out, "ok") {
		t.Fatalf("OpenSSH sees a valid certificate as revoked: %v %s", err, out)
	}
	cf := filepath.Join(dir, "k-cert.pub")
	_ = os.WriteFile(cf, []byte(keepLine+"\n"), 0o600)
	out, err := exec.Command(keygen, "-L", "-f", cf).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "alice") || !strings.Contains(string(out), ca.Fingerprint) {
		t.Fatalf("ssh-keygen -L: %v %s", err, out)
	}
}

// The CA's key never leaves: listing and reading return the public key and
// the lines to install, never sealed key material.
func TestSSHCAReadsArePublicOnly(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &routetest.Recorder{}
	router := sshRouter(svc, rec)
	ca, err := svc.CreateSSHCA(context.Background(), "t1", "u-ssh", CreateSSHCARequest{Name: "pub", AllowedPrincipals: []string{"*"}, CertTypes: []string{"user", "host"}})
	if err != nil {
		t.Fatal(err)
	}
	w := sshCall(t, router, sshAdmin, http.MethodGet, "/certs/ssh/cas/"+ca.ID, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `"known_hosts":"@cert-authority * ecdsa-sha2-nistp384 `) || strings.Contains(body, "PRIVATE") || strings.Contains(body, "wrapped") {
		t.Fatalf("read: %d %s", w.Code, body)
	}
	list := sshCall(t, router, sshAdmin, http.MethodGet, "/certs/ssh/cas", nil)
	if !strings.Contains(list.Body.String(), ca.Fingerprint) || strings.Contains(list.Body.String(), "PUBLIC KEY") {
		t.Fatalf("list: %s", list.Body)
	}
}

// An HSM SSH CA's key is generated and used in the HSM: nothing sealed is
// stored, each certificate is signed there for the caller (usage
// certificate-sign), and it verifies.
func TestSSHCAKeyInTheHSM(t *testing.T) {
	srv := softhsmtest.Start(t, "kms-keycore", "t1")
	svc, _ := newCertsService(t)
	kc := &hsmKeycore{client: hsm.New(srv.URL)}
	svc.keycore = kc
	ctx := context.Background()
	if _, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "hsm-rsa", Algorithm: "RSA-3072", KeyBackend: "hsm", AllowedPrincipals: []string{"*"}}); err == nil {
		t.Fatal("an RSA SSH CA key was made in the HSM, which keeps ECDSA CA keys")
	}
	ca, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "hsm", Algorithm: "ECDSA-P384", KeyBackend: "hsm", AllowedPrincipals: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := svc.store.GetSSHCA(ctx, "t1", ca.ID)
	if stored.signer.KeyVersion != signerVersionHSM || len(stored.signer.Ciphertext) != 0 || stored.KeyRef == "" {
		t.Fatalf("stored: %+v", stored.signer)
	}
	_, line, err := svc.SignSSH(ctx, "t1", ca.ID, "u-ssh", SignSSHRequest{PublicKey: testSSHPublicKey(t), Principals: []string{"ops"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
	caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), caPub.Marshal()) }}
	if _, err := checker.Authenticate(fakeConnMeta("ops"), parsed.(*ssh.Certificate)); err != nil {
		t.Fatalf("HSM-signed certificate: %v", err)
	}
	if len(kc.usages) == 0 || kc.usages[len(kc.usages)-1] != "certificate-sign" {
		t.Fatalf("usages %v", kc.usages)
	}
}

// The same on Postgres (CI integration-postgres): migration 017, a
// revocation read back as revoked, the KRL listing it, a second revoke
// refused.
func TestSSHRevocationPostgres(t *testing.T) {
	conn := postgresTestDB(t)
	svc := NewService(NewSQLStore(conn), nopCertPublisher{}, NoopKeyCoreSigner{}, []byte("0123456789ABCDEF0123456789ABCDEF"), false, false)
	ctx := context.Background()
	ca, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "pg", AllowedPrincipals: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateSSHCA(ctx, "t1", "u-ssh", CreateSSHCARequest{Name: "pg", AllowedPrincipals: []string{"*"}}); err == nil {
		t.Fatal("a second CA with the same name was created")
	}
	rec, _, err := svc.SignSSH(ctx, "t1", ca.ID, "u-ssh", SignSSHRequest{PublicKey: testSSHPublicKey(t), Principals: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.RevokeSSHCertificate(ctx, "t1", rec.ID, "u-ssh", "test")
	if err != nil || got.RevokedAt == nil || got.RevokeReason != "test" {
		t.Fatalf("revoke: %+v %v", got, err)
	}
	if _, err := svc.RevokeSSHCertificate(ctx, "t1", rec.ID, "u-ssh", ""); err == nil {
		t.Fatal("revoked twice")
	}
	if _, n, err := svc.sshKRL(ctx, ca, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("krl: %d %v", n, err)
	}
	if !got.ValidBefore.After(got.ValidAfter) || got.IssuedAt.IsZero() {
		t.Fatalf("times: %+v", got)
	}
}
