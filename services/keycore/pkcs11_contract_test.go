package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The PKCS#11 module (sdk/pkcs11, 13.59.0-beta) against keycore's real
// routes, loaded as an application loads it: the C driver dlopens it and
// checks login, objects, attributes, ECDSA and RSA-PSS signing, AES-GCM
// with a caller's and with the KMS's IV, decrypting after a rotation,
// threads and fork, built with AddressSanitizer and UBSan. pkcs11-tool
// (OpenSC), where installed, signs and reads the public key on its own;
// Go then verifies that signature. VECTA_REQUIRE_PKCS11=1 (CI) makes a
// missing compiler, libcurl or pkcs11-tool a failure.
func TestPKCS11AgainstKeycore(t *testing.T) {
	require := os.Getenv("VECTA_REQUIRE_PKCS11") == "1"
	skip := func(why string) {
		t.Helper()
		if require {
			t.Fatal(why)
		}
		t.Skip(why)
	}
	for _, tool := range []string{"make", "cc", "curl-config"} {
		if _, err := exec.LookPath(tool); err != nil {
			skip(tool + " is not installed (the PKCS#11 module needs a C compiler and libcurl's development files)")
		}
	}
	dir, err := filepath.Abs("../../sdk/pkcs11")
	if err != nil {
		t.Fatal(err)
	}
	// build makes the module and the driver; with asan, under sanitizers.
	build := func(asan bool) (module, driver string) {
		t.Helper()
		mk := exec.Command("make", "-C", dir, "B="+t.TempDir(), "contract")
		if !asan {
			mk.Args = append(mk.Args, "NO_ASAN=1")
		}
		out, err := mk.CombinedOutput()
		if err != nil {
			t.Fatalf("make: %v\n%s", err, out)
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "module: "); ok {
				module = v
			}
			if v, ok := strings.CutPrefix(sc.Text(), "driver: "); ok {
				driver = v
			}
		}
		if module == "" || driver == "" {
			t.Fatalf("make named no module or driver:\n%s", out)
		}
		return module, driver
	}
	module, driver := build(os.Getenv("VECTA_PKCS11_NO_ASAN") != "1")

	rig := newSDKRig(t)
	ctx := adminCtx()
	grant := func(id string, ops ...string) {
		t.Helper()
		if err := rig.svc.store.ReplaceKeyAccessGrants(ctx, "t1", id, []KeyAccessGrant{{SubjectType: AccessSubjectClient, SubjectID: "release-pipeline", Operations: ops}}, "owner-1"); err != nil {
			t.Fatal(err)
		}
	}
	rsaKey, err := rig.svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "rsa-signer", Algorithm: "RSA-2048", KeyType: "asymmetric", Purpose: "sign", CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	grant(rsaKey.ID, "sign", "verify", "read")
	rotated, err := rig.svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "rotated", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := rig.svc.Encrypt(ctx, rotated.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte("written before rotation"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.RotateKey(ctx, "t1", rotated.ID, "scheduled", ""); err != nil {
		t.Fatal(err)
	}
	grant(rotated.ID, "encrypt", "decrypt", "read")
	ct, _ := base64.StdEncoding.DecodeString(before.CipherB64)
	iv, _ := base64.StdEncoding.DecodeString(before.IVB64)

	tmp := t.TempDir()
	ca := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(ca, rig.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	conf := func(name, body string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	digest := sha256.Sum256([]byte("release v1"))
	baseEnv := []string{
		"VECTA_URL=" + rig.srv.URL, "VECTA_TENANT_ID=t1", "VECTA_CA_FILE=" + ca, "VECTA_CLIENT_ID=",
		"VECTA_PKCS11_LOG=" + filepath.Join(tmp, "module.log"),
		"P11_PIN=client-token", "P11_BAD_PIN=someone-elses-token", "P11_TOKEN_LABEL=t1",
		"P11_EXPECT_OBJECTS=6", "P11_SIGN_ID=" + rig.signer, "P11_DIGEST_HEX=" + hex.EncodeToString(digest[:]),
		"P11_ROTATED_CT=" + hex.EncodeToString(ct), "P11_ROTATED_IV=" + hex.EncodeToString(iv),
		"P11_ROTATED_PT=written before rotation",
		"ASAN_OPTIONS=detect_leaks=0", // libcurl's process-wide state outlives C_Finalize
	}
	callerMode := "caller"
	if fips140.Enforced() {
		callerMode = "refused" // FIPS strict mode takes no caller AES-GCM IV
	}
	for _, run := range []struct{ mode, conf string }{
		{callerMode, conf("caller.conf", "# the defaults\n")},
		{"generated", conf("generated.conf", "gcm_iv = generated\n")},
	} {
		cmd := exec.Command(driver)
		cmd.Env = append(append(os.Environ(), baseEnv...), "P11_MODULE="+module, "P11_IV_MODE="+run.mode, "VECTA_PKCS11_CONF="+run.conf)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "p11check ok") {
			logs, _ := os.ReadFile(filepath.Join(tmp, "module.log"))
			if strings.Contains(string(logs), "can't require TLS 1.3") {
				// macOS's own libcurl (SecureTransport): the module refuses
				// to connect below TLS 1.3, so there is nothing to check.
				skip("this libcurl can't require TLS 1.3; build against one on OpenSSL 3 (docs/PKCS11.md)")
			}
			t.Fatalf("p11check (%s IV): %v\n%s\nmodule log:\n%s", run.mode, err, out, logs)
		}
	}

	// pkcs11-tool, the OpenSC command-line consumer: list, sign, read the
	// public key; the signature checked here, independently of the module.
	tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		if require {
			t.Fatal("pkcs11-tool is not installed")
		}
		t.Log("pkcs11-tool is not installed; skipping the OpenSC checks")
		return
	}
	plain, _ := build(false) // pkcs11-tool can't load a sanitizer build
	p11 := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(tool, append([]string{"--module", plain}, args...)...)
		cmd.Env = append(append(os.Environ(), baseEnv...), "VECTA_PKCS11_CONF="+filepath.Join(tmp, "caller.conf"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pkcs11-tool %v: %v\n%s", args, err, out)
		}
		return out
	}
	if out := p11("--list-slots"); !strings.Contains(string(out), "Vecta KMS") {
		t.Fatalf("list-slots:\n%s", out)
	}
	if out := p11("--login", "--pin", "client-token", "--list-objects"); !strings.Contains(string(out), "signer") || !strings.Contains(string(out), "rsa-signer") || !strings.Contains(string(out), "rotated") {
		t.Fatalf("list-objects:\n%s", out)
	}
	data := filepath.Join(tmp, "data.txt")
	if err := os.WriteFile(data, []byte("release v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigFile, pubFile := filepath.Join(tmp, "sig.bin"), filepath.Join(tmp, "pub.der")
	id := hex.EncodeToString([]byte(rig.signer)) // CKA_ID is the key's ID
	p11("--login", "--pin", "client-token", "--sign", "--mechanism", "ECDSA-SHA256", "--id", id, "--input-file", data, "--output-file", sigFile)
	p11("--login", "--pin", "client-token", "--read-object", "--type", "pubkey", "--id", id, "--output-file", pubFile)
	sig, _ := os.ReadFile(sigFile)
	der, _ := os.ReadFile(pubFile)
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("pkcs11-tool's public key: %v", err)
	}
	if len(sig) != 64 || !ecdsa.Verify(pk.(*ecdsa.PublicKey), digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatalf("pkcs11-tool's signature (%d bytes) doesn't verify under its public key", len(sig))
	}
}
