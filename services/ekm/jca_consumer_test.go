package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Java JCA provider (services/jca-provider) driven by a real JCA
// consumer: ConsumerCheck registers it with java.security, gets
// Cipher.VectaKeyWrap through javax.crypto, and wraps and unwraps an AES key
// through this ekm API over TLS 1.3.
//
// Needs javac on PATH. The consumer runs on the java on PATH, or in the
// Docker image VECTA_TEST_JDK_IMAGE (for example eclipse-temurin:17-jdk).
// Oracle JDK only loads JCE providers signed with an Oracle JCE code-signing
// certificate, so on Oracle JDK the test skips: use an OpenJDK build.
func TestJCAProviderWithRealJCAConsumer(t *testing.T) {
	skip := t.Skip
	if os.Getenv("VECTA_REQUIRE_JDK") == "1" { // CI: a missing JDK is a failure, not a skip
		skip = t.Fatal
	}
	javac, errc := exec.LookPath("javac")
	if errc != nil {
		skip("needs a JDK (javac on PATH)")
	}
	image := strings.TrimSpace(os.Getenv("VECTA_TEST_JDK_IMAGE"))
	h, svc, _, pub := newEKMHandler(t)
	key, err := svc.CreateTDEKey(context.Background(), CreateTDEKeyRequest{TenantID: "t1", Name: "jca-consumer"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	baseURL := srv.URL
	if image != "" {
		// The container reaches this host as example.com, a name the test
		// server's certificate carries.
		baseURL = strings.Replace(srv.URL, "127.0.0.1", "example.com", 1)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var sources []string
	if err := filepath.WalkDir("../jca-provider/src", func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".java") {
			sources = append(sources, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	classes := filepath.Join(dir, "classes")
	if out, err := exec.Command(javac, append([]string{"-Xlint:all", "-Werror", "-d", classes}, sources...)...).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, out)
	}

	consumer := func(base, token string, withCA bool) ([]byte, error) {
		env := []string{"VECTA_BASE_URL=" + base, "VECTA_TENANT_ID=t1", "VECTA_AUTH_TOKEN=" + token}
		if image == "" {
			java, err := exec.LookPath("java")
			if err != nil {
				skip("needs java on PATH or VECTA_TEST_JDK_IMAGE")
			}
			cmd := exec.Command(java, "-cp", classes, "com.vecta.kms.ConsumerCheck", key.ID)
			if withCA {
				env = append(env, "VECTA_CA_CERT="+caFile)
			}
			cmd.Env = append(os.Environ(), env...)
			return cmd.CombinedOutput()
		}
		args := []string{"run", "--rm", "--add-host", "example.com:host-gateway", "-v", classes + ":/classes:ro", "-v", caFile + ":/ca.pem:ro"}
		if withCA {
			env = append(env, "VECTA_CA_CERT=/ca.pem")
		}
		for _, e := range env {
			args = append(args, "-e", e)
		}
		args = append(args, image, "java", "-cp", "/classes", "com.vecta.kms.ConsumerCheck", key.ID)
		return exec.Command("docker", args...).CombinedOutput()
	}

	out, err := consumer(baseURL, "jwt:t1:admin", true)
	if strings.Contains(string(out), "JCE cannot authenticate the provider") {
		skip("this is Oracle JDK, which needs an Oracle-signed JCE provider jar; run with an OpenJDK (VECTA_TEST_JDK_IMAGE=eclipse-temurin:17-jdk)")
	}
	if err != nil || !strings.Contains(string(out), "OK") {
		t.Fatalf("JCA consumer failed: %v\n%s", err, out)
	}
	// The wrap and unwrap were real ekm operations, audited as such.
	if n := pub.Count("audit.ekm.tde_key_accessed"); n < 2 {
		t.Fatalf("wrap and unwrap not audited: %d tde_key_accessed events", n)
	}

	// Without a valid token the provider gets nothing.
	if out, err := consumer(baseURL, "forged", true); err == nil || strings.Contains(string(out), "OK") {
		t.Fatalf("consumer succeeded with a forged token:\n%s", out)
	}
	// A server the configured CA did not issue is not trusted.
	if out, err := consumer(baseURL, "jwt:t1:admin", false); err == nil || strings.Contains(string(out), "OK") {
		t.Fatalf("consumer trusted an unknown server certificate:\n%s", out)
	}
	// Plain HTTP is refused before any request is made.
	if out, err := consumer(strings.Replace(baseURL, "https://", "http://", 1), "jwt:t1:admin", true); err == nil || !strings.Contains(string(out), "https://") {
		t.Fatalf("consumer ran over plain HTTP:\n%s", out)
	}
}

// The SDK download is the provider source built into the binary, file for
// file: no Java written anywhere else.
func TestSDKDownloadIsTheProviderSource(t *testing.T) {
	svc, _, _, _ := newEKMService(t)
	art, err := svc.BuildSDKArtifact(context.Background(), "t1", "jca", "all")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(art.Content)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		inZip, _ := io.ReadAll(rc)
		_ = rc.Close()
		onDisk, err := os.ReadFile(filepath.Join("../jca-provider", strings.TrimPrefix(f.Name, "vecta-jca-provider/")))
		if err != nil || !bytes.Equal(inZip, onDisk) {
			t.Fatalf("%s in the SDK is not the file in services/jca-provider (%v)", f.Name, err)
		}
		got[f.Name] = true
	}
	for _, want := range []string{"vecta-jca-provider/pom.xml", "vecta-jca-provider/README.md",
		"vecta-jca-provider/src/main/java/com/vecta/kms/spi/VectaKeyWrapCipherSpi.java"} {
		if !got[want] {
			t.Fatalf("SDK is missing %s: %v", want, got)
		}
	}
}
