package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func TestNormalizeWrapperSDKTargetOS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{in: "linux", want: "linux"},
		{in: "LINUX", want: "linux"},
		{in: " win ", want: "windows"},
		{in: "windows", want: "windows"},
		{in: "darwin", want: "macos"},
		{in: "mac", want: "macos"},
		{in: "macos", want: "macos"},
		{in: "solaris", want: ""},
		{in: "", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := normalizeWrapperSDKTargetOS(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeWrapperSDKTargetOS(%q)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBuildFieldEncryptionWrapperArchive_TargetScripts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		targetOS      string
		expectedPath  string
		expectedBuild string
		expectedHint  string
	}{
		{
			targetOS:      "linux",
			expectedPath:  "scripts/build-linux.sh",
			expectedBuild: "include/linux",
			expectedHint:  "scripts/build-linux.sh",
		},
		{
			targetOS:      "windows",
			expectedPath:  "scripts/build-windows.ps1",
			expectedBuild: "include\\win32",
			expectedHint:  "scripts/build-windows.ps1",
		},
		{
			targetOS:      "macos",
			expectedPath:  "scripts/build-macos.sh",
			expectedBuild: "include/darwin",
			expectedHint:  "scripts/build-macos.sh",
		},
	}
	commonFiles := []string{
		"README.md",
		"config/vecta-wrapper.env.example",
		"java/pom.xml",
		"java/src/main/java/com/vecta/fieldencryption/NativeKeyCache.java",
		"java/src/main/java/com/vecta/fieldencryption/FieldEncryptionRuntime.java",
		"java/src/main/java/com/vecta/fieldencryption/FieldPolicy.java",
		"java/src/main/java/com/vecta/fieldencryption/FieldProtectionRule.java",
		"java/src/main/java/com/vecta/fieldencryption/FieldProtectionBundle.java",
		"java/src/main/java/com/vecta/fieldencryption/LeaseContext.java",
		"java/src/main/java/com/vecta/fieldencryption/RuntimeContext.java",
		"java/src/main/java/com/vecta/fieldencryption/PolicyResolverClient.java",
		"java/src/main/java/com/vecta/fieldencryption/HttpPolicyResolverClient.java",
		"java/src/main/java/com/vecta/fieldencryption/PolicyBundleCache.java",
		"java/src/main/java/com/vecta/fieldencryption/PolicyAwareRuntimeContext.java",
		"java/src/main/java/com/vecta/fieldencryption/JdbcFieldEncryptionInterceptor.java",
		"native/vecta_field_native.c",
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.targetOS, func(t *testing.T) {
			t.Parallel()
			payload, filename, err := buildFieldEncryptionWrapperArchive(tc.targetOS)
			if err != nil {
				t.Fatalf("buildFieldEncryptionWrapperArchive(%q): %v", tc.targetOS, err)
			}
			if !strings.Contains(filename, tc.targetOS) {
				t.Fatalf("filename %q does not include target %q", filename, tc.targetOS)
			}
			files := unzipArchiveFiles(t, payload)
			for _, path := range commonFiles {
				if _, ok := files[path]; !ok {
					t.Fatalf("archive missing file %q", path)
				}
			}
			script, ok := files[tc.expectedPath]
			if !ok {
				t.Fatalf("archive missing build script %q", tc.expectedPath)
			}
			if !strings.Contains(script, tc.expectedBuild) {
				t.Fatalf("script %q missing marker %q", tc.expectedPath, tc.expectedBuild)
			}
			if !strings.Contains(files["README.md"], tc.expectedHint) {
				t.Fatalf("README does not include build hint %q", tc.expectedHint)
			}
			if !strings.Contains(files["README.md"], "mvn -f java/pom.xml -DskipTests package") {
				t.Fatalf("README does not include maven build command")
			}
			if !strings.Contains(files["java/pom.xml"], "<artifactId>vecta-jdbc-protect</artifactId>") {
				t.Fatalf("pom.xml does not include vecta-jdbc-protect artifact id")
			}
		})
	}
}

func TestBuildFieldEncryptionWrapperArchive_DeterministicOutput(t *testing.T) {
	t.Parallel()
	first, _, err := buildFieldEncryptionWrapperArchive("linux")
	if err != nil {
		t.Fatalf("first build failed: %v", err)
	}
	second, _, err := buildFieldEncryptionWrapperArchive("linux")
	if err != nil {
		t.Fatalf("second build failed: %v", err)
	}
	sumFirst := sha256.Sum256(first)
	sumSecond := sha256.Sum256(second)
	if sumFirst != sumSecond {
		t.Fatalf(
			"archive output is non-deterministic: %s vs %s",
			hex.EncodeToString(sumFirst[:]),
			hex.EncodeToString(sumSecond[:]),
		)
	}
}

func TestBuildFieldEncryptionWrapperSDKArtifact_ServiceBehavior(t *testing.T) {
	t.Parallel()
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()

	out, err := svc.BuildFieldEncryptionWrapperSDKArtifact(ctx, "tenant-sdk", "")
	if err != nil {
		t.Fatalf("BuildFieldEncryptionWrapperSDKArtifact: %v", err)
	}
	if out.TargetOS != "linux" {
		t.Fatalf("default target os=%q want=linux", out.TargetOS)
	}
	if out.Filename == "" || !strings.Contains(out.Filename, "linux") {
		t.Fatalf("unexpected filename: %q", out.Filename)
	}
	if out.Encoding != "base64" {
		t.Fatalf("unexpected encoding: %q", out.Encoding)
	}
	if out.ContentType != "application/zip" {
		t.Fatalf("unexpected content type: %q", out.ContentType)
	}
	if strings.TrimSpace(out.Content) == "" || out.SizeBytes <= 0 || strings.TrimSpace(out.SHA256) == "" {
		t.Fatalf("incomplete artifact metadata: %+v", out)
	}
	if pub.Count("audit.dataprotect.field_encryption.sdk_downloaded") == 0 {
		t.Fatalf("expected sdk download audit event")
	}

	if _, err := svc.BuildFieldEncryptionWrapperSDKArtifact(ctx, "", "linux"); err == nil {
		t.Fatal("expected tenant validation error")
	}
}

func unzipArchiveFiles(t *testing.T, payload []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	out := make(map[string]string, len(zr.File))
	for _, file := range zr.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open zip member %q: %v", file.Name, err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read zip member %q: %v", file.Name, err)
		}
		out[file.Name] = string(body)
	}
	return out
}
