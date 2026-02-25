package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

func (s *Service) BuildFieldEncryptionWrapperSDKArtifact(ctx context.Context, tenantID string, targetOS string) (FieldEncryptionSDKArtifact, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetOS = normalizeWrapperSDKTargetOS(targetOS)
	if tenantID == "" {
		return FieldEncryptionSDKArtifact{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if targetOS == "" {
		targetOS = "linux"
	}
	payload, filename, err := buildFieldEncryptionWrapperArchive(targetOS)
	if err != nil {
		return FieldEncryptionSDKArtifact{}, err
	}
	sum := sha256.Sum256(payload)
	out := FieldEncryptionSDKArtifact{
		TargetOS:    targetOS,
		Filename:    filename,
		ContentType: "application/zip",
		Encoding:    "base64",
		Content:     base64.StdEncoding.EncodeToString(payload),
		SizeBytes:   len(payload),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.sdk_downloaded", tenantID, map[string]interface{}{
		"target_os":  targetOS,
		"filename":   filename,
		"size_bytes": len(payload),
		"sha256":     out.SHA256,
	})
	return out, nil
}

func normalizeWrapperSDKTargetOS(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "linux":
		return "linux"
	case "windows", "win":
		return "windows"
	case "macos", "darwin", "mac":
		return "macos"
	default:
		return ""
	}
}

func buildFieldEncryptionWrapperArchive(targetOS string) ([]byte, string, error) {
	files := map[string]string{
		"README.md":                        wrapperSDKReadme(targetOS),
		"config/vecta-wrapper.env.example": wrapperSDKEnvExample(),
		"java/src/main/java/com/vecta/fieldencryption/NativeKeyCache.java":         wrapperSDKJavaNativeBridge(),
		"java/src/main/java/com/vecta/fieldencryption/FieldEncryptionRuntime.java": wrapperSDKJavaRuntime(),
		"native/vecta_field_native.c":                                              wrapperSDKNativeC(),
		"scripts/build-linux.sh":                                                   wrapperSDKBuildLinux(),
		"scripts/build-windows.ps1":                                                wrapperSDKBuildWindows(),
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, content := range files {
		w, err := zw.Create(path)
		if err != nil {
			return nil, "", err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), fmt.Sprintf("vecta-field-encryption-wrapper-sdk-%s.zip", targetOS), nil
}

func wrapperSDKReadme(targetOS string) string {
	const readmeTemplate = `# Vecta Field Encryption Wrapper SDK (%s)

This package contains a JDBC/runtime wrapper pattern for local field crypto with KMS policy fallback.

## Security model
- Wrapper must register via challenge/response (/field-encryption/register/init -> /field-encryption/register/complete).
- Registration completion returns:
  - scoped JWT profile (short lived),
  - optional signed client certificate from CSR,
  - immutable wrapper binding (tenant/app/keys/fingerprint).
- Local key material is only from lease package (/field-encryption/leases) and must be submitted as signed usage receipts (/field-encryption/receipts).

## Runtime behavior
- cache_enabled=false: wrapper must use remote KMS crypto path.
- cache_enabled=true: wrapper can execute local crypto using leased wrapped keys.
- Forbidden operations/policies must hard-fallback to remote KMS API.

## Native memory hardening module
- NativeKeyCache.hardenProcess():
  - disables core dumps (best effort),
  - marks process as non-dumpable on Linux (best effort).
- NativeKeyCache.lock(...):
  - Linux: mlock
  - Windows: VirtualLock
- Memory is explicitly zeroized and unlocked on key eviction.

## Build
- Linux/macOS: scripts/build-linux.sh
- Windows: scripts/build-windows.ps1

## Integration steps
1. Generate wrapper signing/encryption keys locally.
2. Call register init endpoint with wrapper metadata + public keys.
3. Sign challenge with wrapper private signing key.
4. Optionally provide CSR during complete registration for mTLS cert issuance.
5. Use returned JWT profile and lease package APIs for local runtime.
6. Submit signed usage receipts to maintain lease validity.
`
	return fmt.Sprintf(readmeTemplate, strings.ToUpper(targetOS))
}

func wrapperSDKEnvExample() string {
	return `VECTA_BASE_URL=https://kms.example.com/svc/dataprotect
VECTA_TENANT_ID=root
VECTA_WRAPPER_ID=wrapper-prod-01
VECTA_APP_ID=payments-api
VECTA_WRAPPER_JWT=<issued_during_registration>
VECTA_TLS_CERT=wrapper.crt.pem
VECTA_TLS_KEY=wrapper.key.pem
`
}

func wrapperSDKJavaNativeBridge() string {
	return `package com.vecta.fieldencryption;

public final class NativeKeyCache {
  static {
    try {
      System.loadLibrary("vecta_field_native");
    } catch (UnsatisfiedLinkError ignored) {
    }
  }

  private NativeKeyCache() {}

  public static native int hardenProcess();
  public static native int lockMemory(byte[] keyMaterial);
  public static native int unlockMemory(byte[] keyMaterial);
  public static native void zeroize(byte[] keyMaterial);
}
`
}

func wrapperSDKJavaRuntime() string {
	return `package com.vecta.fieldencryption;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public final class FieldEncryptionRuntime {
  private static final SecureRandom RNG = new SecureRandom();

  // Local encrypt path: use only when lease + policy permit local crypto.
  public static Map<String, String> encryptLocal(byte[] leasedKey, String plaintext, String aad) throws Exception {
    NativeKeyCache.hardenProcess();
    NativeKeyCache.lockMemory(leasedKey);
    try {
      byte[] iv = new byte[12];
      RNG.nextBytes(iv);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(leasedKey, "AES"), new GCMParameterSpec(128, iv));
      if (aad != null && !aad.isEmpty()) {
        cipher.updateAAD(aad.getBytes("UTF-8"));
      }
      byte[] out = cipher.doFinal(plaintext.getBytes("UTF-8"));
      return Map.of(
        "alg", "AES-GCM",
        "iv_b64", Base64.getEncoder().encodeToString(iv),
        "ct_b64", Base64.getEncoder().encodeToString(out)
      );
    } finally {
      NativeKeyCache.zeroize(leasedKey);
      NativeKeyCache.unlockMemory(leasedKey);
    }
  }

  // For policy-denied operations, wrappers must call remote KMS endpoints.
  public static boolean requiresRemoteFallback(boolean cacheEnabled, boolean localAllowed) {
    return !cacheEnabled || !localAllowed;
  }
}
`
}

func wrapperSDKNativeC() string {
	return `#include <jni.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#endif

static void wipe(uint8_t *p, size_t n) {
  if (!p || n == 0) return;
  volatile uint8_t *v = (volatile uint8_t*)p;
  while (n--) {
    *v++ = 0;
  }
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_hardenProcess
  (JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
#if defined(_WIN32)
  return 0;
#else
  struct rlimit lim;
  lim.rlim_cur = 0;
  lim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &lim); // best effort
#if defined(__linux__)
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); // best effort
#endif
  return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_lockMemory
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return -1;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return -2;
  jsize n = (*env)->GetArrayLength(env, arr);
#if defined(_WIN32)
  BOOL ok = VirtualLock((LPVOID)p, (SIZE_T)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return ok ? 0 : -3;
#else
  int rc = mlock((const void*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return rc == 0 ? 0 : -3;
#endif
}

JNIEXPORT jint JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_unlockMemory
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return -1;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return -2;
  jsize n = (*env)->GetArrayLength(env, arr);
#if defined(_WIN32)
  BOOL ok = VirtualUnlock((LPVOID)p, (SIZE_T)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return ok ? 0 : -3;
#else
  int rc = munlock((const void*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
  return rc == 0 ? 0 : -3;
#endif
}

JNIEXPORT void JNICALL Java_com_vecta_fieldencryption_NativeKeyCache_zeroize
  (JNIEnv *env, jclass cls, jbyteArray arr) {
  (void)cls;
  if (!arr) return;
  jbyte *p = (*env)->GetByteArrayElements(env, arr, NULL);
  if (!p) return;
  jsize n = (*env)->GetArrayLength(env, arr);
  wipe((uint8_t*)p, (size_t)n);
  (*env)->ReleaseByteArrayElements(env, arr, p, 0);
}
`
}

func wrapperSDKBuildLinux() string {
	return `#!/usr/bin/env bash
set -euo pipefail
JAVA_HOME="${JAVA_HOME:-}"
if [[ -z "${JAVA_HOME}" ]]; then
  echo "JAVA_HOME is required"
  exit 1
fi
mkdir -p native/build
cc -O2 -fPIC -shared \
  -I"${JAVA_HOME}/include" \
  -I"${JAVA_HOME}/include/linux" \
  native/vecta_field_native.c \
  -o native/build/libvecta_field_native.so
echo "Built native/build/libvecta_field_native.so"
`
}

func wrapperSDKBuildWindows() string {
	newline := "\r\n"
	lines := []string{
		"$ErrorActionPreference = \"Stop\"",
		"if (-not $env:JAVA_HOME) {",
		"  throw \"JAVA_HOME is required\"",
		"}",
		"New-Item -ItemType Directory -Force -Path native\\build | Out-Null",
		"cl /LD /O2 /I\"$env:JAVA_HOME\\include\" /I\"$env:JAVA_HOME\\include\\win32\" native\\vecta_field_native.c /Fe:native\\build\\vecta_field_native.dll",
		"Write-Host \"Built native\\build\\vecta_field_native.dll\"",
	}
	return strings.Join(lines, newline) + newline
}
