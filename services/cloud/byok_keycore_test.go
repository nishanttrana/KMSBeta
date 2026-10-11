package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// testKeycore stands in for keycore in the cloud service's tests: it holds
// real material per key version and wraps it with pkg/crypto exactly as
// keycore's /keys/{id}/cloud-wrap does (keycore's own tests prove that
// route, its access decision and its HSM path). The cloud doubles unwrap
// what it produces with their private keys, so a test proves the bytes a
// cloud receives are the KMS version's material.
type testKeycore struct {
	mu   sync.Mutex
	keys map[string]*testKey
	// refuse makes cloud-wrap refuse as keycore would (code → status).
	refuse map[string]*keycoreError
}

type testKey struct {
	algorithm string
	exportOK  bool
	hsm       bool
	versions  [][]byte
}

func newTestKeycore() *testKeycore {
	return &testKeycore{keys: map[string]*testKey{}, refuse: map[string]*keycoreError{}}
}

// Seed adds an exportable key with one version.
func (k *testKeycore) Seed(tenantID, keyID, algorithm string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[tenantID+"/"+keyID] = &testKey{algorithm: algorithm, exportOK: true, versions: [][]byte{randomBytes(32)}}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = pkgcrypto.Reader.Read(b)
	return b
}

// material returns version v (1-based; 0 is current).
func (k *testKeycore) material(tenantID, keyID string, v int) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := k.keys[tenantID+"/"+keyID]
	if v == 0 {
		v = len(key.versions)
	}
	return key.versions[v-1]
}

func kcvOf(material []byte) string {
	block, _ := aes.NewCipher(material)
	out := make([]byte, 16)
	block.Encrypt(out, make([]byte, 16))
	return strings.ToUpper(hex.EncodeToString(out[:3]))
}

func (k *testKeycore) KeyInfo(_ context.Context, tenantID, keyID string) (map[string]interface{}, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[tenantID+"/"+keyID]
	if !ok {
		return nil, &keycoreError{Status: http.StatusNotFound, Code: "not_found", Message: "key not found"}
	}
	labels := map[string]interface{}{}
	if key.hsm {
		labels["hsm"] = "resident"
	}
	return map[string]interface{}{"id": keyID, "algorithm": key.algorithm, "export_allowed": key.exportOK,
		"purpose": "encrypt-decrypt", "labels": labels, "current_version": len(key.versions)}, nil
}

func (k *testKeycore) CloudWrap(_ context.Context, tenantID, keyID string, wrappingKey []byte, scheme string, version int, digest bool) (CloudWrapResult, []byte, []byte, error) {
	k.mu.Lock()
	if e := k.refuse[keyID]; e != nil {
		k.mu.Unlock()
		return CloudWrapResult{}, nil, nil, e
	}
	key := k.keys[tenantID+"/"+keyID]
	k.mu.Unlock()
	if !key.exportOK {
		return CloudWrapResult{}, nil, nil, &keycoreError{Status: http.StatusForbidden, Code: "export_not_allowed", Message: "export is disabled by key policy"}
	}
	material := k.material(tenantID, keyID, version)
	if version == 0 {
		version = len(key.versions)
	}
	pub, err := pkgcrypto.ParseCloudWrappingKey(wrappingKey)
	if err != nil {
		return CloudWrapResult{}, nil, nil, &keycoreError{Status: http.StatusBadRequest, Code: "bad_wrapping_key", Message: err.Error()}
	}
	wrapped, err := pkgcrypto.WrapForCloudImport(pub, material, scheme)
	if err != nil {
		return CloudWrapResult{}, nil, nil, &keycoreError{Status: http.StatusForbidden, Code: "fips_mode_violation", Message: err.Error()}
	}
	fp, _ := pkgcrypto.FingerprintPublicKey(pub)
	source := SourceKMS
	if key.hsm {
		source = SourceHSM
	}
	var sum []byte
	if digest {
		sum = pkgcrypto.SHA256(material)
	}
	return CloudWrapResult{KeyID: keyID, Version: version, Scheme: scheme, KCV: kcvOf(material), Source: source, WrappingKeySHA256: fp}, wrapped, sum, nil
}

func (k *testKeycore) RotateForBYOK(_ context.Context, tenantID, keyID, _ string) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := k.keys[tenantID+"/"+keyID]
	key.versions = append(key.versions, randomBytes(32))
	return len(key.versions), nil
}

func decodeStd(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
