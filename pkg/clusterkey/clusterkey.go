// Package clusterkey moves a service's cluster-wide secret (the audit signing
// key, the certs root wrapping key) from a primary to a joining member
// (docs/CLUSTERING.md). The plaintext secret never leaves the owning service:
//
//  1. the member's service creates a one-time ML-KEM-768 join key (JoinKeys.Create);
//  2. the primary's service seals its secret to it (Seal), bound to the join
//     context and a per-secret label;
//  3. the member's service opens it once (JoinKeys.Open) and checks the
//     fingerprint the primary reported.
//
// Only the cluster-manager service identity may drive these steps (Caller).
// keycore's master-key transfer (services/keycore/cluster_mek.go) predates
// this package and follows the same protocol.
package clusterkey

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/tenantcheck"
)

const (
	JoinKeyTTL      = 10 * time.Minute
	ClusterManager  = "kms-cluster-manager"
	fingerprintSalt = "vecta-cluster-secret-fingerprint|"
)

var (
	ErrCaller      = errors.New("cluster key transfer is restricted to the cluster-manager service identity")
	ErrJoinKey     = errors.New("unknown or expired cluster join key")
	ErrFingerprint = errors.New("received secret does not match the expected fingerprint")
)

// Caller reports whether claims belong to the cluster-manager service identity.
func Caller(claims *pkgauth.Claims) error {
	if !tenantcheck.IsServicePrincipal(claims) || claims.ClientID != ClusterManager {
		return ErrCaller
	}
	return nil
}

// Fingerprint identifies a secret without revealing it: HMAC-SHA256 keyed by
// the secret over a per-label constant, truncated to 64 bits.
func Fingerprint(label string, secret []byte) string {
	mac, err := crypto.HMAC("SHA-256", secret, []byte(fingerprintSalt+label))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(mac[:8])
}

type pending struct {
	recipient *crypto.KEMRecipient
	expires   time.Time
}

// JoinKeys holds a service's outstanding one-time join keys (in memory: a
// restart during a join simply makes the member ask again).
type JoinKeys struct {
	mu   sync.Mutex
	keys map[string]pending
}

// Create returns a new join key id and its base64 ML-KEM encapsulation key.
func (j *JoinKeys) Create() (string, string, error) {
	r, err := crypto.NewKEMRecipient()
	if err != nil {
		return "", "", err
	}
	raw, err := crypto.RandomBytes(12)
	if err != nil {
		return "", "", err
	}
	id := "cjk_" + hex.EncodeToString(raw)
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.keys == nil {
		j.keys = map[string]pending{}
	}
	for k, v := range j.keys {
		if now.After(v.expires) {
			delete(j.keys, k)
		}
	}
	j.keys[id] = pending{recipient: r, expires: now.Add(JoinKeyTTL)}
	return id, base64.StdEncoding.EncodeToString(r.EncapsulationKey()), nil
}

// Open consumes a join key (one use, success or not) and opens the sealed
// secret, which must match fingerprint.
func (j *JoinKeys) Open(id, sealedB64, context_, label, fingerprint string) ([]byte, error) {
	j.mu.Lock()
	p, ok := j.keys[id]
	delete(j.keys, id)
	j.mu.Unlock()
	if !ok || time.Now().After(p.expires) {
		return nil, ErrJoinKey
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealedB64))
	if err != nil {
		return nil, errors.New("sealed secret must be base64")
	}
	secret, err := p.recipient.Open(sealed, []byte(context_), label)
	if err != nil {
		return nil, err
	}
	if Fingerprint(label, secret) != strings.TrimSpace(fingerprint) {
		crypto.Zeroize(secret)
		return nil, ErrFingerprint
	}
	return secret, nil
}

// Seal seals secret to a member's base64 encapsulation key and returns the
// sealed blob and the secret's fingerprint.
func Seal(encapsulationKeyB64 string, secret []byte, context_, label string) (string, string, error) {
	ek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encapsulationKeyB64))
	if err != nil {
		return "", "", errors.New("encapsulation_key must be base64")
	}
	if strings.TrimSpace(context_) == "" {
		return "", "", errors.New("context is required")
	}
	sealed, err := crypto.KEMSeal(ek, secret, []byte(context_), label)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), Fingerprint(label, secret), nil
}

// WriteFileAtomic writes data with mode 0600, replacing path atomically.
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
