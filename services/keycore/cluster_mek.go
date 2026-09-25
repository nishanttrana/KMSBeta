package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"vecta-kms/pkg/crypto"
)

// Cluster master-key transfer (docs/CLUSTERING.md, slice 2).
//
// Replicated key material is encrypted under the primary's master key (MEK),
// so a joining member needs that MEK. The plaintext MEK never leaves a keycore
// process: the member's keycore creates a one-time ML-KEM-768 join key, the
// primary's keycore seals its MEK to it (pkg/crypto.KEMSeal, bound to the join
// context), and the member's keycore opens it, stores it on its own data
// volume and restarts on it. Only the cluster-manager service identity may
// call these operations; every step is audited.

const (
	clusterMEKLabel    = "keycore-mek"
	clusterJoinKeyTTL  = 10 * time.Minute
	clusterManagerID   = "kms-cluster-manager"
	defaultClusterFile = "/app/data/cluster-mek.b64"
)

var (
	errClusterCaller      = errors.New("cluster master-key operations are restricted to the cluster-manager service identity")
	errClusterJoinKey     = errors.New("unknown or expired cluster join key")
	errClusterMEKMismatch = errors.New("received master key does not match the expected fingerprint")
	errClusterHasKeys     = errors.New("this node already holds keys; importing a cluster master key would make them unreadable (confirm_replace is required)")
)

type clusterJoinKey struct {
	recipient *crypto.KEMRecipient
	expires   time.Time
}

type clusterMEKState struct {
	mu      sync.Mutex
	pending map[string]clusterJoinKey
}

// MEKFingerprint identifies a master key without revealing it.
func MEKFingerprint(mek []byte) string {
	sum := sha256.Sum256(append([]byte("vecta-mek-fingerprint|"), mek...))
	return hex.EncodeToString(sum[:8])
}

func clusterMEKFile() string {
	if p := strings.TrimSpace(os.Getenv("KEYCORE_CLUSTER_MEK_FILE")); p != "" {
		return p
	}
	return defaultClusterFile
}

func (s *Service) requireClusterManager(ctx context.Context) error {
	actor := accessActorFromContext(ctx)
	if !actorIsServicePrincipal(actor) || actor.ClientID != clusterManagerID {
		return errClusterCaller
	}
	return nil
}

// CreateClusterJoinKey (member) returns a one-time ML-KEM encapsulation key.
func (s *Service) CreateClusterJoinKey(ctx context.Context) (string, string, error) {
	if err := s.requireClusterManager(ctx); err != nil {
		return "", "", err
	}
	r, err := crypto.NewKEMRecipient()
	if err != nil {
		return "", "", err
	}
	id := newID("cjk")
	s.clusterMEK.mu.Lock()
	if s.clusterMEK.pending == nil {
		s.clusterMEK.pending = map[string]clusterJoinKey{}
	}
	now := time.Now()
	for k, v := range s.clusterMEK.pending {
		if now.After(v.expires) {
			delete(s.clusterMEK.pending, k)
		}
	}
	s.clusterMEK.pending[id] = clusterJoinKey{recipient: r, expires: now.Add(clusterJoinKeyTTL)}
	s.clusterMEK.mu.Unlock()
	_ = s.publishAudit(ctx, "audit.key.cluster_join_key_created", "root", map[string]any{
		"join_key_id": id, "expires_in_s": int(clusterJoinKeyTTL.Seconds()), "severity": "info",
	})
	return id, base64.StdEncoding.EncodeToString(r.EncapsulationKey()), nil
}

// ExportClusterMEK (primary) seals this node's MEK to a joining member.
func (s *Service) ExportClusterMEK(ctx context.Context, encapsulationKeyB64, context_, memberNodeID string) (string, string, error) {
	if err := s.requireClusterManager(ctx); err != nil {
		return "", "", err
	}
	ek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encapsulationKeyB64))
	if err != nil {
		return "", "", errors.New("encapsulation_key must be base64")
	}
	if strings.TrimSpace(context_) == "" || strings.TrimSpace(memberNodeID) == "" {
		return "", "", errors.New("context and member_node_id are required")
	}
	sealed, err := crypto.KEMSeal(ek, s.mek, []byte(context_), clusterMEKLabel)
	if err != nil {
		return "", "", err
	}
	fp := MEKFingerprint(s.mek)
	_ = s.publishAudit(ctx, "audit.key.cluster_mek_exported", "root", map[string]any{
		"member_node_id": memberNodeID, "context": context_, "mek_fingerprint": fp,
		"severity": "critical", "result": "success",
		"description": "master key sealed (ML-KEM-768) to a joining cluster member",
	})
	return base64.StdEncoding.EncodeToString(sealed), fp, nil
}

// ImportClusterMEK (member) opens the primary's MEK, stores it and restarts
// keycore on it. confirmReplace acknowledges that keys this node created
// before joining become unreadable (the join replaces them with the primary's).
func (s *Service) ImportClusterMEK(ctx context.Context, joinKeyID, sealedB64, context_, expectedFingerprint string, confirmReplace bool) error {
	if err := s.requireClusterManager(ctx); err != nil {
		return err
	}
	s.clusterMEK.mu.Lock()
	jk, ok := s.clusterMEK.pending[joinKeyID]
	delete(s.clusterMEK.pending, joinKeyID) // one use, success or not
	s.clusterMEK.mu.Unlock()
	if !ok || time.Now().After(jk.expires) {
		return errClusterJoinKey
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealedB64))
	if err != nil {
		return errors.New("sealed_mek must be base64")
	}
	mek, err := jk.recipient.Open(sealed, []byte(context_), clusterMEKLabel)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(mek)
	if len(mek) != 32 || MEKFingerprint(mek) != strings.TrimSpace(expectedFingerprint) {
		return errClusterMEKMismatch
	}
	if !confirmReplace {
		n, err := s.store.CountKeys(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return errClusterHasKeys
		}
	}
	path := clusterMEKFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(mek)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.cluster_mek_imported", "root", map[string]any{
		"context": context_, "mek_fingerprint": MEKFingerprint(mek), "replaced_local_keys": confirmReplace,
		"severity": "critical", "result": "success",
		"description": "cluster master key installed; keycore restarts to use it",
	})
	// Restart on the new MEK: graceful shutdown, then the supervisor starts
	// keycore again and loadMEK picks up the cluster file.
	go func() {
		time.Sleep(time.Second)
		s.restartSelf()
	}()
	return nil
}

func defaultRestartSelf() { _ = syscall.Kill(os.Getpid(), syscall.SIGTERM) }
