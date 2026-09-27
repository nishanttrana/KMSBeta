package svctls

import (
	"crypto/fips140"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Per-service mTLS policy (docs/SECURITY/INTERNAL_TLS.md, slice 3). The certs
// service publishes it in the public trust directory every service mounts,
// as PolicyFileName: which certificate key each identity uses, which TLS 1.3
// key-exchange groups its server accepts, and a generation that an
// administrator bumps to rotate the certificate. A service reads it before
// enrolling and watches it: on a change it restarts (gracefully, or at once
// when forced), and the new process enrols with a fresh key under the policy.

const (
	PolicyFileName = "mtls-policy.json"

	KXPQCRequired  = "pqc-required"  // hybrid ML-KEM groups only; classical-only peers refused
	KXPQCPreferred = "pqc-preferred" // hybrid ML-KEM first, classical accepted (default)
	KXClassical    = "classical"     // no ML-KEM

	RestartGraceful = "graceful"
	RestartForce    = "force"
)

// policyWatchInterval is how often a service re-reads its policy.
var policyWatchInterval = 15 * time.Second

// KeyAlgorithms are the certificate keys an internal identity may use: what
// Go's TLS stack can present and svctls.KeyAlgorithm accepts. ML-DSA
// certificates aren't supported by Go's TLS, so none is offered.
var KeyAlgorithms = []string{pkgcrypto.AlgECDSAP256, pkgcrypto.AlgECDSAP384, pkgcrypto.AlgRSA3072}

// KXProfiles lists the key-exchange profiles.
var KXProfiles = []string{KXPQCRequired, KXPQCPreferred, KXClassical}

// ServicePolicy is one identity's entry.
type ServicePolicy struct {
	KeyAlgorithm string    `json:"key_algorithm"`
	KXProfile    string    `json:"kx_profile"`
	Generation   int64     `json:"generation"`
	RestartMode  string    `json:"restart_mode"`
	ApplyAfter   time.Time `json:"apply_after,omitempty"`
}

// PolicyFile is the published document.
type PolicyFile struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	Services  map[string]ServicePolicy `json:"services"`
}

// DefaultPolicy is what an identity without an entry uses.
func DefaultPolicy() ServicePolicy {
	return ServicePolicy{KeyAlgorithm: pkgcrypto.AlgECDSAP256, KXProfile: KXPQCPreferred, RestartMode: RestartGraceful}
}

// Normalize fills defaults and validates an entry.
func (p ServicePolicy) Normalize() (ServicePolicy, error) {
	d := DefaultPolicy()
	if strings.TrimSpace(p.KeyAlgorithm) == "" {
		p.KeyAlgorithm = d.KeyAlgorithm
	}
	if strings.TrimSpace(p.KXProfile) == "" {
		p.KXProfile = d.KXProfile
	}
	if strings.TrimSpace(p.RestartMode) == "" {
		p.RestartMode = d.RestartMode
	}
	if !contains(KeyAlgorithms, p.KeyAlgorithm) {
		return p, fmt.Errorf("key algorithm %q is not one of %s", p.KeyAlgorithm, strings.Join(KeyAlgorithms, ", "))
	}
	if !contains(KXProfiles, p.KXProfile) {
		return p, fmt.Errorf("key-exchange profile %q is not one of %s", p.KXProfile, strings.Join(KXProfiles, ", "))
	}
	if p.RestartMode != RestartGraceful && p.RestartMode != RestartForce {
		return p, fmt.Errorf("restart mode %q is not graceful or force", p.RestartMode)
	}
	return p, nil
}

// ReadPolicy returns identity's entry from the policy file at path, or the
// default when the file or the entry is absent.
func ReadPolicy(path, identity string) (ServicePolicy, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return DefaultPolicy(), err
	}
	var f PolicyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return DefaultPolicy(), fmt.Errorf("mTLS policy %s: %w", path, err)
	}
	p, ok := f.Services[identity]
	if !ok {
		return DefaultPolicy(), nil
	}
	return p.Normalize()
}

var (
	hybridGroups   = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
	classicalFIPS  = []tls.CurveID{tls.CurveP256, tls.CurveP384}
	classicalOther = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
)

func classicalGroups() []tls.CurveID {
	// Go's TLS refuses X25519 alone whenever FIPS mode is on.
	if fips140.Enabled() {
		return classicalFIPS
	}
	return classicalOther
}

// ServerGroups are the groups a server with profile accepts, in order.
func ServerGroups(profile string) []tls.CurveID {
	switch profile {
	case KXPQCRequired:
		return append([]tls.CurveID{}, hybridGroups...)
	case KXClassical:
		return append([]tls.CurveID{}, classicalGroups()...)
	default:
		return append(append([]tls.CurveID{}, hybridGroups...), classicalGroups()...)
	}
}

// ClientGroups are offered by a client with profile. Every profile offers
// every group, only the order differs, so no choice cuts a service off from
// a server with another profile (a mismatch costs a HelloRetryRequest).
func ClientGroups(profile string) []tls.CurveID {
	if profile == KXClassical {
		return append(append([]tls.CurveID{}, classicalGroups()...), hybridGroups...)
	}
	return append(append([]tls.CurveID{}, hybridGroups...), classicalGroups()...)
}

// GroupName is the IANA-style name of a TLS group.
func GroupName(id tls.CurveID) string {
	if id == 0 {
		return ""
	}
	return id.String()
}

// Status is what a running service reports about its internal mTLS.
type Status struct {
	Identity           string    `json:"identity"`
	Serial             string    `json:"serial"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KXProfile          string    `json:"kx_profile"`
	ServerGroups       []string  `json:"server_groups"`
	Generation         int64     `json:"generation"`
	StartedAt          time.Time `json:"started_at"`
	LastHandshakeGroup string    `json:"last_handshake_group,omitempty"`
	LastHandshakeAt    time.Time `json:"last_handshake_at,omitempty"`
}

type handshake struct {
	group tls.CurveID
	at    time.Time
}

// Status returns the live state of this identity.
func (id *Identity) Status() Status {
	s := Status{
		Identity: id.Name, KeyAlgorithm: id.Algorithm, KXProfile: id.policy.KXProfile,
		Generation: id.policy.Generation, StartedAt: id.started,
	}
	for _, g := range ServerGroups(id.policy.KXProfile) {
		s.ServerGroups = append(s.ServerGroups, GroupName(g))
	}
	if leaf := id.Leaf(); leaf != nil {
		s.Serial, s.NotAfter = leaf.SerialNumber.Text(16), leaf.NotAfter
	}
	if h := id.lastHandshake.Load(); h != nil {
		s.LastHandshakeGroup, s.LastHandshakeAt = GroupName(h.group), h.at
	}
	return s
}

// Policy returns the policy this process applied at start.
func (id *Identity) Policy() ServicePolicy { return id.policy }

func (id *Identity) recordHandshake(cs tls.ConnectionState) error {
	id.lastHandshake.Store(&handshake{group: cs.CurveID, at: time.Now().UTC()})
	return nil
}

// policyChanged reports whether next asks this process to restart.
func policyChanged(applied, next ServicePolicy) bool {
	return next.Generation != applied.Generation || next.KeyAlgorithm != applied.KeyAlgorithm || next.KXProfile != applied.KXProfile
}

// watchPolicy restarts the process when its policy changes: SIGTERM for a
// graceful restart (the service drains and the supervisor starts it again),
// an immediate exit when forced. The restarted process reads the new policy
// and enrols with a fresh key.
func (id *Identity) watchPolicy(stop <-chan struct{}, onChange func(mode string)) {
	t := time.NewTicker(policyWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		next, err := ReadPolicy(id.policyFile, id.Name)
		if err != nil || !policyChanged(id.policy, next) {
			continue
		}
		if wait := time.Until(next.ApplyAfter); wait > 0 {
			id.logger.Printf("mTLS policy for %s changed (generation %d); applying in %s", id.Name, next.Generation, wait.Round(time.Second))
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			if again, err := ReadPolicy(id.policyFile, id.Name); err != nil || !policyChanged(id.policy, again) {
				continue
			} else {
				next = again
			}
		}
		id.logger.Printf("mTLS policy for %s changed (generation %d -> %d, %s, %s): %s restart", id.Name,
			id.policy.Generation, next.Generation, next.KeyAlgorithm, next.KXProfile, next.RestartMode)
		onChange(next.RestartMode)
		return
	}
}

// restartSelf is the default policy-change action.
func restartSelf(mode string) {
	if mode == RestartForce {
		// Forced: no drain. The supervisor's restart policy brings it back.
		os.Exit(75)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
