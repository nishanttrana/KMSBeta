package svctls

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// enrolledWithPolicy enrols identity with policy published next to the
// trust file; policy changes are captured instead of restarting the test.
func enrolledWithPolicy(t *testing.T, ca *testCA, identity string, p ServicePolicy) (*Identity, string, chan string) {
	t.Helper()
	dir := t.TempDir()
	trust := filepath.Join(dir, "internal-ca.crt")
	if err := os.WriteFile(trust, []byte(ca.pem), 0o600); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, PolicyFileName)
	writePolicy(t, policyFile, identity, p)
	changes := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	id, err := Init(ctx, identity, Options{
		Enroller: ca, TrustFile: trust, KeepDefaultTransport: true, Logger: log.New(io.Discard, "", 0),
		OnPolicyChange: func(mode string) { changes <- mode },
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, policyFile, changes
}

func writePolicy(t *testing.T, path, identity string, p ServicePolicy) {
	t.Helper()
	raw, _ := json.Marshal(PolicyFile{Version: 1, UpdatedAt: time.Now().UTC(), Services: map[string]ServicePolicy{identity: p}})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// classicalOnlyClient offers no ML-KEM group at all.
func classicalOnlyClient(caller *Identity) *tls.Config {
	cfg := caller.ClientConfig()
	cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
	return cfg
}

func hybridOnlyClient(caller *Identity) *tls.Config {
	cfg := caller.ClientConfig()
	cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
	return cfg
}

func isHybrid(id tls.CurveID) bool {
	return id == tls.X25519MLKEM768 || id == tls.SecP256r1MLKEM768 || id == tls.SecP384r1MLKEM1024
}

// "PQC required": a peer that offers no hybrid ML-KEM group is refused; every
// platform client (which offers all groups) still connects, over a hybrid.
func TestPQCRequiredServerRefusesClassicalOnlyPeers(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	keycore, _, _ := enrolledWithPolicy(t, ca, "kms-keycore", ServicePolicy{KXProfile: KXPQCRequired})
	auth := enrolled(t, ca, "kms-auth")
	_, client := mtlsServer(t, keycore)

	if _, err := client(classicalOnlyClient(auth)).Get("https://keycore/x"); err == nil {
		t.Fatal("a classical-only peer must be refused by a pqc-required server")
	}
	res, err := client(auth.ClientConfig()).Get("https://keycore/x")
	if err != nil {
		t.Fatalf("a platform client must still connect: %v", err)
	}
	res.Body.Close()
	if !isHybrid(res.TLS.CurveID) {
		t.Fatalf("negotiated %v, want a hybrid ML-KEM group", res.TLS.CurveID)
	}
	st := keycore.Status()
	if !strings.Contains(st.LastHandshakeGroup, "MLKEM") || st.LastHandshakeAt.IsZero() {
		t.Fatalf("the server must record the negotiated group: %+v", st)
	}
	for _, g := range st.ServerGroups {
		if !strings.Contains(g, "MLKEM") {
			t.Fatalf("pqc-required must accept only hybrid groups, reports %v", st.ServerGroups)
		}
	}
}

// "Classical": no ML-KEM; a hybrid-only peer is refused, platform clients
// fall back (HelloRetryRequest) to a classical group.
func TestClassicalServerRefusesHybridOnlyPeers(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	keycore, _, _ := enrolledWithPolicy(t, ca, "kms-keycore", ServicePolicy{KXProfile: KXClassical})
	auth := enrolled(t, ca, "kms-auth")
	_, client := mtlsServer(t, keycore)

	if _, err := client(hybridOnlyClient(auth)).Get("https://keycore/x"); err == nil {
		t.Fatal("a hybrid-only peer must be refused by a classical server")
	}
	res, err := client(auth.ClientConfig()).Get("https://keycore/x")
	if err != nil {
		t.Fatalf("a platform client must still connect: %v", err)
	}
	res.Body.Close()
	if isHybrid(res.TLS.CurveID) {
		t.Fatalf("classical server negotiated %v", res.TLS.CurveID)
	}
}

// The policy's key algorithm is used for the key generated at enrolment.
func TestPolicyKeyAlgorithmIsEnrolled(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	id, _, _ := enrolledWithPolicy(t, ca, "kms-keycore", ServicePolicy{KeyAlgorithm: pkgcrypto.AlgECDSAP384})
	pub, ok := id.Leaf().PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().BitSize != 384 || id.Status().KeyAlgorithm != pkgcrypto.AlgECDSAP384 {
		t.Fatalf("the certificate key must follow the policy (ECDSA P-384), got %T", id.Leaf().PublicKey)
	}
}

// A rotation (generation bump) or policy change restarts the service in the
// requested mode, not before its apply_after time.
func TestPolicyChangeTriggersRestart(t *testing.T) {
	old := policyWatchInterval
	policyWatchInterval = 50 * time.Millisecond
	t.Cleanup(func() { policyWatchInterval = old })

	ca := newTestCA(t, "vecta-internal-services")
	_, file, changes := enrolledWithPolicy(t, ca, "kms-keycore", ServicePolicy{Generation: 1})
	select {
	case m := <-changes:
		t.Fatalf("no change, no restart (got %s)", m)
	case <-time.After(200 * time.Millisecond):
	}
	writePolicy(t, file, "kms-keycore", ServicePolicy{Generation: 2, RestartMode: RestartForce, ApplyAfter: time.Now().Add(400 * time.Millisecond)})
	select {
	case m := <-changes:
		t.Fatalf("restarted before apply_after (%s)", m)
	case <-time.After(250 * time.Millisecond):
	}
	select {
	case m := <-changes:
		if m != RestartForce {
			t.Fatalf("restart mode %q, want force", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a rotation must restart the service")
	}
}

func TestPolicyNormalizeRefusesUnknownValues(t *testing.T) {
	for _, p := range []ServicePolicy{{KeyAlgorithm: "ML-DSA-65"}, {KXProfile: "x25519-only"}, {RestartMode: "later"}, {KeyAlgorithm: pkgcrypto.AlgRSA2048}} {
		if _, err := p.Normalize(); err == nil {
			t.Fatalf("%+v must be refused", p)
		}
	}
	if p, err := (ServicePolicy{}).Normalize(); err != nil || p != DefaultPolicy() {
		t.Fatalf("an empty entry is the default: %+v %v", p, err)
	}
}
