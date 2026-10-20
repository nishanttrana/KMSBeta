package tlsreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, dir, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
}

func served(t *testing.T, r *Reloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	return leaf.Subject.CommonName
}

// A replaced certificate is served on the next handshake after the check
// interval; a replacement that doesn't load keeps the one in force.
func TestReloaderPicksUpAReplacementAndKeepsAGoodOne(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "first")
	r := &Reloader{CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), Name: "test certificate", Logf: t.Logf}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	if got := served(t, r); got != "first" {
		t.Fatalf("served %q", got)
	}
	time.Sleep(10 * time.Millisecond)
	writePair(t, dir, "second")
	r.checked = time.Time{}
	if got := served(t, r); got != "second" {
		t.Fatalf("after replacement served %q", got)
	}
	_ = os.WriteFile(filepath.Join(dir, "tls.key"), []byte("not a key"), 0o600)
	r.checked = time.Time{}
	if got := served(t, r); got != "second" {
		t.Fatalf("after a broken replacement served %q", got)
	}
	if err := (&Reloader{CertFile: "missing", KeyFile: "missing"}).Load(); err == nil {
		t.Fatal("loaded missing files")
	}
}
