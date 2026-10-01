package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startSSHServer runs a real SSH server (golang.org/x/crypto/ssh) on
// loopback with the given key exchanges and host keys, and returns its
// address and each host key's ssh-keygen fingerprint by type.
func startSSHServer(t *testing.T, kex []string, keys ...interface{}) (string, map[string]string) {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.KeyExchanges = kex
	fps := map[string]string{}
	for _, k := range keys {
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		cfg.AddHostKey(signer)
		fps[signer.PublicKey().Type()] = ssh.FingerprintSHA256(signer.PublicKey())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	return ln.Addr().String(), fps
}

func sshHostKeys(t *testing.T) []interface{} {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []interface{}{ed, rk, ek}
}

// The probe reads the offered algorithms and every host key, with its real
// size and fingerprint, from a real SSH server: over curve25519, and over
// ecdh-sha2-nistp256 as a server in FIPS mode offers.
func TestSSHProbeReadsHostKeys(t *testing.T) {
	keys := sshHostKeys(t)
	for _, kex := range []string{"curve25519-sha256", "ecdh-sha2-nistp256"} {
		t.Run(kex, func(t *testing.T) {
			// The test server, not the probe, is the limit: with FIPS mode
			// on, x/crypto/ssh stops offering X25519. The nistp256 case
			// covers the probe in every mode.
			if kex == "curve25519-sha256" && fips140.Enabled() {
				t.Skip("x/crypto/ssh offers no X25519 in FIPS mode")
			}
			addr, fps := startSSHServer(t, []string{kex}, keys...)
			p, err := probeSSH(context.Background(), addr, 5*time.Second, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(p.banner, "SSH-2.0-") || !containsString(p.kex(), kex) || len(p.ciphers()) == 0 {
				t.Fatalf("KEXINIT not read: banner %q kex %v ciphers %v", p.banner, p.kex(), p.ciphers())
			}
			if len(p.keyErrs) != 0 {
				t.Fatalf("host key errors: %v", p.keyErrs)
			}
			for typ, alg := range map[string]string{"ssh-ed25519": "ED25519", "ssh-rsa": "RSA-2048", "ecdsa-sha2-nistp256": "ECDSA-P256"} {
				if k := p.keys[typ]; k.algorithm != alg || k.fingerprint != fps[typ] {
					t.Errorf("%s: read %+v, want %s %s", typ, k, alg, fps[typ])
				}
			}
		})
	}
}

// An SSH target and an address range go through the network scan; in a
// range an address without the service is counted, not an error.
func TestNetworkScanSSHTargetAndRange(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", "")
	sshAddr, _ := startSSHServer(t, []string{"ecdh-sha2-nistp256"}, sshHostKeys(t)...)
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	port := func(addr string) int { p, _ := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:]); return p }
	for i, tg := range []ScanTarget{
		{Host: "127.0.0.1", Port: port(sshAddr), Protocol: "ssh"},
		{Host: "127.0.0.1/32", Port: port(tlsSrv.URL), Protocol: "tls"},
		{Host: "127.0.0.1/32", Port: closedPort, Protocol: "tls"},
	} {
		tg.ID, tg.TenantID = "target_"+strconv.Itoa(i), "t1"
		if err := svc.store.CreateTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	res, err := svc.sweepNetwork(ctx, "t1", "s")
	if err != nil {
		t.Fatal(err)
	}
	if res.probed != 3 || res.noService != 1 {
		t.Fatalf("probed %d, no service %d", res.probed, res.noService)
	}
	types := map[string]int{}
	for _, a := range res.assets {
		types[a.AssetType]++
	}
	if !reflect.DeepEqual(types, map[string]int{"ssh_endpoint": 1, "ssh_host_key": 3, "tls_endpoint": 1, "tls_certificate": 1}) {
		t.Fatalf("assets by type: %v", types)
	}
}

func TestSSHNamesComeFromTheCatalogue(t *testing.T) {
	for in, want := range map[string]string{
		"mlkem768x25519-sha256":                "X25519-ML-KEM-768-HYBRID",
		"curve25519-sha256@libssh.org":         "X25519",
		"ecdh-sha2-nistp384":                   "ECDH-P384",
		"diffie-hellman-group14-sha256":        "DH-2048",
		"diffie-hellman-group1-sha1":           "DH-1024",
		"diffie-hellman-group-exchange-sha256": "DH-GROUP-EXCHANGE",
		"sntrup761x25519-sha512@openssh.com":   "SNTRUP761X25519-SHA512",
	} {
		if got, _ := sshKexName(in); got != want {
			t.Errorf("sshKexName(%q) = %q, want %q", in, got, want)
		}
	}
	for m, weak := range map[string]bool{"diffie-hellman-group1-sha1": true, "diffie-hellman-group14-sha1": true, "diffie-hellman-group-exchange-sha1": true,
		"diffie-hellman-group14-sha256": false, "curve25519-sha256": false, "ecdh-sha2-nistp521": false} {
		if sshKexWeak(m) != weak {
			t.Errorf("sshKexWeak(%q) = %v", m, !weak)
		}
	}
	if got := strongestKex([]string{"diffie-hellman-group1-sha1", "curve25519-sha256", "mlkem768x25519-sha256", "ext-info-s"}); got != "X25519-ML-KEM-768-HYBRID" {
		t.Errorf("strongest = %q", got)
	}
	if got := strongestKex([]string{"diffie-hellman-group1-sha1"}); got != "DH-1024" {
		t.Errorf("strongest of only weak = %q", got)
	}
	if got := weakOffered([]string{"aes128-ctr", "3des-cbc", "arcfour256", "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"}, sshSymName); !reflect.DeepEqual(got, []string{"3des-cbc", "arcfour256"}) {
		t.Errorf("weak ciphers %v", got)
	}
	if got := weakOffered([]string{"hmac-sha2-256-etm@openssh.com", "hmac-md5-96", "hmac-sha1"}, sshSymName); !reflect.DeepEqual(got, []string{"hmac-md5-96"}) {
		t.Errorf("weak MACs %v", got)
	}
	if got := sshSymName("hmac-sha2-512-etm@openssh.com"); got != "HMAC-SHA-512" {
		t.Errorf("MAC name %q", got)
	}
}

// An RSA host key the probe couldn't read stays not assessed; the endpoint
// records the weak methods it still offers.
func TestSSHAssets(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	var kexInit [10][]string
	kexInit[0] = []string{"mlkem768x25519-sha256", "diffie-hellman-group1-sha1", "kex-strict-s-v00@openssh.com"}
	kexInit[1] = []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"}
	p := sshProbe{banner: "SSH-2.0-OpenSSH_9.9", kexInit: kexInit,
		keys:    map[string]sshHostKey{"ssh-ed25519": {algorithm: "ED25519", fingerprint: "SHA256:x"}},
		keyErrs: map[string]string{"ssh-rsa": "EOF"}}
	got := map[string]CryptoAsset{}
	for _, a := range svc.sshAssets("t1", "s", "10.0.0.5:22", p) {
		got[a.AssetType+" "+a.Algorithm] = a
	}
	ep, ok := got["ssh_endpoint X25519-ML-KEM-768-HYBRID"]
	if !ok || !ep.PQCReady || !reflect.DeepEqual(ep.Metadata["weak_key_exchange_offered"], []string{"diffie-hellman-group1-sha1"}) || ep.Metadata["server"] != "OpenSSH_9.9" {
		t.Fatalf("endpoint: %+v", got)
	}
	if rsaKey, ok := got["ssh_host_key RSA"]; !ok || rsaKey.Classification != "unknown" || rsaKey.Metadata["key_error"] != "EOF" {
		t.Fatalf("unread RSA key: %+v", got)
	}
	if ed, ok := got["ssh_host_key ED25519"]; !ok || ed.Classification != "quantum_vulnerable" || len(got) != 3 {
		t.Fatalf("host keys: %+v", got)
	}
}

// The parsers read bytes a remote server or an uploaded file chose; none of
// it may panic. The seeds also run in a plain `go test`.
func FuzzUntrustedParsers(f *testing.F) {
	for _, seed := range [][]byte{
		nil, {sshMsgKexInit}, {0, 0, 0, 1, 0}, []byte("SSH-2.0-x\r\n"), []byte("openssh-key-v1\x00\x00\x00\x00\x04none"),
		append([]byte{sshMsgKexInit}, make([]byte, 20)...), {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0xff, 0xff, 0xff, 0xff},
		[]byte("ssh-rsa AAAAB3NzaC1yc2E= x\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		[]byte("diffie-hellman-group"), []byte("ecdh-sha2-nistp"), []byte("aes-"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseKexInit(b)
		_ = sshKeyName(b)
		_ = openSSHPrivateKeyName(b)
		_ = findMaterial("f.pem", b)
		_ = findMaterial("f.p12", b)
		name := string(b)
		_, _ = sshKexName(name)
		_ = sshKexWeak(name)
		_ = sshSymName(name)
		_ = strongestKex([]string{name})
		_ = uploadName(name)
	})
}

// A server can't make the probe store more than a bounded list of names.
func TestKexInitNamesAreBounded(t *testing.T) {
	msg := append([]byte{sshMsgKexInit}, make([]byte, 16)...)
	long := strings.Repeat("a", sshMaxNameLen+1)
	names := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		names = append(names, "kex"+strconv.Itoa(i))
	}
	msg = appendSSHString(msg, []byte(long+","+strings.Join(names, ",")))
	for i := 0; i < 9; i++ {
		msg = appendSSHString(msg, nil)
	}
	lists, err := parseKexInit(msg)
	if err != nil || len(lists[0]) != sshMaxNames || lists[0][0] != "kex0" {
		t.Fatalf("names kept: %d, first %q, %v", len(lists[0]), lists[0], err)
	}
}
