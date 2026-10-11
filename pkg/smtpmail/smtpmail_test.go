package smtpmail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// relay is a small SMTP server for these tests: a real listener speaking
// the protocol, with or without STARTTLS.
type relay struct {
	ln       net.Listener
	tlsCfg   *tls.Config // nil: STARTTLS is not offered
	implicit bool        // TLS from the first byte (port 465 style)
	caPEM    string

	mu       sync.Mutex
	commands []string // every command line received, in the clear or not
	inTLS    []bool   // whether each was received inside TLS
	data     string
}

func newRelay(t *testing.T, offerTLS, implicit bool) *relay {
	t.Helper()
	r := &relay{implicit: implicit}
	if offerTLS {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"}, DNSNames: []string{"relay.test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		r.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		r.tlsCfg = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *relay) record(line string, secure bool) {
	r.mu.Lock()
	r.commands, r.inTLS = append(r.commands, line), append(r.inTLS, secure)
	r.mu.Unlock()
}

func (r *relay) serve(c net.Conn) {
	defer c.Close() //nolint:errcheck
	secure := false
	if r.implicit {
		tc := tls.Server(c, r.tlsCfg)
		if tc.Handshake() != nil {
			return
		}
		c, secure = tc, true
	}
	rd := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 relay.test ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		r.record(line, secure)
		switch cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); cmd {
		case "EHLO", "HELO":
			if r.tlsCfg != nil && !secure {
				say("250-relay.test\r\n250 STARTTLS")
			} else {
				say("250-relay.test\r\n250 AUTH PLAIN")
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, r.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			c, secure, rd = tc, true, bufio.NewReader(tc)
		case "AUTH":
			say("235 ok")
		case "MAIL", "RCPT":
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			r.mu.Lock()
			r.data = b.String()
			r.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}

// dialTo sends every connection to the test relay, whatever host is named
// (the certificate is for relay.test).
func (r *relay) dialTo() DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, r.ln.Addr().String())
	}
}

// A relay that offers no TLS is refused before the password or the message
// is sent: nothing but EHLO reaches it.
func TestRelayWithoutTLSIsRefusedBeforeAnyCredential(t *testing.T) {
	r := newRelay(t, false, false)
	cfg := Config{Host: "relay.test", Port: "25", Username: "kms", Password: "s3cret-password", From: "kms@example.com"}
	err := Send(context.Background(), cfg, r.dialTo(), Message{To: "ops@example.com", Subject: "x", Body: "the body"})
	if !errors.Is(err, ErrNoTLS) {
		t.Fatalf("send to a plaintext relay: %v", err)
	}
	if err := Check(context.Background(), cfg, r.dialTo()); !errors.Is(err, ErrNoTLS) {
		t.Fatalf("check of a plaintext relay: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.commands {
		if up := strings.ToUpper(c); strings.HasPrefix(up, "AUTH") || strings.HasPrefix(up, "MAIL") || strings.HasPrefix(up, "DATA") {
			t.Fatalf("the relay received %q in the clear", c)
		}
	}
	if r.data != "" {
		t.Fatal("a message was delivered in the clear")
	}
}

// With STARTTLS, or implicit TLS on port 465, the sign-in and the message
// travel inside TLS, and the relay's certificate must chain to the given CA.
func TestMailIsSentInsideTLS(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		implicit   bool
	}{{"STARTTLS", "587", false}, {"implicit TLS", "465", true}} {
		r := newRelay(t, true, tc.implicit)
		cfg := Config{Host: "relay.test", Port: tc.port, Username: "kms", Password: "s3cret-password", From: "kms@example.com", CAPEM: r.caPEM}
		if err := Check(context.Background(), cfg, r.dialTo()); err != nil {
			t.Fatalf("%s check: %v", tc.name, err)
		}
		if err := Send(context.Background(), cfg, r.dialTo(), Message{To: "ops@example.com", Subject: "Approval required", Body: "the body"}); err != nil {
			t.Fatalf("%s send: %v", tc.name, err)
		}
		time.Sleep(50 * time.Millisecond)
		r.mu.Lock()
		sawAuth := false
		for i, c := range r.commands {
			up := strings.ToUpper(c)
			if strings.HasPrefix(up, "AUTH") || strings.HasPrefix(up, "MAIL") || strings.HasPrefix(up, "RCPT") || strings.HasPrefix(up, "DATA") {
				sawAuth = sawAuth || strings.HasPrefix(up, "AUTH")
				if !r.inTLS[i] {
					t.Fatalf("%s: %q was sent outside TLS", tc.name, c)
				}
			}
		}
		if !sawAuth || !strings.Contains(r.data, "Subject: Approval required") || !strings.Contains(r.data, "the body") {
			t.Fatalf("%s: auth=%v data=%q", tc.name, sawAuth, r.data)
		}
		r.mu.Unlock()
		// Without the CA the relay's certificate is not trusted: no sign-in.
		noCA := cfg
		noCA.CAPEM = ""
		if err := Check(context.Background(), noCA, r.dialTo()); err == nil {
			t.Fatalf("%s: an untrusted relay certificate was accepted", tc.name)
		}
	}
}

func TestHeaderInjectionIsRefused(t *testing.T) {
	cfg := Config{Host: "relay.test", Port: "587", From: "kms@example.com"}
	for _, m := range []Message{{To: "a@example.com\r\nBcc: evil@example.com", Subject: "x"}, {To: "a@example.com", Subject: "x\r\nBcc: evil@example.com"}} {
		if err := Send(context.Background(), cfg, func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("a message with a line break in a header reached the dialer")
			return nil, nil
		}, m); err == nil {
			t.Fatal("a line break in a header was accepted")
		}
	}
}
