package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// The KMIP listener's TLS (docs/SECURITY/INTERNAL_TLS.md, "Edge
// certificate"). The server certificate is the file certs writes, from the
// source a root administrator chose (vecta-runtime-root, a PKI CA, or an
// external CA); it is reloaded on the next handshake after certs replaces
// it. Client certificates are always verified against the client CA:
// KMIP takes the caller's identity from that certificate.
//
// Until 6.14.0-beta a missing or unreadable file silently switched the
// listener to a self-generated development certificate that accepted any
// client certificate unverified, and KMIP_CLIENT_CERT_VERIFY_DISABLED did
// the same on request. Both are gone: the listener refuses to start.

type kmipTLSFiles struct {
	Cert, Key, ClientCA, CRL string
}

func kmipTLSFilesFromEnv() kmipTLSFiles {
	return kmipTLSFiles{
		Cert:     strings.TrimSpace(os.Getenv("KMIP_TLS_CERT_FILE")),
		Key:      strings.TrimSpace(os.Getenv("KMIP_TLS_KEY_FILE")),
		ClientCA: strings.TrimSpace(os.Getenv("KMIP_TLS_CLIENT_CA_FILE")),
		CRL:      strings.TrimSpace(os.Getenv("KMIP_CLIENT_CRL_FILE")),
	}
}

// kmipTLSWait is how long the listener waits for certs to write its files.
var kmipTLSWait = 3 * time.Minute

// loadKMIPTLSConfig builds the listener's TLS config, waiting for certs to
// write the files, and fails if they never appear or don't load.
func loadKMIPTLSConfig(ctx context.Context, f kmipTLSFiles, logf func(string, ...interface{})) (*tls.Config, error) {
	if f.Cert == "" || f.Key == "" || f.ClientCA == "" {
		return nil, errors.New("KMIP_TLS_CERT_FILE, KMIP_TLS_KEY_FILE and KMIP_TLS_CLIENT_CA_FILE are required")
	}
	reloader := &certReloader{certFile: f.Cert, keyFile: f.Key}
	deadline := time.Now().Add(kmipTLSWait)
	for {
		err := reloader.load()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("KMIP server certificate: %w", err)
		}
		logf("waiting for the KMIP server certificate from certs: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	caRaw, err := os.ReadFile(f.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("KMIP client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caRaw) {
		return nil, fmt.Errorf("KMIP client CA %s holds no certificate", f.ClientCA)
	}
	cfg := &tls.Config{
		MinVersion:     allowedKMIPMinVersion(),
		GetCertificate: reloader.get,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		CipherSuites:   fipsApprovedCipherSuites,
	}
	if f.CRL != "" {
		// A configured CRL that can't be read refuses start rather than
		// accepting revoked clients.
		vf, err := loadKMIPClientCertVerifier(f.CRL)
		if err != nil {
			return nil, fmt.Errorf("KMIP client CRL: %w", err)
		}
		cfg.VerifyPeerCertificate = vf
	}
	return cfg, nil
}

// certReloader serves the certificate files, re-reading them when they
// change (checked at most once a second). A replacement that doesn't load
// keeps the one in force.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
}

func fileStamp(paths ...string) (string, error) {
	var b strings.Builder
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s:%d:%d;", p, st.Size(), st.ModTime().UnixNano())
	}
	return b.String(), nil
}

func (r *certReloader) load() error {
	stamp, err := fileStamp(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert, r.stamp = &cert, stamp
	r.mu.Unlock()
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	due := time.Since(r.checked) >= time.Second
	if due {
		r.checked = time.Now()
	}
	cur, stamp := r.cert, r.stamp
	r.mu.Unlock()
	if due {
		if now, err := fileStamp(r.certFile, r.keyFile); err == nil && now != stamp {
			if err := r.load(); err != nil {
				logger.Printf("KMIP server certificate changed but did not load (%v); keeping the current one", err)
			} else {
				r.mu.Lock()
				cur = r.cert
				r.mu.Unlock()
				logger.Printf("KMIP server certificate reloaded")
			}
		}
	}
	if cur == nil {
		return nil, errors.New("no KMIP server certificate")
	}
	return cur, nil
}
