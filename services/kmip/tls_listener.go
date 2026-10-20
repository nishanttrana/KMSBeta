package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"vecta-kms/pkg/tlsreload"
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
	reloader := &tlsreload.Reloader{CertFile: f.Cert, KeyFile: f.Key, Name: "KMIP server certificate", Logf: logger.Printf}
	deadline := time.Now().Add(kmipTLSWait)
	for {
		err := reloader.Load()
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
		GetCertificate: reloader.GetCertificate,
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
