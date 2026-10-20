package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"vecta-kms/pkg/securityheaders"
	"vecta-kms/pkg/tlsreload"
)

// The Azure EKM listener (azure_ekm.go). It serves the KMS's external
// certificate, the one a root administrator chose for the HTTPS edge in the
// PKI tab (docs/SECURITY/INTERNAL_TLS.md, "Edge certificate"): Managed HSM
// is configured with the CA that issued it. TLS 1.3 only, as the EKM Proxy
// API requires. A client certificate is required at the handshake and
// verified per request against the CA and subject CN of the tenant the path
// prefix names, which the handshake can't know yet.
//
// AZURE_EKM_PORT unset leaves the listener off. Set, it refuses to start
// without its certificate files rather than serve without them.

type azureListenerConfig struct {
	Port, CertFile, KeyFile string
}

func azureListenerConfigFromEnv() azureListenerConfig {
	return azureListenerConfig{
		Port:     strings.TrimSpace(os.Getenv("AZURE_EKM_PORT")),
		CertFile: strings.TrimSpace(os.Getenv("AZURE_EKM_TLS_CERT_FILE")),
		KeyFile:  strings.TrimSpace(os.Getenv("AZURE_EKM_TLS_KEY_FILE")),
	}
}

// azureCertWait is how long the listener waits for certs to write the edge
// certificate on a fresh stack.
var azureCertWait = 3 * time.Minute

func azureListenerTLS(ctx context.Context, c azureListenerConfig, logf func(string, ...interface{})) (*tls.Config, error) {
	if c.CertFile == "" || c.KeyFile == "" {
		return nil, errors.New("AZURE_EKM_TLS_CERT_FILE and AZURE_EKM_TLS_KEY_FILE are required when AZURE_EKM_PORT is set")
	}
	reloader := &tlsreload.Reloader{CertFile: c.CertFile, KeyFile: c.KeyFile, Name: "Azure EKM server certificate", Logf: logf}
	deadline := time.Now().Add(azureCertWait)
	for {
		err := reloader.Load()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("Azure EKM server certificate: %w", err)
		}
		logf("waiting for the edge certificate from certs: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: reloader.GetCertificate,
		// Verified per request against the tenant's own CA (verifyAzureClient).
		ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"},
	}, nil
}

// startAzureListener serves h until ctx ends; nil when the port is unset.
func startAzureListener(ctx context.Context, c azureListenerConfig, h http.Handler, logf func(string, ...interface{})) (*http.Server, error) {
	if c.Port == "" {
		return nil, nil
	}
	cfg, err := azureListenerTLS(ctx, c, logf)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              ":" + c.Port,
		Handler:           securityheaders.Wrap(h),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		logf("Azure EKM (mTLS) listening on :%s", c.Port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("Azure EKM listener failed: %v", err)
		}
	}()
	return srv, nil
}
