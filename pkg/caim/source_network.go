package caim

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// ScanTarget defines a host:port to scan for TLS information.
type ScanTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// NetworkScanner discovers crypto assets by performing TLS handshakes against targets.
type NetworkScanner struct {
	targets        []ScanTarget
	timeout        time.Duration
	maxConcurrency int
}

// NewNetworkScanner creates a scanner with the given targets and connection timeout.
func NewNetworkScanner(targets []ScanTarget, timeout time.Duration, maxConcurrency int) *NetworkScanner {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 20
	}
	return &NetworkScanner{
		targets:        targets,
		timeout:        timeout,
		maxConcurrency: maxConcurrency,
	}
}

// Name returns the source identifier.
func (s *NetworkScanner) Name() string {
	return "network_tls_scan"
}

// Discover performs TLS handshakes against all targets and extracts cryptographic assets.
func (s *NetworkScanner) Discover(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	type result struct {
		assets []CryptoAsset
		err    error
	}

	sem := make(chan struct{}, s.maxConcurrency)
	results := make(chan result, len(s.targets))

	for _, target := range s.targets {
		target := target
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			assets, err := s.scanTarget(ctx, tenantID, target)
			results <- result{assets: assets, err: err}
		}()
	}

	var allAssets []CryptoAsset
	for i := 0; i < len(s.targets); i++ {
		select {
		case <-ctx.Done():
			return allAssets, ctx.Err()
		case r := <-results:
			if r.err != nil {
				// Log but continue scanning other targets
				continue
			}
			allAssets = append(allAssets, r.assets...)
		}
	}

	return allAssets, nil
}

// scanTarget performs a TLS handshake and extracts crypto information.
func (s *NetworkScanner) scanTarget(ctx context.Context, tenantID string, target ScanTarget) ([]CryptoAsset, error) {
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)

	dialer := &net.Dialer{Timeout: s.timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("caim/network: dial %s: %w", addr, err)
	}

	var peerCerts []*x509.Certificate
	var negotiatedVersion uint16
	var negotiatedCipher uint16

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Intentional for discovery scanning
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				peerCerts = append(peerCerts, cert)
			}
			return nil
		},
		// Support a range of TLS versions to detect what the server negotiates
		MinVersion: tls.VersionTLS10, //nolint:gosec // Intentional to detect deprecated versions
		MaxVersion: tls.VersionTLS13,
	}

	tlsConn := tls.Client(netConn, tlsConf)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("caim/network: tls handshake %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()
	negotiatedVersion = state.Version
	negotiatedCipher = state.CipherSuite

	var assets []CryptoAsset
	now := time.Now()

	// Extract certificate chain assets
	for i, cert := range peerCerts {
		algo, keySize := extractCertKeyInfo(cert)
		sigAlgo := cert.SignatureAlgorithm.String()

		assets = append(assets, CryptoAsset{
			TenantID:        tenantID,
			AssetType:       AssetTypeCert,
			Name:            cert.Subject.CommonName,
			Location:        Location{Service: "tls", Host: target.Host, Path: fmt.Sprintf(":%d/chain[%d]", target.Port, i)},
			Algorithm:       algo,
			KeySize:         keySize,
			CreatedAt:       cert.NotBefore,
			ExpiresAt:       cert.NotAfter,
			Owner:           cert.Issuer.CommonName,
			DiscoverySource: "network_tls_scan",
			LastSeen:        now,
			Metadata: map[string]string{
				"subject":    cert.Subject.String(),
				"issuer":     cert.Issuer.String(),
				"serial":     cert.SerialNumber.String(),
				"sig_algo":   sigAlgo,
				"is_ca":      fmt.Sprintf("%v", cert.IsCA),
				"dns_names":  strings.Join(cert.DNSNames, ","),
			},
		})
	}

	// Extract TLS protocol asset
	tlsVersionStr := tlsVersionString(negotiatedVersion)
	cipherSuiteStr := tls.CipherSuiteName(negotiatedCipher)
	usesPFS := cipherSuiteUsesPFS(cipherSuiteStr)

	assets = append(assets, CryptoAsset{
		TenantID:        tenantID,
		AssetType:       AssetTypeProtocol,
		Name:            tlsVersionStr,
		Location:        Location{Service: "tls", Host: target.Host, Path: fmt.Sprintf(":%d", target.Port)},
		Algorithm:       cipherSuiteStr,
		DiscoverySource: "network_tls_scan",
		LastSeen:        now,
		Metadata: map[string]string{
			"cipher_suite": cipherSuiteStr,
			"pfs":          fmt.Sprintf("%v", usesPFS),
			"tls_version":  tlsVersionStr,
		},
	})

	return assets, nil
}

// extractCertKeyInfo returns the algorithm name and key size from a certificate.
func extractCertKeyInfo(cert *x509.Certificate) (algorithm string, keySize int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", pub.Curve.Params().Name), pub.Curve.Params().BitSize
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// tlsVersionString converts a TLS version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// cipherSuiteUsesPFS checks whether the cipher suite provides Perfect Forward Secrecy.
func cipherSuiteUsesPFS(cipherName string) bool {
	pfsIndicators := []string{"ECDHE", "DHE", "TLS_AES", "TLS_CHACHA"}
	upper := strings.ToUpper(cipherName)
	for _, ind := range pfsIndicators {
		if strings.Contains(upper, ind) {
			return true
		}
	}
	return false
}
