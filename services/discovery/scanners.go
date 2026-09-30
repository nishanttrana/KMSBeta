package main

import (
	"bufio"
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Every scanner reports what it observed or returns an error. None invents an
// asset. Before 1.26.0-beta the network scan never connected (it picked each
// endpoint's "algorithm" from the sum of the hostname's bytes), the cloud and
// certificate scans made up keys and certificates when they found none, and the
// code scan labelled secrets with an arbitrary algorithm and stored the secret.

var errScanNotConfigured = errors.New("scan source not configured")

// scanNetwork handshakes with each endpoint in DISCOVERY_TLS_ENDPOINTS
// (operator configuration) and each target the tenant added
// (POST /discovery/targets), and records the negotiated key exchange and the
// leaf certificate's key. A tenant's target is dialled through s.targetGuard,
// which refuses loopback, link-local and other reserved addresses after DNS
// resolution (SSRF).
func (s *Service) scanNetwork(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	type probeTarget struct {
		endpoint string
		guard    func(network, address string, c syscall.RawConn) error
	}
	var targets []probeTarget
	seen := map[string]bool{}
	for _, ep := range parseEndpoints(os.Getenv("DISCOVERY_TLS_ENDPOINTS")) {
		seen[ep] = true
		targets = append(targets, probeTarget{endpoint: ep})
	}
	tenantTargets, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read scan targets: %w", err)
	}
	for _, t := range tenantTargets {
		if ep := t.endpoint(); !seen[ep] {
			seen[ep] = true
			targets = append(targets, probeTarget{endpoint: ep, guard: s.targetGuard})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: add a TLS target (host and port) in Crypto Discovery, or set DISCOVERY_TLS_ENDPOINTS", errScanNotConfigured)
	}
	out := make([]CryptoAsset, 0, 2*len(targets))
	var failed []string
	for _, t := range targets {
		probe, err := probeTLS(ctx, t.endpoint, 8*time.Second, t.guard)
		if err != nil {
			failed = append(failed, t.endpoint+": "+err.Error())
			continue
		}
		out = append(out, s.tlsAssets(tenantID, scanID, t.endpoint, probe)...)
	}
	if len(failed) > 0 {
		return out, fmt.Errorf("%d of %d endpoints failed: %s", len(failed), len(targets), strings.Join(failed, "; "))
	}
	return out, nil
}

type tlsProbe struct {
	version, cipher string
	kex             string
	leaf            *x509.Certificate
	trusted         bool
}

func probeTLS(ctx context.Context, endpoint string, timeout time.Duration, guard func(network, address string, c syscall.RawConn) error) (tlsProbe, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return tlsProbe{}, err
	}
	var p tlsProbe
	cfg := &tls.Config{
		ServerName: host,
		// Inventory only: the chain is verified below and recorded as
		// trusted or not, instead of failing the scan; nothing is sent.
		InsecureSkipVerify: true, //nolint:gosec
		// FIPS exception: external protocol mandate. Discovery must see
		// endpoints that still offer TLS 1.2; no data crosses this link.
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate presented")
			}
			p.leaf = cs.PeerCertificates[0]
			pool := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				pool.AddCert(c)
			}
			_, verr := p.leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: pool})
			p.trusted = verr == nil
			return nil
		},
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Control: guard}, Config: cfg}).DialContext(dctx, "tcp", endpoint)
	if err != nil {
		return tlsProbe{}, err
	}
	defer conn.Close() //nolint:errcheck
	cs := conn.(*tls.Conn).ConnectionState()
	p.version = tls.VersionName(cs.Version)
	p.cipher = tls.CipherSuiteName(cs.CipherSuite)
	p.kex = keyExchangeName(cs.CurveID)
	return p, nil
}

// keyExchangeName names a negotiated group in this service's algorithm
// vocabulary; 0 is a TLS 1.2 RSA key exchange.
func keyExchangeName(id tls.CurveID) string {
	switch id {
	case 0:
		return "RSA-KEX"
	case tls.X25519MLKEM768:
		return "X25519-ML-KEM-768-HYBRID"
	case tls.SecP256r1MLKEM768:
		return "ECDH-P256-ML-KEM-768-HYBRID"
	case tls.SecP384r1MLKEM1024:
		return "ECDH-P384-ML-KEM-1024-HYBRID"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "ECDH-P256"
	case tls.CurveP384:
		return "ECDH-P384"
	case tls.CurveP521:
		return "ECDH-P521"
	}
	return strings.ToUpper(id.String())
}

func publicKeyName(pub any) string {
	family, bits := pkgcrypto.DescribePublicKey(pub)
	switch family {
	case "RSA":
		return fmt.Sprintf("RSA-%d", bits)
	case "ECDSA":
		return fmt.Sprintf("ECDSA-P%d", bits)
	case "ED25519":
		return "ED25519"
	}
	return "UNKNOWN"
}

func (s *Service) tlsAssets(tenantID, scanID, ep string, p tlsProbe) []CryptoAsset {
	now := s.now()
	kex := CryptoAsset{
		ID: assetDeterministicID(tenantID, "network", "tls_endpoint", ep, ep, ""), TenantID: tenantID, ScanID: scanID,
		AssetType: "tls_endpoint", Name: ep, Location: ep, Source: "network",
		Algorithm: p.kex, StrengthBits: strengthBits(p.kex), Status: "active",
		Classification: classifyAlgorithm(p.kex),
		PQCReady:       pqcReady(p.kex), QSLScore: round2(algorithmQSL(p.kex)),
		Metadata:  map[string]interface{}{"protocol": p.version, "cipher_suite": p.cipher, "key_exchange": p.kex},
		FirstSeen: now, LastSeen: now,
	}
	alg := publicKeyName(p.leaf.PublicKey)
	cert := CryptoAsset{
		ID: assetDeterministicID(tenantID, "network", "tls_certificate", ep, ep, ""), TenantID: tenantID, ScanID: scanID,
		AssetType: "tls_certificate", Name: p.leaf.Subject.CommonName, Location: ep, Source: "network",
		Algorithm: alg, StrengthBits: strengthBits(alg), Status: "active",
		Classification: classifyAlgorithm(alg), PQCReady: pqcReady(alg), QSLScore: round2(algorithmQSL(alg)),
		Metadata: map[string]interface{}{
			"subject": p.leaf.Subject.String(), "issuer": p.leaf.Issuer.String(),
			"not_after": p.leaf.NotAfter.UTC().Format(time.RFC3339), "signature_algorithm": p.leaf.SignatureAlgorithm.String(),
			"chain_trusted": p.trusted,
		},
		FirstSeen: now, LastSeen: now,
	}
	if time.Now().After(p.leaf.NotAfter) {
		cert.Status = "expired"
	}
	return []CryptoAsset{kex, cert}
}

// scanCloud reads each registered cloud account's key inventory through the
// cloud service, which calls the provider's KMS API.
func (s *Service) scanCloud(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	if s.cloud == nil {
		return nil, fmt.Errorf("%w: no cloud service client", errScanNotConfigured)
	}
	accounts, err := s.cloud.ListAccounts(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list cloud accounts: %w", err)
	}
	out := []CryptoAsset{}
	var failed []string
	for _, acct := range accounts {
		accountID, provider := firstString(acct["id"]), strings.ToLower(firstString(acct["provider"]))
		items, err := s.cloud.Inventory(ctx, tenantID, accountID)
		if err != nil {
			failed = append(failed, provider+"/"+accountID+": "+err.Error())
			continue
		}
		for _, it := range items {
			alg := normalizeAlgorithm(firstString(it["algorithm"]))
			keyID := firstString(it["cloud_key_id"])
			loc := provider + "/" + firstString(it["region"])
			out = append(out, CryptoAsset{
				ID: assetDeterministicID(tenantID, "cloud", "kms_key", keyID, loc, ""), TenantID: tenantID, ScanID: scanID,
				AssetType: "kms_key", Name: keyID, Location: loc, Source: "cloud",
				Algorithm: alg, StrengthBits: strengthBits(alg), Status: strings.ToLower(defaultString(firstString(it["state"]), "unknown")),
				Classification: classifyAlgorithm(alg), PQCReady: pqcReady(alg), QSLScore: round2(algorithmQSL(alg)),
				Metadata: map[string]interface{}{
					"provider": provider, "account_id": accountID, "cloud_key_ref": firstString(it["cloud_key_ref"]),
					"managed_by_vecta": it["managed_by_vecta"],
				},
				FirstSeen: s.now(), LastSeen: s.now(),
			})
		}
	}
	if len(failed) > 0 {
		return out, fmt.Errorf("%d of %d cloud accounts failed: %s", len(failed), len(accounts), strings.Join(failed, "; "))
	}
	return out, nil
}

// scanCertificates inventories the certificates the certs service holds.
func (s *Service) scanCertificates(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	if s.certs == nil {
		return nil, fmt.Errorf("%w: no certs service client", errScanNotConfigured)
	}
	items, err := s.certs.ListCertificates(ctx, tenantID, 2000)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	out := make([]CryptoAsset, 0, len(items))
	for _, c := range items {
		alg := normalizeAlgorithm(firstString(c["algorithm"], c["signature_algorithm"]))
		cn := firstString(c["subject_cn"], c["id"])
		id := firstString(c["id"])
		out = append(out, CryptoAsset{
			ID: assetDeterministicID(tenantID, "certs", "certificate", id, cn, alg), TenantID: tenantID, ScanID: scanID,
			AssetType: "certificate", Name: cn, Location: defaultString(firstString(c["location"], c["subject_cn"]), cn), Source: "certs",
			Algorithm: alg, StrengthBits: strengthBits(alg), Status: strings.ToLower(defaultString(firstString(c["status"]), "active")),
			Classification: classifyAlgorithm(alg), PQCReady: pqcReady(alg), QSLScore: round2(algorithmQSL(alg)),
			Metadata:  map[string]interface{}{"cert_id": id, "not_after": firstString(c["not_after"])},
			FirstSeen: s.now(), LastSeen: s.now(),
		})
	}
	return out, nil
}

// scanCode walks the source tree mounted at WORKSPACE_ROOT for embedded
// secrets and private keys. A finding records where it is and a fingerprint,
// never the secret; a private key is named by the key it parses to.
func (s *Service) scanCode(_ context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	root := strings.TrimSpace(s.root)
	if root == "" {
		return nil, fmt.Errorf("%w: mount the source tree and set WORKSPACE_ROOT to scan code", errScanNotConfigured)
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("WORKSPACE_ROOT %q is not a readable directory", root)
	}
	out := make([]CryptoAsset, 0)
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case ".git", "node_modules", "vendor", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".yaml", ".yml", ".json", ".env", ".txt", ".pem", ".key":
		default:
			return nil
		}
		if count >= 2000 {
			return fs.SkipAll
		}
		count++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, f := range findSecrets(raw) {
			now := s.now()
			out = append(out, CryptoAsset{
				ID: assetDeterministicID(tenantID, "code", f.kind, rel, fmt.Sprint(f.line), f.fingerprint), TenantID: tenantID, ScanID: scanID,
				AssetType: f.kind, Name: filepath.Base(rel), Location: fmt.Sprintf("%s:%d", rel, f.line), Source: "code",
				Algorithm: f.algorithm, StrengthBits: strengthBits(f.algorithm), Status: "active", Classification: "exposed",
				Metadata:  map[string]interface{}{"fingerprint_sha256_prefix": f.fingerprint, "line": f.line},
				FirstSeen: now, LastSeen: now,
			})
		}
		return nil
	})
	return out, err
}

type secretFinding struct {
	kind, algorithm, fingerprint string
	line                         int
}

func fingerprint(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:6])
}

func findSecrets(raw []byte) []secretFinding {
	var out []secretFinding
	line := 0
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line++
		text := sc.Text()
		if m := reAKIA.FindString(text); m != "" {
			out = append(out, secretFinding{kind: "cloud_access_key", fingerprint: fingerprint([]byte(m)), line: line})
		} else if m := reHexSecret.FindString(text); m != "" {
			out = append(out, secretFinding{kind: "hex_secret", fingerprint: fingerprint([]byte(m)), line: line})
		}
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		out = append(out, secretFinding{kind: "private_key_material", algorithm: privateKeyName(block), fingerprint: fingerprint(block.Bytes), line: pemLine(raw, block)})
	}
	return out
}

func privateKeyName(block *pem.Block) string {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(interface{ Public() stdcrypto.PublicKey }); ok {
			return publicKeyName(s.Public())
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return publicKeyName(&k.PublicKey)
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return publicKeyName(&k.PublicKey)
	}
	return "UNKNOWN" // e.g. OpenSSH format: reported, not guessed
}

func pemLine(raw []byte, block *pem.Block) int {
	idx := strings.Index(string(raw), "-----BEGIN "+block.Type)
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

func parseEndpoints(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" && reTLSHostPort.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}
