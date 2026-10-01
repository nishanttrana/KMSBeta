package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Every scanner reports what it observed or returns an error. None invents an
// asset. Before 1.26.0-beta the network scan never connected (it picked each
// endpoint's "algorithm" from the sum of the hostname's bytes), the cloud and
// certificate scans made up keys and certificates when they found none, and the
// code scan labelled secrets with an arbitrary algorithm and stored the secret.

var errScanNotConfigured = errors.New("scan source not configured")

// scanNetwork probes each endpoint in DISCOVERY_TLS_ENDPOINTS (operator
// configuration) and each target the tenant added (POST /discovery/targets):
// a TLS handshake, or for an SSH target the server's offered algorithms and
// host keys (ssh.go). A target can be an address range (7.18.0-beta), swept
// with a shorter timeout; an address in a range that doesn't answer has no
// service, which is not an error. Every endpoint is dialled through
// s.targetGuard, which refuses reserved addresses and the KMS platform's own
// after DNS resolution (targets.go). The inventory is the customer's estate;
// the KMS's internal certificates are in the PKI tab (7.13.0-beta).
func (s *Service) scanNetwork(ctx context.Context, tenantID string, scanID string) ([]CryptoAsset, error) {
	res, err := s.sweepNetwork(ctx, tenantID, scanID)
	return res.assets, err
}

// netEndpoint is one host:port the network scan probes.
type netEndpoint struct {
	addr     string
	protocol string // "tls" or "ssh"
	sweep    bool   // from an address range
}

type netResult struct {
	assets                     []CryptoAsset
	probed, noService, skipped int
}

const (
	probeTimeout = 8 * time.Second
	sweepTimeout = 3 * time.Second
	probeWorkers = 32
)

func (s *Service) networkEndpoints(ctx context.Context, tenantID string) ([]netEndpoint, error) {
	var out []netEndpoint
	seen := map[string]bool{}
	add := func(e netEndpoint) {
		if !seen[e.addr] {
			seen[e.addr] = true
			out = append(out, e)
		}
	}
	for _, ep := range parseEndpoints(os.Getenv("DISCOVERY_TLS_ENDPOINTS")) {
		add(netEndpoint{addr: ep, protocol: "tls"})
	}
	targets, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read scan targets: %w", err)
	}
	for _, t := range targets {
		if p, err := netip.ParsePrefix(t.Host); err == nil {
			for _, a := range prefixHosts(p) {
				add(netEndpoint{addr: netip.AddrPortFrom(a, uint16(t.Port)).String(), protocol: t.proto(), sweep: true})
			}
			continue
		}
		add(netEndpoint{addr: t.endpoint(), protocol: t.proto()})
	}
	return out, nil
}

func (s *Service) sweepNetwork(ctx context.Context, tenantID string, scanID string) (netResult, error) {
	eps, err := s.networkEndpoints(ctx, tenantID)
	if err != nil {
		return netResult{}, err
	}
	if len(eps) == 0 {
		return netResult{}, fmt.Errorf("%w: add a target (host, IP or range) in Crypto Discovery, or set DISCOVERY_TLS_ENDPOINTS", errScanNotConfigured)
	}
	guard := s.targetGuard(ctx)
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		res    netResult
		failed []string
	)
	jobs := make(chan netEndpoint)
	for i := 0; i < min(probeWorkers, len(eps)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				assets, err := s.probeEndpoint(ctx, tenantID, scanID, ep, guard)
				mu.Lock()
				res.probed++
				switch {
				case err == nil:
					res.assets = append(res.assets, assets...)
				case ep.sweep && (errors.Is(err, errPlatformTarget) || errors.Is(err, errReservedTarget)):
					res.skipped++
				case ep.sweep:
					res.noService++
				default:
					failed = append(failed, ep.addr+": "+err.Error())
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, ep := range eps {
		select {
		case jobs <- ep:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if res.probed < len(eps) {
		failed = append(failed, fmt.Sprintf("%d endpoints not probed: %v", len(eps)-res.probed, ctx.Err()))
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return res, fmt.Errorf("%d of %d endpoints failed: %s", len(failed), len(eps), strings.Join(failed, "; "))
	}
	return res, nil
}

func (s *Service) probeEndpoint(ctx context.Context, tenantID, scanID string, ep netEndpoint, guard dialControl) (assets []CryptoAsset, err error) {
	// Each probe runs on a worker goroutine and parses a remote server's
	// bytes: a panic is that endpoint's error.
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("scan %s: probe of %s panicked: %v", scanID, ep.addr, r)
			assets, err = nil, errors.New("probe failed unexpectedly")
		}
	}()
	timeout := probeTimeout
	if ep.sweep {
		timeout = sweepTimeout
	}
	if ep.protocol == "ssh" {
		p, err := probeSSH(ctx, ep.addr, timeout, guard)
		if err != nil {
			return nil, err
		}
		return s.sshAssets(tenantID, scanID, ep.addr, p), nil
	}
	p, err := probeTLS(ctx, ep.addr, timeout, guard)
	if err != nil {
		return nil, err
	}
	return s.tlsAssets(tenantID, scanID, ep.addr, p), nil
}

type tlsProbe struct {
	version, cipher string
	kex             string
	leaf            *x509.Certificate
	trusted         bool
}

func probeTLS(ctx context.Context, endpoint string, timeout time.Duration, guard dialControl) (tlsProbe, error) {
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
	// Certificates without a CommonName are named by their first DNS name.
	name := p.leaf.Subject.CommonName
	if name == "" && len(p.leaf.DNSNames) > 0 {
		name = p.leaf.DNSNames[0]
	}
	cert := CryptoAsset{
		ID: assetDeterministicID(tenantID, "network", "tls_certificate", ep, ep, ""), TenantID: tenantID, ScanID: scanID,
		AssetType: "tls_certificate", Name: defaultString(name, ep), Location: ep, Source: "network",
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
		// The platform's own service mTLS certificates (internal-services
		// Sub CA) are shown in the PKI tab, not the customer's inventory.
		if strings.EqualFold(firstString(c["cert_class"]), "internal-mtls") {
			continue
		}
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

// scanCode walks the source tree mounted at WORKSPACE_ROOT for key material
// (material.go): secrets and private keys, recorded by location and
// fingerprint, never the secret; certificates and public keys by the key
// they hold.
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
		if !codeScanFile(d.Name()) {
			return nil
		}
		if count >= 2000 {
			return fs.SkipAll
		}
		count++
		if info, err := d.Info(); err != nil || info.Size() > maxUploadBytes {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, s.materialAssets(tenantID, scanID, "code", rel, findMaterial(rel, raw))...)
		return nil
	})
	return out, err
}

// codeScanFile: source, configuration and key or certificate files. Lock
// files are skipped: they hold other projects' checksums, not this one's
// keys.
func codeScanFile(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "authorized_keys", "known_hosts", "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "dockerfile":
		return true
	case "package-lock.json", "go.sum", "pnpm-lock.yaml", "npm-shrinkwrap.json":
		return false
	}
	ext := filepath.Ext(name)
	return ext != ".lock" && (codeScanExt[ext] || keystoreExt[ext] || strings.HasPrefix(name, ".env"))
}

var codeScanExt = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(`.go .yaml .yml .json .env .txt .pem .key .crt .cer .der .csr .pub
		.js .ts .jsx .tsx .py .rb .java .kt .cs .php .rs .c .h .cpp .sh .ps1
		.tf .tfvars .properties .conf .cfg .ini .toml .xml`) {
		m[e] = true
	}
	return m
}()

func parseEndpoints(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" && reTLSHostPort.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}
