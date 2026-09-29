package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/svctls"
)

// Edge certificate (docs/SECURITY/INTERNAL_TLS.md, "Edge certificate"): the
// certificate Envoy's HTTPS edge serves. A root administrator chooses its
// source; every node's materializer applies the choice to its own edge
// (Envoy reloads the files through SDS), and certs' edge probe pins the
// served certificate to the installed one.

const (
	edgeSourceRuntime  = "runtime"  // vecta-runtime-root (default)
	edgeSourceCA       = "ca"       // a software CA from the PKI tab, renewed by certs
	edgeSourceExternal = "external" // an external CA's certificate for this node's own key
)

var edgeSources = []string{edgeSourceRuntime, edgeSourceCA, edgeSourceExternal}

type edgeCertChoice struct {
	Source       string    `json:"source"`
	CAID         string    `json:"ca_id,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

func (s *SQLStore) GetEdgeCertChoice(ctx context.Context) (edgeCertChoice, error) {
	var c edgeCertChoice
	var updated interface{}
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT source, ca_id, key_algorithm, reason, updated_by, updated_at FROM cert_edge_certificate WHERE id = 'edge'`).
		Scan(&c.Source, &c.CAID, &c.KeyAlgorithm, &c.Reason, &c.UpdatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return edgeCertChoice{Source: edgeSourceRuntime}, nil
	}
	c.UpdatedAt = parseTimeValue(updated)
	return c, err
}

func (s *SQLStore) UpsertEdgeCertChoice(ctx context.Context, c edgeCertChoice) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_edge_certificate (id, source, ca_id, key_algorithm, reason, updated_by, updated_at)
VALUES ('edge',$1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET source = EXCLUDED.source, ca_id = EXCLUDED.ca_id, key_algorithm = EXCLUDED.key_algorithm,
	reason = EXCLUDED.reason, updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP`,
		c.Source, c.CAID, c.KeyAlgorithm, c.Reason, c.UpdatedBy)
	return err
}

type edgeCertStore interface {
	GetEdgeCertChoice(ctx context.Context) (edgeCertChoice, error)
	UpsertEdgeCertChoice(ctx context.Context, c edgeCertChoice) error
}

func (s *Service) edgeStore() (edgeCertStore, error) {
	st, ok := s.store.(edgeCertStore)
	if !ok {
		return nil, errors.New("the edge certificate needs the SQL store")
	}
	return st, nil
}

// edgeFiles are this node's edge files on the runtime certificate volume
// (base is the materializer directory).
type edgeFiles string

func (b edgeFiles) dir() string     { return filepath.Join(string(b), "envoy") }
func (b edgeFiles) pending() string { return filepath.Join(string(b), "envoy-pending") }

// marker records the serial of the external certificate installed on this
// node, so it is never confused with one certs issued.
func (b edgeFiles) marker() string { return filepath.Join(string(b), "envoy-external.serial") }

func (s *Service) edgeFiles() edgeFiles { return edgeFiles(s.runtimeCfg.MaterializeDir) }
func (s *Service) edgeDir() string      { return s.edgeFiles().dir() }

func (b edgeFiles) installedExternal(leaf *x509.Certificate) bool {
	raw, err := os.ReadFile(b.marker())
	return err == nil && leaf != nil && strings.TrimSpace(string(raw)) == leaf.SerialNumber.Text(16)
}

type edgePending struct {
	SubjectCN    string    `json:"subject_cn"`
	SANs         []string  `json:"sans"`
	KeyAlgorithm string    `json:"key_algorithm"`
	CSRPEM       string    `json:"csr_pem"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
}

func edgeIdentity(cfg RuntimeCertMaterializerConfig) (string, []string) {
	cn := strings.TrimSpace(cfg.EnvoyCN)
	if cn == "" {
		cn = "vecta-envoy"
	}
	sans := dedupStrings(append([]string{}, cfg.EnvoySANs...))
	if len(sans) == 0 {
		sans = []string{"localhost", "envoy", "127.0.0.1"}
	}
	return cn, sans
}

// installedLeaf is the certificate this node's edge is configured with.
func installedLeaf(dir string) (*x509.Certificate, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		return nil, nil, err
	}
	leaf, err := parseCertificatePEM(string(raw))
	return leaf, raw, err
}

func issuedBy(leaf *x509.Certificate, ca CA) bool {
	caCert, err := parseCertificatePEM(ca.CertPEM)
	return err == nil && leaf.CheckSignatureFrom(caCert) == nil
}

// caChainPEM is ca and its parents, leaf-most first.
func (s *Service) caChainPEM(ctx context.Context, tenantID string, ca CA) (string, error) {
	var parts []string
	for cur, i := ca, 0; i < 8; i++ {
		parts = append(parts, strings.TrimSpace(cur.CertPEM))
		if strings.TrimSpace(cur.ParentCAID) == "" {
			break
		}
		next, err := s.store.GetCA(ctx, tenantID, cur.ParentCAID)
		if err != nil {
			return "", err
		}
		cur = next
	}
	return strings.Join(parts, "\n"), nil
}

// edgeCA resolves a CA that may issue the edge certificate.
func (s *Service) edgeCA(ctx context.Context, tenantID, caID string) (CA, error) {
	ca, err := s.store.GetCA(ctx, tenantID, strings.TrimSpace(caID))
	if err != nil {
		return CA{}, mtlsRefusal{"unknown_ca", fmt.Sprintf("CA %q is not in the PKI tab", caID)}
	}
	if !strings.EqualFold(ca.Status, CAStatusActive) {
		return CA{}, mtlsRefusal{"ca_not_active", fmt.Sprintf("CA %q is %s", ca.Name, ca.Status)}
	}
	if ca.KeyBackend == "hsm" {
		// Renewal runs unattended; an HSM CA signs only for a user it acts for.
		return CA{}, mtlsRefusal{"hsm_ca_not_supported", "an HSM CA signs only for a user; certs renews the edge certificate unattended"}
	}
	if _, sub, err := s.EnsureInternalPKI(ctx, tenantID); err == nil && sub.ID == ca.ID {
		return CA{}, mtlsRefusal{"internal_services_ca", "the internal-services Sub CA issues only internal identities"}
	}
	return ca, nil
}

// writeEdgeCert issues the edge certificate from ca and installs it.
func (s *Service) writeEdgeCert(ctx context.Context, tenantID string, ca CA, algorithm string, cfg RuntimeCertMaterializerConfig) error {
	cn, sans := edgeIdentity(cfg)
	chain, err := s.caChainPEM(ctx, tenantID, ca)
	if err != nil {
		return err
	}
	days := cfg.ValidityDays
	if days <= 0 {
		days = 90
	}
	_, err = s.writeRuntimeEndpointCert(ctx, tenantID, ca, edgeFiles(cfg.MaterializeDir).dir(), algorithm, "tls-server", cn, sans, days, chain)
	return err
}

// applyEdgeCertificate makes this node's edge serve the chosen source,
// renewing before expiry. force reissues now (after a change).
func (s *Service) applyEdgeCertificate(ctx context.Context, tenantID string, runtimeRoot CA, cfg RuntimeCertMaterializerConfig, force bool) error {
	st, err := s.edgeStore()
	if err != nil {
		return err
	}
	choice, err := st.GetEdgeCertChoice(ctx)
	if err != nil {
		return err
	}
	files := edgeFiles(cfg.MaterializeDir)
	dir := files.dir()
	renewBefore := cfg.RenewBefore
	if renewBefore <= 0 {
		renewBefore = 24 * time.Hour
	}
	leaf, _, _ := installedLeaf(dir)
	due := force || leaf == nil || runtimeCertNeedsRenew(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), renewBefore)
	switch choice.Source {
	case edgeSourceCA:
		ca, err := s.edgeCA(ctx, tenantID, choice.CAID)
		if err != nil {
			return err
		}
		if due || !issuedBy(leaf, ca) || !sameKeyLabel(fileKeyAlgorithm(filepath.Join(dir, "tls.crt")), choice.KeyAlgorithm) {
			return s.writeEdgeCert(ctx, tenantID, ca, choice.KeyAlgorithm, cfg)
		}
		return nil
	case edgeSourceExternal:
		// This node's own key and its external certificate, once installed.
		// Until then (or once it expires) the edge keeps a runtime-root
		// certificate rather than go dark.
		if files.installedExternal(leaf) && time.Now().Before(leaf.NotAfter) {
			return nil
		}
	}
	if due || leaf == nil || !issuedBy(leaf, runtimeRoot) {
		return s.writeEdgeCert(ctx, tenantID, runtimeRoot, "RSA-3072", cfg)
	}
	return nil
}

func (s *Service) runtimeRoot(ctx context.Context, tenantID string) (CA, error) {
	name := strings.TrimSpace(s.runtimeCfg.RootCAName)
	if name == "" {
		name = s.runtimeRootCAName(ctx, tenantID)
	}
	return s.ensureRuntimeRootCA(ctx, tenantID, name)
}

// SetEdgeCertificateSource changes the source and applies it on this node.
// Other nodes apply it on their next materializer pass.
func (s *Service) SetEdgeCertificateSource(ctx context.Context, tenantID string, next edgeCertChoice) (edgeCertChoice, edgeCertChoice, error) {
	st, err := s.edgeStore()
	if err != nil {
		return edgeCertChoice{}, edgeCertChoice{}, err
	}
	prev, err := st.GetEdgeCertChoice(ctx)
	if err != nil {
		return edgeCertChoice{}, edgeCertChoice{}, err
	}
	next.Source = strings.TrimSpace(next.Source)
	if !containsString(edgeSources, next.Source) {
		return prev, next, mtlsRefusal{"invalid_source", fmt.Sprintf("source %q is not one of %s", next.Source, strings.Join(edgeSources, ", "))}
	}
	switch next.Source {
	case edgeSourceCA:
		if next.KeyAlgorithm == "" {
			next.KeyAlgorithm = pkgcrypto.AlgECDSAP256
		}
		if !containsString(svctls.KeyAlgorithms, next.KeyAlgorithm) {
			return prev, next, mtlsRefusal{"invalid_key_algorithm", fmt.Sprintf("key algorithm %q is not one of %s", next.KeyAlgorithm, strings.Join(svctls.KeyAlgorithms, ", "))}
		}
		if _, err := s.edgeCA(ctx, tenantID, next.CAID); err != nil {
			return prev, next, err
		}
	default:
		next.CAID, next.KeyAlgorithm = "", ""
	}
	if next.Source == prev.Source && next.CAID == prev.CAID && next.KeyAlgorithm == prev.KeyAlgorithm {
		return prev, next, mtlsRefusal{"unchanged", "the edge certificate already comes from " + next.Source}
	}
	if err := st.UpsertEdgeCertChoice(ctx, next); err != nil {
		return prev, next, err
	}
	root, err := s.runtimeRoot(ctx, tenantID)
	if err != nil {
		return prev, next, err
	}
	if err := s.applyEdgeCertificate(ctx, tenantID, root, s.runtimeCfg, next.Source != edgeSourceExternal); err != nil {
		return prev, next, fmt.Errorf("apply on this node: %w", err)
	}
	return prev, next, nil
}

// CreateEdgeCSR generates this node's edge key and returns a CSR for an
// external CA. The key stays in this node's pending directory until the
// signed certificate is installed; a new CSR replaces it.
func (s *Service) CreateEdgeCSR(ctx context.Context, subjectCN string, sans []string, algorithm, actor string) (edgePending, error) {
	st, err := s.edgeStore()
	if err != nil {
		return edgePending{}, err
	}
	choice, err := st.GetEdgeCertChoice(ctx)
	if err != nil {
		return edgePending{}, err
	}
	if choice.Source != edgeSourceExternal {
		return edgePending{}, mtlsRefusal{"source_not_external", "choose the external source before requesting a CSR"}
	}
	subjectCN = strings.TrimSpace(subjectCN)
	sans = dedupStrings(sans)
	if subjectCN == "" && len(sans) == 0 {
		return edgePending{}, mtlsRefusal{"invalid_request", "subject_cn or sans is required"}
	}
	if algorithm == "" {
		algorithm = pkgcrypto.AlgECDSAP256
	}
	if !containsString(svctls.KeyAlgorithms, algorithm) {
		return edgePending{}, mtlsRefusal{"invalid_key_algorithm", fmt.Sprintf("key algorithm %q is not one of %s", algorithm, strings.Join(svctls.KeyAlgorithms, ", "))}
	}
	signer, keyPEM, err := generateLeafKey(algorithm)
	if err != nil {
		return edgePending{}, err
	}
	keyBytes := []byte(keyPEM)
	defer pkgcrypto.Zeroize(keyBytes)
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: subjectCN}}
	for _, n := range sans {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificateRequest(pkgcrypto.Reader, tpl, signer)
	if err != nil {
		return edgePending{}, err
	}
	p := edgePending{SubjectCN: subjectCN, SANs: sans, KeyAlgorithm: algorithm, CreatedAt: time.Now().UTC(), CreatedBy: actor,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	meta, _ := json.MarshalIndent(p, "", "  ")
	if err := writeFileAtomically(filepath.Join(s.edgeFiles().pending(), "tls.key"), keyBytes, 0o600); err != nil {
		return edgePending{}, err
	}
	if err := writeFileAtomically(filepath.Join(s.edgeFiles().pending(), "pending.json"), meta, 0o600); err != nil {
		return edgePending{}, err
	}
	return p, nil
}

func (s *Service) edgePending() *edgePending {
	raw, err := os.ReadFile(filepath.Join(s.edgeFiles().pending(), "pending.json"))
	if err != nil {
		return nil
	}
	var p edgePending
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	return &p
}

// InstallEdgeCertificate installs the external CA's certificate for this
// node's pending key: it must match the key, be valid now, allow server
// authentication, and be signed by the first certificate of the chain.
func (s *Service) InstallEdgeCertificate(ctx context.Context, certPEM, chainPEM string) (*x509.Certificate, error) {
	st, err := s.edgeStore()
	if err != nil {
		return nil, err
	}
	choice, err := st.GetEdgeCertChoice(ctx)
	if err != nil {
		return nil, err
	}
	if choice.Source != edgeSourceExternal {
		return nil, mtlsRefusal{"source_not_external", "choose the external source first"}
	}
	keyPath := filepath.Join(s.edgeFiles().pending(), "tls.key")
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, mtlsRefusal{"no_pending_key", "request a CSR on this node first"}
	}
	defer pkgcrypto.Zeroize(keyRaw)
	certs, err := parsePEMCertificates(certPEM + "\n" + chainPEM)
	if err != nil || len(certs) == 0 {
		return nil, mtlsRefusal{"invalid_certificate", "certificate_pem holds no certificate"}
	}
	leaf, chain := certs[0], certs[1:]
	signer, err := parseAnyPrivateKeyPEM(string(keyRaw))
	if err != nil {
		return nil, err
	}
	if ok, err := publicKeysEqual(leaf.PublicKey, signer.Public()); err != nil || !ok {
		return nil, mtlsRefusal{"key_mismatch", "the certificate is not for this node's pending key (request a new CSR if it was replaced)"}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, mtlsRefusal{"not_valid_now", fmt.Sprintf("the certificate is valid from %s to %s", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))}
	}
	if len(leaf.ExtKeyUsage) > 0 && !containsEKU(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return nil, mtlsRefusal{"not_server_certificate", "the certificate does not allow TLS server authentication"}
	}
	if len(chain) > 0 && leaf.CheckSignatureFrom(chain[0]) != nil {
		return nil, mtlsRefusal{"bad_chain", "the first chain certificate did not sign the certificate"}
	}
	if len(chain) == 0 && leaf.CheckSignatureFrom(leaf) != nil {
		return nil, mtlsRefusal{"chain_required", "include the issuing CA certificate(s) in chain_pem"}
	}
	var out strings.Builder
	for _, c := range certs {
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if err := writeFileAtomically(filepath.Join(s.edgeDir(), "tls.crt"), []byte(out.String()), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomically(filepath.Join(s.edgeDir(), "tls.key"), keyRaw, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomically(s.edgeFiles().marker(), []byte(leaf.SerialNumber.Text(16)+"\n"), 0o600); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(s.edgeFiles().pending())
	return leaf, nil
}

func containsEKU(list []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, u := range list {
		if u == want || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func parsePEMCertificates(raw string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(raw)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out, nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

// edgeCertView is the edge certificate on this node.
type edgeCertView struct {
	Choice    edgeCertChoice `json:"choice"`
	Installed *struct {
		Serial       string    `json:"serial"`
		Subject      string    `json:"subject"`
		Issuer       string    `json:"issuer"`
		SANs         []string  `json:"sans"`
		NotAfter     time.Time `json:"not_after"`
		KeyAlgorithm string    `json:"key_algorithm"`
		FromChoice   bool      `json:"from_choice"`
	} `json:"installed,omitempty"`
	Pending *edgePending `json:"pending_csr,omitempty"`
	Served  bool         `json:"served"`
}

func (s *Service) edgeCertificateView(ctx context.Context, tenantID string, observedSerial string) edgeCertView {
	v := edgeCertView{Pending: s.edgePending()}
	if st, err := s.edgeStore(); err == nil {
		v.Choice, _ = st.GetEdgeCertChoice(ctx)
	}
	leaf, _, err := installedLeaf(s.edgeDir())
	if err != nil {
		return v
	}
	v.Installed = &struct {
		Serial       string    `json:"serial"`
		Subject      string    `json:"subject"`
		Issuer       string    `json:"issuer"`
		SANs         []string  `json:"sans"`
		NotAfter     time.Time `json:"not_after"`
		KeyAlgorithm string    `json:"key_algorithm"`
		FromChoice   bool      `json:"from_choice"`
	}{Serial: leaf.SerialNumber.Text(16), Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		SANs: append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...), NotAfter: leaf.NotAfter,
		KeyAlgorithm: algorithmFromPublicKey(leaf.PublicKey)}
	switch v.Choice.Source {
	case edgeSourceCA:
		if ca, err := s.edgeCA(ctx, tenantID, v.Choice.CAID); err == nil {
			v.Installed.FromChoice = issuedBy(leaf, ca)
		}
	case edgeSourceExternal:
		v.Installed.FromChoice = s.edgeFiles().installedExternal(leaf)
	default:
		root, err := s.runtimeRoot(ctx, tenantID)
		v.Installed.FromChoice = err == nil && issuedBy(leaf, root)
	}
	v.Served = observedSerial != "" && observedSerial == v.Installed.Serial
	return v
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
