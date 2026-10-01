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

// External listener certificates (docs/SECURITY/INTERNAL_TLS.md, "Edge
// certificate"): what Envoy's HTTPS edge and the KMIP listener serve. A root
// administrator chooses each one's source; every node's materializer
// applies the choice to its own listeners (Envoy reloads through SDS, KMIP
// on the next handshake), and certs' edge probe pins the served
// certificate to the installed one.

const (
	listenerHTTPS = "https"
	listenerKMIP  = "kmip"
)

var certListeners = []string{listenerHTTPS, listenerKMIP}

// listenerRow is the listener's row id (the HTTPS edge kept "edge").
func listenerRow(l string) string {
	if l == listenerKMIP {
		return "kmip"
	}
	return "edge"
}

// listenerDir is the listener's directory on the runtime certificate volume.
func listenerDir(l string) string {
	if l == listenerKMIP {
		return "kmip"
	}
	return "envoy"
}

// normListener validates a listener name ("" is the HTTPS edge).
func normListener(l string) (string, error) {
	switch strings.TrimSpace(l) {
	case "", listenerHTTPS:
		return listenerHTTPS, nil
	case listenerKMIP:
		return listenerKMIP, nil
	}
	return "", mtlsRefusal{"invalid_listener", fmt.Sprintf("listener %q is not one of %s", l, strings.Join(certListeners, ", "))}
}

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

func (s *SQLStore) GetEdgeCertChoice(ctx context.Context, listener string) (edgeCertChoice, error) {
	var c edgeCertChoice
	var updated interface{}
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT source, ca_id, key_algorithm, reason, updated_by, updated_at FROM cert_edge_certificate WHERE id = $1`, listenerRow(listener)).
		Scan(&c.Source, &c.CAID, &c.KeyAlgorithm, &c.Reason, &c.UpdatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return edgeCertChoice{Source: edgeSourceRuntime}, nil
	}
	c.UpdatedAt = parseTimeValue(updated)
	return c, err
}

func (s *SQLStore) UpsertEdgeCertChoice(ctx context.Context, listener string, c edgeCertChoice) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_edge_certificate (id, source, ca_id, key_algorithm, reason, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET source = EXCLUDED.source, ca_id = EXCLUDED.ca_id, key_algorithm = EXCLUDED.key_algorithm,
	reason = EXCLUDED.reason, updated_by = EXCLUDED.updated_by, updated_at = CURRENT_TIMESTAMP`,
		listenerRow(listener), c.Source, c.CAID, c.KeyAlgorithm, c.Reason, c.UpdatedBy)
	return err
}

type edgeCertStore interface {
	GetEdgeCertChoice(ctx context.Context, listener string) (edgeCertChoice, error)
	UpsertEdgeCertChoice(ctx context.Context, listener string, c edgeCertChoice) error
}

func (s *Service) edgeStore() (edgeCertStore, error) {
	st, ok := s.store.(edgeCertStore)
	if !ok {
		return nil, errors.New("the edge certificate needs the SQL store")
	}
	return st, nil
}

// edgeFiles are a listener's files under base. base is the runtime
// certificate volume the listener reads (the materializer directory), which
// is tmpfs and empty after a restart, or this node's kept copy of what certs
// can't issue again: an external certificate with its key, and the key of a
// pending CSR (keptFor).
type edgeFiles struct{ base, name string }

func filesFor(base, listener string) edgeFiles { return edgeFiles{base, listenerDir(listener)} }

const defaultEdgeExternalDir = "/var/lib/vecta/certs/edge"

// keptFor is this node's kept copy, on the certs key volume. It never leaves
// the node.
func keptFor(cfg RuntimeCertMaterializerConfig, listener string) edgeFiles {
	dir := strings.TrimSpace(cfg.ExternalDir)
	if dir == "" {
		dir = defaultEdgeExternalDir
	}
	return filesFor(dir, listener)
}

func (b edgeFiles) dir() string     { return filepath.Join(b.base, b.name) }
func (b edgeFiles) pending() string { return filepath.Join(b.base, b.name+"-pending") }

// marker records the serial of the external certificate installed on this
// node, so it is never confused with one certs issued.
func (b edgeFiles) marker() string { return filepath.Join(b.base, b.name+"-external.serial") }

// issued lists, in this node's kept copy, the certificate certs last issued
// for the listener ("-" while an external one is installed) and then any it
// replaced that are not revoked yet.
func (b edgeFiles) issued() string { return filepath.Join(b.base, b.name+".issued") }

// recordIssued puts id first in the issued list.
func (b edgeFiles) recordIssued(id string) error {
	raw, _ := os.ReadFile(b.issued())
	ids := []string{id}
	for _, old := range strings.Fields(string(raw)) {
		if old != id && old != "-" {
			ids = append(ids, old)
		}
	}
	return writeFileAtomically(b.issued(), []byte(strings.Join(ids, "\n")+"\n"), 0o600)
}

// revokeReplacedEdge revokes the certificates this node's listener no longer
// serves. The runtime directory is tmpfs, so their keys are gone: nothing
// can present them, and the inventory must not list them as active. One
// that can't be revoked now stays listed and is tried on the next pass.
func (s *Service) revokeReplacedEdge(ctx context.Context, tenantID string, kept edgeFiles) {
	raw, err := os.ReadFile(kept.issued())
	ids := strings.Fields(string(raw))
	if err != nil || len(ids) < 2 {
		return
	}
	left := ids[:1]
	for _, id := range ids[1:] {
		c, err := s.store.GetCertificate(ctx, tenantID, id)
		if err == nil && strings.EqualFold(strings.TrimSpace(c.Status), CertStatusActive) {
			err = s.RevokeCertificate(ctx, RevokeCertificateRequest{TenantID: tenantID, CertID: id, Reason: "superseded"})
		}
		if err != nil {
			left = append(left, id)
		}
	}
	_ = writeFileAtomically(kept.issued(), []byte(strings.Join(left, "\n")+"\n"), 0o600)
}

func (s *Service) edgeFiles(listener string) edgeFiles {
	return filesFor(s.runtimeCfg.MaterializeDir, listener)
}
func (s *Service) edgeKept(listener string) edgeFiles { return keptFor(s.runtimeCfg, listener) }
func (s *Service) edgeDir() string                    { return s.edgeFiles(listenerHTTPS).dir() }

func (b edgeFiles) installedExternal(leaf *x509.Certificate) bool {
	raw, err := os.ReadFile(b.marker())
	return err == nil && leaf != nil && strings.TrimSpace(string(raw)) == leaf.SerialNumber.Text(16)
}

// writeExternal writes an external certificate (chain is the leaf and its
// issuers) and its key under b.
func (b edgeFiles) writeExternal(key, chain []byte, leaf *x509.Certificate) error {
	// Key first: a reader that sees the new certificate finds its key.
	if err := writeFileAtomically(filepath.Join(b.dir(), "tls.key"), key, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomically(filepath.Join(b.dir(), "tls.crt"), chain, 0o600); err != nil {
		return err
	}
	return writeFileAtomically(b.marker(), []byte(leaf.SerialNumber.Text(16)+"\n"), 0o600)
}

// discardExternal removes the external certificate and its key under b. A
// pending CSR key is left: it has no certificate yet.
func (b edgeFiles) discardExternal() {
	_ = os.RemoveAll(b.dir())
	_ = os.Remove(b.marker())
}

// restoreExternal copies this node's kept external certificate into the
// runtime directory and returns its leaf, or nil if there is none to serve.
// A kept copy that expired or isn't an installed external certificate is
// discarded; one whose key can't be read is left for the operator, and the
// listener falls back to a runtime-root certificate.
func (b edgeFiles) restoreExternal(runtime edgeFiles) (*x509.Certificate, error) {
	leaf, chain, err := installedLeaf(b.dir())
	if err != nil {
		return nil, nil
	}
	if !b.installedExternal(leaf) || !time.Now().Before(leaf.NotAfter) {
		b.discardExternal()
		return nil, nil
	}
	key, err := os.ReadFile(filepath.Join(b.dir(), "tls.key"))
	if err != nil {
		return nil, nil
	}
	defer pkgcrypto.Zeroize(key)
	return leaf, runtime.writeExternal(key, chain, leaf)
}

type edgePending struct {
	SubjectCN    string    `json:"subject_cn"`
	SANs         []string  `json:"sans"`
	KeyAlgorithm string    `json:"key_algorithm"`
	CSRPEM       string    `json:"csr_pem"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
}

func edgeIdentity(cfg RuntimeCertMaterializerConfig, listener string) (string, []string) {
	cn, sans, host := cfg.EnvoyCN, cfg.EnvoySANs, "envoy"
	if listener == listenerKMIP {
		cn, sans, host = cfg.KMIPCN, cfg.KMIPSANs, "kmip"
	}
	cn = strings.TrimSpace(cn)
	if cn == "" {
		cn = "vecta-" + host
	}
	sans = dedupStrings(append([]string{}, sans...))
	if len(sans) == 0 {
		sans = []string{"localhost", host, "127.0.0.1"}
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

// writeEdgeCert issues the listener's certificate from ca and installs it.
func (s *Service) writeEdgeCert(ctx context.Context, tenantID string, ca CA, algorithm string, cfg RuntimeCertMaterializerConfig, listener string) error {
	cn, sans := edgeIdentity(cfg, listener)
	chain, err := s.caChainPEM(ctx, tenantID, ca)
	if err != nil {
		return err
	}
	days := cfg.ValidityDays
	if days <= 0 {
		days = 90
	}
	issued, err := s.writeRuntimeEndpointCert(ctx, tenantID, ca, filesFor(cfg.MaterializeDir, listener).dir(), algorithm, "tls-server", cn, sans, days, chain)
	if err != nil {
		return err
	}
	kept := keptFor(cfg, listener)
	if err := kept.recordIssued(issued.ID); err != nil {
		return err
	}
	s.revokeReplacedEdge(ctx, tenantID, kept)
	return nil
}

// applyEdgeCertificate makes this node's listener serve the chosen source,
// renewing before expiry. force reissues now (after a change).
func (s *Service) applyEdgeCertificate(ctx context.Context, tenantID string, runtimeRoot CA, cfg RuntimeCertMaterializerConfig, force bool, listener string) error {
	st, err := s.edgeStore()
	if err != nil {
		return err
	}
	choice, err := st.GetEdgeCertChoice(ctx, listener)
	if err != nil {
		return err
	}
	files := filesFor(cfg.MaterializeDir, listener)
	dir := files.dir()
	renewBefore := cfg.RenewBefore
	if renewBefore <= 0 {
		renewBefore = 24 * time.Hour
	}
	leaf, _, _ := installedLeaf(dir)
	due := force || leaf == nil || runtimeCertNeedsRenew(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), renewBefore)
	kept := keptFor(cfg, listener)
	s.revokeReplacedEdge(ctx, tenantID, kept)
	if choice.Source != edgeSourceExternal {
		// Leaving the external source ends that certificate on this node.
		kept.discardExternal()
	}
	switch choice.Source {
	case edgeSourceCA:
		ca, err := s.edgeCA(ctx, tenantID, choice.CAID)
		if err != nil {
			return err
		}
		if due || !issuedBy(leaf, ca) || !sameKeyLabel(fileKeyAlgorithm(filepath.Join(dir, "tls.crt")), choice.KeyAlgorithm) {
			return s.writeEdgeCert(ctx, tenantID, ca, choice.KeyAlgorithm, cfg, listener)
		}
		return nil
	case edgeSourceExternal:
		// This node's own key and its external certificate, once installed.
		// Until then (or once it expires) the edge keeps a runtime-root
		// certificate rather than go dark.
		if files.installedExternal(leaf) && time.Now().Before(leaf.NotAfter) {
			return nil
		}
		// The runtime directory is tmpfs: after a restart the installed
		// certificate comes back from this node's kept copy.
		restored, err := kept.restoreExternal(files)
		if err != nil {
			return err
		}
		if restored != nil {
			_ = s.publishAudit(ctx, "audit.certs.edge_tls_certificate_restored", tenantID, map[string]interface{}{
				"target_id": listener, "listener": listener, "result": "success",
				"serial": restored.SerialNumber.Text(16), "subject": restored.Subject.String(),
				"issuer": restored.Issuer.String(), "not_after": restored.NotAfter.UTC().Format(time.RFC3339),
				"description": "the external " + listener + " certificate was restored from this node's kept copy after a restart",
			})
			return nil
		}
	}
	if due || leaf == nil || !issuedBy(leaf, runtimeRoot) {
		return s.writeEdgeCert(ctx, tenantID, runtimeRoot, "RSA-3072", cfg, listener)
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
func (s *Service) SetEdgeCertificateSource(ctx context.Context, tenantID, listener string, next edgeCertChoice) (edgeCertChoice, edgeCertChoice, error) {
	st, err := s.edgeStore()
	if err != nil {
		return edgeCertChoice{}, edgeCertChoice{}, err
	}
	if listener, err = normListener(listener); err != nil {
		return edgeCertChoice{}, next, err
	}
	prev, err := st.GetEdgeCertChoice(ctx, listener)
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
		return prev, next, mtlsRefusal{"unchanged", "the " + listener + " certificate already comes from " + next.Source}
	}
	if err := st.UpsertEdgeCertChoice(ctx, listener, next); err != nil {
		return prev, next, err
	}
	root, err := s.runtimeRoot(ctx, tenantID)
	if err != nil {
		return prev, next, err
	}
	if err := s.applyEdgeCertificate(ctx, tenantID, root, s.runtimeCfg, next.Source != edgeSourceExternal, listener); err != nil {
		return prev, next, fmt.Errorf("apply on this node: %w", err)
	}
	return prev, next, nil
}

// CreateEdgeCSR generates this node's edge key and returns a CSR for an
// external CA. The key stays in this node's pending directory (in its kept
// copy, so a restart doesn't lose it) until the signed certificate is
// installed; a new CSR replaces it.
func (s *Service) CreateEdgeCSR(ctx context.Context, listener, subjectCN string, sans []string, algorithm, actor string) (edgePending, error) {
	st, err := s.edgeStore()
	if err != nil {
		return edgePending{}, err
	}
	if listener, err = normListener(listener); err != nil {
		return edgePending{}, err
	}
	choice, err := st.GetEdgeCertChoice(ctx, listener)
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
	if err := writeFileAtomically(filepath.Join(s.edgeKept(listener).pending(), "tls.key"), keyBytes, 0o600); err != nil {
		return edgePending{}, err
	}
	if err := writeFileAtomically(filepath.Join(s.edgeKept(listener).pending(), "pending.json"), meta, 0o600); err != nil {
		return edgePending{}, err
	}
	return p, nil
}

func (s *Service) edgePending(listener string) *edgePending {
	raw, err := os.ReadFile(filepath.Join(s.edgeKept(listener).pending(), "pending.json"))
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
func (s *Service) InstallEdgeCertificate(ctx context.Context, listener, certPEM, chainPEM string) (*x509.Certificate, error) {
	st, err := s.edgeStore()
	if err != nil {
		return nil, err
	}
	if listener, err = normListener(listener); err != nil {
		return nil, err
	}
	files, kept := s.edgeFiles(listener), s.edgeKept(listener)
	choice, err := st.GetEdgeCertChoice(ctx, listener)
	if err != nil {
		return nil, err
	}
	if choice.Source != edgeSourceExternal {
		return nil, mtlsRefusal{"source_not_external", "choose the external source first"}
	}
	keyPath := filepath.Join(kept.pending(), "tls.key")
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
	// The kept copy first: the runtime directory is refilled from it after a
	// restart.
	for _, dst := range []edgeFiles{kept, files} {
		if err := dst.writeExternal(keyRaw, []byte(out.String()), leaf); err != nil {
			return nil, err
		}
	}
	_ = os.RemoveAll(kept.pending())
	// The certificate certs had issued for this listener is replaced.
	if err := kept.recordIssued("-"); err != nil {
		return nil, err
	}
	s.revokeReplacedEdge(ctx, s.internalTenant(), kept)
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

// edgeCertView is a listener's certificate on this node.
type edgeCertView struct {
	Listener  string         `json:"listener"`
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

func (s *Service) edgeCertificateView(ctx context.Context, tenantID, listener string, observedSerial string) edgeCertView {
	v := edgeCertView{Listener: listener, Pending: s.edgePending(listener)}
	if st, err := s.edgeStore(); err == nil {
		v.Choice, _ = st.GetEdgeCertChoice(ctx, listener)
	}
	leaf, _, err := installedLeaf(s.edgeFiles(listener).dir())
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
		v.Installed.FromChoice = s.edgeFiles(listener).installedExternal(leaf)
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
