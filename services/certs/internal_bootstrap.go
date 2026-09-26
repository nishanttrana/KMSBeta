package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/svctls"
)

// Internal PKI before the database (docs/SECURITY/INTERNAL_TLS.md).
//
// Postgres, NATS, Valkey and Consul only accept mTLS with certificates from
// the internal-services Sub CA, and the certs service stores its CAs in
// Postgres. To break that cycle the runtime root and the Sub CA are also kept
// in a cache file on the certs key volume. Their signing keys stay wrapped by
// the certs root wrapping key (CRWK), exactly as in the database rows. At
// start the certs service loads (or, on a fresh install, creates) them from
// the cache, issues its own certificate and the infrastructure server
// certificates, and only then connects to Postgres and NATS. The CAs and the
// certificates issued before the database are then recorded there.

const defaultPKICachePath = "/var/lib/vecta/certs/internal-pki.json"

// cachedCA is a cert_cas row. Byte columns are hex with a \x prefix, the form
// psql's row_to_json produces, so an export from an existing database loads
// as is.
type cachedCA struct {
	ID                 string `json:"id"`
	TenantID           string `json:"tenant_id"`
	Name               string `json:"name"`
	ParentCAID         string `json:"parent_ca_id"`
	CALevel            string `json:"ca_level"`
	Algorithm          string `json:"algorithm"`
	CAType             string `json:"ca_type"`
	KeyBackend         string `json:"key_backend"`
	KeyRef             string `json:"key_ref"`
	CertPEM            string `json:"cert_pem"`
	Subject            string `json:"subject"`
	Status             string `json:"status"`
	SignerWrappedDEK   string `json:"signer_wrapped_dek"`
	SignerWrappedDEKIV string `json:"signer_wrapped_dek_iv"`
	SignerCiphertext   string `json:"signer_ciphertext"`
	SignerDataIV       string `json:"signer_data_iv"`
	SignerKeyVersion   string `json:"signer_kek_version"`
	SignerFingerprint  string `json:"signer_fingerprint_sha256"`
}

type pkiCache struct {
	Root *cachedCA `json:"root"`
	Sub  *cachedCA `json:"sub"`
}

func pgHex(b []byte) string { return `\x` + hex.EncodeToString(b) }

func unPGHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), `\x`))
}

func cacheFromCA(ca CA) *cachedCA {
	return &cachedCA{
		ID: ca.ID, TenantID: ca.TenantID, Name: ca.Name, ParentCAID: ca.ParentCAID, CALevel: ca.CALevel,
		Algorithm: ca.Algorithm, CAType: ca.CAType, KeyBackend: ca.KeyBackend, KeyRef: ca.KeyRef,
		CertPEM: ca.CertPEM, Subject: ca.Subject, Status: ca.Status,
		SignerWrappedDEK: pgHex(ca.SignerWrappedDEK), SignerWrappedDEKIV: pgHex(ca.SignerWrappedDEKIV),
		SignerCiphertext: pgHex(ca.SignerCiphertext), SignerDataIV: pgHex(ca.SignerDataIV),
		SignerKeyVersion: ca.SignerKeyVersion, SignerFingerprint: ca.SignerFingerprint,
	}
}

func (c *cachedCA) toCA() (CA, error) {
	var err error
	ca := CA{
		ID: c.ID, TenantID: c.TenantID, Name: c.Name, ParentCAID: c.ParentCAID, CALevel: c.CALevel,
		Algorithm: c.Algorithm, CAType: c.CAType, KeyBackend: c.KeyBackend, KeyRef: c.KeyRef,
		CertPEM: c.CertPEM, Subject: c.Subject, Status: c.Status,
		SignerKeyVersion: c.SignerKeyVersion, SignerFingerprint: c.SignerFingerprint,
	}
	for dst, src := range map[*[]byte]string{
		&ca.SignerWrappedDEK: c.SignerWrappedDEK, &ca.SignerWrappedDEKIV: c.SignerWrappedDEKIV,
		&ca.SignerCiphertext: c.SignerCiphertext, &ca.SignerDataIV: c.SignerDataIV,
	} {
		if *dst, err = unPGHex(src); err != nil {
			return CA{}, fmt.Errorf("internal PKI cache: CA %s: %w", c.Name, err)
		}
	}
	return ca, nil
}

func loadPKICache(path string) (pkiCache, bool, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return pkiCache{}, false, nil
	}
	if err != nil {
		return pkiCache{}, false, err
	}
	var c pkiCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return pkiCache{}, false, fmt.Errorf("internal PKI cache %s: %w", path, err)
	}
	return c, c.Root != nil, nil
}

func savePKICache(path string, root, sub CA) error {
	raw, err := json.Marshal(pkiCache{Root: cacheFromCA(root), Sub: cacheFromCA(sub)})
	if err != nil {
		return err
	}
	return writeFileAtomically(path, raw, 0o600)
}

// bootstrapPKI issues internal certificates before the database, then
// records them there and hands issuance over to the normal path.
type bootstrapPKI struct {
	svc       *Service
	tenant    string
	cachePath string
	root, sub CA
	created   []string

	mu      sync.Mutex
	issued  []Certificate
	dbReady atomic.Bool
}

// BootstrapInternalPKI loads the runtime root and internal-services Sub CA
// from the cache, creating what is missing, and writes the cache back.
func (s *Service) BootstrapInternalPKI(tenant, cachePath string) (*bootstrapPKI, error) {
	b := &bootstrapPKI{svc: s, tenant: tenant, cachePath: cachePath}
	cache, ok, err := loadPKICache(cachePath)
	if err != nil {
		return nil, err
	}
	if ok {
		if b.root, err = cache.Root.toCA(); err != nil {
			return nil, err
		}
	} else {
		if b.root, err = s.bootstrapCA(tenant, defaultRuntimeRootCANameFromEnv(), nil); err != nil {
			return nil, fmt.Errorf("create runtime root CA: %w", err)
		}
		b.created = append(b.created, b.root.Name)
	}
	if ok && cache.Sub != nil {
		if b.sub, err = cache.Sub.toCA(); err != nil {
			return nil, err
		}
	} else {
		if b.sub, err = s.bootstrapCA(tenant, internalSubCAName(), &b.root); err != nil {
			return nil, fmt.Errorf("create internal-services Sub CA: %w", err)
		}
		b.created = append(b.created, b.sub.Name)
	}
	if err := b.verifyChain(); err != nil {
		return nil, err
	}
	if !ok || cache.Sub == nil {
		if err := savePKICache(cachePath, b.root, b.sub); err != nil {
			return nil, fmt.Errorf("write internal PKI cache: %w", err)
		}
	}
	return b, nil
}

func (s *Service) bootstrapCA(tenant, name string, parent *CA) (CA, error) {
	req := CreateCARequest{
		TenantID: tenant, Name: name, CALevel: "root", Algorithm: "ECDSA-P384", CAType: "classical",
		KeyBackend: "software", Subject: fmt.Sprintf("CN=%s,O=Vecta KMS Runtime", name), ValidityDays: 3650,
	}
	if parent != nil {
		req.CALevel, req.ParentCAID, req.ValidityDays = "intermediate", parent.ID, 1825
		req.Subject = fmt.Sprintf("CN=%s,O=Vecta KMS Internal", name)
	}
	signer, signerPEM, err := generateSigningKey(req.Algorithm)
	if err != nil {
		return CA{}, err
	}
	defer zeroizeString(&signerPEM)
	enc, err := s.encryptSigner([]byte(signerPEM))
	if err != nil {
		return CA{}, err
	}
	return s.mintCA(req, newID("ca"), signer, enc, parent)
}

func (b *bootstrapPKI) verifyChain() error {
	if !strings.EqualFold(b.root.Status, CAStatusActive) || !strings.EqualFold(b.sub.Status, CAStatusActive) {
		return errors.New("internal PKI cache holds an inactive CA")
	}
	if b.sub.ParentCAID != b.root.ID {
		return errors.New("internal PKI cache: the Sub CA is not under the runtime root")
	}
	rootCert, err := parseCertificatePEM(b.root.CertPEM)
	if err != nil {
		return err
	}
	subCert, err := parseCertificatePEM(b.sub.CertPEM)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	if _, err := subCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("internal PKI cache: Sub CA does not chain to the root: %w", err)
	}
	return nil
}

// issue signs a leaf under the Sub CA without the database; the record is
// kept until Reconcile stores it.
func (b *bootstrapPKI) issue(pub crypto.PublicKey, alg, cn string, sans []string, certType string, days int64) (Certificate, error) {
	signer, err := b.svc.loadCASigner(b.sub)
	if err != nil {
		return Certificate{}, fmt.Errorf("internal Sub CA signer: %w", err)
	}
	issuer, err := parseCertificatePEM(b.sub.CertPEM)
	if err != nil {
		return Certificate{}, err
	}
	serial, err := pkgcrypto.RandomInt(new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return Certificate{}, err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  selectExtKeyUsage(certType),
	}
	tpl.DNSNames, tpl.IPAddresses = splitSANs(sans)
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, issuer, pub, signer)
	if err != nil {
		return Certificate{}, err
	}
	c := Certificate{
		ID: newID("crt"), TenantID: b.tenant, CAID: b.sub.ID, SerialNumber: serial.Text(16),
		SubjectCN: cn, SANs: sans, CertType: certType, Algorithm: alg,
		Protocol: "internal-mtls", CertClass: "internal-mtls",
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Status:  CertStatusActive, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter,
	}
	b.mu.Lock()
	b.issued = append(b.issued, c)
	b.mu.Unlock()
	return c, nil
}

// Enroll implements svctls.Enroller: bootstrap issuance until the database
// is up, the normal CSR path afterwards.
func (b *bootstrapPKI) Enroll(ctx context.Context, identity string, csrDER []byte) (svctls.EnrollResponse, error) {
	if b.dbReady.Load() {
		return b.svc.EnrollInternal(ctx, b.tenant, identity, csrDER)
	}
	host, ok := svctls.HostFor(identity)
	if !ok {
		return svctls.EnrollResponse{}, fmt.Errorf("unknown identity %q", identity)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return svctls.EnrollResponse{}, errors.New("invalid CSR")
	}
	alg, err := svctls.KeyAlgorithm(csr.PublicKey)
	if err != nil {
		return svctls.EnrollResponse{}, err
	}
	c, err := b.issue(csr.PublicKey, alg, identity, []string{host, identity}, "tls-server", internalCertValidityDays())
	if err != nil {
		return svctls.EnrollResponse{}, err
	}
	return svctls.EnrollResponse{CertificatePEM: c.CertPEM, ChainPEM: b.sub.CertPEM, Serial: c.SerialNumber, NotAfter: c.NotAfter}, nil
}

// WriteInfraCerts issues each infrastructure server (Postgres, NATS, Valkey,
// Consul) a Sub CA certificate into dir/<host>/, unless a valid one exists.
// The key is generated here: these daemons can't enrol themselves.
func (b *bootstrapPKI) WriteInfraCerts(dir string) error {
	for identity, host := range svctls.Infrastructure {
		out := filepath.Join(dir, host)
		if !runtimeCertNeedsRenew(filepath.Join(out, "tls.crt"), filepath.Join(out, "tls.key"), time.Duration(internalCertValidityDays())*24*time.Hour/3) {
			continue
		}
		kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(kp.Private)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pkgcrypto.Zeroize(keyDER)
		c, err := b.issue(kp.Public, pkgcrypto.AlgECDSAP256, identity, []string{host, identity}, infraCertType(host), internalCertValidityDays())
		if err != nil {
			return err
		}
		if err := writeFileAtomically(filepath.Join(out, "tls.crt"), []byte(strings.TrimSpace(c.CertPEM)+"\n"+strings.TrimSpace(b.sub.CertPEM)+"\n"), 0o600); err != nil {
			return err
		}
		err = writeFileAtomically(filepath.Join(out, "tls.key"), keyPEM, 0o600)
		pkgcrypto.Zeroize(keyPEM)
		if err != nil {
			return err
		}
	}
	return nil
}

// Reconcile records the cached CAs and the bootstrap-issued certificates in
// the database, then switches issuance to the database path. A database
// that holds a different active CA under the same name is refused: the cache
// and the database must describe the same PKI.
func (b *bootstrapPKI) Reconcile(ctx context.Context) error {
	store := b.svc.store
	for _, ca := range []CA{b.root, b.sub} {
		existing, err := store.GetCA(ctx, b.tenant, ca.ID)
		switch {
		case err == nil:
			if strings.TrimSpace(existing.CertPEM) != strings.TrimSpace(ca.CertPEM) {
				return fmt.Errorf("CA %s: the database certificate differs from the internal PKI cache", ca.Name)
			}
			continue
		case !errors.Is(err, errStoreNotFound):
			return err
		}
		all, err := store.ListCAs(ctx, b.tenant)
		if err != nil {
			return err
		}
		for _, other := range all {
			if strings.EqualFold(other.Name, ca.Name) && strings.EqualFold(other.Status, CAStatusActive) {
				return fmt.Errorf("the database has another active CA named %s (%s) than the internal PKI cache (%s)", ca.Name, other.ID, ca.ID)
			}
		}
		if err := store.CreateCA(ctx, ca); err != nil {
			return fmt.Errorf("record CA %s: %w", ca.Name, err)
		}
	}
	b.mu.Lock()
	issued := b.issued
	b.issued = nil
	b.mu.Unlock()
	for _, c := range issued {
		if err := store.CreateCertificate(ctx, c); err != nil {
			return fmt.Errorf("record bootstrap certificate %s: %w", c.SubjectCN, err)
		}
	}
	b.svc.internalPKI = b
	b.dbReady.Store(true)
	_ = b.svc.publishAudit(ctx, "audit.cert.internal_pki_bootstrapped", b.tenant, map[string]interface{}{
		"root_ca_id": b.root.ID, "sub_ca_id": b.sub.ID, "created": b.created, "issued_before_database": len(issued),
		"description": "internal PKI loaded before the database; CAs and bootstrap certificates recorded",
	})
	return nil
}

// infraCertType: server authentication only, except Consul, which also
// presents its certificate as a client on its internal RPC (verify_outgoing).
func infraCertType(host string) string {
	if host == "consul" {
		return "tls-server"
	}
	return "tls-server-only"
}
