package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"

	"golang.org/x/crypto/ocsp"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	oidVectaMeta                     = []int{1, 3, 6, 1, 4, 1, 55555, 7, 1}
	oidVectaComposite                = []int{1, 3, 6, 1, 4, 1, 55555, 7, 2}
	oidVectaOTSIndex                 = []int{1, 3, 6, 1, 4, 1, 55555, 7, 3}
	defaultValidityCA          int64 = 3650
	defaultValidityLeaf        int64 = 397
	defaultCertExpiryAlertDays       = 30
)

const (
	protocolACME   = "acme"
	protocolEST    = "est"
	protocolSCEP   = "scep"
	protocolCMPv2  = "cmpv2"
	protocolRTMTLS = "runtime-mtls"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store             Store
	events            EventPublisher
	keycore           KeyCoreSigner
	mek               []byte
	securityProvider  certRootKeyProvider
	certStorageMode   string
	rootKeyMode       string
	securityInitError string
	fipsStrict        bool
	keycoreFailClosed bool
}

type RuntimeCertMaterializerConfig struct {
	Enabled        bool
	MaterializeDir string
	TenantID       string
	RootCAName     string
	ValidityDays   int64
	Interval       time.Duration
	RenewBefore    time.Duration
	EnvoyCN        string
	EnvoySANs      []string
	KMIPCN         string
	KMIPSANs       []string
}

func NewService(store Store, events EventPublisher, keycore KeyCoreSigner, mek []byte, fipsStrict bool, keycoreFailClosed bool) *Service {
	cfg := ServiceSecurityConfig{
		CertStorageMode: "legacy",
		RootKeyMode:     "legacy",
		LegacyMEK:       mek,
	}
	return NewServiceWithSecurity(store, events, keycore, cfg, fipsStrict, keycoreFailClosed)
}

type ServiceSecurityConfig struct {
	CertStorageMode string
	RootKeyMode     string
	RootProvider    certRootKeyProvider
	SecurityErr     string
	LegacyMEK       []byte
}

func NewServiceWithSecurity(store Store, events EventPublisher, keycore KeyCoreSigner, sec ServiceSecurityConfig, fipsStrict bool, keycoreFailClosed bool) *Service {
	if keycore == nil {
		keycore = NoopKeyCoreSigner{}
	}
	legacyMEK := sec.LegacyMEK
	if len(legacyMEK) < 32 {
		sum := sha256.Sum256([]byte("vecta-certs-dev-mek"))
		legacyMEK = sum[:]
	}
	return &Service{
		store:             store,
		events:            events,
		keycore:           keycore,
		mek:               append([]byte{}, legacyMEK[:32]...),
		securityProvider:  sec.RootProvider,
		certStorageMode:   normalizeStorageMode(sec.CertStorageMode),
		rootKeyMode:       normalizeRootKeyMode(sec.RootKeyMode),
		securityInitError: strings.TrimSpace(sec.SecurityErr),
		fipsStrict:        fipsStrict,
		keycoreFailClosed: keycoreFailClosed,
	}
}

func (s *Service) CreateCA(ctx context.Context, req CreateCARequest) (CA, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.CALevel = normalizeCALevel(req.CALevel)
	req.Algorithm = normalizeAlgorithm(req.Algorithm)
	req.KeyBackend = normalizeKeyBackend(req.KeyBackend)
	req.Subject = strings.TrimSpace(req.Subject)
	req.CAType = normalizeCAType(req.CAType, req.Algorithm)
	if req.ValidityDays <= 0 {
		req.ValidityDays = defaultValidityCA
	}
	if req.OTSMax < 0 {
		req.OTSMax = 0
	}
	if req.OTSAlertThreshold < 0 {
		req.OTSAlertThreshold = 0
	}
	if req.TenantID == "" || req.Name == "" || req.CALevel == "" || req.Algorithm == "" {
		return CA{}, errors.New("tenant_id, name, ca_level, algorithm are required")
	}
	if err := s.enforceFIPS(req.Algorithm); err != nil {
		return CA{}, err
	}
	if req.CALevel == "intermediate" && strings.TrimSpace(req.ParentCAID) == "" {
		return CA{}, errors.New("parent_ca_id is required for intermediate CA")
	}
	if req.CALevel == "root" {
		req.ParentCAID = ""
	}

	caID := newID("ca")
	if req.KeyBackend == "keycore" {
		ref, err := s.keycore.EnsureKey(ctx, req.TenantID, req.KeyRef, req.Algorithm, req.Name+"-ca")
		if err != nil {
			return CA{}, err
		}
		req.KeyRef = ref
	}

	signer, signerPEM, err := generateSigningKey(req.Algorithm)
	if err != nil {
		return CA{}, err
	}
	defer zeroizeString(&signerPEM)
	encSigner, err := s.encryptSigner([]byte(signerPEM))
	if err != nil {
		return CA{}, err
	}

	subject := parseSubject(req.Subject, req.Name)
	now := time.Now().UTC()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	addCertMetaExtensions(tpl, req.Algorithm, req.CAType, 0, nil)

	parentTpl := tpl
	parentSigner := signer
	if req.CALevel == "intermediate" {
		parent, err := s.store.GetCA(ctx, req.TenantID, req.ParentCAID)
		if err != nil {
			return CA{}, err
		}
		if parent.Status != CAStatusActive {
			return CA{}, errors.New("parent ca is not active")
		}
		parentCert, err := parseCertificatePEM(parent.CertPEM)
		if err != nil {
			return CA{}, err
		}
		parentKey, err := s.loadCASigner(parent)
		if err != nil {
			return CA{}, err
		}
		parentTpl = parentCert
		parentSigner = parentKey
		tpl.MaxPathLen = 1
	}

	if _, err := s.signWithKeyCoreIfConfigured(ctx, req.TenantID, req.KeyBackend, req.KeyRef, buildCASigningIntent(req)); err != nil {
		return CA{}, err
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentTpl, signer.Public(), parentSigner)
	if err != nil {
		return CA{}, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	ca := CA{
		ID:                 caID,
		TenantID:           req.TenantID,
		Name:               req.Name,
		ParentCAID:         req.ParentCAID,
		CALevel:            req.CALevel,
		Algorithm:          req.Algorithm,
		CAType:             req.CAType,
		KeyBackend:         req.KeyBackend,
		KeyRef:             req.KeyRef,
		CertPEM:            certPEM,
		Subject:            req.Subject,
		Status:             CAStatusActive,
		OTSCurrent:         0,
		OTSMax:             req.OTSMax,
		OTSAlertThreshold:  req.OTSAlertThreshold,
		SignerWrappedDEK:   encSigner.WrappedDEK,
		SignerWrappedDEKIV: encSigner.WrappedDEKIV,
		SignerCiphertext:   encSigner.Ciphertext,
		SignerDataIV:       encSigner.DataIV,
		SignerKeyVersion:   encSigner.KeyVersion,
		SignerFingerprint:  encSigner.Fingerprint,
	}
	if err := s.store.CreateCA(ctx, ca); err != nil {
		return CA{}, err
	}
	out, err := s.store.GetCA(ctx, req.TenantID, caID)
	if err != nil {
		return CA{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.ca_created", req.TenantID, map[string]interface{}{
		"ca_id":       out.ID,
		"ca_level":    out.CALevel,
		"algorithm":   out.Algorithm,
		"ca_type":     out.CAType,
		"key_backend": out.KeyBackend,
	})
	return out, nil
}

func (s *Service) ListCAs(ctx context.Context, tenantID string) ([]CA, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	// Ensure a runtime root CA exists per tenant. The tenant can choose default
	// root naming or a custom runtime root through runtime-mtls configuration.
	rootName := s.runtimeRootCAName(ctx, tenantID)
	_, _ = s.ensureRuntimeRootCA(ctx, tenantID, rootName)
	return s.store.ListCAs(ctx, tenantID)
}

func (s *Service) CreateProfile(ctx context.Context, req CreateProfileRequest) (CertificateProfile, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.CertType = defaultString(req.CertType, "tls-server")
	req.Algorithm = normalizeAlgorithm(req.Algorithm)
	req.CertClass = normalizeCertClass(req.CertClass, req.Algorithm)
	if req.TenantID == "" || req.Name == "" || req.Algorithm == "" {
		return CertificateProfile{}, errors.New("tenant_id, name, algorithm are required")
	}
	if err := s.enforceFIPS(req.Algorithm); err != nil {
		return CertificateProfile{}, err
	}
	p := CertificateProfile{
		ID:          newID("cpf"),
		TenantID:    req.TenantID,
		Name:        req.Name,
		CertType:    req.CertType,
		Algorithm:   req.Algorithm,
		CertClass:   req.CertClass,
		ProfileJSON: defaultString(strings.TrimSpace(req.ProfileJSON), "{}"),
		IsDefault:   req.IsDefault,
	}
	if err := s.store.CreateProfile(ctx, p); err != nil {
		return CertificateProfile{}, err
	}
	out, err := s.store.GetProfile(ctx, req.TenantID, p.ID)
	if err != nil {
		return CertificateProfile{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.profile_created", req.TenantID, map[string]interface{}{
		"profile_id": out.ID,
		"name":       out.Name,
		"algorithm":  out.Algorithm,
		"class":      out.CertClass,
	})
	return out, nil
}

func (s *Service) ListProfiles(ctx context.Context, tenantID string) ([]CertificateProfile, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if err := s.ensureDefaultProfiles(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.store.ListProfiles(ctx, tenantID)
}

func (s *Service) GetProfile(ctx context.Context, tenantID string, profileID string) (CertificateProfile, error) {
	tenantID = strings.TrimSpace(tenantID)
	profileID = strings.TrimSpace(profileID)
	if tenantID == "" || profileID == "" {
		return CertificateProfile{}, errors.New("tenant_id and profile_id are required")
	}
	if err := s.ensureDefaultProfiles(ctx, tenantID); err != nil {
		return CertificateProfile{}, err
	}
	return s.store.GetProfile(ctx, tenantID, profileID)
}

func (s *Service) IssueCertificate(ctx context.Context, req IssueCertificateRequest) (Certificate, string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CAID = strings.TrimSpace(req.CAID)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.CertType = defaultString(strings.TrimSpace(req.CertType), "tls-server")
	req.Algorithm = normalizeAlgorithm(req.Algorithm)
	req.Protocol = defaultString(strings.TrimSpace(req.Protocol), "rest")
	req.NotAfter = strings.TrimSpace(req.NotAfter)
	if req.NotAfter == "" && req.ValidityDays <= 0 {
		req.ValidityDays = defaultValidityLeaf
	}
	if req.TenantID == "" || req.CAID == "" {
		return Certificate{}, "", errors.New("tenant_id and ca_id are required")
	}

	if err := s.ensureDefaultProfiles(ctx, req.TenantID); err != nil {
		return Certificate{}, "", err
	}

	var profile CertificateProfile
	if req.ProfileID != "" {
		p, err := s.store.GetProfile(ctx, req.TenantID, req.ProfileID)
		if err != nil {
			return Certificate{}, "", err
		}
		profile = p
		if req.Algorithm == "" {
			req.Algorithm = p.Algorithm
		}
		if strings.TrimSpace(req.CertClass) == "" {
			req.CertClass = p.CertClass
		}
		if strings.TrimSpace(req.CertType) == "" {
			req.CertType = p.CertType
		}
	}
	if req.Algorithm == "" {
		req.Algorithm = "ECDSA-P384"
	}
	if err := s.enforceFIPS(req.Algorithm); err != nil {
		return Certificate{}, "", err
	}
	req.CertClass = normalizeCertClass(req.CertClass, req.Algorithm)

	ca, err := s.store.GetCA(ctx, req.TenantID, req.CAID)
	if err != nil {
		return Certificate{}, "", err
	}
	if ca.Status != CAStatusActive {
		return Certificate{}, "", errors.New("ca is not active")
	}
	issuerCert, err := parseCertificatePEM(ca.CertPEM)
	if err != nil {
		return Certificate{}, "", err
	}
	issuerSigner, err := s.loadCASigner(ca)
	if err != nil {
		return Certificate{}, "", err
	}

	subjectCN := strings.TrimSpace(req.SubjectCN)
	sans := dedupStrings(req.SANs)
	var (
		pubKey        interface{}
		privateKeyPEM string
	)
	if strings.TrimSpace(req.CSRPem) != "" {
		csr, err := parseCSRPEM(req.CSRPem)
		if err == nil {
			if err := csr.CheckSignature(); err != nil {
				return Certificate{}, "", err
			}
			pubKey = csr.PublicKey
			if subjectCN == "" {
				subjectCN = strings.TrimSpace(csr.Subject.CommonName)
			}
			if len(sans) == 0 {
				sans = csrSANs(csr)
			}
		} else if !isPQCAlgorithm(req.Algorithm) && !isHybridAlgorithm(req.Algorithm) {
			return Certificate{}, "", errors.New("invalid csr_pem")
		}
	}
	if pubKey == nil {
		leafSigner, leafKeyPEM, err := generateLeafKey(req.Algorithm)
		if err != nil {
			return Certificate{}, "", err
		}
		pubKey = leafSigner.Public()
		if req.ServerKeygen {
			privateKeyPEM = leafKeyPEM
		}
	}
	if subjectCN == "" {
		return Certificate{}, "", errors.New("subject_cn is required")
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(req.ValidityDays) * 24 * time.Hour)
	if req.NotAfter != "" {
		parsed, err := time.Parse(time.RFC3339, req.NotAfter)
		if err != nil {
			return Certificate{}, "", errors.New("not_after must be RFC3339")
		}
		notAfter = parsed.UTC()
	}
	if !notAfter.After(now.Add(5 * time.Minute)) {
		return Certificate{}, "", errors.New("not_after must be at least 5 minutes in the future")
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  selectExtKeyUsage(req.CertType),
	}
	tpl.DNSNames, tpl.IPAddresses = splitSANs(sans)

	var otsIndex int64
	if isStatefulAlgorithm(ca.Algorithm) {
		idx, err := s.store.ReserveOTSIndex(ctx, req.TenantID, ca.ID)
		if err != nil {
			return Certificate{}, "", err
		}
		otsIndex = idx
	}
	compositeSig, err := s.signWithKeyCoreIfConfigured(ctx, req.TenantID, ca.KeyBackend, ca.KeyRef, buildLeafSigningIntent(req, serial, sans, otsIndex))
	if err != nil {
		return Certificate{}, "", err
	}
	addCertMetaExtensions(tpl, req.Algorithm, req.CertClass, otsIndex, compositeSig)

	der, err := x509.CreateCertificate(rand.Reader, tpl, issuerCert, pubKey, issuerSigner)
	if err != nil {
		return Certificate{}, "", err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	c := Certificate{
		ID:           newID("crt"),
		TenantID:     req.TenantID,
		CAID:         ca.ID,
		SerialNumber: serial.Text(16),
		SubjectCN:    subjectCN,
		SANs:         sans,
		CertType:     req.CertType,
		Algorithm:    req.Algorithm,
		ProfileID:    profile.ID,
		Protocol:     req.Protocol,
		CertClass:    req.CertClass,
		CertPEM:      certPEM,
		Status:       CertStatusActive,
		NotBefore:    tpl.NotBefore.UTC(),
		NotAfter:     tpl.NotAfter.UTC(),
		KeyRef:       ca.KeyRef,
	}
	if err := s.store.CreateCertificate(ctx, c); err != nil {
		return Certificate{}, "", err
	}
	out, err := s.store.GetCertificate(ctx, req.TenantID, c.ID)
	if err != nil {
		return Certificate{}, "", err
	}
	event := "audit.cert.issued"
	if out.CertClass == "pqc" || out.CertClass == "hybrid" {
		event = "audit.cert.pqc_cert_issued"
	}
	_ = s.publishAudit(ctx, event, req.TenantID, map[string]interface{}{
		"cert_id":       out.ID,
		"ca_id":         out.CAID,
		"algorithm":     out.Algorithm,
		"class":         out.CertClass,
		"protocol":      out.Protocol,
		"ots_index":     otsIndex,
		"server_keygen": req.ServerKeygen,
	})
	return out, privateKeyPEM, nil
}

func (s *Service) ListCertificates(ctx context.Context, tenantID string, status string, certClass string, limit int, offset int) ([]Certificate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	_ = s.RunTenantExpiryAlertSweep(ctx, tenantID)
	return s.store.ListCertificates(ctx, tenantID, strings.TrimSpace(status), strings.TrimSpace(certClass), limit, offset)
}

func (s *Service) GetCertificate(ctx context.Context, tenantID string, certID string) (Certificate, error) {
	tenantID = strings.TrimSpace(tenantID)
	certID = strings.TrimSpace(certID)
	if tenantID == "" || certID == "" {
		return Certificate{}, errors.New("tenant_id and cert_id are required")
	}
	return s.store.GetCertificate(ctx, tenantID, certID)
}

func (s *Service) DownloadCertificate(ctx context.Context, req DownloadCertificateRequest) (string, string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CertID = strings.TrimSpace(req.CertID)
	req.Asset = normalizeDownloadAsset(req.Asset)
	req.Format = normalizeDownloadFormat(req.Format)
	if req.TenantID == "" || req.CertID == "" {
		return "", "", errors.New("tenant_id and cert_id are required")
	}
	c, err := s.GetCertificate(ctx, req.TenantID, req.CertID)
	if err != nil {
		return "", "", err
	}
	issuingCA, err := s.store.GetCA(ctx, req.TenantID, c.CAID)
	if err != nil {
		return "", "", err
	}
	leafCert, err := parseCertificatePEM(c.CertPEM)
	if err != nil {
		return "", "", err
	}
	chainCAs, err := s.caChain(ctx, req.TenantID, issuingCA.ID)
	if err != nil {
		return "", "", err
	}
	chainParsed := make([]*x509.Certificate, 0, len(chainCAs))
	for _, ca := range chainCAs {
		parsed, parseErr := parseCertificatePEM(ca.CertPEM)
		if parseErr != nil {
			return "", "", parseErr
		}
		chainParsed = append(chainParsed, parsed)
	}

	encodeCertListToPEM := func(list []*x509.Certificate) string {
		if len(list) == 0 {
			return ""
		}
		var b strings.Builder
		for idx, cert := range list {
			if idx > 0 {
				b.WriteString("\n")
			}
			b.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		}
		return b.String()
	}
	makeDERPayload := func(list []*x509.Certificate) (string, string, error) {
		if len(list) == 0 {
			return "", "", errors.New("no certificates available for der export")
		}
		if len(list) == 1 {
			return base64.StdEncoding.EncodeToString(list[0].Raw), "application/pkix-cert", nil
		}
		chunks := make([]string, 0, len(list))
		for _, cert := range list {
			chunks = append(chunks, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		raw, marshalErr := json.Marshal(map[string]interface{}{"der_base64": chunks})
		if marshalErr != nil {
			return "", "", marshalErr
		}
		return string(raw), "application/json", nil
	}
	makePublicKeyPEM := func() (string, string, error) {
		der, marshalErr := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
		if marshalErr != nil {
			return "", "", marshalErr
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "application/x-pem-file", nil
	}

	selectedCerts := []*x509.Certificate{}
	switch req.Asset {
	case "certificate":
		selectedCerts = append(selectedCerts, leafCert)
		if req.IncludeChain {
			selectedCerts = append(selectedCerts, chainParsed...)
		}
	case "chain":
		selectedCerts = append(selectedCerts, leafCert)
		selectedCerts = append(selectedCerts, chainParsed...)
	case "ca":
		if req.IncludeChain {
			selectedCerts = append(selectedCerts, chainParsed...)
		} else if len(chainParsed) > 0 {
			selectedCerts = append(selectedCerts, chainParsed[0])
		}
	case "public-key":
		switch req.Format {
		case "pem", "pkcs8":
			return makePublicKeyPEM()
		case "der":
			der, marshalErr := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
			if marshalErr != nil {
				return "", "", marshalErr
			}
			return base64.StdEncoding.EncodeToString(der), "application/pkix-cert", nil
		default:
			return "", "", errors.New("unsupported public key format")
		}
	case "pkcs11":
		descriptor := map[string]interface{}{
			"pkcs11_uri": fmt.Sprintf("pkcs11:token=vecta-kms;object=%s;type=cert;id=%s", c.ID, c.ID),
			"cert_id":    c.ID,
			"tenant_id":  c.TenantID,
			"algorithm":  c.Algorithm,
		}
		raw, marshalErr := json.MarshalIndent(descriptor, "", "  ")
		if marshalErr != nil {
			return "", "", marshalErr
		}
		return string(raw), "application/json", nil
	default:
		return "", "", errors.New("unsupported asset")
	}

	switch req.Format {
	case "pem":
		return encodeCertListToPEM(selectedCerts), "application/x-pem-file", nil
	case "der":
		return makeDERPayload(selectedCerts)
	case "pkcs12", "pfx":
		password := strings.TrimSpace(req.Password)
		if password == "" {
			return "", "", errors.New("password is required for pkcs12 export")
		}
		pfx, encodeErr := pkcs12.EncodeTrustStore(rand.Reader, selectedCerts, password)
		if encodeErr != nil {
			return "", "", encodeErr
		}
		return base64.StdEncoding.EncodeToString(pfx), "application/x-pkcs12", nil
	default:
		return "", "", errors.New("unsupported format")
	}
}

func normalizeDownloadAsset(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "cert", "certificate":
		return "certificate"
	case "chain", "certificate-chain":
		return "chain"
	case "ca", "issuing-ca", "issuing_ca":
		return "ca"
	case "public-key", "public_key", "pubkey":
		return "public-key"
	case "pkcs11", "pkcs11-uri", "pkcs11_uri":
		return "pkcs11"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func normalizeDownloadFormat(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "pem":
		return "pem"
	case "der":
		return "der"
	case "pkcs12", "pfx":
		return "pkcs12"
	case "pkcs8":
		return "pkcs8"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func (s *Service) caChain(ctx context.Context, tenantID string, issuingCAID string) ([]CA, error) {
	all, err := s.store.ListCAs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]CA, len(all))
	for _, ca := range all {
		byID[strings.TrimSpace(ca.ID)] = ca
	}
	chain := make([]CA, 0, 4)
	visited := map[string]struct{}{}
	nextID := strings.TrimSpace(issuingCAID)
	for nextID != "" {
		if _, seen := visited[nextID]; seen {
			break
		}
		visited[nextID] = struct{}{}
		ca, ok := byID[nextID]
		if !ok {
			break
		}
		chain = append(chain, ca)
		nextID = strings.TrimSpace(ca.ParentCAID)
	}
	return chain, nil
}

func (s *Service) RenewCertificate(ctx context.Context, req RenewCertificateRequest) (Certificate, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CertID = strings.TrimSpace(req.CertID)
	if req.TenantID == "" || req.CertID == "" {
		return Certificate{}, errors.New("tenant_id and cert_id are required")
	}
	oldCert, err := s.store.GetCertificate(ctx, req.TenantID, req.CertID)
	if err != nil {
		return Certificate{}, err
	}
	oldStatus := strings.ToLower(strings.TrimSpace(oldCert.Status))
	if oldStatus == CertStatusDeleted {
		return Certificate{}, errors.New("cannot renew deleted certificate")
	}
	if oldStatus == CertStatusRevoked {
		return Certificate{}, errors.New("cannot renew revoked certificate")
	}
	out, _, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         oldCert.CAID,
		ProfileID:    oldCert.ProfileID,
		CertType:     oldCert.CertType,
		Algorithm:    oldCert.Algorithm,
		CertClass:    oldCert.CertClass,
		SubjectCN:    oldCert.SubjectCN,
		SANs:         oldCert.SANs,
		ValidityDays: req.ValidityDays,
		Protocol:     "renew",
	})
	if err != nil {
		return Certificate{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.renewed", req.TenantID, map[string]interface{}{
		"old_cert_id": req.CertID,
		"new_cert_id": out.ID,
	})
	return out, nil
}

func (s *Service) RevokeCertificate(ctx context.Context, req RevokeCertificateRequest) error {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CertID = strings.TrimSpace(req.CertID)
	req.Reason = defaultString(strings.TrimSpace(req.Reason), "unspecified")
	if req.TenantID == "" || req.CertID == "" {
		return errors.New("tenant_id and cert_id are required")
	}
	current, err := s.store.GetCertificate(ctx, req.TenantID, req.CertID)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), CertStatusDeleted) {
		return errors.New("cannot revoke deleted certificate")
	}
	if err := s.store.RevokeCertificate(ctx, req.TenantID, req.CertID, req.Reason); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.cert.revoked", req.TenantID, map[string]interface{}{
		"cert_id": req.CertID,
		"reason":  req.Reason,
	})
	return nil
}

func (s *Service) DeleteCertificate(ctx context.Context, tenantID string, certID string) error {
	tenantID = strings.TrimSpace(tenantID)
	certID = strings.TrimSpace(certID)
	if tenantID == "" || certID == "" {
		return errors.New("tenant_id and cert_id are required")
	}
	current, err := s.store.GetCertificate(ctx, tenantID, certID)
	if err != nil {
		return err
	}
	// Runtime/internal mTLS certificates are managed lifecycle objects.
	// They must not be deleted manually across any tenant.
	if strings.EqualFold(strings.TrimSpace(current.CertClass), "internal-mtls") ||
		strings.Contains(strings.ToLower(strings.TrimSpace(current.Protocol)), "internal-mtls") {
		return errors.New("cannot delete internal-mtls certificate; use renew or rotate")
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), CertStatusDeleted) {
		return nil
	}
	if err := s.store.DeleteCertificate(ctx, tenantID, certID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.cert.deleted", tenantID, map[string]interface{}{
		"cert_id": certID,
	})
	return nil
}

func (s *Service) ValidatePQCChain(ctx context.Context, req ValidatePQCChainRequest) (bool, []string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" || len(req.CertIDs) == 0 {
		return false, nil, errors.New("tenant_id and cert_ids are required")
	}
	issues := make([]string, 0)
	for _, certID := range req.CertIDs {
		c, err := s.store.GetCertificate(ctx, req.TenantID, certID)
		if err != nil {
			issues = append(issues, "missing cert "+certID)
			continue
		}
		if c.CertClass != "pqc" && c.CertClass != "hybrid" {
			issues = append(issues, "non-pqc class for cert "+certID)
		}
		if c.Status != CertStatusActive {
			issues = append(issues, "non-active cert "+certID)
		}
		if time.Now().UTC().After(c.NotAfter) {
			issues = append(issues, "expired cert "+certID)
		}
		if _, err := s.store.GetCA(ctx, req.TenantID, c.CAID); err != nil {
			issues = append(issues, "missing issuer ca for cert "+certID)
		}
	}
	valid := len(issues) == 0
	_ = s.publishAudit(ctx, "audit.cert.pqc_cert_validated", req.TenantID, map[string]interface{}{
		"cert_ids": req.CertIDs,
		"valid":    valid,
		"issues":   issues,
	})
	return valid, issues, nil
}

func (s *Service) MigrateToPQC(ctx context.Context, req MigrateToPQCRequest) (Certificate, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CertID = strings.TrimSpace(req.CertID)
	req.TargetAlgorithm = normalizeAlgorithm(req.TargetAlgorithm)
	if req.TenantID == "" || req.CertID == "" || req.TargetAlgorithm == "" {
		return Certificate{}, errors.New("tenant_id, cert_id, target_algorithm are required")
	}
	oldCert, err := s.store.GetCertificate(ctx, req.TenantID, req.CertID)
	if err != nil {
		return Certificate{}, err
	}
	out, _, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         oldCert.CAID,
		ProfileID:    req.TargetProfileID,
		CertType:     oldCert.CertType,
		Algorithm:    req.TargetAlgorithm,
		CertClass:    normalizeCertClass("", req.TargetAlgorithm),
		SubjectCN:    oldCert.SubjectCN,
		SANs:         oldCert.SANs,
		Protocol:     "migrate",
		ValidityDays: defaultValidityLeaf,
	})
	if err != nil {
		return Certificate{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.pqc_migration_executed", req.TenantID, map[string]interface{}{
		"source_cert_id": req.CertID,
		"target_cert_id": out.ID,
		"algorithm":      req.TargetAlgorithm,
	})
	return out, nil
}

func (s *Service) GetOTSStatus(ctx context.Context, tenantID string, caID string) (OTSStatus, error) {
	tenantID = strings.TrimSpace(tenantID)
	caID = strings.TrimSpace(caID)
	if tenantID == "" || caID == "" {
		return OTSStatus{}, errors.New("tenant_id and ca_id are required")
	}
	ca, err := s.store.GetCA(ctx, tenantID, caID)
	if err != nil {
		return OTSStatus{}, err
	}
	remaining := int64(0)
	if ca.OTSMax > 0 {
		remaining = ca.OTSMax - ca.OTSCurrent
		if remaining < 0 {
			remaining = 0
		}
	}
	alert := ca.OTSAlertThreshold > 0 && remaining <= ca.OTSAlertThreshold
	return OTSStatus{
		CurrentIndex: ca.OTSCurrent,
		MaxIndex:     ca.OTSMax,
		Remaining:    remaining,
		Alert:        alert,
	}, nil
}

func (s *Service) GetPQCReadiness(ctx context.Context, tenantID string) (PQCReadiness, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PQCReadiness{}, errors.New("tenant_id is required")
	}
	return s.store.GetPQCReadiness(ctx, tenantID)
}

func (s *Service) GenerateCRL(ctx context.Context, tenantID string, caID string) (string, time.Time, error) {
	tenantID = strings.TrimSpace(tenantID)
	caID = strings.TrimSpace(caID)
	if tenantID == "" || caID == "" {
		return "", time.Time{}, errors.New("tenant_id and ca_id are required")
	}
	ca, err := s.store.GetCA(ctx, tenantID, caID)
	if err != nil {
		return "", time.Time{}, err
	}
	issuerCert, err := parseCertificatePEM(ca.CertPEM)
	if err != nil {
		return "", time.Time{}, err
	}
	issuerSigner, err := s.loadCASigner(ca)
	if err != nil {
		return "", time.Time{}, err
	}
	revoked, err := s.store.ListRevokedByCA(ctx, tenantID, caID)
	if err != nil {
		return "", time.Time{}, err
	}
	entries := make([]pkix.RevokedCertificate, 0, len(revoked))
	for _, c := range revoked {
		serial := new(big.Int)
		_, ok := serial.SetString(strings.TrimPrefix(c.SerialNumber, "0x"), 16)
		if !ok {
			continue
		}
		entries = append(entries, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: c.RevokedAt.UTC(),
		})
	}
	now := time.Now().UTC()
	number, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 80))
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  issuerCert.SignatureAlgorithm,
		RevokedCertificates: entries,
		Number:              number,
		ThisUpdate:          now,
		NextUpdate:          now.Add(24 * time.Hour),
	}, issuerCert, issuerSigner)
	if err != nil {
		blob, _ := json.Marshal(map[string]interface{}{
			"ca_id":       caID,
			"generated":   now.Format(time.RFC3339Nano),
			"revocations": len(entries),
		})
		crlDER = blob
	}
	crlPEM := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))
	_ = s.publishAudit(ctx, "audit.cert.crl_generated", tenantID, map[string]interface{}{
		"ca_id":       caID,
		"revoked_cnt": len(entries),
	})
	return crlPEM, now, nil
}

func (s *Service) CheckOCSP(ctx context.Context, tenantID string, certID string, serial string) (string, string, time.Time, error) {
	tenantID = strings.TrimSpace(tenantID)
	certID = strings.TrimSpace(certID)
	serial = strings.TrimSpace(serial)
	if tenantID == "" {
		return "", "", time.Time{}, errors.New("tenant_id is required")
	}
	var (
		c   Certificate
		err error
	)
	if certID != "" {
		c, err = s.store.GetCertificate(ctx, tenantID, certID)
	} else if serial != "" {
		c, err = s.store.GetCertificateBySerial(ctx, tenantID, serial)
	} else {
		return "", "", time.Time{}, errors.New("cert_id or serial_number is required")
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	status := "good"
	reason := ""
	if c.Status == CertStatusRevoked {
		status = "revoked"
		reason = defaultString(c.RevocationReason, "unspecified")
	} else if time.Now().UTC().After(c.NotAfter) {
		status = "expired"
	}
	producedAt := time.Now().UTC()
	_ = s.publishAudit(ctx, "audit.cert.ocsp_query", tenantID, map[string]interface{}{
		"cert_id":     c.ID,
		"serial":      c.SerialNumber,
		"ocsp_status": status,
		"ocsp_reason": reason,
	})
	return status, reason, producedAt, nil
}

func (s *Service) CheckOCSPDER(ctx context.Context, tenantID string, reqDER []byte) ([]byte, string, string, time.Time, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, "", "", time.Time{}, errors.New("tenant_id is required")
	}
	if len(bytes.TrimSpace(reqDER)) == 0 {
		return nil, "", "", time.Time{}, errors.New("ocsp request body is required")
	}

	ocspReq, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, "", "", time.Time{}, fmt.Errorf("invalid ocsp request: %w", err)
	}

	serial := strings.ToLower(strings.TrimSpace(ocspReq.SerialNumber.Text(16)))
	if serial == "" {
		return nil, "", "", time.Time{}, errors.New("invalid ocsp serial")
	}

	c, err := s.store.GetCertificateBySerial(ctx, tenantID, serial)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}
	if strings.EqualFold(strings.TrimSpace(c.CAID), "external-ca") {
		return nil, "", "", time.Time{}, errors.New("ocsp responder is unavailable for external certificates")
	}
	ca, err := s.store.GetCA(ctx, tenantID, c.CAID)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}
	issuerCert, err := parseCertificatePEM(ca.CertPEM)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}
	issuerSigner, err := s.loadCASigner(ca)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}

	status := "good"
	reason := ""
	ocspStatus := ocsp.Good
	ocspReason := ocsp.Unspecified
	if c.Status == CertStatusRevoked {
		status = "revoked"
		reason = defaultString(c.RevocationReason, "unspecified")
		ocspStatus = ocsp.Revoked
		switch strings.ToLower(strings.TrimSpace(reason)) {
		case "key_compromise":
			ocspReason = ocsp.KeyCompromise
		case "ca_compromise":
			ocspReason = ocsp.CACompromise
		case "affiliation_changed":
			ocspReason = ocsp.AffiliationChanged
		case "superseded":
			ocspReason = ocsp.Superseded
		case "cessation_of_operation":
			ocspReason = ocsp.CessationOfOperation
		case "certificate_hold":
			ocspReason = ocsp.CertificateHold
		default:
			ocspReason = ocsp.Unspecified
		}
	} else if time.Now().UTC().After(c.NotAfter) {
		status = "expired"
		reason = "certificate expired"
		ocspStatus = ocsp.Unknown
	}

	producedAt := time.Now().UTC()
	resp := ocsp.Response{
		Status:           ocspStatus,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       producedAt.Add(-2 * time.Minute),
		NextUpdate:       producedAt.Add(24 * time.Hour),
		ProducedAt:       producedAt,
		RevokedAt:        c.RevokedAt.UTC(),
		RevocationReason: ocspReason,
	}
	der, err := ocsp.CreateResponse(issuerCert, issuerCert, resp, issuerSigner)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.ocsp_query", tenantID, map[string]interface{}{
		"cert_id":     c.ID,
		"serial":      c.SerialNumber,
		"ocsp_status": status,
		"ocsp_reason": reason,
		"wire":        true,
	})
	return der, status, reason, producedAt, nil
}

func (s *Service) Inventory(ctx context.Context, tenantID string) ([]InventoryCertificateItem, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	_ = s.RunTenantExpiryAlertSweep(ctx, tenantID)
	return s.store.GetInventory(ctx, tenantID)
}

func (s *Service) ListProtocolConfigs(ctx context.Context, tenantID string) ([]ProtocolConfig, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	items, err := s.store.ListProtocolConfigs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byProtocol := make(map[string]ProtocolConfig, len(items))
	for _, it := range items {
		byProtocol[normalizeProtocol(it.Protocol)] = it
	}
	out := make([]ProtocolConfig, 0, 5)
	for _, protocol := range []string{protocolACME, protocolEST, protocolSCEP, protocolCMPv2, protocolRTMTLS} {
		if cfg, ok := byProtocol[protocol]; ok {
			if strings.TrimSpace(cfg.ConfigJSON) == "" {
				cfg.ConfigJSON = "{}"
			}
			out = append(out, cfg)
			continue
		}
		out = append(out, defaultProtocolConfig(tenantID, protocol))
	}
	return out, nil
}

func (s *Service) UpsertProtocolConfig(ctx context.Context, req UpsertProtocolConfigRequest) (ProtocolConfig, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Protocol = normalizeProtocol(req.Protocol)
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	if req.TenantID == "" {
		return ProtocolConfig{}, errors.New("tenant_id is required")
	}
	if !isKnownProtocol(req.Protocol) {
		return ProtocolConfig{}, errors.New("unsupported protocol")
	}
	normalizedJSON, err := normalizeProtocolConfigJSON(req.Protocol, req.ConfigJSON)
	if err != nil {
		return ProtocolConfig{}, err
	}
	cfg := ProtocolConfig{
		TenantID:   req.TenantID,
		Protocol:   req.Protocol,
		Enabled:    req.Enabled,
		ConfigJSON: normalizedJSON,
		UpdatedBy:  req.UpdatedBy,
	}
	if err := s.store.UpsertProtocolConfig(ctx, cfg); err != nil {
		return ProtocolConfig{}, err
	}
	out, err := s.store.GetProtocolConfig(ctx, req.TenantID, req.Protocol)
	if err != nil {
		return ProtocolConfig{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.protocol_config_updated", req.TenantID, map[string]interface{}{
		"protocol":   out.Protocol,
		"enabled":    out.Enabled,
		"updated_by": out.UpdatedBy,
	})
	return out, nil
}

func (s *Service) GetCertExpiryAlertPolicy(ctx context.Context, tenantID string) (CertExpiryAlertPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CertExpiryAlertPolicy{}, errors.New("tenant_id is required")
	}
	item, err := s.store.GetCertExpiryAlertPolicy(ctx, tenantID)
	if errors.Is(err, errStoreNotFound) {
		return CertExpiryAlertPolicy{
			TenantID:        tenantID,
			DaysBefore:      defaultCertExpiryAlertDays,
			IncludeExternal: true,
			UpdatedBy:       "",
		}, nil
	}
	if err != nil {
		return CertExpiryAlertPolicy{}, err
	}
	if item.DaysBefore <= 0 {
		item.DaysBefore = defaultCertExpiryAlertDays
	}
	return item, nil
}

func (s *Service) UpsertCertExpiryAlertPolicy(ctx context.Context, req UpsertCertExpiryAlertPolicyRequest) (CertExpiryAlertPolicy, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	if req.TenantID == "" {
		return CertExpiryAlertPolicy{}, errors.New("tenant_id is required")
	}
	if req.DaysBefore < 1 || req.DaysBefore > 3650 {
		return CertExpiryAlertPolicy{}, errors.New("days_before must be between 1 and 3650")
	}
	item := CertExpiryAlertPolicy{
		TenantID:        req.TenantID,
		DaysBefore:      req.DaysBefore,
		IncludeExternal: req.IncludeExternal,
		UpdatedBy:       req.UpdatedBy,
	}
	if err := s.store.UpsertCertExpiryAlertPolicy(ctx, item); err != nil {
		return CertExpiryAlertPolicy{}, err
	}
	out, err := s.store.GetCertExpiryAlertPolicy(ctx, req.TenantID)
	if err != nil {
		return CertExpiryAlertPolicy{}, err
	}
	_ = s.publishAudit(ctx, "cert.expiry_policy_updated", req.TenantID, map[string]interface{}{
		"days_before":      out.DaysBefore,
		"include_external": out.IncludeExternal,
		"updated_by":       out.UpdatedBy,
	})
	return out, nil
}

func (s *Service) RunExpiryAlertSweep(ctx context.Context) error {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		if err := s.RunTenantExpiryAlertSweep(ctx, tenantID); err != nil {
			continue
		}
	}
	return nil
}

func (s *Service) RunTenantExpiryAlertSweep(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	policy, err := s.GetCertExpiryAlertPolicy(ctx, tenantID)
	if err != nil {
		return err
	}
	all, err := s.store.ListCertificates(ctx, tenantID, "", "", 5000, 0)
	if err != nil {
		return err
	}
	stateRows, err := s.store.ListCertExpiryAlertStates(ctx, tenantID)
	if err != nil {
		return err
	}
	stateByCert := make(map[string]CertExpiryAlertState, len(stateRows))
	for _, row := range stateRows {
		stateByCert[strings.TrimSpace(row.CertID)] = row
	}
	activeCerts := make(map[string]struct{}, len(all))
	now := time.Now().UTC()
	for _, cert := range all {
		certID := strings.TrimSpace(cert.ID)
		if certID == "" {
			continue
		}
		activeCerts[certID] = struct{}{}
		status := strings.ToLower(strings.TrimSpace(cert.Status))
		if status == CertStatusDeleted || status == CertStatusRevoked {
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
			continue
		}
		if !policy.IncludeExternal && strings.EqualFold(strings.TrimSpace(cert.CAID), "external-ca") {
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
			continue
		}
		if now.After(cert.NotAfter.UTC()) {
			if status != CertStatusExpired {
				_ = s.store.UpdateCertificateStatus(ctx, tenantID, certID, CertStatusExpired)
				_ = s.publishAudit(ctx, "cert.expired", tenantID, map[string]interface{}{
					"target_id":   certID,
					"cert_id":     certID,
					"subject_cn":  cert.SubjectCN,
					"not_after":   cert.NotAfter.UTC().Format(time.RFC3339),
					"description": fmt.Sprintf("Certificate %s expired at %s", defaultString(cert.SubjectCN, certID), cert.NotAfter.UTC().Format(time.RFC3339)),
				})
			}
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
			continue
		}
		if status != CertStatusActive {
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
			continue
		}
		daysLeft := int(cert.NotAfter.UTC().Sub(now).Hours() / 24)
		if daysLeft < 0 || daysLeft > policy.DaysBefore {
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
			continue
		}
		prev, exists := stateByCert[certID]
		if exists && prev.LastDaysLeft == daysLeft {
			continue
		}
		_ = s.publishAudit(ctx, "cert.expiring", tenantID, map[string]interface{}{
			"target_id":   certID,
			"cert_id":     certID,
			"subject_cn":  cert.SubjectCN,
			"days_left":   daysLeft,
			"not_after":   cert.NotAfter.UTC().Format(time.RFC3339),
			"description": fmt.Sprintf("Certificate %s expires in %d day(s)", defaultString(cert.SubjectCN, certID), daysLeft),
		})
		_ = s.store.UpsertCertExpiryAlertState(ctx, CertExpiryAlertState{
			TenantID:     tenantID,
			CertID:       certID,
			LastDaysLeft: daysLeft,
		})
	}
	for certID := range stateByCert {
		if _, ok := activeCerts[certID]; !ok {
			_ = s.store.DeleteCertExpiryAlertState(ctx, tenantID, certID)
		}
	}
	return nil
}

func (s *Service) AcmeNewAccount(ctx context.Context, req ACMENewAccountRequest) (AcmeAccount, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.TenantID == "" || req.Email == "" {
		return AcmeAccount{}, errors.New("tenant_id and email are required")
	}
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolACME); err != nil {
		return AcmeAccount{}, err
	}
	acct := AcmeAccount{
		ID:       newID("acme_acc"),
		TenantID: req.TenantID,
		Email:    req.Email,
		Status:   "valid",
	}
	if err := s.store.CreateACMEAccount(ctx, acct); err != nil {
		return AcmeAccount{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.acme_account_created", req.TenantID, map[string]interface{}{
		"account_id": acct.ID,
		"email":      acct.Email,
	})
	return acct, nil
}

func (s *Service) AcmeNewOrder(ctx context.Context, req ACMENewOrderRequest) (AcmeOrder, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CAID = strings.TrimSpace(req.CAID)
	req.AccountID = strings.TrimSpace(req.AccountID)
	req.SubjectCN = strings.TrimSpace(req.SubjectCN)
	if req.TenantID == "" || req.CAID == "" || req.SubjectCN == "" {
		return AcmeOrder{}, errors.New("tenant_id, ca_id, subject_cn are required")
	}
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolACME); err != nil {
		return AcmeOrder{}, err
	}
	options, err := s.acmeOptions(ctx, req.TenantID)
	if err != nil {
		return AcmeOrder{}, err
	}
	req.SANs = dedupStrings(req.SANs)
	if len(req.SANs) > options.MaxSANs {
		return AcmeOrder{}, fmt.Errorf("acme san limit exceeded: %d > %d", len(req.SANs), options.MaxSANs)
	}
	if strings.HasPrefix(strings.ToLower(req.SubjectCN), "*.") && !options.AllowWildcard {
		return AcmeOrder{}, errors.New("wildcard identifiers are disabled in acme config")
	}
	if !options.AllowIPIdentifiers {
		for _, san := range req.SANs {
			if net.ParseIP(strings.TrimSpace(san)) != nil {
				return AcmeOrder{}, errors.New("ip subjectAltName is disabled in acme config")
			}
		}
	}
	req.ChallengeType = strings.ToLower(strings.TrimSpace(req.ChallengeType))
	if req.ChallengeType == "" {
		req.ChallengeType = options.ChallengeTypes[0]
	}
	allowedChallenge := false
	for _, c := range options.ChallengeTypes {
		if strings.EqualFold(c, req.ChallengeType) {
			allowedChallenge = true
			break
		}
	}
	if !allowedChallenge {
		return AcmeOrder{}, fmt.Errorf("acme challenge type %q is not allowed", req.ChallengeType)
	}
	if options.RequireEAB {
		if strings.TrimSpace(req.ExternalAccountID) == "" || strings.TrimSpace(req.ExternalHMAC) == "" {
			return AcmeOrder{}, errors.New("external account binding is required for acme")
		}
	}
	order := AcmeOrder{
		ID:          newID("acme_ord"),
		TenantID:    req.TenantID,
		AccountID:   req.AccountID,
		CAID:        req.CAID,
		SubjectCN:   req.SubjectCN,
		SANs:        req.SANs,
		ChallengeID: newID("acme_chl"),
		Status:      "pending",
	}
	if err := s.store.CreateACMEOrder(ctx, order); err != nil {
		return AcmeOrder{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.acme_challenge_created", req.TenantID, map[string]interface{}{
		"order_id":     order.ID,
		"challenge_id": order.ChallengeID,
		"challenge":    req.ChallengeType,
	})
	return s.store.GetACMEOrder(ctx, req.TenantID, order.ID)
}

func (s *Service) AcmeRespondChallenge(ctx context.Context, tenantID string, orderID string, challengeID string, success bool) error {
	tenantID = strings.TrimSpace(tenantID)
	orderID = strings.TrimSpace(orderID)
	challengeID = strings.TrimSpace(challengeID)
	if tenantID == "" || orderID == "" || challengeID == "" {
		return errors.New("tenant_id, order_id, challenge_id are required")
	}
	if err := s.ensureProtocolEnabled(ctx, tenantID, protocolACME); err != nil {
		return err
	}
	order, err := s.store.GetACMEOrder(ctx, tenantID, orderID)
	if err != nil {
		return err
	}
	if order.ChallengeID != challengeID {
		return errors.New("challenge mismatch")
	}
	status := "invalid"
	event := "audit.cert.acme_challenge_failed"
	if success {
		status = "ready"
		event = "audit.cert.acme_challenge_completed"
	}
	if err := s.store.UpdateACMEOrder(ctx, tenantID, orderID, status, order.CSRPem, order.CertID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, event, tenantID, map[string]interface{}{
		"order_id":     orderID,
		"challenge_id": challengeID,
	})
	return nil
}

func (s *Service) AcmeFinalize(ctx context.Context, req ACMEFinalizeRequest) (Certificate, string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.OrderID = strings.TrimSpace(req.OrderID)
	if req.TenantID == "" || req.OrderID == "" {
		return Certificate{}, "", errors.New("tenant_id and order_id are required")
	}
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolACME); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.acmeOptions(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	order, err := s.store.GetACMEOrder(ctx, req.TenantID, req.OrderID)
	if err != nil {
		return Certificate{}, "", err
	}
	if strings.ToLower(strings.TrimSpace(order.Status)) != "ready" {
		return Certificate{}, "", errors.New("acme order is not ready")
	}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         order.CAID,
		SubjectCN:    order.SubjectCN,
		SANs:         order.SANs,
		CSRPem:       req.CSRPem,
		Protocol:     "acme",
		CertType:     "tls-server",
		ValidityDays: options.DefaultValidityDays,
	})
	if err != nil {
		_ = s.store.UpdateACMEOrder(ctx, req.TenantID, req.OrderID, "invalid", req.CSRPem, "")
		_ = s.publishAudit(ctx, "audit.cert.acme_challenge_failed", req.TenantID, map[string]interface{}{"order_id": req.OrderID, "error": err.Error()})
		return Certificate{}, "", err
	}
	_ = s.store.UpdateACMEOrder(ctx, req.TenantID, req.OrderID, "valid", req.CSRPem, out.ID)
	_ = s.publishAudit(ctx, "audit.cert.acme_challenge_completed", req.TenantID, map[string]interface{}{
		"order_id": order.ID,
		"cert_id":  out.ID,
	})
	return out, keyPEM, nil
}

func (s *Service) ESTSimpleEnroll(ctx context.Context, req ESTSimpleEnrollRequest) (Certificate, string, error) {
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolEST); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.estOptions(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	if err := validateESTAuth(req.AuthMethod, req.AuthToken, options.AuthMode); err != nil {
		return Certificate{}, "", err
	}
	if options.RequireCSRPoP && strings.TrimSpace(req.CSRPem) == "" {
		return Certificate{}, "", errors.New("csr_pem is required by est require_csr_pop policy")
	}
	if len(req.CSRPem) > options.MaxCSRBytes {
		return Certificate{}, "", errors.New("csr_pem exceeds configured est max_csr_bytes")
	}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         req.CAID,
		ProfileID:    req.ProfileID,
		CSRPem:       req.CSRPem,
		Protocol:     "est",
		CertType:     "device",
		ValidityDays: options.DefaultValidityDays,
	})
	if err != nil {
		return Certificate{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cert.est_enroll", req.TenantID, map[string]interface{}{"cert_id": out.ID, "ca_id": req.CAID})
	return out, keyPEM, nil
}

func (s *Service) ESTSimpleReenroll(ctx context.Context, req ESTSimpleReenrollRequest) (Certificate, string, error) {
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolEST); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.estOptions(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	if !options.AllowReenroll {
		return Certificate{}, "", errors.New("est reenroll is disabled by policy")
	}
	if err := validateESTAuth(req.AuthMethod, req.AuthToken, options.AuthMode); err != nil {
		return Certificate{}, "", err
	}
	if options.RequireCSRPoP && strings.TrimSpace(req.CSRPem) == "" {
		return Certificate{}, "", errors.New("csr_pem is required by est require_csr_pop policy")
	}
	if len(req.CSRPem) > options.MaxCSRBytes {
		return Certificate{}, "", errors.New("csr_pem exceeds configured est max_csr_bytes")
	}
	oldCert, err := s.store.GetCertificate(ctx, req.TenantID, req.CertID)
	if err != nil {
		return Certificate{}, "", err
	}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         oldCert.CAID,
		ProfileID:    oldCert.ProfileID,
		CSRPem:       req.CSRPem,
		CertType:     oldCert.CertType,
		Algorithm:    oldCert.Algorithm,
		CertClass:    oldCert.CertClass,
		Protocol:     "est-reenroll",
		ValidityDays: options.DefaultValidityDays,
	})
	if err != nil {
		return Certificate{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cert.est_reenroll", req.TenantID, map[string]interface{}{"old_cert_id": req.CertID, "new_cert_id": out.ID})
	return out, keyPEM, nil
}

func (s *Service) ESTServerKeygen(ctx context.Context, req ESTServerKeygenRequest) (Certificate, string, error) {
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolEST); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.estOptions(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	if !options.ServerKeygen {
		return Certificate{}, "", errors.New("est serverkeygen is disabled by policy")
	}
	if err := validateESTAuth(req.AuthMethod, req.AuthToken, options.AuthMode); err != nil {
		return Certificate{}, "", err
	}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         req.CAID,
		ProfileID:    req.ProfileID,
		SubjectCN:    req.SubjectCN,
		SANs:         req.SANs,
		ServerKeygen: true,
		CertType:     "device",
		Protocol:     "est-serverkeygen",
		ValidityDays: options.DefaultValidityDays,
	})
	if err != nil {
		return Certificate{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cert.est_serverkeygen", req.TenantID, map[string]interface{}{"cert_id": out.ID})
	return out, keyPEM, nil
}

func (s *Service) SCEPPKIOperation(ctx context.Context, req SCEPPKIOperationRequest) (Certificate, string, error) {
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolSCEP); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.scepOptions(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	if options.ChallengePasswordRequired {
		if strings.TrimSpace(req.ChallengePassword) == "" {
			return Certificate{}, "", errors.New("scep challenge_password is required by policy")
		}
		if strings.TrimSpace(options.ChallengePassword) != "" && strings.TrimSpace(req.ChallengePassword) != strings.TrimSpace(options.ChallengePassword) {
			return Certificate{}, "", errors.New("scep challenge_password mismatch")
		}
	}
	msgType := strings.ToLower(strings.TrimSpace(req.MessageType))
	if msgType == "" {
		msgType = "pkcsreq"
	}
	switch msgType {
	case "pkcsreq", "renewalreq", "updatereq":
	default:
		return Certificate{}, "", errors.New("unsupported scep message_type")
	}
	if msgType == "renewalreq" && !options.AllowRenewal {
		return Certificate{}, "", errors.New("scep renewal is disabled by policy")
	}
	if strings.TrimSpace(req.CSRPem) == "" {
		return Certificate{}, "", errors.New("csr_pem is required")
	}
	if len(req.CSRPem) > options.MaxCSRBytes {
		return Certificate{}, "", errors.New("csr_pem exceeds configured scep max_csr_bytes")
	}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         req.CAID,
		CSRPem:       req.CSRPem,
		Protocol:     "scep-" + msgType,
		CertType:     "device",
		ValidityDays: options.DefaultValidityDays,
	})
	if err != nil {
		return Certificate{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cert.scep_enroll", req.TenantID, map[string]interface{}{
		"cert_id":        out.ID,
		"transaction_id": req.TransactionID,
	})
	return out, keyPEM, nil
}

func (s *Service) CMPv2Request(ctx context.Context, req CMPv2RequestMessage) (Certificate, string, error) {
	if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolCMPv2); err != nil {
		return Certificate{}, "", err
	}
	options, err := s.cmpv2Options(ctx, req.TenantID)
	if err != nil {
		return Certificate{}, "", err
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.CAID = strings.TrimSpace(req.CAID)
	req.CSRPem = strings.TrimSpace(req.CSRPem)
	req.CertID = strings.TrimSpace(req.CertID)
	req.TransactionID = strings.TrimSpace(req.TransactionID)
	mt := strings.ToLower(strings.TrimSpace(req.MessageType))
	if options.RequireMessageProtection && !req.Protected {
		return Certificate{}, "", errors.New("cmpv2 message protection is required by policy")
	}
	if options.RequireTransactionID && req.TransactionID == "" {
		return Certificate{}, "", errors.New("cmpv2 transaction_id is required by policy")
	}
	allowed := false
	for _, t := range options.MessageTypes {
		if strings.EqualFold(t, mt) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Certificate{}, "", fmt.Errorf("cmpv2 message_type %q is not enabled by policy", mt)
	}
	switch mt {
	case "ir", "cr":
		payload := struct {
			SubjectCN string   `json:"subject_cn"`
			SANs      []string `json:"sans"`
			CertType  string   `json:"cert_type"`
			Algorithm string   `json:"algorithm"`
			ProfileID string   `json:"profile_id"`
		}{}
		if strings.TrimSpace(req.PayloadJSON) != "" {
			_ = json.Unmarshal([]byte(req.PayloadJSON), &payload)
		}
		subjectCN := strings.TrimSpace(payload.SubjectCN)
		if subjectCN == "" && req.CSRPem == "" {
			subjectCN = "cmpv2-client.local"
		}
		out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
			TenantID:     req.TenantID,
			CAID:         req.CAID,
			ProfileID:    strings.TrimSpace(payload.ProfileID),
			CSRPem:       req.CSRPem,
			SubjectCN:    subjectCN,
			SANs:         payload.SANs,
			Protocol:     "cmpv2-" + mt,
			CertType:     defaultString(strings.TrimSpace(payload.CertType), "tls-client"),
			Algorithm:    strings.TrimSpace(payload.Algorithm),
			ValidityDays: options.DefaultValidityDays,
		})
		if err != nil {
			return Certificate{}, "", err
		}
		_ = s.publishAudit(ctx, "audit.cert.cmpv2_request", req.TenantID, map[string]interface{}{"message_type": mt, "cert_id": out.ID})
		return out, keyPEM, nil
	case "kur":
		out, err := s.RenewCertificate(ctx, RenewCertificateRequest{TenantID: req.TenantID, CertID: req.CertID, ValidityDays: options.DefaultValidityDays})
		if err != nil {
			return Certificate{}, "", err
		}
		_ = s.publishAudit(ctx, "audit.cert.cmpv2_request", req.TenantID, map[string]interface{}{"message_type": mt, "cert_id": out.ID})
		return out, "", nil
	case "rr":
		if err := s.RevokeCertificate(ctx, RevokeCertificateRequest{TenantID: req.TenantID, CertID: req.CertID, Reason: "cmpv2-request"}); err != nil {
			return Certificate{}, "", err
		}
		revoked, err := s.store.GetCertificate(ctx, req.TenantID, req.CertID)
		if err != nil {
			return Certificate{}, "", err
		}
		_ = s.publishAudit(ctx, "audit.cert.cmpv2_request", req.TenantID, map[string]interface{}{"message_type": mt, "cert_id": revoked.ID})
		return revoked, "", nil
	default:
		return Certificate{}, "", errors.New("unsupported cmpv2 message_type")
	}
}

func (s *Service) IssueInternalMTLS(ctx context.Context, serviceName string, req InternalMTLSRequest) (Certificate, string, error) {
	serviceName = strings.TrimSpace(strings.ToLower(serviceName))
	if serviceName == "" {
		return Certificate{}, "", errors.New("service name is required")
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return Certificate{}, "", errors.New("tenant_id is required")
	}
	req.CAID = strings.TrimSpace(req.CAID)
	if req.CAID == "" {
		rootName := s.runtimeRootCAName(ctx, req.TenantID)
		ca, err := s.ensureRuntimeRootCA(ctx, req.TenantID, rootName)
		if err != nil {
			return Certificate{}, "", err
		}
		req.CAID = ca.ID
	}
	cn := "kms-" + serviceName
	sans := []string{cn, cn + ".svc", cn + ".svc.cluster.local"}
	out, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     req.TenantID,
		CAID:         req.CAID,
		CertType:     "tls-client",
		CertClass:    "internal-mtls",
		Algorithm:    "ECDSA-P384",
		SubjectCN:    cn,
		SANs:         sans,
		ServerKeygen: true,
		ValidityDays: req.ValidityDays,
		Protocol:     "internal-mtls",
	})
	if err != nil {
		return Certificate{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cert.internal_mtls_issued", req.TenantID, map[string]interface{}{
		"service": serviceName,
		"cert_id": out.ID,
	})
	return out, keyPEM, nil
}

func (s *Service) UploadThirdPartyCertificate(ctx context.Context, req UploadThirdPartyCertificateRequest) (Certificate, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Purpose = strings.TrimSpace(req.Purpose)
	req.CertificatePEM = strings.TrimSpace(req.CertificatePEM)
	req.PrivateKeyPEM = strings.TrimSpace(req.PrivateKeyPEM)
	req.CABundlePEM = strings.TrimSpace(req.CABundlePEM)
	req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
	if req.TenantID == "" || req.Purpose == "" || req.CertificatePEM == "" {
		return Certificate{}, errors.New("tenant_id, purpose, certificate_pem are required")
	}
	if req.AutoRenewACME {
		if err := s.ensureProtocolEnabled(ctx, req.TenantID, protocolACME); err != nil {
			return Certificate{}, err
		}
	}

	leaf, err := parseCertificatePEM(req.CertificatePEM)
	if err != nil {
		return Certificate{}, err
	}
	if req.PrivateKeyPEM != "" {
		signer, err := parseAnyPrivateKeyPEM(req.PrivateKeyPEM)
		if err != nil {
			return Certificate{}, err
		}
		matches, err := publicKeysEqual(leaf.PublicKey, signer.Public())
		if err != nil {
			return Certificate{}, err
		}
		if !matches {
			return Certificate{}, errors.New("private key does not match certificate public key")
		}
	}

	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	if serial == "" {
		serial = newID("serial")
	}
	if _, err := s.store.GetCertificateBySerial(ctx, req.TenantID, serial); err == nil {
		serial = serial + "-" + newID("dup")[4:]
	} else if !errors.Is(err, errStoreNotFound) {
		return Certificate{}, err
	}

	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	algo := algorithmFromPublicKey(leaf.PublicKey)
	c := Certificate{
		ID:           newID("crt"),
		TenantID:     req.TenantID,
		CAID:         "external-ca",
		SerialNumber: serial,
		SubjectCN:    defaultString(strings.TrimSpace(leaf.Subject.CommonName), "external-cert"),
		SANs:         sans,
		CertType:     certTypeFromUploadPurpose(req.Purpose),
		Algorithm:    algo,
		CertClass:    normalizeCertClass("", algo),
		CertPEM:      req.CertificatePEM,
		Status:       CertStatusActive,
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		Protocol:     "upload-3p",
	}
	if err := s.store.CreateCertificate(ctx, c); err != nil {
		return Certificate{}, err
	}
	created, err := s.store.GetCertificate(ctx, req.TenantID, c.ID)
	if err != nil {
		return Certificate{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.uploaded_3p", req.TenantID, map[string]interface{}{
		"cert_id":            created.ID,
		"purpose":            req.Purpose,
		"set_active":         req.SetActive,
		"enable_ocsp":        req.EnableOCSP,
		"auto_renew_acme":    req.AutoRenewACME,
		"has_private_key":    req.PrivateKeyPEM != "",
		"has_ca_bundle":      req.CABundlePEM != "",
		"updated_by":         req.UpdatedBy,
		"certificate_serial": serial,
	})
	return created, nil
}

func (s *Service) CACertBundle(ctx context.Context, tenantID string) (string, error) {
	cas, err := s.store.ListCAs(ctx, tenantID)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(cas))
	for _, ca := range cas {
		if strings.TrimSpace(ca.CertPEM) != "" {
			parts = append(parts, strings.TrimSpace(ca.CertPEM))
		}
	}
	return strings.Join(parts, "\n"), nil
}

func (s *Service) SCEPCapabilities(ctx context.Context, tenantID string) (string, error) {
	opts, err := s.scepOptions(ctx, tenantID)
	if err != nil {
		return "", err
	}
	lines := []string{"POSTPKIOperation", "GetNextCACert", "SHA-256", "SHA-384"}
	if opts.AllowRenewal {
		lines = append(lines, "Renewal")
	}
	for _, alg := range opts.EncryptionAlgorithms {
		switch strings.ToLower(strings.TrimSpace(alg)) {
		case "aes256", "aes192", "aes128":
			lines = append(lines, "AES")
		case "des3":
			lines = append(lines, "DES3")
		}
	}
	for _, d := range opts.DigestAlgorithms {
		switch strings.ToLower(strings.TrimSpace(d)) {
		case "sha1":
			lines = append(lines, "SHA-1")
		case "sha224":
			lines = append(lines, "SHA-224")
		case "sha256":
			lines = append(lines, "SHA-256")
		case "sha384":
			lines = append(lines, "SHA-384")
		case "sha512":
			lines = append(lines, "SHA-512")
		}
	}
	lines = dedupStrings(lines)
	return strings.Join(lines, "\n"), nil
}

func (s *Service) ensureProtocolEnabled(ctx context.Context, tenantID string, protocol string) error {
	protocol = normalizeProtocol(protocol)
	if !isKnownProtocol(protocol) {
		return errors.New("unsupported protocol")
	}
	cfg, err := s.store.GetProtocolConfig(ctx, tenantID, protocol)
	if errors.Is(err, errStoreNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return fmt.Errorf("%s protocol is disabled for tenant", strings.ToUpper(protocol))
	}
	return nil
}

func (s *Service) protocolConfigJSON(ctx context.Context, tenantID string, protocol string) (string, error) {
	protocol = normalizeProtocol(protocol)
	if !isKnownProtocol(protocol) {
		return "", errors.New("unsupported protocol")
	}
	cfg, err := s.store.GetProtocolConfig(ctx, tenantID, protocol)
	if errors.Is(err, errStoreNotFound) {
		return defaultProtocolConfigJSON(protocol), nil
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(cfg.ConfigJSON) == "" {
		return defaultProtocolConfigJSON(protocol), nil
	}
	return cfg.ConfigJSON, nil
}

func (s *Service) acmeOptions(ctx context.Context, tenantID string) (ACMEProtocolOptions, error) {
	raw, err := s.protocolConfigJSON(ctx, tenantID, protocolACME)
	if err != nil {
		return ACMEProtocolOptions{}, err
	}
	return parseACMEProtocolOptions(raw)
}

func (s *Service) estOptions(ctx context.Context, tenantID string) (ESTProtocolOptions, error) {
	raw, err := s.protocolConfigJSON(ctx, tenantID, protocolEST)
	if err != nil {
		return ESTProtocolOptions{}, err
	}
	return parseESTProtocolOptions(raw)
}

func (s *Service) scepOptions(ctx context.Context, tenantID string) (SCEPProtocolOptions, error) {
	raw, err := s.protocolConfigJSON(ctx, tenantID, protocolSCEP)
	if err != nil {
		return SCEPProtocolOptions{}, err
	}
	return parseSCEPProtocolOptions(raw)
}

func (s *Service) cmpv2Options(ctx context.Context, tenantID string) (CMPv2ProtocolOptions, error) {
	raw, err := s.protocolConfigJSON(ctx, tenantID, protocolCMPv2)
	if err != nil {
		return CMPv2ProtocolOptions{}, err
	}
	return parseCMPv2ProtocolOptions(raw)
}

func (s *Service) runtimeMTLSOptions(ctx context.Context, tenantID string) (RuntimeMTLSProtocolOptions, bool, error) {
	cfg, err := s.store.GetProtocolConfig(ctx, tenantID, protocolRTMTLS)
	if errors.Is(err, errStoreNotFound) {
		return defaultRuntimeMTLSProtocolOptions(), true, nil
	}
	if err != nil {
		return RuntimeMTLSProtocolOptions{}, false, err
	}
	opts, err := parseRuntimeMTLSProtocolOptions(cfg.ConfigJSON)
	if err != nil {
		return RuntimeMTLSProtocolOptions{}, false, err
	}
	return opts, cfg.Enabled, nil
}

func defaultRuntimeRootCANameFromEnv() string {
	rootName := strings.TrimSpace(os.Getenv("CERTS_RUNTIME_ROOT_CA_NAME"))
	if rootName == "" {
		rootName = "vecta-runtime-root"
	}
	return rootName
}

func (s *Service) runtimeRootCAName(ctx context.Context, tenantID string) string {
	fallback := defaultRuntimeRootCANameFromEnv()
	opts, enabled, err := s.runtimeMTLSOptions(ctx, tenantID)
	if err != nil || !enabled {
		return fallback
	}
	if strings.EqualFold(strings.TrimSpace(opts.Mode), "custom") {
		custom := strings.TrimSpace(opts.RuntimeRootCAName)
		if custom != "" {
			return custom
		}
	}
	return fallback
}

func validateESTAuth(authMethod string, authToken string, requiredMode string) error {
	mode := strings.ToLower(strings.TrimSpace(requiredMode))
	method := strings.ToLower(strings.TrimSpace(authMethod))
	switch mode {
	case "none":
		return nil
	case "mtls":
		if method == "" {
			method = "mtls"
		}
		if method != "mtls" {
			return errors.New("est auth method must be mTLS by policy")
		}
		return nil
	case "basic", "bearer":
		if method != mode {
			return fmt.Errorf("est auth method must be %s by policy", mode)
		}
		if strings.TrimSpace(authToken) == "" {
			return errors.New("est auth token is required by policy")
		}
		return nil
	default:
		return errors.New("unsupported est auth mode")
	}
}

func normalizeProtocol(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case protocolACME:
		return protocolACME
	case protocolEST:
		return protocolEST
	case protocolSCEP:
		return protocolSCEP
	case "cmp", protocolCMPv2:
		return protocolCMPv2
	case protocolRTMTLS, "runtime_mtls", "internal-mtls":
		return protocolRTMTLS
	default:
		return ""
	}
}

func isKnownProtocol(v string) bool {
	return v == protocolACME || v == protocolEST || v == protocolSCEP || v == protocolCMPv2 || v == protocolRTMTLS
}

func defaultProtocolConfig(tenantID string, protocol string) ProtocolConfig {
	return ProtocolConfig{
		TenantID:   tenantID,
		Protocol:   normalizeProtocol(protocol),
		Enabled:    true,
		ConfigJSON: defaultProtocolConfigJSON(protocol),
	}
}

func (s *Service) ensureDefaultProfiles(ctx context.Context, tenantID string) error {
	defaults := []CreateProfileRequest{
		{TenantID: tenantID, Name: "pqc-tls-server", CertType: "tls-server", Algorithm: "ML-DSA-65", CertClass: "pqc", ProfileJSON: `{"key_exchange":"ECDHE","pqc":"enabled"}`, IsDefault: true},
		{TenantID: tenantID, Name: "hybrid-tls", CertType: "tls-server", Algorithm: "ECDSA-P384+ML-DSA-65", CertClass: "hybrid", ProfileJSON: `{"composite_signature":true}`, IsDefault: true},
		{TenantID: tenantID, Name: "quantum-safe-smime", CertType: "email", Algorithm: "ML-DSA-87+ML-KEM-1024", CertClass: "pqc", ProfileJSON: `{"eku":"emailProtection"}`, IsDefault: true},
		{TenantID: tenantID, Name: "pqc-code-signing", CertType: "code-signing", Algorithm: "SLH-DSA-256f", CertClass: "pqc", ProfileJSON: `{"eku":"codeSigning"}`, IsDefault: true},
		{TenantID: tenantID, Name: "internal-mtls-service", CertType: "tls-client", Algorithm: "ECDSA-P384", CertClass: "classical", ProfileJSON: `{"mtls":"internal"}`, IsDefault: true},
	}
	for _, p := range defaults {
		if _, err := s.store.GetProfileByName(ctx, tenantID, p.Name); err == nil {
			continue
		}
		_, _ = s.CreateProfile(ctx, p)
	}
	return nil
}

func (s *Service) loadCASigner(ca CA) (crypto.Signer, error) {
	raw, err := s.decryptSigner(ca)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(raw)
	signer, err := parseSignerPEM(raw)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func (s *Service) encryptSigner(raw []byte) (EncryptedSigner, error) {
	fingerprint := signerFingerprint(raw)
	if s.securityProvider == nil || s.certStorageMode != "db_encrypted" {
		env, err := pkgcrypto.EncryptEnvelope(s.mek, raw)
		if err != nil {
			return EncryptedSigner{}, err
		}
		return EncryptedSigner{
			WrappedDEK:   env.WrappedDEK,
			WrappedDEKIV: env.WrappedDEKIV,
			Ciphertext:   env.Ciphertext,
			DataIV:       env.DataIV,
			KeyVersion:   "legacy-v1",
			Fingerprint:  fingerprint,
		}, nil
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return EncryptedSigner{}, err
	}
	defer pkgcrypto.Zeroize(dek)
	ciphertext, dataIV, err := aesGCMEncryptRaw(dek, raw)
	if err != nil {
		return EncryptedSigner{}, err
	}
	wrapped, wrappedIV, keyVersion, err := s.securityProvider.WrapDEK(context.Background(), dek)
	if err != nil {
		return EncryptedSigner{}, err
	}
	if strings.TrimSpace(keyVersion) == "" {
		keyVersion = "crwk-v1"
	}
	return EncryptedSigner{
		WrappedDEK:   wrapped,
		WrappedDEKIV: wrappedIV,
		Ciphertext:   ciphertext,
		DataIV:       dataIV,
		KeyVersion:   keyVersion,
		Fingerprint:  fingerprint,
	}, nil
}

func (s *Service) decryptSigner(ca CA) ([]byte, error) {
	if s.securityProvider != nil && s.certStorageMode == "db_encrypted" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ca.SignerKeyVersion)), "legacy") {
		dek, err := s.securityProvider.UnwrapDEK(context.Background(), ca.SignerWrappedDEK, ca.SignerWrappedDEKIV, ca.SignerKeyVersion)
		if err == nil {
			defer pkgcrypto.Zeroize(dek)
			return aesGCMDecryptRaw(dek, ca.SignerCiphertext, ca.SignerDataIV)
		}
		if len(s.mek) == 0 {
			return nil, err
		}
	}
	return pkgcrypto.DecryptEnvelope(s.mek, &pkgcrypto.EnvelopeCiphertext{
		WrappedDEK:   ca.SignerWrappedDEK,
		WrappedDEKIV: ca.SignerWrappedDEKIV,
		Ciphertext:   ca.SignerCiphertext,
		DataIV:       ca.SignerDataIV,
	})
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	payload := map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "certs",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	}
	for _, key := range []string{"target_id", "description", "actor_id", "source_ip", "correlation_id"} {
		if data == nil {
			continue
		}
		if v, ok := data[key]; ok {
			payload[key] = v
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func (s *Service) SecurityStatus() CertRootKeyStatus {
	status := CertRootKeyStatus{
		StorageMode: s.certStorageMode,
		RootKeyMode: s.rootKeyMode,
		Ready:       false,
		State:       "legacy",
	}
	if s.securityProvider != nil {
		status = s.securityProvider.Status()
		if strings.TrimSpace(status.StorageMode) == "" {
			status.StorageMode = s.certStorageMode
		}
		if strings.TrimSpace(status.RootKeyMode) == "" {
			status.RootKeyMode = s.rootKeyMode
		}
	}
	if strings.TrimSpace(s.securityInitError) != "" && strings.TrimSpace(status.LastError) == "" {
		status.LastError = s.securityInitError
	}
	return status
}

func (s *Service) RewrapLegacyCASigners(ctx context.Context) (int, error) {
	if s.securityProvider == nil || s.certStorageMode != "db_encrypted" {
		return 0, nil
	}
	status := s.securityProvider.Status()
	if !status.Ready {
		return 0, nil
	}

	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}

	rewrapped := 0
	for _, tenantID := range tenants {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			continue
		}
		cas, listErr := s.store.ListCAs(ctx, tenantID)
		if listErr != nil {
			return rewrapped, listErr
		}
		for _, ca := range cas {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ca.SignerKeyVersion)), "legacy") {
				continue
			}
			if len(ca.SignerCiphertext) == 0 {
				continue
			}
			raw, decErr := s.decryptSigner(ca)
			if decErr != nil {
				return rewrapped, fmt.Errorf("decrypt legacy signer for ca %s failed: %w", ca.ID, decErr)
			}
			enc, encErr := s.encryptSigner(raw)
			pkgcrypto.Zeroize(raw)
			if encErr != nil {
				return rewrapped, fmt.Errorf("encrypt signer for ca %s failed: %w", ca.ID, encErr)
			}
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(enc.KeyVersion)), "legacy") {
				return rewrapped, fmt.Errorf("refusing legacy rewrap output for ca %s", ca.ID)
			}
			if updErr := s.store.UpdateCASignerEncryption(ctx, tenantID, ca.ID, enc); updErr != nil {
				return rewrapped, fmt.Errorf("persist rewrapped signer for ca %s failed: %w", ca.ID, updErr)
			}
			rewrapped++
			_ = s.publishAudit(ctx, "audit.cert.ca_signer_rewrapped", tenantID, map[string]interface{}{
				"ca_id":              ca.ID,
				"from_version":       defaultString(ca.SignerKeyVersion, "legacy-v1"),
				"to_version":         enc.KeyVersion,
				"fingerprint_sha256": enc.Fingerprint,
				"storage_mode":       s.certStorageMode,
				"root_key_mode":      s.rootKeyMode,
				"security_ready":     status.Ready,
				"security_state":     status.State,
			})
		}
	}
	return rewrapped, nil
}

func (s *Service) MaterializeRuntimeCerts(ctx context.Context, cfg RuntimeCertMaterializerConfig) error {
	if !cfg.Enabled {
		return nil
	}
	tenantID := strings.TrimSpace(cfg.TenantID)
	if tenantID == "" {
		tenantID = "bank-alpha"
	}
	rootName := strings.TrimSpace(cfg.RootCAName)
	if rootName == "" {
		rootName = s.runtimeRootCAName(ctx, tenantID)
	}
	materializeDir := strings.TrimSpace(cfg.MaterializeDir)
	if materializeDir == "" {
		materializeDir = "/run/vecta/certs"
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 90
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 24 * time.Hour
	}
	envoyCN := strings.TrimSpace(cfg.EnvoyCN)
	if envoyCN == "" {
		envoyCN = "vecta-envoy"
	}
	envoySANs := dedupStrings(append([]string{}, cfg.EnvoySANs...))
	if len(envoySANs) == 0 {
		envoySANs = []string{"localhost", "envoy", "127.0.0.1"}
	}
	kmipCN := strings.TrimSpace(cfg.KMIPCN)
	if kmipCN == "" {
		kmipCN = "vecta-kmip"
	}
	kmipSANs := dedupStrings(append([]string{}, cfg.KMIPSANs...))
	if len(kmipSANs) == 0 {
		kmipSANs = []string{"localhost", "kmip", "127.0.0.1"}
	}

	ca, err := s.ensureRuntimeRootCA(ctx, tenantID, rootName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(materializeDir, "ca"), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomically(filepath.Join(materializeDir, "ca", "ca.crt"), []byte(strings.TrimSpace(ca.CertPEM)+"\n"), 0o600); err != nil {
		return err
	}
	if err := s.ensureRuntimeEndpointCert(ctx, tenantID, ca, filepath.Join(materializeDir, "envoy"), "RSA-3072", envoyCN, envoySANs, cfg.ValidityDays, cfg.RenewBefore); err != nil {
		return err
	}
	if err := s.ensureRuntimeEndpointCert(ctx, tenantID, ca, filepath.Join(materializeDir, "kmip"), "RSA-3072", kmipCN, kmipSANs, cfg.ValidityDays, cfg.RenewBefore); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.cert.runtime_materialized", tenantID, map[string]interface{}{
		"materialize_dir": materializeDir,
		"root_ca_name":    rootName,
		"envoy_cn":        envoyCN,
		"kmip_cn":         kmipCN,
	})
	return nil
}

func (s *Service) ensureRuntimeRootCA(ctx context.Context, tenantID string, name string) (CA, error) {
	cas, err := s.store.ListCAs(ctx, tenantID)
	if err != nil {
		return CA{}, err
	}
	for _, ca := range cas {
		if strings.EqualFold(strings.TrimSpace(ca.Name), strings.TrimSpace(name)) && strings.ToLower(strings.TrimSpace(ca.Status)) == CAStatusActive {
			return ca, nil
		}
	}
	created, err := s.CreateCA(ctx, CreateCARequest{
		TenantID:     tenantID,
		Name:         name,
		CALevel:      "root",
		Algorithm:    "ECDSA-P384",
		CAType:       "classical",
		KeyBackend:   "software",
		Subject:      fmt.Sprintf("CN=%s,O=Vecta KMS Runtime", name),
		ValidityDays: 3650,
	})
	if err == nil {
		return created, nil
	}
	// Handle race on initial startup by re-reading.
	cas, listErr := s.store.ListCAs(ctx, tenantID)
	if listErr != nil {
		return CA{}, err
	}
	for _, ca := range cas {
		if strings.EqualFold(strings.TrimSpace(ca.Name), strings.TrimSpace(name)) && strings.ToLower(strings.TrimSpace(ca.Status)) == CAStatusActive {
			return ca, nil
		}
	}
	return CA{}, err
}

func (s *Service) ensureRuntimeEndpointCert(ctx context.Context, tenantID string, ca CA, outDir string, algorithm string, cn string, sans []string, validityDays int64, renewBefore time.Duration) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(outDir, "tls.crt")
	keyPath := filepath.Join(outDir, "tls.key")
	if !runtimeCertNeedsRenew(certPath, keyPath, renewBefore) {
		return nil
	}
	issued, keyPEM, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     tenantID,
		CAID:         ca.ID,
		CertType:     "tls-server",
		Algorithm:    algorithm,
		CertClass:    "internal-mtls",
		SubjectCN:    cn,
		SANs:         dedupStrings(sans),
		ServerKeygen: true,
		ValidityDays: validityDays,
		Protocol:     "internal-mtls",
		MetadataJSON: `{"runtime_materializer":true}`,
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(keyPEM) == "" {
		return errors.New("runtime materializer received empty private key")
	}
	keyBytes := []byte(keyPEM)
	defer pkgcrypto.Zeroize(keyBytes)
	if err := writeFileAtomically(certPath, []byte(strings.TrimSpace(issued.CertPEM)+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomically(keyPath, keyBytes, 0o600); err != nil {
		return err
	}
	return nil
}

func runtimeCertNeedsRenew(certPath string, keyPath string, renewBefore time.Duration) bool {
	if renewBefore <= 0 {
		renewBefore = 24 * time.Hour
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil || keyInfo.Size() == 0 {
		return true
	}
	raw, err := os.ReadFile(certPath)
	if err != nil || len(raw) == 0 {
		return true
	}
	cert, err := parseCertificatePEM(string(raw))
	if err != nil {
		return true
	}
	now := time.Now().UTC()
	if now.After(cert.NotAfter) {
		return true
	}
	if cert.NotBefore.After(now.Add(5 * time.Minute)) {
		return true
	}
	return cert.NotAfter.Sub(now) <= renewBefore
}

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Service) signWithKeyCoreIfConfigured(ctx context.Context, tenantID string, keyBackend string, keyRef string, payload []byte) ([]byte, error) {
	backend := normalizeKeyBackend(keyBackend)
	if backend != "keycore" && backend != "hsm" {
		return nil, nil
	}
	if strings.TrimSpace(keyRef) == "" {
		return nil, errors.New("key_ref required for keycore/hsm backend")
	}
	sig, err := s.keycore.Sign(ctx, tenantID, keyRef, payload)
	if err != nil {
		if s.keycoreFailClosed {
			return nil, err
		}
		return nil, nil
	}
	return sig, nil
}

func (s *Service) enforceFIPS(algorithm string) error {
	if !s.fipsStrict {
		return nil
	}
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "ML-DSA"),
		strings.Contains(alg, "SLH-DSA"),
		strings.Contains(alg, "ML-KEM"),
		strings.Contains(alg, "HSS"),
		strings.Contains(alg, "LMS"),
		strings.Contains(alg, "XMSS"),
		strings.Contains(alg, "ECDSA"),
		strings.Contains(alg, "RSA"),
		strings.Contains(alg, "ED25519"):
		return nil
	default:
		return fmt.Errorf("algorithm %q blocked in strict fips mode", algorithm)
	}
}

func addCertMetaExtensions(tpl *x509.Certificate, algorithm string, certClass string, otsIndex int64, compositeSig []byte) {
	meta, _ := json.Marshal(map[string]interface{}{
		"algorithm": normalizeAlgorithm(algorithm),
		"class":     normalizeCertClass(certClass, algorithm),
		"issued_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
		Id:       oidVectaMeta,
		Critical: false,
		Value:    meta,
	})
	if len(compositeSig) > 0 {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:       oidVectaComposite,
			Critical: false,
			Value:    []byte(base64.StdEncoding.EncodeToString(compositeSig)),
		})
	}
	if otsIndex > 0 {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:       oidVectaOTSIndex,
			Critical: false,
			Value:    []byte(fmt.Sprintf("%d", otsIndex)),
		})
	}
}

func parseCSRPEM(raw string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("csr pem decode failed")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func parseCertificatePEM(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("certificate pem decode failed")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSignerPEM(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key pem decode failed")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key type")
}

func normalizePrivateKeyToPKCS8PEM(raw string) (string, error) {
	signer, err := parseSignerPEM([]byte(raw))
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func parseAnyPrivateKeyPEM(raw string) (crypto.Signer, error) {
	return parseSignerPEM([]byte(raw))
}

func publicKeysEqual(left interface{}, right interface{}) (bool, error) {
	l, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false, err
	}
	r, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(l, r), nil
}

func algorithmFromPublicKey(pub interface{}) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 384:
			return "ECDSA-P384"
		case 521:
			return "ECDSA-P521"
		default:
			return "ECDSA-P256"
		}
	case ed25519.PublicKey:
		return "ED25519"
	default:
		return "ECDSA-P256"
	}
}

func certTypeFromUploadPurpose(purpose string) string {
	p := strings.ToLower(strings.TrimSpace(purpose))
	switch {
	case strings.Contains(p, "kmip"):
		return "kmip-server"
	case strings.Contains(p, "syslog"):
		return "syslog-tls"
	case strings.Contains(p, "client"), strings.Contains(p, "mtls"):
		return "tls-client"
	default:
		return "tls-server"
	}
}

func generateSigningKey(algorithm string) (crypto.Signer, string, error) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "RSA"):
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, "", err
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	case strings.Contains(alg, "ED25519"):
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, "", err
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	default:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, "", err
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	}
}

func generateLeafKey(algorithm string) (crypto.Signer, string, error) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "RSA"):
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, "", err
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	case strings.Contains(alg, "ED25519"):
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, "", err
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	default:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, "", err
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return key, string(p), nil
	}
}

func selectExtKeyUsage(certType string) []x509.ExtKeyUsage {
	switch strings.ToLower(strings.TrimSpace(certType)) {
	case "tls-client", "mtls":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "email", "smime":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	case "code-signing":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
}

func parseSubject(raw string, fallbackCN string) pkix.Name {
	if strings.TrimSpace(raw) == "" {
		return pkix.Name{CommonName: fallbackCN}
	}
	out := pkix.Name{CommonName: fallbackCN}
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "CN":
			out.CommonName = v
		case "O":
			out.Organization = append(out.Organization, v)
		case "OU":
			out.OrganizationalUnit = append(out.OrganizationalUnit, v)
		case "C":
			out.Country = append(out.Country, v)
		case "L":
			out.Locality = append(out.Locality, v)
		case "ST", "S":
			out.Province = append(out.Province, v)
		}
	}
	return out
}

func csrSANs(csr *x509.CertificateRequest) []string {
	out := make([]string, 0, len(csr.DNSNames)+len(csr.IPAddresses))
	out = append(out, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		out = append(out, ip.String())
	}
	return dedupStrings(out)
}

func splitSANs(in []string) ([]string, []net.IP) {
	dns := make([]string, 0, len(in))
	ips := make([]net.IP, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, s)
	}
	return dns, ips
}

func buildCASigningIntent(req CreateCARequest) []byte {
	raw, _ := json.Marshal(map[string]interface{}{
		"tenant_id": req.TenantID,
		"name":      req.Name,
		"ca_level":  req.CALevel,
		"algorithm": req.Algorithm,
		"subject":   req.Subject,
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
	})
	sum := sha256.Sum256(raw)
	return sum[:]
}

func buildLeafSigningIntent(req IssueCertificateRequest, serial *big.Int, sans []string, otsIndex int64) []byte {
	raw, _ := json.Marshal(map[string]interface{}{
		"tenant_id":  req.TenantID,
		"ca_id":      req.CAID,
		"serial":     serial.Text(16),
		"subject_cn": req.SubjectCN,
		"sans":       sans,
		"algorithm":  req.Algorithm,
		"cert_class": req.CertClass,
		"protocol":   req.Protocol,
		"ots_index":  otsIndex,
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	})
	sum := sha256.Sum256(raw)
	return sum[:]
}

func normalizeCALevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "root":
		return "root"
	case "intermediate":
		return "intermediate"
	default:
		return ""
	}
}

func normalizeCAType(v string, algorithm string) string {
	n := strings.ToLower(strings.TrimSpace(v))
	if n == "classical" || n == "hybrid" || n == "pqc" || n == "composite" {
		return n
	}
	if isHybridAlgorithm(algorithm) {
		return "hybrid"
	}
	if isPQCAlgorithm(algorithm) {
		return "pqc"
	}
	return "classical"
}

func normalizeCertClass(v string, algorithm string) string {
	n := strings.ToLower(strings.TrimSpace(v))
	if n == "classical" || n == "hybrid" || n == "pqc" || n == "internal-mtls" {
		return n
	}
	if isHybridAlgorithm(algorithm) {
		return "hybrid"
	}
	if isPQCAlgorithm(algorithm) {
		return "pqc"
	}
	return "classical"
}

func normalizeAlgorithm(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return strings.ToUpper(v)
}

func normalizeKeyBackend(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "keycore", "hsm":
		return "keycore"
	default:
		return "software"
	}
}

func isPQCAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.Contains(alg, "ML-DSA") ||
		strings.Contains(alg, "SLH-DSA") ||
		strings.Contains(alg, "ML-KEM") ||
		strings.Contains(alg, "HSS") ||
		strings.Contains(alg, "LMS") ||
		strings.Contains(alg, "XMSS")
}

func isHybridAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.Contains(alg, "+") || strings.Contains(alg, "HYBRID")
}

func isStatefulAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.Contains(alg, "HSS") || strings.Contains(alg, "LMS") || strings.Contains(alg, "XMSS")
}

func dedupStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func zeroizeString(v *string) {
	if v == nil {
		return
	}
	raw := []byte(*v)
	pkgcrypto.Zeroize(raw)
	*v = ""
}
