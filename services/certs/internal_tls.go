package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	pkgsecurityheaders "vecta-kms/pkg/securityheaders"
	"vecta-kms/pkg/svctls"
)

// Internal PKI (docs/SECURITY/INTERNAL_TLS.md): vecta-runtime-root ->
// vecta-internal-services Sub CA -> one certificate per platform service,
// issued against a CSR whose key stays in the service.

const defaultInternalSubCAName = "vecta-internal-services"

func internalSubCAName() string { return envOr("CERTS_INTERNAL_SUBCA_NAME", defaultInternalSubCAName) }

func internalCertValidityDays() int64 {
	if d := int64(envInt("CERTS_INTERNAL_MTLS_VALIDITY_DAYS", 7)); d > 0 && d <= 90 {
		return d
	}
	return 7
}

// EnsureInternalPKI returns the runtime root and the internal-services Sub CA,
// creating the Sub CA under the root on first start.
func (s *Service) EnsureInternalPKI(ctx context.Context, tenantID string) (CA, CA, error) {
	if b := s.internalPKI; b != nil && b.tenant == tenantID {
		return b.root, b.sub, nil
	}
	root, err := s.ensureRuntimeRootCA(ctx, tenantID, s.runtimeRootCAName(ctx, tenantID))
	if err != nil {
		return CA{}, CA{}, fmt.Errorf("runtime root CA: %w", err)
	}
	name := internalSubCAName()
	cas, err := s.store.ListCAs(ctx, tenantID)
	if err != nil {
		return CA{}, CA{}, err
	}
	for _, ca := range cas {
		if strings.EqualFold(ca.Name, name) && ca.ParentCAID == root.ID && strings.EqualFold(ca.Status, CAStatusActive) {
			return root, ca, nil
		}
	}
	sub, err := s.CreateCA(ctx, CreateCARequest{
		TenantID:     tenantID,
		Name:         name,
		ParentCAID:   root.ID,
		CALevel:      "intermediate",
		Algorithm:    "ECDSA-P384",
		CAType:       "classical",
		KeyBackend:   "software",
		Subject:      fmt.Sprintf("CN=%s,O=Vecta KMS Internal", name),
		ValidityDays: 1825,
	})
	if err != nil {
		return CA{}, CA{}, fmt.Errorf("internal services Sub CA: %w", err)
	}
	_ = s.publishAudit(ctx, "audit.cert.internal_subca_created", tenantID, map[string]interface{}{
		"ca_id": sub.ID, "name": name, "parent_ca_id": root.ID, "algorithm": "ECDSA-P384",
		"description": "internal-services Sub CA created under the runtime root",
	})
	return root, sub, nil
}

// WriteTrustBundle publishes the public internal trust anchors every service
// mounts read-only: the Sub CA (internal-ca.crt), the root (root-ca.crt) and
// both (internal-chain.crt).
func WriteTrustBundle(dir string, root, sub CA) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomically(filepath.Join(dir, "internal-ca.crt"), []byte(strings.TrimSpace(sub.CertPEM)+"\n"), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomically(filepath.Join(dir, "root-ca.crt"), []byte(strings.TrimSpace(root.CertPEM)+"\n"), 0o644); err != nil {
		return err
	}
	// Sub CA + root for verifiers (OpenSSL/nginx) that must build the chain
	// to a self-signed root; they still require the Sub CA as issuer.
	return writeFileAtomically(filepath.Join(dir, "internal-chain.crt"), []byte(strings.TrimSpace(sub.CertPEM)+"\n"+strings.TrimSpace(root.CertPEM)+"\n"), 0o644)
}

// EnrollInternal issues an internal certificate for identity from its CSR.
// SANs come from the platform registry, never from the CSR; the previous
// certificate of the identity is revoked as superseded.
func (s *Service) EnrollInternal(ctx context.Context, tenantID, identity string, csrDER []byte) (svctls.EnrollResponse, error) {
	host, ok := svctls.HostFor(identity)
	if !ok {
		return svctls.EnrollResponse{}, fmt.Errorf("unknown identity %q", identity)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return svctls.EnrollResponse{}, errors.New("invalid CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return svctls.EnrollResponse{}, errors.New("CSR signature does not verify")
	}
	alg, err := svctls.KeyAlgorithm(csr.PublicKey)
	if err != nil {
		return svctls.EnrollResponse{}, err
	}
	_, sub, err := s.EnsureInternalPKI(ctx, tenantID)
	if err != nil {
		return svctls.EnrollResponse{}, err
	}
	meta, _ := json.Marshal(map[string]string{"identity": identity, "host": host, "enrolled_by": "csr"})
	issued, _, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     tenantID,
		CAID:         sub.ID,
		CertType:     "tls-server", // server and client auth
		Algorithm:    alg,
		CertClass:    "internal-mtls",
		SubjectCN:    identity,
		SANs:         []string{host, identity},
		CSRPem:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		ValidityDays: internalCertValidityDays(),
		Protocol:     "internal-mtls",
		MetadataJSON: string(meta),
	})
	if err != nil {
		return svctls.EnrollResponse{}, err
	}
	superseded := s.supersedeInternalCerts(ctx, tenantID, identity, issued.ID)
	_ = s.publishAudit(ctx, "audit.cert.internal_enrolled", tenantID, map[string]interface{}{
		"identity": identity, "cert_id": issued.ID, "serial_number": issued.SerialNumber, "ca_id": sub.ID,
		"key_algorithm": alg, "not_after": issued.NotAfter, "superseded": superseded,
		"description": "internal mTLS certificate issued from a CSR; the key stays in the service",
	})
	return svctls.EnrollResponse{
		CertificatePEM: issued.CertPEM,
		ChainPEM:       sub.CertPEM,
		Serial:         issued.SerialNumber,
		NotAfter:       issued.NotAfter,
	}, nil
}

func (s *Service) supersedeInternalCerts(ctx context.Context, tenantID, identity, keepID string) int {
	certs, err := s.store.ListCertificates(ctx, tenantID, CertStatusActive, "internal-mtls", 1000, 0)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range certs {
		if c.ID != keepID && strings.EqualFold(c.SubjectCN, identity) {
			if s.RevokeCertificate(ctx, RevokeCertificateRequest{TenantID: tenantID, CertID: c.ID, Reason: "superseded"}) == nil {
				n++
			}
		}
	}
	return n
}

// localEnroller lets the certs service enrol itself without the network.
type localEnroller struct {
	svc    *Service
	tenant string
}

func (l localEnroller) Enroll(ctx context.Context, identity string, csrDER []byte) (svctls.EnrollResponse, error) {
	return l.svc.EnrollInternal(ctx, l.tenant, identity, csrDER)
}

// enrollHandler serves POST /v1/enroll through the route kernel (audited as
// audit.cert.internal_enroll, refusals with their reason) on the enrolment
// listener: TLS with the certs service's own certificate and no client
// certificate, since the caller has none yet. The HMAC proof authenticates
// the identity, so the route is Public to the JWT layer.
func (s *Service) enrollHandler(tenantID, bootstrapSecret string, audit route.Emitter) http.Handler {
	kernel := route.New("cert", audit, logger)
	kernel.Handle("POST "+svctls.EnrollPath, route.Spec{
		Action: "internal_enroll", Resource: "internal_certificate",
		Public: true, Tenancy: route.PlatformScoped, Severity: "warning",
	}, func(c *route.Call) {
		var req svctls.EnrollRequest
		if err := json.NewDecoder(io.LimitReader(c.R.Body, 64<<10)).Decode(&req); err != nil {
			c.Refuse(http.StatusBadRequest, "invalid_request", "invalid enrolment request")
			return
		}
		c.Target(req.Identity)
		c.Detail("identity", req.Identity)
		c.Detail("remote_addr", c.R.RemoteAddr)
		block, _ := pem.Decode([]byte(req.CSRPEM))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			c.Refuse(http.StatusBadRequest, "invalid_csr", "csr_pem is not a PEM certificate request")
			return
		}
		if err := svctls.VerifyProof(bootstrapSecret, req, block.Bytes, c.R.Header.Get(svctls.ProofHeader()), time.Now()); err != nil {
			c.Refuse(http.StatusForbidden, "proof_rejected", err.Error())
			return
		}
		out, err := s.EnrollInternal(c.R.Context(), tenantID, req.Identity, block.Bytes)
		if err != nil {
			c.Refuse(http.StatusBadRequest, "issuance_refused", err.Error())
			return
		}
		c.Detail("serial_number", out.Serial)
		c.JSON(http.StatusOK, map[string]interface{}{
			"certificate_pem": out.CertificatePEM, "chain_pem": out.ChainPEM,
			"serial": out.Serial, "not_after": out.NotAfter,
		})
	})
	return pkgsecurityheaders.Wrap(kernel)
}

// StartEnrollmentListener serves enrolment on port until ctx ends.
func (s *Service) StartEnrollmentListener(ctx context.Context, id *svctls.Identity, port, tenantID, bootstrapSecret string, audit route.Emitter) error {
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           s.enrollHandler(tenantID, bootstrapSecret, audit),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			ClientAuth:     tls.NoClientCert,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return id.Certificate() },
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		logger.Printf("internal mTLS enrolment listening on :%s (TLS, CSR + HMAC proof)", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("enrolment listener stopped: %v", err)
		}
	}()
	return nil
}
