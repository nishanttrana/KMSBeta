package main

import (
	"context"
	"fmt"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Until 1.16.0-beta, key generation ignored the size in the algorithm name
// (generateKeyFor): an "RSA-3072" certificate got a 2048-bit key, an
// "ECDSA-P384" one a P-256 key, and a CA got RSA-3072 or P-384 whatever was
// asked. The records kept the requested name, so they claimed a key the
// certificate doesn't have. CorrectKeyLabels sets each record to the key its
// certificate actually carries and audits every correction
// (audit.certs.certificate_key_label_corrected). Idempotent; primary only.
//
// PQC and hybrid labels are left alone for now: issuance gave those an ECDSA
// key too (the certified module v1.0.0 has no ML-DSA), and whether that
// capability is removed or made a preview is the owner's decision
// (docs/DECISIONS.md, 2026-09-27).

// actualKeyAlgorithm names the key in certPEM, "" if not a classical key.
func actualKeyAlgorithm(certPEM string) string {
	c, err := parseCertificatePEM(certPEM)
	if err != nil {
		return ""
	}
	return describeKey(c.PublicKey)
}

// describeKey names a public key as the algorithm names in this service do.
func describeKey(pub any) string {
	switch family, bits := pkgcrypto.DescribePublicKey(pub); family {
	case "RSA":
		return fmt.Sprintf("RSA-%d", bits)
	case "ECDSA":
		return fmt.Sprintf("ECDSA-P%d", bits)
	case "ED25519":
		return "Ed25519"
	}
	return ""
}

// sameKeyLabel compares a recorded name with the actual one, ignoring case
// and punctuation ("ecdsa-p256" == "ECDSA-P256", "RSA2048" == "RSA-2048").
func sameKeyLabel(recorded, actual string) bool {
	norm := func(s string) string {
		return strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToUpper(s))
	}
	return norm(recorded) == norm(actual)
}

func (s *SQLStore) setCertificateAlgorithm(ctx context.Context, tenantID, id, alg string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cert_certificates SET algorithm = $1 WHERE tenant_id = $2 AND id = $3`, alg, tenantID, id)
	return err
}

func (s *SQLStore) setCAAlgorithm(ctx context.Context, tenantID, id, alg string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cert_cas SET algorithm = $1, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = $2 AND id = $3`, alg, tenantID, id)
	return err
}

// CorrectKeyLabels returns how many certificate and CA records it corrected.
func (s *Service) CorrectKeyLabels(ctx context.Context, emit route.Emitter) (int, error) {
	st, ok := s.store.(*SQLStore)
	if !ok {
		return 0, nil
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	correct := func(tenantID, kind, id, recorded, actual string, update func() error) error {
		if err := update(); err != nil {
			return err
		}
		n++
		if emit != nil {
			_ = emit.Emit(ctx, "certificate_key_label_corrected", pkgaudit.Event{
				TenantID: tenantID, ActorID: "kms-certs", ActorType: "service", TargetType: kind, TargetID: id, Result: "success",
				Details: map[string]interface{}{
					"recorded_algorithm": recorded, "actual_algorithm": actual,
					"description": "the record named a key size the certificate doesn't carry (key generation ignored the requested size before 1.16.0-beta); the record now names the actual key",
				},
			})
		}
		return nil
	}
	for _, tenantID := range tenants {
		cas, err := s.store.ListCAs(ctx, tenantID)
		if err != nil {
			return n, err
		}
		for _, ca := range cas {
			actual := actualKeyAlgorithm(ca.CertPEM)
			if actual == "" || sameKeyLabel(ca.Algorithm, actual) || isPQCAlgorithm(ca.Algorithm) || isHybridAlgorithm(ca.Algorithm) {
				continue
			}
			if err := correct(tenantID, "ca", ca.ID, ca.Algorithm, actual, func() error { return st.setCAAlgorithm(ctx, tenantID, ca.ID, actual) }); err != nil {
				return n, err
			}
		}
		for offset := 0; ; offset += 500 {
			page, err := s.store.ListCertificates(ctx, tenantID, "", "", 500, offset)
			if err != nil {
				return n, err
			}
			for _, c := range page {
				actual := actualKeyAlgorithm(c.CertPEM)
				if actual == "" || sameKeyLabel(c.Algorithm, actual) || isPQCAlgorithm(c.Algorithm) || isHybridAlgorithm(c.Algorithm) {
					continue
				}
				if err := correct(tenantID, "certificate", c.ID, c.Algorithm, actual, func() error { return st.setCertificateAlgorithm(ctx, tenantID, c.ID, actual) }); err != nil {
					return n, err
				}
			}
			if len(page) < 500 {
				break
			}
		}
	}
	return n, nil
}
