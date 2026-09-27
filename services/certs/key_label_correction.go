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
// Records labelled post-quantum or hybrid (removed in 1.19.0-beta,
// pqc_removed.go) carry a classical key too: they get the actual key name and
// the classical class or CA type (reason pqc_label_removed). Profiles with a
// PQC or hybrid algorithm are deleted, since nothing can issue under them.

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

func (s *SQLStore) setCertificateAlgorithm(ctx context.Context, tenantID, id, alg, class string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cert_certificates SET algorithm = $1, cert_class = $2 WHERE tenant_id = $3 AND id = $4`, alg, class, tenantID, id)
	return err
}

func (s *SQLStore) setCAAlgorithm(ctx context.Context, tenantID, id, alg, caType string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cert_cas SET algorithm = $1, ca_type = $2, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = $3 AND id = $4`, alg, caType, tenantID, id)
	return err
}

// retiredPQCProfiles returns the profiles of tenantID with a PQC or hybrid
// algorithm or class.
func (s *SQLStore) retiredPQCProfiles(ctx context.Context, tenantID string) ([]CertificateProfile, error) {
	all, err := s.ListProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []CertificateProfile
	for _, p := range all {
		if isPQCAlgorithm(p.Algorithm) || isHybridAlgorithm(p.Algorithm) || pqcClasses[strings.ToLower(p.CertClass)] {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *SQLStore) deleteProfile(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM cert_profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// labelIsWrong reports why a record's label must change: its key size, or a
// retired post-quantum label on a classical key. "" when it's right.
func labelIsWrong(recordedAlg, class, actual string) string {
	switch {
	case actual == "":
		return ""
	case isPQCAlgorithm(recordedAlg) || isHybridAlgorithm(recordedAlg) || pqcClasses[strings.ToLower(strings.TrimSpace(class))]:
		return "pqc_label_removed"
	case !sameKeyLabel(recordedAlg, actual):
		return "key_size_mismatch"
	}
	return ""
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
	correct := func(tenantID, kind, id, recorded, recordedClass, actual, reason string, update func() error) error {
		if err := update(); err != nil {
			return err
		}
		n++
		description := "the record named a key size the certificate doesn't carry (key generation ignored the requested size before 1.16.0-beta); the record now names the actual key"
		if reason == "pqc_label_removed" {
			description = "the record was labelled post-quantum or hybrid but the certificate carries a classical key (PQC certificates were never real and are removed in 1.19.0-beta); the record now names the actual key and the classical class"
		}
		if emit != nil {
			_ = emit.Emit(ctx, "certificate_key_label_corrected", pkgaudit.Event{
				TenantID: tenantID, ActorID: "kms-certs", ActorType: "service", TargetType: kind, TargetID: id, Result: "success",
				Details: map[string]interface{}{
					"recorded_algorithm": recorded, "recorded_class": recordedClass, "actual_algorithm": actual,
					"reason": reason, "description": description,
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
			reason := labelIsWrong(ca.Algorithm, ca.CAType, actual)
			if reason == "" {
				continue
			}
			caType := ca.CAType
			if pqcClasses[strings.ToLower(caType)] {
				caType = "classical"
			}
			if err := correct(tenantID, "ca", ca.ID, ca.Algorithm, ca.CAType, actual, reason, func() error { return st.setCAAlgorithm(ctx, tenantID, ca.ID, actual, caType) }); err != nil {
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
				reason := labelIsWrong(c.Algorithm, c.CertClass, actual)
				if reason == "" {
					continue
				}
				class := c.CertClass
				if pqcClasses[strings.ToLower(class)] {
					class = "classical"
				}
				if err := correct(tenantID, "certificate", c.ID, c.Algorithm, c.CertClass, actual, reason, func() error { return st.setCertificateAlgorithm(ctx, tenantID, c.ID, actual, class) }); err != nil {
					return n, err
				}
			}
			if len(page) < 500 {
				break
			}
		}
		profiles, err := st.retiredPQCProfiles(ctx, tenantID)
		if err != nil {
			return n, err
		}
		for _, p := range profiles {
			if err := st.deleteProfile(ctx, tenantID, p.ID); err != nil {
				return n, err
			}
			n++
			if emit != nil {
				_ = emit.Emit(ctx, "pqc_profile_removed", pkgaudit.Event{
					TenantID: tenantID, ActorID: "kms-certs", ActorType: "service", TargetType: "certificate_profile", TargetID: p.ID, Result: "success",
					Details: map[string]interface{}{"name": p.Name, "algorithm": p.Algorithm, "class": p.CertClass, "reason": "pqc_certificates_removed"},
				})
			}
		}
	}
	return n, nil
}
