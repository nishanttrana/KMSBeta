package main

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdh"
	"crypto/x509"
	"fmt"
	"strings"

	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Until 1.26.0-beta generateMaterialForCreate stored 32 random bytes for any
// algorithm it had no branch for (XMSS, HSS/LMS, DSA, DH, ML-DSA-44, hybrid
// pairs, SLH-DSA other than 256f), made Brainpool and secp256k1 keys on P-256
// and RSA-1024 keys at 2048 bits. CorrectKeyAlgorithmLabels sets each such
// record to the key it actually holds, or to invalidKeyMaterial when the
// material is not a key of any algorithm (every operation then refuses it),
// and audits each correction (audit.key.algorithm_label_corrected).
// Idempotent; runs on the primary only (the keys table is replicated).

const invalidKeyMaterial = "INVALID-MATERIAL"

// needsLabelCheck reports whether a recorded algorithm is one the old
// generator could have faked: today's generator refuses it, or it names an
// SLH-DSA set whose material may be random bytes.
func needsLabelCheck(algorithm string) bool {
	if strings.EqualFold(algorithm, invalidKeyMaterial) {
		return false
	}
	if isSLHDSAKeyAlgorithm(algorithm) {
		return true
	}
	if symmetricKeyLength(algorithm) > 0 {
		return false
	}
	_, err := planKeyGeneration(algorithm)
	return err != nil
}

// actualKeyAlgorithm names the key in material, or invalidKeyMaterial.
func actualKeyAlgorithm(recorded, keyType string, material []byte) string {
	if isSLHDSAKeyAlgorithm(recorded) {
		// Any n*2 bytes decode as an SLH-DSA public key, so a private record
		// must hold a private key.
		if isPublicKeyType(keyType) {
			if _, err := parseSLHDSAPublicMaterial(recorded, material); err == nil {
				return recorded
			}
		} else if _, err := parseSLHDSAPrivateMaterial(recorded, material); err == nil {
			return recorded
		}
		return invalidKeyMaterial
	}
	if k, err := x509.ParsePKCS8PrivateKey(material); err == nil {
		if x, ok := k.(*ecdh.PrivateKey); ok {
			return describeKeyName(x.PublicKey())
		}
		if s, ok := k.(interface{ Public() stdcrypto.PublicKey }); ok {
			return describeKeyName(s.Public())
		}
	}
	if pub, err := x509.ParsePKIXPublicKey(material); err == nil {
		return describeKeyName(pub)
	}
	return invalidKeyMaterial
}

func describeKeyName(pub any) string {
	if x, ok := pub.(*ecdh.PublicKey); ok && x.Curve() == ecdh.X25519() {
		return "X25519"
	}
	switch family, bits := pkgcrypto.DescribePublicKey(pub); family {
	case "RSA":
		return fmt.Sprintf("RSA-%d", bits)
	case "ECDSA":
		return fmt.Sprintf("ECDSA-P%d", bits)
	case "ED25519":
		return "Ed25519"
	}
	return invalidKeyMaterial
}

// CorrectKeyAlgorithmLabels returns how many key records it corrected.
func (s *Service) CorrectKeyAlgorithmLabels(ctx context.Context) (int, error) {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0, nil
	}
	st, ok := s.store.(*SQLStore)
	if !ok {
		return 0, nil
	}
	refs, err := st.listKeyAlgorithms(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ref := range refs {
		if !needsLabelCheck(ref.algorithm) {
			continue
		}
		ver, err := s.GetVersion(ctx, ref.tenantID, ref.id, 0)
		if err != nil {
			continue // HSM-backed or destroyed: no local material to judge
		}
		material, err := s.decryptMaterial(ver)
		if err != nil {
			continue
		}
		actual := actualKeyAlgorithm(ref.algorithm, ref.keyType, material)
		pkgcrypto.Zeroize(material)
		if actual == ref.algorithm {
			continue
		}
		if err := st.setKeyAlgorithm(ctx, ref.tenantID, ref.id, actual); err != nil {
			return n, err
		}
		_ = s.cache.Delete(ctx, ref.tenantID, ref.id)
		n++
		_ = s.publishAudit(ctx, "audit.key.algorithm_label_corrected", ref.tenantID, map[string]any{
			"key_id":             ref.id,
			"recorded_algorithm": ref.algorithm,
			"actual_algorithm":   actual,
			"description":        "key generation before 1.26.0-beta stored random bytes or a substitute key under this name; the record now names what the key actually is",
		})
	}
	return n, nil
}

type keyAlgorithmRef struct{ tenantID, id, algorithm, keyType string }

func (s *SQLStore) listKeyAlgorithms(ctx context.Context) ([]keyAlgorithmRef, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT tenant_id, id, algorithm, key_type FROM keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []keyAlgorithmRef
	for rows.Next() {
		var r keyAlgorithmRef
		if err := rows.Scan(&r.tenantID, &r.id, &r.algorithm, &r.keyType); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) setKeyAlgorithm(ctx context.Context, tenantID, id, algorithm string) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE keys SET algorithm = $1, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = $2 AND id = $3`, algorithm, tenantID, id)
	return err
}
