package main

import (
	"context"
	"errors"
	"strings"
)

// PQC and hybrid certificates are removed (1.19.0-beta, CLAUDE.md rule 8).
// Issuance of "ML-DSA", "SLH-DSA", "HSS/LMS", "XMSS" or hybrid "A+B"
// certificates and CAs gave them a classical ECDSA key while recording and
// auditing them as post-quantum. They can't be made real here: the certified
// Go Cryptographic Module v1.0.0 has no ML-DSA. Such a request is refused and
// audited. Post-quantum protection of internal traffic is the TLS key
// exchange (docs/SECURITY/INTERNAL_TLS.md).

var errPQCRemoved = errors.New("post-quantum and hybrid certificates are not supported: the certified FIPS 140-3 Go Cryptographic Module v1.0.0 has no ML-DSA, and a classical key must not be labelled post-quantum")

// pqcClasses are the retired certificate classes and CA types.
var pqcClasses = map[string]bool{"pqc": true, "hybrid": true, "composite": true}

// refusePQC refuses a post-quantum or hybrid algorithm or class for kind
// ("certificate", "ca", "profile") and audits the refusal.
func (s *Service) refusePQC(ctx context.Context, tenantID, kind, algorithm, class string) error {
	if !isPQCAlgorithm(algorithm) && !isHybridAlgorithm(algorithm) && !pqcClasses[strings.ToLower(strings.TrimSpace(class))] {
		return nil
	}
	_ = s.publishAudit(ctx, "audit.cert.pqc_issuance_refused", tenantID, map[string]interface{}{
		"kind": kind, "algorithm": algorithm, "class": class, "result": "refused", "reason": "pqc_certificates_removed",
		"description": "post-quantum and hybrid certificates are not supported on the certified module (no ML-DSA)",
	})
	return errPQCRemoved
}
