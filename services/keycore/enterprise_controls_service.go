package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"vecta-kms/pkg/crypto"
)

func (s *Service) UpsertEnterpriseControl(ctx context.Context, record EnterpriseControlRecord) (EnterpriseControlRecord, error) {
	if strings.TrimSpace(record.TenantID) == "" {
		return EnterpriseControlRecord{}, errors.New("tenant_id is required")
	}
	record.Category = normalizeEnterpriseCategory(record.Category)
	if record.Category == "" {
		return EnterpriseControlRecord{}, errors.New("category is required")
	}
	if strings.TrimSpace(record.Name) == "" {
		record.Name = strings.ReplaceAll(record.Category, "_", " ")
	}
	record.Metadata = sanitizeEnterpriseMetadata(record.Metadata)
	if strings.TrimSpace(record.KeyID) != "" {
		if _, err := s.GetKey(ctx, record.TenantID, record.KeyID); err != nil {
			return EnterpriseControlRecord{}, err
		}
	}
	saved, err := s.store.UpsertEnterpriseControlRecord(ctx, record)
	if err != nil {
		return EnterpriseControlRecord{}, err
	}
	_ = s.publishAudit(ctx, auditSubjectForEnterpriseCategory(saved.Category, "upserted"), saved.TenantID, map[string]any{
		"record_id":  saved.RecordID,
		"category":   saved.Category,
		"key_id":     saved.KeyID,
		"status":     saved.Status,
		"severity":   saved.Severity,
		"risk_score": saved.RiskScore,
	})
	if saved.RiskScore >= 50 || saved.Severity == "high" || saved.Severity == "critical" {
		_, _ = s.UpsertDSPMFinding(ctx, DSPMFinding{
			TenantID:          saved.TenantID,
			Source:            "keycore",
			FindingType:       saved.Category,
			Title:             "KeyCore enterprise control requires review: " + saved.Name,
			Description:       "Enterprise control state indicates elevated KMS risk.",
			Severity:          saved.Severity,
			RiskScore:         saved.RiskScore,
			Status:            "open",
			KeyID:             saved.KeyID,
			RecommendedAction: "Review the enterprise control record and close with evidence.",
			Evidence: map[string]any{
				"record_id": saved.RecordID,
				"category":  saved.Category,
				"metadata":  saved.Metadata,
			},
		})
	}
	return saved, nil
}

func (s *Service) RunEnterpriseAnomalyDetection(ctx context.Context, tenantID string, days int) ([]DSPMFinding, error) {
	if days <= 0 {
		days = 7
	}
	if days > 365 {
		days = 365
	}
	now := time.Now().UTC()
	since := now.AddDate(0, 0, -days)
	findings := make([]DSPMFinding, 0)

	health, err := s.store.GetKeyHealthSummary(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if health.CriticalKeys > 0 || health.AtRiskKeys > 0 {
		severity := "medium"
		risk := 45 + health.AtRiskKeys*4 + health.CriticalKeys*12
		if health.CriticalKeys > 0 {
			severity = "high"
		}
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "key_health_degradation", ""),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "key_health_degradation",
			Title:             "Key health degradation detected",
			Description:       "Key health scoring found at-risk or critical keys in the active inventory.",
			Severity:          severity,
			RiskScore:         clampScore(risk),
			Status:            "open",
			RecommendedAction: "Review low-scoring keys, rotate overdue keys, and verify backup coverage.",
			Evidence: map[string]any{
				"critical_keys": health.CriticalKeys,
				"at_risk_keys":  health.AtRiskKeys,
				"avg_health":    health.AverageHealth,
				"window_days":   days,
			},
		})
	}

	compromise, err := s.store.GetCompromiseSummary(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if compromise.OpenEvents > 0 || compromise.CriticalEvents > 0 {
		severity := "high"
		if compromise.CriticalEvents > 0 {
			severity = "critical"
		}
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "open_compromise_events", ""),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "open_compromise_events",
			Title:             "Open key compromise events require response",
			Description:       "Compromise workflow contains unresolved high-risk events.",
			Severity:          severity,
			RiskScore:         clampScore(70 + compromise.CriticalEvents*10 + compromise.HighEvents*5),
			Status:            "open",
			RecommendedAction: "Complete incident workflow, rotate or retire impacted keys, and attach remediation evidence.",
			Evidence: map[string]any{
				"open_events":        compromise.OpenEvents,
				"critical_events":    compromise.CriticalEvents,
				"auto_suspended_key": compromise.AutoSuspendedKeys,
			},
		})
	}

	duplicates, err := s.DetectDuplicateKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	inventory, err := s.store.GetInventorySummary(ctx, tenantID, len(duplicates))
	if err != nil {
		return nil, err
	}
	if inventory.OrphanedKeys > 0 || inventory.DuplicateSets > 0 {
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "inventory_dependency_gap", ""),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "inventory_dependency_gap",
			Title:             "Key inventory dependency gaps detected",
			Description:       "Inventory contains orphaned keys or duplicate key-control values.",
			Severity:          "medium",
			RiskScore:         clampScore(40 + inventory.OrphanedKeys*3 + inventory.DuplicateSets*8),
			Status:            "open",
			RecommendedAction: "Map dependencies, validate ownership, and remove or rotate duplicate/orphaned keys.",
			Evidence: map[string]any{
				"orphaned_keys":  inventory.OrphanedKeys,
				"duplicate_sets": inventory.DuplicateSets,
				"total_keys":     inventory.TotalKeys,
			},
		})
	}

	hotspots, err := s.store.ListKeyHotspots(ctx, tenantID, since, 10)
	if err != nil {
		return nil, err
	}
	for _, hot := range hotspots {
		if hot.AccessCount < 1000 && hot.Percentile < 95 {
			continue
		}
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "key_usage_hotspot", hot.KeyID),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "key_usage_hotspot",
			Title:             "Key usage hotspot detected",
			Description:       "A key is in the highest usage band for the selected window.",
			Severity:          "medium",
			RiskScore:         clampScore(35 + int(hot.Percentile/2)),
			Status:            "open",
			KeyID:             hot.KeyID,
			RecommendedAction: "Benchmark dependent services, verify rate limits, and consider key sharding or envelope rewrap.",
			Evidence: map[string]any{
				"access_count": hot.AccessCount,
				"percentile":   hot.Percentile,
				"service_ids":  hot.ServiceIDs,
				"window_days":  days,
			},
		})
	}

	benchmarks, err := s.store.GetAlgorithmBenchmarks(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	for _, bench := range benchmarks {
		if bench.FailureRate < 0.05 && bench.PerformanceBand != "poor" {
			continue
		}
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "algorithm_performance_degradation", bench.Algorithm+"-"+bench.Operation),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "algorithm_performance_degradation",
			Title:             "Algorithm performance degradation detected",
			Description:       "Algorithm benchmark metrics show elevated latency or failures.",
			Severity:          "medium",
			RiskScore:         clampScore(45 + int(bench.FailureRate*100)),
			Status:            "open",
			RecommendedAction: "Review algorithm/provider performance, HSM health, and retry behavior.",
			Evidence: map[string]any{
				"algorithm":          bench.Algorithm,
				"operation":          bench.Operation,
				"failure_rate":       bench.FailureRate,
				"average_latency_ms": bench.AverageLatency,
				"performance_band":   bench.PerformanceBand,
			},
		})
	}

	// Post-quantum readiness: flag in-use classical asymmetric algorithms
	// (RSA/ECC/DH) that are vulnerable to quantum cryptanalysis. Reuses the
	// algorithm benchmarks already gathered above — no extra query.
	quantumVulnerable := make([]map[string]any, 0)
	var quantumVulnerableOps int64
	for _, bench := range benchmarks {
		family, vulnerable := classifyQuantumVulnerability(bench.Algorithm)
		if !vulnerable {
			continue
		}
		quantumVulnerableOps += bench.Count
		quantumVulnerable = append(quantumVulnerable, map[string]any{
			"algorithm": bench.Algorithm,
			"family":    family,
			"operation": bench.Operation,
			"count":     bench.Count,
		})
	}
	if len(quantumVulnerable) > 0 {
		severity := "medium"
		if quantumVulnerableOps >= 1000 || len(quantumVulnerable) >= 3 {
			severity = "high"
		}
		findings = append(findings, DSPMFinding{
			FindingID:         stableFindingID(tenantID, "anomaly", "quantum_vulnerable_algorithm", ""),
			TenantID:          tenantID,
			Source:            "keycore-anomaly",
			FindingType:       "quantum_vulnerable_algorithm",
			Title:             "Quantum-vulnerable algorithms in active use",
			Description:       "Keys using classical asymmetric algorithms (RSA/ECC/DH) are vulnerable to future quantum cryptanalysis and should be migrated to NIST PQC standards.",
			Severity:          severity,
			RiskScore:         clampScore(50 + len(quantumVulnerable)*6 + int(quantumVulnerableOps/200)),
			Status:            "open",
			RecommendedAction: "Plan PQC migration: re-key to ML-KEM (FIPS 203) and ML-DSA (FIPS 204), or deploy hybrid suites; prioritize long-lived and externally-exposed keys.",
			Evidence: map[string]any{
				"vulnerable_algorithms": quantumVulnerable,
				"vulnerable_operations": quantumVulnerableOps,
				"window_days":           days,
				"recommended_targets":   []string{"ML-KEM-768", "ML-DSA-65", "SLH-DSA"},
			},
		})
	}

	for i := range findings {
		saved, err := s.UpsertDSPMFinding(ctx, findings[i])
		if err != nil {
			return nil, err
		}
		findings[i] = saved
		_, _ = s.store.UpsertEnterpriseControlRecord(ctx, EnterpriseControlRecord{
			RecordID:  saved.FindingID,
			TenantID:  tenantID,
			Category:  controlCategoryAnomaly,
			KeyID:     saved.KeyID,
			Name:      saved.Title,
			Status:    saved.Status,
			Severity:  saved.Severity,
			RiskScore: saved.RiskScore,
			Metadata:  saved.Evidence,
		})
	}
	_ = s.publishAudit(ctx, "audit.key.anomaly_scan_completed", tenantID, map[string]any{
		"finding_count": len(findings),
		"window_days":   days,
		"since":         since.Format(time.RFC3339),
	})
	return findings, nil
}

// classifyQuantumVulnerability reports whether an algorithm is a classical
// asymmetric primitive broken by a cryptographically-relevant quantum computer
// (Shor's algorithm). Symmetric/hash primitives (AES, SHA-2/3) and NIST PQC
// algorithms (ML-KEM, ML-DSA, SLH-DSA, Falcon) are not flagged. The PQC set is
// checked first to avoid substring false positives (e.g. ML-DSA contains DSA).
func classifyQuantumVulnerability(algorithm string) (family string, vulnerable bool) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return "", false
	}
	for _, safe := range []string{"ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "HQC", "BIKE"} {
		if strings.Contains(a, safe) {
			return "pqc", false
		}
	}
	switch {
	case strings.Contains(a, "RSA"):
		return "rsa", true
	case strings.Contains(a, "ECDSA"), strings.Contains(a, "ECDH"), strings.Contains(a, "ED25519"),
		strings.Contains(a, "ED448"), strings.Contains(a, "X25519"), strings.Contains(a, "X448"),
		strings.Contains(a, "SECP"), strings.Contains(a, "P-256"), strings.Contains(a, "P-384"),
		strings.Contains(a, "P-521"), strings.Contains(a, "BRAINPOOL"):
		return "ecc", true
	case strings.HasPrefix(a, "DH"), strings.Contains(a, "DIFFIE"), strings.Contains(a, "DSA"):
		return "dh", true
	}
	return "symmetric", false
}

func (s *Service) UpsertDSPMFinding(ctx context.Context, finding DSPMFinding) (DSPMFinding, error) {
	if strings.TrimSpace(finding.TenantID) == "" {
		return DSPMFinding{}, errors.New("tenant_id is required")
	}
	if strings.TrimSpace(finding.FindingType) == "" {
		return DSPMFinding{}, errors.New("finding_type is required")
	}
	if strings.TrimSpace(finding.Title) == "" {
		finding.Title = strings.ReplaceAll(finding.FindingType, "_", " ")
	}
	if strings.TrimSpace(finding.Status) == "" {
		finding.Status = "open"
	}
	finding.Evidence = sanitizeEnterpriseMetadata(finding.Evidence)
	saved, err := s.store.UpsertDSPMFinding(ctx, finding)
	if err != nil {
		return DSPMFinding{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.dspm_finding_upserted", saved.TenantID, map[string]any{
		"finding_id":   saved.FindingID,
		"finding_type": saved.FindingType,
		"severity":     saved.Severity,
		"risk_score":   saved.RiskScore,
		"status":       saved.Status,
		"key_id":       saved.KeyID,
		"resource_id":  saved.KeyID,
	})
	return saved, nil
}

func (s *Service) ExportDSPMPostureEvents(ctx context.Context, tenantID string, q DSPMFindingQuery) ([]map[string]any, error) {
	findings, err := s.store.ListDSPMFindings(ctx, tenantID, q)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, map[string]any{
			"id":          f.FindingID,
			"timestamp":   f.UpdatedAt.Format(time.RFC3339Nano),
			"tenant_id":   f.TenantID,
			"service":     "keycore",
			"action":      "audit.key.dspm_finding",
			"result":      "success",
			"severity":    f.Severity,
			"resource_id": f.KeyID,
			"details": map[string]any{
				"finding_type":       f.FindingType,
				"title":              f.Title,
				"description":        f.Description,
				"risk_score":         f.RiskScore,
				"status":             f.Status,
				"recommended_action": f.RecommendedAction,
				"evidence":           f.Evidence,
			},
		})
	}
	return items, nil
}

func (s *Service) DeriveEnterpriseKDF(ctx context.Context, req KDFDeriveRequest) (KDFDeriveResponse, error) {
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SecretBase64))
	if err != nil || len(secret) < 16 {
		return KDFDeriveResponse{}, errors.New("secret_base64 must decode to at least 16 bytes")
	}
	defer crypto.Zeroize(secret)
	salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SaltBase64))
	if err != nil || len(salt) < 16 {
		return KDFDeriveResponse{}, errors.New("salt_base64 must decode to at least 16 bytes")
	}
	defer crypto.Zeroize(salt)
	info := []byte{}
	if strings.TrimSpace(req.InfoBase64) != "" {
		info, err = base64.StdEncoding.DecodeString(strings.TrimSpace(req.InfoBase64))
		if err != nil {
			return KDFDeriveResponse{}, errors.New("info_base64 must be valid base64")
		}
	}
	if req.Length <= 0 {
		req.Length = 32
	}
	if req.Length > 128 {
		return KDFDeriveResponse{}, errors.New("length must be <= 128 bytes")
	}

	algorithm := normalizeKDFAlgorithm(req.Algorithm)
	if algorithm == "" {
		return KDFDeriveResponse{}, errors.New("algorithm must be hkdf-sha256, pbkdf2-sha256, scrypt, or argon2id")
	}
	var (
		derived []byte
		params  string
	)
	switch algorithm {
	case "hkdf-sha256":
		reader := hkdf.New(sha256.New, secret, salt, info)
		derived = make([]byte, req.Length)
		if _, err := io.ReadFull(reader, derived); err != nil {
			return KDFDeriveResponse{}, err
		}
		params = "hash=sha256"
	case "pbkdf2-sha256":
		iterations := req.Iterations
		if iterations == 0 {
			iterations = 210000
		}
		if iterations < 100000 {
			return KDFDeriveResponse{}, errors.New("pbkdf2 iterations must be >= 100000")
		}
		derived = pbkdf2.Key(secret, salt, iterations, req.Length, sha256.New)
		params = fmt.Sprintf("hash=sha256,iterations=%d", iterations)
	case "scrypt":
		n, r, p := scryptParameters(req.MemoryKiB, req.Parallelism)
		derived, err = scrypt.Key(secret, salt, n, r, p, req.Length)
		if err != nil {
			return KDFDeriveResponse{}, err
		}
		params = fmt.Sprintf("N=%d,r=%d,p=%d", n, r, p)
	case "argon2id":
		memory := req.MemoryKiB
		if memory == 0 {
			memory = 64 * 1024
		}
		if memory < 19*1024 {
			return KDFDeriveResponse{}, errors.New("argon2id memory_kib must be >= 19456")
		}
		if memory > 256*1024 {
			return KDFDeriveResponse{}, errors.New("argon2id memory_kib must be <= 262144")
		}
		parallelism := req.Parallelism
		if parallelism == 0 {
			parallelism = 1
		}
		if parallelism > 4 {
			return KDFDeriveResponse{}, errors.New("argon2id parallelism must be <= 4")
		}
		timeCost := uint32(req.Iterations)
		if timeCost == 0 {
			timeCost = 3
		}
		if timeCost < 2 {
			return KDFDeriveResponse{}, errors.New("argon2id iterations/time cost must be >= 2")
		}
		derived = argon2.IDKey(secret, salt, timeCost, memory, parallelism, uint32(req.Length))
		params = fmt.Sprintf("time=%d,memory_kib=%d,parallelism=%d", timeCost, memory, parallelism)
	}
	defer crypto.Zeroize(derived)
	sum := sha256.Sum256(derived)
	saltSum := sha256.Sum256(salt)
	resp := KDFDeriveResponse{
		Algorithm:          algorithm,
		DerivedKeyBase64:   base64.StdEncoding.EncodeToString(derived),
		DerivedKeySHA256:   "sha256:" + hex.EncodeToString(sum[:]),
		Length:             req.Length,
		ParameterSummary:   params,
		SaltSHA256:         "sha256:" + hex.EncodeToString(saltSum[:]),
		SecretNotPersisted: true,
	}
	_, _ = s.store.UpsertEnterpriseControlRecord(ctx, EnterpriseControlRecord{
		TenantID:  req.TenantID,
		Category:  controlCategoryKDFDerivation,
		KeyID:     req.KeyID,
		Name:      "KDF derivation",
		Status:    "completed",
		Severity:  "info",
		RiskScore: 0,
		Metadata: map[string]any{
			"algorithm":          algorithm,
			"length":             req.Length,
			"parameter_summary":  params,
			"salt_sha256":        resp.SaltSHA256,
			"derived_key_sha256": resp.DerivedKeySHA256,
		},
	})
	_ = s.publishAudit(ctx, "audit.key.kdf_derived", req.TenantID, map[string]any{
		"key_id":             req.KeyID,
		"algorithm":          algorithm,
		"length":             req.Length,
		"parameter_summary":  params,
		"salt_sha256":        resp.SaltSHA256,
		"derived_key_sha256": resp.DerivedKeySHA256,
	})
	return resp, nil
}

func (s *Service) SplitShamirSecret(ctx context.Context, req ShamirSplitRequest) (ShamirSplitResponse, error) {
	if req.Threshold < 2 {
		return ShamirSplitResponse{}, errors.New("threshold must be >= 2")
	}
	if req.Shares < req.Threshold || req.Shares > 255 {
		return ShamirSplitResponse{}, errors.New("shares must be >= threshold and <= 255")
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SecretBase64))
	if err != nil || len(secret) < 16 {
		return ShamirSplitResponse{}, errors.New("secret_base64 must decode to at least 16 bytes")
	}
	defer crypto.Zeroize(secret)
	shares, err := shamirSplit(secret, req.Threshold, req.Shares)
	if err != nil {
		return ShamirSplitResponse{}, err
	}
	secretHash := sha256Hex(secret)
	out := ShamirSplitResponse{
		SplitID:            newID("ss"),
		Threshold:          req.Threshold,
		Shares:             make([]ShamirShare, 0, len(shares)),
		SecretSHA256:       secretHash,
		SharesReturnedOnce: true,
	}
	for _, share := range shares {
		out.Shares = append(out.Shares, ShamirShare{
			Index:       int(share[0]),
			ShareBase64: base64.StdEncoding.EncodeToString(share),
			ShareSHA256: sha256Hex(share),
		})
		crypto.Zeroize(share)
	}
	_, _ = s.store.UpsertEnterpriseControlRecord(ctx, EnterpriseControlRecord{
		RecordID: out.SplitID,
		TenantID: req.TenantID,
		Category: controlCategoryEscrowShamir,
		Name:     "Shamir escrow split",
		Status:   "active",
		Severity: "info",
		Metadata: map[string]any{
			"threshold":     req.Threshold,
			"shares":        req.Shares,
			"context":       req.Context,
			"secret_sha256": secretHash,
			"returned_once": true,
		},
	})
	_ = s.publishAudit(ctx, "audit.key.escrow_shamir_split", req.TenantID, map[string]any{
		"split_id":      out.SplitID,
		"threshold":     req.Threshold,
		"shares":        req.Shares,
		"secret_sha256": secretHash,
	})
	return out, nil
}

func (s *Service) VerifyShamirSecret(ctx context.Context, req ShamirVerifyRequest) (ShamirVerifyResponse, error) {
	record, err := s.store.GetEnterpriseControlRecord(ctx, req.TenantID, controlCategoryEscrowShamir, req.SplitID)
	if err != nil {
		return ShamirVerifyResponse{}, err
	}
	threshold := intFromAny(record.Metadata["threshold"])
	expectedHash := firstString(record.Metadata["secret_sha256"])
	if threshold < 2 || expectedHash == "" {
		return ShamirVerifyResponse{}, errors.New("split metadata is incomplete")
	}
	if len(req.Shares) < threshold {
		return ShamirVerifyResponse{Valid: false, Message: "not enough shares"}, nil
	}
	rawShares := make([][]byte, 0, len(req.Shares))
	for _, share := range req.Shares {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(share.ShareBase64))
		if err != nil || len(raw) < 2 {
			return ShamirVerifyResponse{}, errors.New("shares must be valid base64-encoded Shamir shares")
		}
		rawShares = append(rawShares, raw)
		defer crypto.Zeroize(raw)
	}
	secret, err := shamirRecover(rawShares[:threshold])
	if err != nil {
		return ShamirVerifyResponse{}, err
	}
	defer crypto.Zeroize(secret)
	gotHash := sha256Hex(secret)
	valid := hmac.Equal([]byte(gotHash), []byte(expectedHash))
	_ = s.publishAudit(ctx, "audit.key.escrow_shamir_verified", req.TenantID, map[string]any{
		"split_id":      req.SplitID,
		"valid":         valid,
		"secret_sha256": gotHash,
	})
	if !valid {
		return ShamirVerifyResponse{Valid: false, Message: "shares reconstructed a different secret"}, nil
	}
	return ShamirVerifyResponse{Valid: true, SecretSHA256: gotHash, Message: "shares verified"}, nil
}

func (s *Service) AnchorEnterpriseAuditChain(ctx context.Context, tenantID, anchorType, externalRef string, metadata map[string]any) (AuditChainAnchor, error) {
	if strings.TrimSpace(anchorType) == "" {
		anchorType = "internal_merkle"
	}
	now := time.Now().UTC()
	seed := fmt.Sprintf("%s|%s|%s|%d", tenantID, anchorType, externalRef, now.UnixNano())
	root := sha256Hex([]byte(seed))
	anchors, _ := s.store.ListAuditChainAnchors(ctx, tenantID, 1)
	previous := ""
	if len(anchors) > 0 {
		previous = anchors[0].AnchorHash
	}
	anchorHash := sha256Hex([]byte(previous + "|" + root + "|" + externalRef))
	anchor, err := s.store.RecordAuditChainAnchor(ctx, AuditChainAnchor{
		TenantID:          tenantID,
		AnchorType:        anchorType,
		MerkleRoot:        "sha256:" + root,
		PreviousHash:      previous,
		AnchorHash:        "sha256:" + anchorHash,
		ExternalReference: externalRef,
		Status:            "anchored",
		Metadata:          metadata,
		AnchoredAt:        now,
	})
	if err != nil {
		return AuditChainAnchor{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.audit_chain_anchored", tenantID, map[string]any{
		"anchor_id":          anchor.AnchorID,
		"anchor_type":        anchor.AnchorType,
		"merkle_root":        anchor.MerkleRoot,
		"anchor_hash":        anchor.AnchorHash,
		"external_reference": anchor.ExternalReference,
	})
	return anchor, nil
}

func (s *Service) VerifyKeyMaterialFingerprint(ctx context.Context, tenantID, keyID, fingerprint string) (EnterpriseControlRecord, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return EnterpriseControlRecord{}, err
	}
	expected := strings.ToUpper(strings.TrimSpace(fingerprint))
	actual := strings.ToUpper(hex.EncodeToString(key.KCV))
	status := "verified"
	severity := "info"
	risk := 0
	if expected == "" || !hmac.Equal([]byte(expected), []byte(actual)) {
		status = "failed"
		severity = "high"
		risk = 80
	}
	record, err := s.UpsertEnterpriseControl(ctx, EnterpriseControlRecord{
		TenantID:  tenantID,
		Category:  controlCategoryVerification,
		KeyID:     keyID,
		Name:      "Key material fingerprint verification",
		Status:    status,
		Severity:  severity,
		RiskScore: risk,
		Metadata: map[string]any{
			"expected_kcv": expected,
			"actual_kcv":   actual,
			"algorithm":    key.KCVAlgorithm,
		},
	})
	if err != nil {
		return EnterpriseControlRecord{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.material_fingerprint_verified", tenantID, map[string]any{
		"key_id":      keyID,
		"status":      status,
		"risk_score":  risk,
		"kcv_match":   status == "verified",
		"kcv_alg":     key.KCVAlgorithm,
		"result":      statusResult(status),
		"error":       errorForStatus(status, "fingerprint mismatch"),
		"status_code": statusCodeForStatus(status),
	})
	return record, nil
}

func (s *Service) BuildEnterpriseComplianceDashboard(ctx context.Context, tenantID string) (EnterpriseComplianceDashboard, error) {
	health, err := s.store.GetKeyHealthSummary(ctx, tenantID)
	if err != nil {
		return EnterpriseComplianceDashboard{}, err
	}
	compromise, err := s.store.GetCompromiseSummary(ctx, tenantID)
	if err != nil {
		return EnterpriseComplianceDashboard{}, err
	}
	controls, err := s.store.ListEnterpriseControlRecords(ctx, tenantID, EnterpriseControlQuery{Limit: 1000})
	if err != nil {
		return EnterpriseComplianceDashboard{}, err
	}
	findings, err := s.store.ListDSPMFindings(ctx, tenantID, DSPMFindingQuery{Status: "open", Limit: 1000})
	if err != nil {
		return EnterpriseComplianceDashboard{}, err
	}
	critical := 0
	for _, finding := range findings {
		if finding.Severity == "critical" {
			critical++
		}
	}
	controlScores := map[string]int{
		"key_health":          clampScore(int(health.HealthPercentage)),
		"compromise_response": clampScore(100 - compromise.OpenEvents*12 - compromise.CriticalEvents*20),
		"dspm_findings":       clampScore(100 - len(findings)*4 - critical*10),
		"enterprise_controls": controlCoverageScore(controls),
	}
	total := 0
	for _, score := range controlScores {
		total += score
	}
	dash := EnterpriseComplianceDashboard{
		TenantID:         tenantID,
		OverallScore:     total / len(controlScores),
		ControlScores:    controlScores,
		OpenFindings:     len(findings),
		CriticalFindings: critical,
		Evidence: map[string]interface{}{
			"health":        health,
			"compromise":    compromise,
			"control_count": len(controls),
		},
		GeneratedAt: time.Now().UTC(),
	}
	_ = s.publishAudit(ctx, "audit.key.compliance_dashboard_viewed", tenantID, map[string]any{
		"overall_score":     dash.OverallScore,
		"open_findings":     dash.OpenFindings,
		"critical_findings": dash.CriticalFindings,
	})
	return dash, nil
}

func (s *Service) BuildEnterpriseCostOptimization(ctx context.Context, tenantID string, days int) (EnterpriseCostOptimization, error) {
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	usage, err := s.store.GetKeyUsageMetricSummary(ctx, tenantID, "", since)
	if err != nil {
		return EnterpriseCostOptimization{}, err
	}
	hotspots, err := s.store.ListKeyHotspots(ctx, tenantID, since, 10)
	if err != nil {
		return EnterpriseCostOptimization{}, err
	}
	var ops int64
	for _, metric := range usage.Metrics {
		if strings.HasPrefix(metric.Type, "usage_") {
			ops += metric.Count
		}
	}
	recs := []string{"continue usage metering"}
	score := 100
	if len(hotspots) > 0 {
		recs = append(recs, "review hotspot keys for sharding, caching, or envelope rewrap")
		score -= len(hotspots) * 5
	}
	if ops > 1000000 {
		recs = append(recs, "evaluate high-volume workload pricing and batch crypto windows")
		score -= 10
	}
	out := EnterpriseCostOptimization{
		TenantID:            tenantID,
		WindowDays:          days,
		EstimatedOperations: ops,
		EstimatedCostUSD:    float64(ops) * 0.000003,
		OptimizationScore:   clampScore(score),
		Recommendations:     uniqueStrings(recs),
		Evidence: map[string]interface{}{
			"metric_count": len(usage.Metrics),
			"hotspots":     hotspots,
		},
		GeneratedAt: time.Now().UTC(),
	}
	_ = s.publishAudit(ctx, "audit.key.cost_optimization_viewed", tenantID, map[string]any{
		"window_days":          days,
		"estimated_operations": ops,
		"optimization_score":   out.OptimizationScore,
	})
	return out, nil
}

func normalizeEnterpriseCategory(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case controlCategoryAnomaly, controlCategoryOrchestrationWorkflow, controlCategoryOrchestrationRun,
		controlCategoryFederationProvider, controlCategoryFederationMapping, controlCategoryFederationFailover,
		controlCategoryEscrowTier, controlCategoryEscrowShamir, controlCategoryKDFDerivation, controlCategoryVerification,
		controlCategoryAdvancedEncryption, controlCategoryBindingPolicy, controlCategoryEdgeAgent, controlCategoryEdgeLease,
		controlCategoryEdgeReceipt, controlCategorySharingGrant, controlCategoryMetadataProfile, controlCategoryThreatSignal:
		return strings.ToLower(strings.TrimSpace(raw))
	case "workflow":
		return controlCategoryOrchestrationWorkflow
	case "provider":
		return controlCategoryFederationProvider
	case "mapping":
		return controlCategoryFederationMapping
	case "sharing":
		return controlCategorySharingGrant
	case "metadata":
		return controlCategoryMetadataProfile
	case "threat":
		return controlCategoryThreatSignal
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), " ", "_"))
	}
}

func auditSubjectForEnterpriseCategory(category string, verb string) string {
	category = strings.ReplaceAll(normalizeEnterpriseCategory(category), "_", ".")
	if category == "" {
		category = "control"
	}
	if verb == "" {
		verb = "updated"
	}
	return "audit.key.enterprise." + category + "." + verb
}

func normalizeKDFAlgorithm(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "hkdf", "hkdf-sha256", "hkdf_sha256":
		return "hkdf-sha256"
	case "pbkdf2", "pbkdf2-sha256", "pbkdf2_sha256":
		return "pbkdf2-sha256"
	case "scrypt":
		return "scrypt"
	case "argon2", "argon2id", "argon2-id":
		return "argon2id"
	default:
		return ""
	}
}

func scryptParameters(memoryKiB uint32, parallelism uint8) (int, int, int) {
	r := 8
	p := int(parallelism)
	if p <= 0 {
		p = 1
	}
	if p > 4 {
		p = 4
	}
	n := 32768
	if memoryKiB >= 128*1024 {
		n = 65536
	}
	if memoryKiB > 0 && memoryKiB < 32*1024 {
		n = 16384
	}
	return n, r, p
}

func stableFindingID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(strings.TrimSpace(part)))
		_, _ = h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return "dspm_" + hex.EncodeToString(sum[:12])
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func controlCoverageScore(records []EnterpriseControlRecord) int {
	if len(records) == 0 {
		return 50
	}
	totalRisk := 0
	active := 0
	for _, record := range records {
		if record.Status == "active" || record.Status == "open" || record.Status == "failed" {
			active++
			totalRisk += record.RiskScore
		}
	}
	return clampScore(100 - active*2 - totalRisk/max(1, len(records))/2)
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func sanitizeEnterpriseMetadata(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		cleanKey := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(cleanKey, "secret") ||
			strings.Contains(cleanKey, "password") ||
			strings.Contains(cleanKey, "token") ||
			strings.Contains(cleanKey, "credential") ||
			strings.Contains(cleanKey, "material") ||
			strings.Contains(cleanKey, "private") {
			out[key] = "***"
			continue
		}
		switch v := value.(type) {
		case map[string]any:
			out[key] = sanitizeEnterpriseMetadata(v)
		case []any:
			items := make([]any, 0, len(v))
			for _, item := range v {
				if nested, ok := item.(map[string]any); ok {
					items = append(items, sanitizeEnterpriseMetadata(nested))
					continue
				}
				items = append(items, item)
			}
			out[key] = items
		default:
			out[key] = value
		}
	}
	return out
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var out int
		_, _ = fmt.Sscanf(t, "%d", &out)
		return out
	default:
		return 0
	}
}

func firstString(values ...any) string {
	for _, value := range values {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case fmt.Stringer:
			if strings.TrimSpace(v.String()) != "" {
				return strings.TrimSpace(v.String())
			}
		}
	}
	return ""
}

func statusResult(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "blocked", "denied":
		return "failure"
	default:
		return "success"
	}
}

func errorForStatus(status string, msg string) string {
	if statusResult(status) == "failure" {
		return msg
	}
	return ""
}

func statusCodeForStatus(status string) int {
	if statusResult(status) == "failure" {
		return 409
	}
	return 200
}

func shamirSplit(secret []byte, threshold int, shares int) ([][]byte, error) {
	if threshold < 2 || threshold > shares || shares > 255 {
		return nil, errors.New("invalid Shamir parameters")
	}
	polynomials := make([][]byte, len(secret))
	for i, b := range secret {
		poly := make([]byte, threshold)
		poly[0] = b
		if _, err := rand.Read(poly[1:]); err != nil {
			return nil, err
		}
		polynomials[i] = poly
	}
	out := make([][]byte, shares)
	for x := 1; x <= shares; x++ {
		share := make([]byte, len(secret)+1)
		share[0] = byte(x)
		for i, poly := range polynomials {
			share[i+1] = shamirEval(poly, byte(x))
		}
		out[x-1] = share
	}
	for _, poly := range polynomials {
		crypto.Zeroize(poly)
	}
	return out, nil
}

func shamirRecover(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("at least two shares are required")
	}
	size := len(shares[0]) - 1
	if size <= 0 {
		return nil, errors.New("invalid share length")
	}
	seen := map[byte]bool{}
	for _, share := range shares {
		if len(share) != size+1 {
			return nil, errors.New("shares must have identical lengths")
		}
		if share[0] == 0 || seen[share[0]] {
			return nil, errors.New("shares must have unique non-zero indexes")
		}
		seen[share[0]] = true
	}
	secret := make([]byte, size)
	for b := 0; b < size; b++ {
		var value byte
		for i, share := range shares {
			xi := share[0]
			yi := share[b+1]
			li := byte(1)
			for j, other := range shares {
				if i == j {
					continue
				}
				xj := other[0]
				li = gfMul(li, gfDiv(xj, gfAdd(xi, xj)))
			}
			value = gfAdd(value, gfMul(yi, li))
		}
		secret[b] = value
	}
	return secret, nil
}

func shamirEval(poly []byte, x byte) byte {
	out := byte(0)
	for i := len(poly) - 1; i >= 0; i-- {
		out = gfMul(out, x)
		out = gfAdd(out, poly[i])
	}
	return out
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	var out byte
	for b > 0 {
		if b&1 == 1 {
			out ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return out
}

func gfPow(a byte, n int) byte {
	out := byte(1)
	for n > 0 {
		if n&1 == 1 {
			out = gfMul(out, a)
		}
		a = gfMul(a, a)
		n >>= 1
	}
	return out
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfPow(b, 254))
}

func searchableToken(secret []byte, plaintext []byte) string {
	mac := hmac.New(sha512.New512_256, secret)
	_, _ = mac.Write(bytes.ToLower(bytes.TrimSpace(plaintext)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
