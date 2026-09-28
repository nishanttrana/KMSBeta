package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func eventHashInput(e AuditEvent) []byte {
	payload := map[string]interface{}{
		"tenant_id":       e.TenantID,
		"timestamp":       canonicalTimestamp(e.Timestamp),
		"service":         e.Service,
		"action":          e.Action,
		"actor_id":        e.ActorID,
		"actor_type":      e.ActorType,
		"target_type":     e.TargetType,
		"target_id":       e.TargetID,
		"method":          e.Method,
		"endpoint":        e.Endpoint,
		"source_ip":       e.SourceIP,
		"user_agent":      e.UserAgent,
		"request_hash":    e.RequestHash,
		"correlation_id":  e.CorrelationID,
		"parent_event_id": e.ParentEventID,
		"session_id":      e.SessionID,
		"result":          e.Result,
		"status_code":     e.StatusCode,
		"error_message":   e.ErrorMessage,
		"duration_ms":     e.DurationMS,
		"fips_compliant":  e.FIPSCompliant,
		"approval_id":     e.ApprovalID,
		"risk_score":      e.RiskScore,
		"tags":            e.Tags,
		"node_id":         e.NodeID,
		"details":         e.Details,
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func canonicalTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	t := ts.UTC().Truncate(time.Second)
	return strings.TrimSpace(t.Format(time.RFC3339))
}

func chainHash(previous string, input []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(previous))
	_, _ = h.Write(input)
	return hex.EncodeToString(h.Sum(nil))
}

// categoryGroupForService maps a service name to a FIPS 140-3 functional category.
func categoryGroupForService(service string) CategoryGroup {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "auth":
		return CatAuthentication
	case "key", "keycore", "autokey", "keyaccess":
		return CatKeyManagement
	case "pqc":
		return CatCryptographicOps
	case "secrets", "dataprotect":
		return CatDataProtection
	case "certs", "signing":
		return CatCertificateManagement
	case "policy", "governance", "compliance", "posture":
		return CatPolicyAndGovernance
	case "audit", "cluster", "reporting", "discovery", "sbom":
		return CatSystemAdministration
	case "hyok", "ekm", "workload", "confidential":
		return CatNetworkAndAccess
	case "payment", "kmip":
		return CatFinancial
	case "byok", "cloud":
		return CatCloudIntegration
	case "ai", "ai-gateway":
		return CatSystemAdministration
	default:
		return CatSystemAdministration
	}
}
