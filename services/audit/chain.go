package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
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

// eventHMAC computes HMAC-SHA256(chain_hash, signingKey).
// This provides event authenticity: the HMAC can only be produced by a party
// holding the service signing key, separate from chain integrity.
// signingKey must be 32 bytes (256-bit). If empty, returns empty string.
func eventHMAC(chainHashHex string, signingKey []byte) string {
	if len(signingKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(chainHashHex))
	return hex.EncodeToString(mac.Sum(nil))
}

// epochHash computes SHA256(previousEpochRoot || treeRoot) for cross-epoch linking.
// If previousEpochRoot is empty (epoch 0), uses "EPOCH_GENESIS" as the prefix.
func epochHash(previousEpochRoot, treeRoot string) string {
	prefix := previousEpochRoot
	if prefix == "" {
		prefix = "EPOCH_GENESIS"
	}
	h := sha256.New()
	_, _ = h.Write([]byte(prefix))
	_, _ = h.Write([]byte(treeRoot))
	return hex.EncodeToString(h.Sum(nil))
}

// categoryGroupForService maps a service name to a FIPS 140-3 functional category.
func categoryGroupForService(service string) CategoryGroup {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "auth":
		return CatAuthentication
	case "key", "keycore", "autokey", "keyaccess":
		return CatKeyManagement
	case "pqc", "mpc":
		return CatCryptographicOps
	case "secrets", "dataprotect":
		return CatDataProtection
	case "certs", "signing":
		return CatCertificateManagement
	case "policy", "governance", "compliance", "posture":
		return CatPolicyAndGovernance
	case "audit", "cluster", "reporting", "discovery", "sbom":
		return CatSystemAdministration
	case "hyok", "ekm", "workload", "confidential", "tfe", "dam":
		return CatNetworkAndAccess
	case "payment", "kmip":
		return CatFinancial
	case "byok", "cloud":
		return CatCloudIntegration
	case "qkd", "qrng":
		return CatQuantum
	case "ai", "ai-gateway":
		return CatSystemAdministration
	default:
		return CatSystemAdministration
	}
}

func dedupKey(event AuditEvent, windowSeconds int) string {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	bucket := event.Timestamp.UTC().Unix() / int64(windowSeconds)
	return event.TenantID + "|" + event.Action + "|" + event.SourceIP + "|" + event.ActorID + "|" + itoa(bucket)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
