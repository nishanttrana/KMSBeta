package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type serviceError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e serviceError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return e.Code
	}
	return e.Message
}

func newServiceError(status int, code string, message string) serviceError {
	return serviceError{
		Code:       strings.TrimSpace(code),
		Message:    strings.TrimSpace(message),
		HTTPStatus: status,
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func normalizeProtocol(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProtocolDKE:
		return ProtocolDKE
	case ProtocolSalesforce:
		return ProtocolSalesforce
	case ProtocolGoogleEKM:
		return ProtocolGoogleEKM
	case ProtocolGeneric:
		return ProtocolGeneric
	default:
		return ""
	}
}

func normalizeAuthMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", AuthModeMTLSOrJWT:
		return AuthModeMTLSOrJWT
	case AuthModeMTLS:
		return AuthModeMTLS
	case AuthModeJWT:
		return AuthModeJWT
	default:
		return ""
	}
}

func normalizeOperation(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "encrypt":
		return "encrypt"
	case "decrypt":
		return "decrypt"
	case "wrap":
		return "wrap"
	case "unwrap":
		return "unwrap"
	case "publickey":
		return "publickey"
	default:
		return ""
	}
}

func validateProtocolOperation(protocol string, operation string) error {
	protocol = normalizeProtocol(protocol)
	operation = normalizeOperation(operation)
	if protocol == "" || operation == "" {
		return errors.New("invalid protocol/operation")
	}
	allowed := map[string]map[string]struct{}{
		ProtocolDKE: {
			"decrypt":   {},
			"publickey": {},
		},
		ProtocolSalesforce: {
			"wrap":   {},
			"unwrap": {},
		},
		ProtocolGoogleEKM: {
			"wrap":   {},
			"unwrap": {},
		},
		ProtocolGeneric: {
			"encrypt": {},
			"decrypt": {},
			"wrap":    {},
			"unwrap":  {},
		},
	}
	if _, ok := allowed[protocol][operation]; !ok {
		return errors.New("operation not supported by protocol")
	}
	return nil
}

func defaultEndpointConfig(tenantID string, protocol string) EndpointConfig {
	return EndpointConfig{
		TenantID:           strings.TrimSpace(tenantID),
		Protocol:           normalizeProtocol(protocol),
		Enabled:            true,
		AuthMode:           AuthModeMTLSOrJWT,
		PolicyID:           "",
		GovernanceRequired: false,
		MetadataJSON:       "{}",
	}
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func validJSONOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if json.Valid([]byte(v)) {
		return v
	}
	return fallback
}

func hashJSONPayload(v interface{}) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func extractInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}
