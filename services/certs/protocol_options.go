package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ACMEProtocolOptions struct {
	RFC                 string   `json:"rfc"`
	ChallengeTypes      []string `json:"challenge_types"`
	AutoRenew           bool     `json:"auto_renew"`
	EnableARI           bool     `json:"enable_ari"`
	ARIPollHours        int      `json:"ari_poll_hours"`
	ARIWindowBiasPercent int     `json:"ari_window_bias_percent"`
	EmergencyRotationThresholdHours int `json:"emergency_rotation_threshold_hours"`
	MassRenewalRiskThreshold int  `json:"mass_renewal_risk_threshold"`
	RequireEAB          bool     `json:"require_eab"`
	AllowWildcard       bool     `json:"allow_wildcard"`
	AllowIPIdentifiers  bool     `json:"allow_ip_identifiers"`
	MaxSANs             int      `json:"max_sans"`
	DefaultValidityDays int64    `json:"default_validity_days"`
	RateLimitPerHour    int      `json:"rate_limit_per_hour"`
}

type ESTProtocolOptions struct {
	RFC                 string `json:"rfc"`
	DeviceEnrollment    bool   `json:"device_enrollment"`
	ServerKeygen        bool   `json:"server_keygen"`
	AuthMode            string `json:"auth_mode"`
	RequireCSRPoP       bool   `json:"require_csr_pop"`
	AllowReenroll       bool   `json:"allow_reenroll"`
	DefaultValidityDays int64  `json:"default_validity_days"`
	MaxCSRBytes         int    `json:"max_csr_bytes"`
}

type SCEPProtocolOptions struct {
	RFC                       string   `json:"rfc"`
	LegacyMDM                 bool     `json:"legacy_mdm"`
	ChallengePasswordRequired bool     `json:"challenge_password_required"`
	ChallengePassword         string   `json:"challenge_password"`
	AllowRenewal              bool     `json:"allow_renewal"`
	DefaultValidityDays       int64    `json:"default_validity_days"`
	MaxCSRBytes               int      `json:"max_csr_bytes"`
	DigestAlgorithms          []string `json:"digest_algorithms"`
	EncryptionAlgorithms      []string `json:"encryption_algorithms"`
}

type CMPv2ProtocolOptions struct {
	RFC                      string   `json:"rfc"`
	EnterprisePKI            bool     `json:"enterprise_pki"`
	MessageTypes             []string `json:"message_types"`
	RequireMessageProtection bool     `json:"require_message_protection"`
	RequireTransactionID     bool     `json:"require_transaction_id"`
	AllowImplicitConfirm     bool     `json:"allow_implicit_confirm"`
	DefaultValidityDays      int64    `json:"default_validity_days"`
}

type RuntimeMTLSProtocolOptions struct {
	Mode              string `json:"mode"`
	RuntimeRootCAName string `json:"runtime_root_ca_name"`
}

func defaultACMEProtocolOptions() ACMEProtocolOptions {
	return ACMEProtocolOptions{
		RFC:                 "8555",
		ChallengeTypes:      []string{"http-01", "dns-01"},
		AutoRenew:           true,
		EnableARI:           true,
		ARIPollHours:        defaultARIPollHours,
		ARIWindowBiasPercent: defaultARIWindowBiasPercent,
		EmergencyRotationThresholdHours: defaultEmergencyRotationThresholdHr,
		MassRenewalRiskThreshold: defaultMassRenewalRiskThreshold,
		RequireEAB:          false,
		AllowWildcard:       true,
		AllowIPIdentifiers:  false,
		MaxSANs:             100,
		DefaultValidityDays: defaultValidityLeaf,
		RateLimitPerHour:    1000,
	}
}

func defaultESTProtocolOptions() ESTProtocolOptions {
	return ESTProtocolOptions{
		RFC:                 "7030",
		DeviceEnrollment:    true,
		ServerKeygen:        true,
		AuthMode:            "mtls",
		RequireCSRPoP:       true,
		AllowReenroll:       true,
		DefaultValidityDays: defaultValidityLeaf,
		MaxCSRBytes:         32768,
	}
}

func defaultSCEPProtocolOptions() SCEPProtocolOptions {
	return SCEPProtocolOptions{
		RFC:                       "8894",
		LegacyMDM:                 true,
		ChallengePasswordRequired: false,
		ChallengePassword:         "",
		AllowRenewal:              true,
		DefaultValidityDays:       defaultValidityLeaf,
		MaxCSRBytes:               32768,
		DigestAlgorithms:          []string{"sha256", "sha384"},
		EncryptionAlgorithms:      []string{"aes256", "aes128", "des3"},
	}
}

func defaultCMPv2ProtocolOptions() CMPv2ProtocolOptions {
	return CMPv2ProtocolOptions{
		RFC:                      "4210",
		EnterprisePKI:            true,
		MessageTypes:             []string{"ir", "cr", "kur", "rr"},
		RequireMessageProtection: true,
		RequireTransactionID:     true,
		AllowImplicitConfirm:     true,
		DefaultValidityDays:      defaultValidityLeaf,
	}
}

func defaultRuntimeMTLSProtocolOptions() RuntimeMTLSProtocolOptions {
	return RuntimeMTLSProtocolOptions{
		Mode:              "default",
		RuntimeRootCAName: "",
	}
}

func normalizeProtocolConfigJSON(protocol string, raw string) (string, error) {
	switch normalizeProtocol(protocol) {
	case protocolACME:
		cfg, err := parseACMEProtocolOptions(raw)
		if err != nil {
			return "", err
		}
		return mustJSON(cfg), nil
	case protocolEST:
		cfg, err := parseESTProtocolOptions(raw)
		if err != nil {
			return "", err
		}
		return mustJSON(cfg), nil
	case protocolSCEP:
		cfg, err := parseSCEPProtocolOptions(raw)
		if err != nil {
			return "", err
		}
		return mustJSON(cfg), nil
	case protocolCMPv2:
		cfg, err := parseCMPv2ProtocolOptions(raw)
		if err != nil {
			return "", err
		}
		return mustJSON(cfg), nil
	case protocolRTMTLS:
		cfg, err := parseRuntimeMTLSProtocolOptions(raw)
		if err != nil {
			return "", err
		}
		return mustJSON(cfg), nil
	default:
		return "", fmt.Errorf("unsupported protocol")
	}
}

func defaultProtocolConfigJSON(protocol string) string {
	switch normalizeProtocol(protocol) {
	case protocolACME:
		return mustJSON(defaultACMEProtocolOptions())
	case protocolEST:
		return mustJSON(defaultESTProtocolOptions())
	case protocolSCEP:
		return mustJSON(defaultSCEPProtocolOptions())
	case protocolCMPv2:
		return mustJSON(defaultCMPv2ProtocolOptions())
	case protocolRTMTLS:
		return mustJSON(defaultRuntimeMTLSProtocolOptions())
	default:
		return "{}"
	}
}

func parseACMEProtocolOptions(raw string) (ACMEProtocolOptions, error) {
	cfg := defaultACMEProtocolOptions()
	if err := applyKnownJSON(raw, &cfg, map[string]struct{}{
		"rfc": {}, "challenge_types": {}, "auto_renew": {}, "enable_ari": {}, "ari_poll_hours": {},
		"ari_window_bias_percent": {}, "emergency_rotation_threshold_hours": {}, "mass_renewal_risk_threshold": {},
		"require_eab": {}, "allow_wildcard": {},
		"allow_ip_identifiers": {}, "max_sans": {}, "default_validity_days": {}, "rate_limit_per_hour": {},
	}); err != nil {
		return ACMEProtocolOptions{}, err
	}
	cfg.RFC = defaultString(strings.TrimSpace(cfg.RFC), "8555")
	cfg.ChallengeTypes = normalizeEnumList(cfg.ChallengeTypes, map[string]struct{}{"http-01": {}, "dns-01": {}, "tls-alpn-01": {}}, defaultACMEProtocolOptions().ChallengeTypes)
	if cfg.MaxSANs <= 0 {
		cfg.MaxSANs = 100
	}
	if cfg.MaxSANs > 1000 {
		cfg.MaxSANs = 1000
	}
	if cfg.DefaultValidityDays <= 0 {
		cfg.DefaultValidityDays = defaultValidityLeaf
	}
	if cfg.DefaultValidityDays > 3650 {
		return ACMEProtocolOptions{}, fmt.Errorf("default_validity_days exceeds 3650")
	}
	if cfg.RateLimitPerHour <= 0 {
		cfg.RateLimitPerHour = 1000
	}
	if cfg.ARIPollHours <= 0 {
		cfg.ARIPollHours = defaultARIPollHours
	}
	if cfg.ARIPollHours > 168 {
		cfg.ARIPollHours = 168
	}
	if cfg.ARIWindowBiasPercent <= 0 {
		cfg.ARIWindowBiasPercent = defaultARIWindowBiasPercent
	}
	if cfg.ARIWindowBiasPercent > 90 {
		cfg.ARIWindowBiasPercent = 90
	}
	if cfg.EmergencyRotationThresholdHours <= 0 {
		cfg.EmergencyRotationThresholdHours = defaultEmergencyRotationThresholdHr
	}
	if cfg.MassRenewalRiskThreshold <= 0 {
		cfg.MassRenewalRiskThreshold = defaultMassRenewalRiskThreshold
	}
	return cfg, nil
}

func parseESTProtocolOptions(raw string) (ESTProtocolOptions, error) {
	cfg := defaultESTProtocolOptions()
	if err := applyKnownJSON(raw, &cfg, map[string]struct{}{
		"rfc": {}, "device_enrollment": {}, "server_keygen": {}, "auth_mode": {}, "require_csr_pop": {},
		"allow_reenroll": {}, "default_validity_days": {}, "max_csr_bytes": {},
	}); err != nil {
		return ESTProtocolOptions{}, err
	}
	cfg.RFC = defaultString(strings.TrimSpace(cfg.RFC), "7030")
	cfg.AuthMode = strings.ToLower(strings.TrimSpace(cfg.AuthMode))
	switch cfg.AuthMode {
	case "mtls", "bearer", "basic", "none":
	default:
		return ESTProtocolOptions{}, fmt.Errorf("unsupported est auth_mode")
	}
	if cfg.DefaultValidityDays <= 0 {
		cfg.DefaultValidityDays = defaultValidityLeaf
	}
	if cfg.DefaultValidityDays > 3650 {
		return ESTProtocolOptions{}, fmt.Errorf("default_validity_days exceeds 3650")
	}
	if cfg.MaxCSRBytes <= 0 {
		cfg.MaxCSRBytes = 32768
	}
	if cfg.MaxCSRBytes > 1_048_576 {
		cfg.MaxCSRBytes = 1_048_576
	}
	return cfg, nil
}

func parseSCEPProtocolOptions(raw string) (SCEPProtocolOptions, error) {
	cfg := defaultSCEPProtocolOptions()
	if err := applyKnownJSON(raw, &cfg, map[string]struct{}{
		"rfc": {}, "legacy_mdm": {}, "challenge_password_required": {}, "challenge_password": {},
		"allow_renewal": {}, "default_validity_days": {}, "max_csr_bytes": {}, "digest_algorithms": {},
		"encryption_algorithms": {},
	}); err != nil {
		return SCEPProtocolOptions{}, err
	}
	cfg.RFC = defaultString(strings.TrimSpace(cfg.RFC), "8894")
	if cfg.ChallengePasswordRequired && strings.TrimSpace(cfg.ChallengePassword) == "" {
		return SCEPProtocolOptions{}, fmt.Errorf("challenge_password is required when challenge_password_required=true")
	}
	cfg.DigestAlgorithms = normalizeEnumList(cfg.DigestAlgorithms, map[string]struct{}{
		"sha1": {}, "sha224": {}, "sha256": {}, "sha384": {}, "sha512": {},
	}, defaultSCEPProtocolOptions().DigestAlgorithms)
	cfg.EncryptionAlgorithms = normalizeEnumList(cfg.EncryptionAlgorithms, map[string]struct{}{
		"des3": {}, "aes128": {}, "aes192": {}, "aes256": {},
	}, defaultSCEPProtocolOptions().EncryptionAlgorithms)
	if cfg.DefaultValidityDays <= 0 {
		cfg.DefaultValidityDays = defaultValidityLeaf
	}
	if cfg.DefaultValidityDays > 3650 {
		return SCEPProtocolOptions{}, fmt.Errorf("default_validity_days exceeds 3650")
	}
	if cfg.MaxCSRBytes <= 0 {
		cfg.MaxCSRBytes = 32768
	}
	if cfg.MaxCSRBytes > 1_048_576 {
		cfg.MaxCSRBytes = 1_048_576
	}
	return cfg, nil
}

func parseCMPv2ProtocolOptions(raw string) (CMPv2ProtocolOptions, error) {
	cfg := defaultCMPv2ProtocolOptions()
	if err := applyKnownJSON(raw, &cfg, map[string]struct{}{
		"rfc": {}, "enterprise_pki": {}, "message_types": {}, "require_message_protection": {},
		"require_transaction_id": {}, "allow_implicit_confirm": {}, "default_validity_days": {},
	}); err != nil {
		return CMPv2ProtocolOptions{}, err
	}
	cfg.RFC = defaultString(strings.TrimSpace(cfg.RFC), "4210")
	cfg.MessageTypes = normalizeEnumList(cfg.MessageTypes, map[string]struct{}{
		"ir": {}, "cr": {}, "kur": {}, "rr": {},
	}, defaultCMPv2ProtocolOptions().MessageTypes)
	if cfg.DefaultValidityDays <= 0 {
		cfg.DefaultValidityDays = defaultValidityLeaf
	}
	if cfg.DefaultValidityDays > 3650 {
		return CMPv2ProtocolOptions{}, fmt.Errorf("default_validity_days exceeds 3650")
	}
	return cfg, nil
}

func parseRuntimeMTLSProtocolOptions(raw string) (RuntimeMTLSProtocolOptions, error) {
	cfg := defaultRuntimeMTLSProtocolOptions()
	if err := applyKnownJSON(raw, &cfg, map[string]struct{}{
		"mode": {}, "runtime_root_ca_name": {},
	}); err != nil {
		return RuntimeMTLSProtocolOptions{}, err
	}
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch cfg.Mode {
	case "", "default":
		cfg.Mode = "default"
		cfg.RuntimeRootCAName = ""
	case "custom":
		cfg.RuntimeRootCAName = strings.TrimSpace(cfg.RuntimeRootCAName)
		if cfg.RuntimeRootCAName == "" {
			return RuntimeMTLSProtocolOptions{}, fmt.Errorf("runtime_root_ca_name is required when mode=custom")
		}
	default:
		return RuntimeMTLSProtocolOptions{}, fmt.Errorf("unsupported runtime-mtls mode")
	}
	return cfg, nil
}

func applyKnownJSON(raw string, out interface{}, allowed map[string]struct{}) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &asMap); err != nil {
		return fmt.Errorf("config_json must be valid JSON object")
	}
	for key := range asMap {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unsupported protocol config option: %s", key)
		}
	}
	if err := json.Unmarshal([]byte(trimmed), out); err != nil {
		return fmt.Errorf("invalid protocol config: %w", err)
	}
	return nil
}

func normalizeEnumList(in []string, allowed map[string]struct{}, defaults []string) []string {
	if len(in) == 0 {
		return append([]string{}, defaults...)
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		k := strings.ToLower(strings.TrimSpace(v))
		if k == "" {
			continue
		}
		if _, ok := allowed[k]; !ok {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if len(out) == 0 {
		return append([]string{}, defaults...)
	}
	return out
}

func mustJSON(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
