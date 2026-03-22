package main

type ProtocolImplementationSchema struct {
	Engine    string   `json:"engine"`
	Language  string   `json:"language"`
	OSSOnly   bool     `json:"oss_only"`
	SDKs      []string `json:"sdks"`
	Hardening []string `json:"hardening"`
	Notes     string   `json:"notes"`
}

type ProtocolOptionSchema struct {
	Key          string      `json:"key"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value"`
	Allowed      []string    `json:"allowed,omitempty"`
	Description  string      `json:"description"`
}

type ProtocolSchema struct {
	Protocol       string                       `json:"protocol"`
	Title          string                       `json:"title"`
	RFC            string                       `json:"rfc"`
	Description    string                       `json:"description"`
	Defaults       map[string]interface{}       `json:"defaults"`
	Options        []ProtocolOptionSchema       `json:"options"`
	Implementation ProtocolImplementationSchema `json:"implementation"`
}

func (s *Service) ListProtocolSchemas() []ProtocolSchema {
	return protocolSchemas()
}

func protocolSchemas() []ProtocolSchema {
	acmeDefaults := defaultACMEProtocolOptions()
	estDefaults := defaultESTProtocolOptions()
	scepDefaults := defaultSCEPProtocolOptions()
	cmpDefaults := defaultCMPv2ProtocolOptions()
	runtimeDefaults := defaultRuntimeMTLSProtocolOptions()

	return []ProtocolSchema{
		{
			Protocol:    protocolACME,
			Title:       "ACME",
			RFC:         "RFC 8555",
			Description: "Automated certificate issuance with challenge-based domain validation.",
			Defaults: map[string]interface{}{
				"rfc":                   acmeDefaults.RFC,
				"challenge_types":       acmeDefaults.ChallengeTypes,
				"auto_renew":            acmeDefaults.AutoRenew,
				"enable_ari":            acmeDefaults.EnableARI,
				"ari_poll_hours":        acmeDefaults.ARIPollHours,
				"ari_window_bias_percent": acmeDefaults.ARIWindowBiasPercent,
				"emergency_rotation_threshold_hours": acmeDefaults.EmergencyRotationThresholdHours,
				"mass_renewal_risk_threshold": acmeDefaults.MassRenewalRiskThreshold,
				"enable_star":           acmeDefaults.EnableSTAR,
				"default_star_validity_hours": acmeDefaults.DefaultSTARValidityHours,
				"max_star_validity_hours": acmeDefaults.MaxSTARValidityHours,
				"allow_star_delegation": acmeDefaults.AllowSTARDelegation,
				"max_star_subscriptions": acmeDefaults.MaxSTARSubscriptions,
				"star_mass_rollout_threshold": acmeDefaults.STARMassRolloutThreshold,
				"require_eab":           acmeDefaults.RequireEAB,
				"allow_wildcard":        acmeDefaults.AllowWildcard,
				"allow_ip_identifiers":  acmeDefaults.AllowIPIdentifiers,
				"max_sans":              acmeDefaults.MaxSANs,
				"default_validity_days": acmeDefaults.DefaultValidityDays,
				"rate_limit_per_hour":   acmeDefaults.RateLimitPerHour,
			},
			Options: []ProtocolOptionSchema{
				{Key: "challenge_types", Type: "string[]", Required: true, DefaultValue: acmeDefaults.ChallengeTypes, Allowed: []string{"http-01", "dns-01", "tls-alpn-01"}, Description: "Allowed ACME challenge methods."},
				{Key: "enable_ari", Type: "bool", Required: false, DefaultValue: acmeDefaults.EnableARI, Description: "Expose ACME Renewal Information (RFC 9773) so clients renew inside coordinated windows."},
				{Key: "ari_poll_hours", Type: "int", Required: false, DefaultValue: acmeDefaults.ARIPollHours, Description: "Recommended client polling interval for ACME Renewal Information refreshes."},
				{Key: "ari_window_bias_percent", Type: "int", Required: false, DefaultValue: acmeDefaults.ARIWindowBiasPercent, Description: "How far ahead of expiry the coordinated renewal window should begin."},
				{Key: "emergency_rotation_threshold_hours", Type: "int", Required: false, DefaultValue: acmeDefaults.EmergencyRotationThresholdHours, Description: "When remaining lifetime falls below this threshold, the certificate enters emergency rotation state."},
				{Key: "mass_renewal_risk_threshold", Type: "int", Required: false, DefaultValue: acmeDefaults.MassRenewalRiskThreshold, Description: "Number of certificates in one CA/day bucket that triggers a mass-renewal hotspot warning."},
				{Key: "enable_star", Type: "bool", Required: false, DefaultValue: acmeDefaults.EnableSTAR, Description: "Enable ACME STAR-style short-lived subscriptions and coordinated auto-renewal."},
				{Key: "default_star_validity_hours", Type: "int", Required: false, DefaultValue: acmeDefaults.DefaultSTARValidityHours, Description: "Default lifetime for newly issued STAR subscriptions."},
				{Key: "max_star_validity_hours", Type: "int", Required: false, DefaultValue: acmeDefaults.MaxSTARValidityHours, Description: "Maximum STAR lifetime a tenant can request."},
				{Key: "allow_star_delegation", Type: "bool", Required: false, DefaultValue: acmeDefaults.AllowSTARDelegation, Description: "Allow subscriber delegation metadata for downstream STAR consumers."},
				{Key: "max_star_subscriptions", Type: "int", Required: false, DefaultValue: acmeDefaults.MaxSTARSubscriptions, Description: "Maximum number of active STAR subscriptions per tenant."},
				{Key: "star_mass_rollout_threshold", Type: "int", Required: false, DefaultValue: acmeDefaults.STARMassRolloutThreshold, Description: "Number of STAR subscriptions scheduled in one rollout group before mass-rollout risk is raised."},
				{Key: "require_eab", Type: "bool", Required: false, DefaultValue: acmeDefaults.RequireEAB, Description: "Require external account binding for account/order creation."},
				{Key: "allow_wildcard", Type: "bool", Required: false, DefaultValue: acmeDefaults.AllowWildcard, Description: "Permit wildcard identifiers (e.g. *.example.com)."},
				{Key: "allow_ip_identifiers", Type: "bool", Required: false, DefaultValue: acmeDefaults.AllowIPIdentifiers, Description: "Permit IP SAN identifiers."},
				{Key: "max_sans", Type: "int", Required: false, DefaultValue: acmeDefaults.MaxSANs, Description: "Maximum SAN entries per order."},
				{Key: "default_validity_days", Type: "int", Required: false, DefaultValue: acmeDefaults.DefaultValidityDays, Description: "Issued certificate validity in days when unspecified."},
				{Key: "rate_limit_per_hour", Type: "int", Required: false, DefaultValue: acmeDefaults.RateLimitPerHour, Description: "Tenant-local issuance throttle target for automation clients."},
			},
			Implementation: ProtocolImplementationSchema{
				Engine:   "native-go",
				Language: "go",
				OSSOnly:  true,
				SDKs: []string{
					"Go standard library (net/http, crypto/x509, encoding/pem)",
				},
				Hardening: []string{
					"strict JSON schema key validation",
					"challenge allowlist enforcement",
					"SAN and identifier policy enforcement",
					"ACME Renewal Information with coordinated renewal windows",
					"ACME STAR-style short-lived subscriptions and delegated subscribers",
					"mass-renewal hotspot detection and emergency-rotation escalation",
				},
				Notes: "ACME endpoints are exposed on RFC-style routes (/acme/*) with server-side policy enforcement, RFC 9773 Renewal Information, ACME STAR-style short-lived subscription management, and audit events.",
			},
		},
		{
			Protocol:    protocolEST,
			Title:       "EST",
			RFC:         "RFC 7030",
			Description: "Enrollment over Secure Transport for managed device certificate lifecycle.",
			Defaults: map[string]interface{}{
				"rfc":                   estDefaults.RFC,
				"device_enrollment":     estDefaults.DeviceEnrollment,
				"server_keygen":         estDefaults.ServerKeygen,
				"auth_mode":             estDefaults.AuthMode,
				"require_csr_pop":       estDefaults.RequireCSRPoP,
				"allow_reenroll":        estDefaults.AllowReenroll,
				"default_validity_days": estDefaults.DefaultValidityDays,
				"max_csr_bytes":         estDefaults.MaxCSRBytes,
			},
			Options: []ProtocolOptionSchema{
				{Key: "device_enrollment", Type: "bool", Required: false, DefaultValue: estDefaults.DeviceEnrollment, Description: "Enable EST simpleenroll flow."},
				{Key: "server_keygen", Type: "bool", Required: false, DefaultValue: estDefaults.ServerKeygen, Description: "Enable EST serverkeygen flow."},
				{Key: "auth_mode", Type: "string", Required: true, DefaultValue: estDefaults.AuthMode, Allowed: []string{"mtls", "basic", "bearer", "none"}, Description: "Required EST client authentication mode."},
				{Key: "require_csr_pop", Type: "bool", Required: false, DefaultValue: estDefaults.RequireCSRPoP, Description: "Require CSR proof-of-possession input."},
				{Key: "allow_reenroll", Type: "bool", Required: false, DefaultValue: estDefaults.AllowReenroll, Description: "Enable EST simplereenroll flow."},
				{Key: "default_validity_days", Type: "int", Required: false, DefaultValue: estDefaults.DefaultValidityDays, Description: "Issued certificate validity in days when unspecified."},
				{Key: "max_csr_bytes", Type: "int", Required: false, DefaultValue: estDefaults.MaxCSRBytes, Description: "Maximum accepted CSR payload size."},
			},
			Implementation: ProtocolImplementationSchema{
				Engine:   "native-go",
				Language: "go",
				OSSOnly:  true,
				SDKs: []string{
					"Go standard library (crypto/x509, net/http)",
				},
				Hardening: []string{
					"auth mode enforcement",
					"reenroll and server-keygen policy gates",
					"CSR size and PoP checks",
				},
				Notes: "EST endpoints support policy-aware enroll/reenroll/serverkeygen and wire-compatible PKCS#10 requests (application/pkcs10).",
			},
		},
		{
			Protocol:    protocolSCEP,
			Title:       "SCEP",
			RFC:         "RFC 8894",
			Description: "Simple Certificate Enrollment Protocol support for MDM and legacy fleet enrollment.",
			Defaults: map[string]interface{}{
				"rfc":                         scepDefaults.RFC,
				"legacy_mdm":                  scepDefaults.LegacyMDM,
				"challenge_password_required": scepDefaults.ChallengePasswordRequired,
				"challenge_password":          scepDefaults.ChallengePassword,
				"allow_renewal":               scepDefaults.AllowRenewal,
				"default_validity_days":       scepDefaults.DefaultValidityDays,
				"max_csr_bytes":               scepDefaults.MaxCSRBytes,
				"digest_algorithms":           scepDefaults.DigestAlgorithms,
				"encryption_algorithms":       scepDefaults.EncryptionAlgorithms,
			},
			Options: []ProtocolOptionSchema{
				{Key: "legacy_mdm", Type: "bool", Required: false, DefaultValue: scepDefaults.LegacyMDM, Description: "Enable SCEP compatibility behavior for legacy MDM clients."},
				{Key: "challenge_password_required", Type: "bool", Required: false, DefaultValue: scepDefaults.ChallengePasswordRequired, Description: "Require challenge password in PKI operations."},
				{Key: "challenge_password", Type: "string", Required: false, DefaultValue: scepDefaults.ChallengePassword, Description: "Expected challenge password when required."},
				{Key: "allow_renewal", Type: "bool", Required: false, DefaultValue: scepDefaults.AllowRenewal, Description: "Allow renewalreq message type."},
				{Key: "default_validity_days", Type: "int", Required: false, DefaultValue: scepDefaults.DefaultValidityDays, Description: "Issued certificate validity in days when unspecified."},
				{Key: "max_csr_bytes", Type: "int", Required: false, DefaultValue: scepDefaults.MaxCSRBytes, Description: "Maximum accepted CSR payload size."},
				{Key: "digest_algorithms", Type: "string[]", Required: false, DefaultValue: scepDefaults.DigestAlgorithms, Allowed: []string{"sha1", "sha224", "sha256", "sha384", "sha512"}, Description: "Allowed digest algorithms exposed in SCEP capability policy."},
				{Key: "encryption_algorithms", Type: "string[]", Required: false, DefaultValue: scepDefaults.EncryptionAlgorithms, Allowed: []string{"des3", "aes128", "aes192", "aes256"}, Description: "Allowed SCEP encryption algorithms exposed in capability policy."},
			},
			Implementation: ProtocolImplementationSchema{
				Engine:   "smallstep-scep",
				Language: "go",
				OSSOnly:  true,
				SDKs: []string{
					"github.com/smallstep/scep (PKIMessage parsing/envelope/decryption/certrep)",
					"Go standard library (net/http, crypto/x509)",
				},
				Hardening: []string{
					"challenge password enforcement",
					"message type allowlist",
					"CSR size limits",
					"GetCACaps derived from active policy",
				},
				Notes: "SCEP PKIOperation uses OSS SCEP PKIMessage handling (smallstep/scep) with RFC-style routing and policy gates.",
			},
		},
		{
			Protocol:    protocolCMPv2,
			Title:       "CMPv2",
			RFC:         "RFC 4210",
			Description: "Certificate Management Protocol v2 for enterprise PKI request workflows.",
			Defaults: map[string]interface{}{
				"rfc":                        cmpDefaults.RFC,
				"enterprise_pki":             cmpDefaults.EnterprisePKI,
				"message_types":              cmpDefaults.MessageTypes,
				"require_message_protection": cmpDefaults.RequireMessageProtection,
				"require_transaction_id":     cmpDefaults.RequireTransactionID,
				"allow_implicit_confirm":     cmpDefaults.AllowImplicitConfirm,
				"default_validity_days":      cmpDefaults.DefaultValidityDays,
			},
			Options: []ProtocolOptionSchema{
				{Key: "enterprise_pki", Type: "bool", Required: false, DefaultValue: cmpDefaults.EnterprisePKI, Description: "Enable CMPv2 enterprise enrollment mode."},
				{Key: "message_types", Type: "string[]", Required: true, DefaultValue: cmpDefaults.MessageTypes, Allowed: []string{"ir", "cr", "kur", "rr"}, Description: "Allowed CMPv2 message types."},
				{Key: "require_message_protection", Type: "bool", Required: false, DefaultValue: cmpDefaults.RequireMessageProtection, Description: "Require CMP protection bit for incoming requests."},
				{Key: "require_transaction_id", Type: "bool", Required: false, DefaultValue: cmpDefaults.RequireTransactionID, Description: "Require transaction_id in request envelope."},
				{Key: "allow_implicit_confirm", Type: "bool", Required: false, DefaultValue: cmpDefaults.AllowImplicitConfirm, Description: "Allow implicit confirmation behavior."},
				{Key: "default_validity_days", Type: "int", Required: false, DefaultValue: cmpDefaults.DefaultValidityDays, Description: "Issued certificate validity in days when unspecified."},
			},
			Implementation: ProtocolImplementationSchema{
				Engine:   "native-go",
				Language: "go",
				OSSOnly:  true,
				SDKs: []string{
					"Go standard library (encoding/json, crypto/x509)",
				},
				Hardening: []string{
					"message protection gate",
					"transaction-id requirement",
					"message type allowlist (IR/CR/KUR/RR)",
				},
				Notes: "CMPv2 route processes policy-gated message types and supports PKIX-CMP content-type interoperability (application/pkixcmp).",
			},
		},
		{
			Protocol:    protocolRTMTLS,
			Title:       "Runtime mTLS",
			RFC:         "Internal",
			Description: "Tenant runtime root CA policy for internal service certificate materialization.",
			Defaults: map[string]interface{}{
				"mode":                 runtimeDefaults.Mode,
				"runtime_root_ca_name": runtimeDefaults.RuntimeRootCAName,
			},
			Options: []ProtocolOptionSchema{
				{Key: "mode", Type: "string", Required: true, DefaultValue: runtimeDefaults.Mode, Allowed: []string{"default", "custom"}, Description: "default uses vecta-runtime-root; custom uses runtime_root_ca_name."},
				{Key: "runtime_root_ca_name", Type: "string", Required: false, DefaultValue: runtimeDefaults.RuntimeRootCAName, Description: "Required only when mode=custom. Root CA is ensured per tenant."},
			},
			Implementation: ProtocolImplementationSchema{
				Engine:   "native-go",
				Language: "go",
				OSSOnly:  true,
				SDKs: []string{
					"Go standard library",
				},
				Hardening: []string{
					"tenant-scoped runtime root resolution",
					"safe fallback to default runtime root",
					"policy-gated custom root selection",
				},
				Notes: "This config controls runtime CA selection only. Certificate private material remains encrypted-at-rest and materialized into tmpfs at runtime.",
			},
		},
	}
}
