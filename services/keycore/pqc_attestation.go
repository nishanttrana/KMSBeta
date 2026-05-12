package main

import "time"

// PQCAttestation records the provenance of a post-quantum key. Auditors
// asking "which HSM produced this ML-KEM key, and against which FIPS 203
// certificate?" want this exact record. The attestation is written at
// key creation and is immutable for the key's lifetime.
type PQCAttestation struct {
	KeyID                string    `json:"key_id"`
	TenantID             string    `json:"tenant_id"`
	Algorithm            string    `json:"algorithm"`
	ParameterSet         string    `json:"parameter_set"`
	ProducerKind         string    `json:"producer_kind"` // "hsm-pkcs11", "software-go", "yubihsm", "luna-9000", ...
	ProducerSerial       string    `json:"producer_serial,omitempty"`
	ProducerFirmware     string    `json:"producer_firmware,omitempty"`
	FIPSValidationCert   string    `json:"fips_validation_cert,omitempty"` // NIST CMVP certificate number
	FIPSValidationStatus string    `json:"fips_validation_status,omitempty"`
	StandardReference    string    `json:"standard_reference,omitempty"` // "FIPS 203", "FIPS 204", "FIPS 205"
	GeneratedAt          time.Time `json:"generated_at"`
	GeneratedBy          string    `json:"generated_by"` // operator id / service account that initiated creation
}

// PQCAttestationStore persists the attestation. The interface is the
// minimum needed by the handler; a SQL implementation lives alongside
// the existing key store and is wired in NewService.
type PQCAttestationStore interface {
	SaveAttestation(att PQCAttestation) error
	GetAttestation(tenantID, keyID string) (PQCAttestation, bool, error)
}

// DefaultProducer returns the attestation values the software keycore
// emits for keys it generates itself (i.e., no external HSM). Operators
// who route generation through an HSM substitute via the SetProducer
// hook so the captured fields reflect reality.
func DefaultProducer() PQCAttestation {
	return PQCAttestation{
		ProducerKind:         "software-go",
		ProducerFirmware:     softwareFirmwareIdent(),
		FIPSValidationStatus: "modules-in-process",
		StandardReference:    "FIPS 203/204/205",
	}
}

// softwareFirmwareIdent is a placeholder for the build-time version
// string. The real value should come from -ldflags at build; for the
// development build we hard-code the marker.
func softwareFirmwareIdent() string {
	return "vecta-keycore/dev"
}
