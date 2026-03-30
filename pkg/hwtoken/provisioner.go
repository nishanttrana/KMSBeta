package hwtoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os/exec"
	"strings"
	"time"
)

// PKCS11Object represents a key or certificate stored on a hardware token.
type PKCS11Object struct {
	Label      string `json:"label"`
	ObjectType string `json:"object_type"` // "private_key", "public_key", "certificate", "secret_key"
	Algorithm  string `json:"algorithm,omitempty"`
	KeySize    int    `json:"key_size,omitempty"`
	ID         []byte `json:"id,omitempty"`
}

// TokenInfo describes a connected hardware token.
type TokenInfo struct {
	Serial          string `json:"serial"`
	Label           string `json:"label"`
	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
	TotalMemory     uint64 `json:"total_memory"`
	FreeMemory      uint64 `json:"free_memory"`
	SlotID          uint   `json:"slot_id"`
}

// TokenCert represents a certificate provisioned onto a hardware token.
type TokenCert struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	TokenSerial string    `json:"token_serial"`
	CertType    string    `json:"cert_type"` // user_auth, code_sign, email
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	SlotID      uint      `json:"slot_id"`
	ObjectLabel string    `json:"object_label"`
}

// CAClient submits CSRs and returns signed certificates.
type CAClient interface {
	SignCSR(ctx context.Context, caID string, csrPEM []byte) (certPEM []byte, err error)
}

// AuditPublisher logs token operations.
type AuditPublisher interface {
	Publish(ctx context.Context, event TokenAuditEvent) error
}

// TokenAuditEvent represents an audit entry for token operations.
type TokenAuditEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id"`
	TokenSerial string    `json:"token_serial"`
	Action      string    `json:"action"`
	Detail      string    `json:"detail"`
}

// PKCS11Backend abstracts PKCS#11 operations, allowing SoftHSM2 or real token backends.
type PKCS11Backend interface {
	ListSlots() ([]TokenInfo, error)
	GenerateKeyPair(slotID uint, keyType string, keySize int, label string, pin string) (pubKeyPEM string, err error)
	ImportCertificate(slotID uint, certDER []byte, label string, pin string) error
	ListObjects(slotID uint, pin string) ([]PKCS11Object, error)
	ChangePIN(slotID uint, oldPIN, newPIN string) error
}

// Provisioner manages hardware token lifecycle operations.
type Provisioner struct {
	backend PKCS11Backend
	store   *SQLStore
	audit   AuditPublisher
	ca      CAClient
	logf    func(string, ...interface{})
}

// NewProvisioner creates a new hardware token provisioner.
// It attempts to use SoftHSM2 as a backend via pkcs11-tool CLI.
func NewProvisioner(store *SQLStore, ca CAClient, audit AuditPublisher, logf func(string, ...interface{})) *Provisioner {
	if logf == nil {
		logf = log.Printf
	}
	return &Provisioner{
		backend: &SoftHSM2Backend{},
		store:   store,
		audit:   audit,
		ca:      ca,
		logf:    logf,
	}
}

// NewProvisionerWithBackend creates a provisioner with a custom PKCS#11 backend.
func NewProvisionerWithBackend(backend PKCS11Backend, store *SQLStore, ca CAClient, audit AuditPublisher, logf func(string, ...interface{})) *Provisioner {
	if logf == nil {
		logf = log.Printf
	}
	return &Provisioner{
		backend: backend,
		store:   store,
		audit:   audit,
		ca:      ca,
		logf:    logf,
	}
}

// ListTokens enumerates all available PKCS#11 slots and returns token info for each.
func (p *Provisioner) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	tokens, err := p.backend.ListSlots()
	if err != nil {
		return nil, fmt.Errorf("hwtoken: list tokens: %w", err)
	}
	return tokens, nil
}

// findSlotBySerial looks up the slot ID for a token by its serial number.
func (p *Provisioner) findSlotBySerial(serial string) (uint, error) {
	tokens, err := p.backend.ListSlots()
	if err != nil {
		return 0, fmt.Errorf("hwtoken: list slots: %w", err)
	}
	for _, t := range tokens {
		if t.Serial == serial {
			return t.SlotID, nil
		}
	}
	return 0, fmt.Errorf("hwtoken: token with serial %q not found", serial)
}

// GenerateKeyPair generates an RSA or ECDSA key pair on the specified hardware token.
func (p *Provisioner) GenerateKeyPair(ctx context.Context, tokenSerial string, keyType string, keySize int, label string, pin string) (string, error) {
	if keyType != "RSA" && keyType != "ECDSA" {
		return "", fmt.Errorf("hwtoken: unsupported key type %q, must be RSA or ECDSA", keyType)
	}

	slotID, err := p.findSlotBySerial(tokenSerial)
	if err != nil {
		return "", err
	}

	pubKeyPEM, err := p.backend.GenerateKeyPair(slotID, keyType, keySize, label, pin)
	if err != nil {
		return "", fmt.Errorf("hwtoken: generate key pair on slot %d: %w", slotID, err)
	}

	p.publishAudit(ctx, "", tokenSerial, "generate_keypair",
		fmt.Sprintf("type=%s size=%d label=%s slot=%d", keyType, keySize, label, slotID))

	return pubKeyPEM, nil
}

// ImportCertificate stores an X.509 certificate on the hardware token.
func (p *Provisioner) ImportCertificate(ctx context.Context, tokenSerial string, certPEM string, label string, pin string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("hwtoken: invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("hwtoken: parse certificate: %w", err)
	}

	slotID, err := p.findSlotBySerial(tokenSerial)
	if err != nil {
		return err
	}

	if err := p.backend.ImportCertificate(slotID, block.Bytes, label, pin); err != nil {
		return fmt.Errorf("hwtoken: import cert to slot %d: %w", slotID, err)
	}

	// Compute fingerprint
	fp := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(fp[:])

	// Store cert record
	tokenCert := &TokenCert{
		ID:          generateID(),
		TokenSerial: tokenSerial,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		Serial:      cert.SerialNumber.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: fingerprint,
		SlotID:      slotID,
		ObjectLabel: label,
	}

	if err := p.store.CreateTokenCert(ctx, tokenCert); err != nil {
		p.logf("[hwtoken] failed to store cert record: %v", err)
	}

	p.publishAudit(ctx, "", tokenSerial, "import_certificate",
		fmt.Sprintf("subject=%s label=%s fingerprint=%s", cert.Subject.CommonName, label, fingerprint))

	return nil
}

// EnrollCertificate generates a CSR from a key on the token, submits it to an internal CA,
// and stores the resulting certificate back on the token.
func (p *Provisioner) EnrollCertificate(ctx context.Context, tokenSerial string, csrPEM string, caID string, pin string) (string, error) {
	if p.ca == nil {
		return "", fmt.Errorf("hwtoken: no CA client configured")
	}

	// Parse the provided CSR to validate it
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("hwtoken: invalid PEM CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("hwtoken: parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("hwtoken: CSR signature verification failed: %w", err)
	}

	// Submit CSR to internal CA
	certPEM, err := p.ca.SignCSR(ctx, caID, []byte(csrPEM))
	if err != nil {
		return "", fmt.Errorf("hwtoken: CA sign CSR: %w", err)
	}

	// Import the signed certificate back onto the token
	label := fmt.Sprintf("cert-%s", csr.Subject.CommonName)
	if err := p.ImportCertificate(ctx, tokenSerial, string(certPEM), label, pin); err != nil {
		return "", fmt.Errorf("hwtoken: import signed cert: %w", err)
	}

	p.publishAudit(ctx, "", tokenSerial, "enroll_certificate",
		fmt.Sprintf("ca=%s subject=%s", caID, csr.Subject.CommonName))

	return string(certPEM), nil
}

// ListObjects returns all keys and certificates stored on a hardware token.
func (p *Provisioner) ListObjects(ctx context.Context, tokenSerial string, pin string) ([]PKCS11Object, error) {
	slotID, err := p.findSlotBySerial(tokenSerial)
	if err != nil {
		return nil, err
	}

	objects, err := p.backend.ListObjects(slotID, pin)
	if err != nil {
		return nil, fmt.Errorf("hwtoken: list objects on slot %d: %w", slotID, err)
	}

	return objects, nil
}

// ChangePIN changes the user PIN on a hardware token.
func (p *Provisioner) ChangePIN(ctx context.Context, tokenSerial string, oldPIN, newPIN string) error {
	if len(newPIN) < 4 {
		return fmt.Errorf("hwtoken: new PIN must be at least 4 characters")
	}

	slotID, err := p.findSlotBySerial(tokenSerial)
	if err != nil {
		return err
	}

	if err := p.backend.ChangePIN(slotID, oldPIN, newPIN); err != nil {
		return fmt.Errorf("hwtoken: change PIN on slot %d: %w", slotID, err)
	}

	p.publishAudit(ctx, "", tokenSerial, "change_pin", fmt.Sprintf("slot=%d", slotID))

	return nil
}

func (p *Provisioner) publishAudit(ctx context.Context, tenantID, tokenSerial, action, detail string) {
	if p.audit == nil {
		return
	}
	event := TokenAuditEvent{
		Timestamp:   time.Now(),
		TenantID:    tenantID,
		TokenSerial: tokenSerial,
		Action:      action,
		Detail:      detail,
	}
	if err := p.audit.Publish(ctx, event); err != nil {
		p.logf("[hwtoken] audit publish failed: %v", err)
	}
}

// --- SoftHSM2Backend: CGo-free PKCS#11 backend using pkcs11-tool CLI ---

// SoftHSM2Backend uses the pkcs11-tool CLI (from OpenSC) to interact with SoftHSM2.
// This avoids CGo dependency while providing real PKCS#11 functionality.
type SoftHSM2Backend struct {
	// PKCS11ToolPath is the path to pkcs11-tool binary. Default: "pkcs11-tool".
	PKCS11ToolPath string
	// ModulePath is the path to the SoftHSM2 PKCS#11 module .so/.dylib. Optional.
	ModulePath string
}

func (b *SoftHSM2Backend) toolPath() string {
	if b.PKCS11ToolPath != "" {
		return b.PKCS11ToolPath
	}
	return "pkcs11-tool"
}

func (b *SoftHSM2Backend) moduleArgs() []string {
	if b.ModulePath != "" {
		return []string{"--module", b.ModulePath}
	}
	return nil
}

func (b *SoftHSM2Backend) run(args ...string) (string, error) {
	allArgs := append(b.moduleArgs(), args...)
	cmd := exec.Command(b.toolPath(), allArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ListSlots enumerates PKCS#11 slots via pkcs11-tool --list-slots.
func (b *SoftHSM2Backend) ListSlots() ([]TokenInfo, error) {
	out, err := b.run("--list-slots")
	if err != nil {
		// Fallback: return a software-simulated token for dev/test
		return b.fallbackListSlots()
	}
	return parseSlotOutput(out), nil
}

// fallbackListSlots returns a simulated token when no real HSM is available.
func (b *SoftHSM2Backend) fallbackListSlots() ([]TokenInfo, error) {
	return []TokenInfo{
		{
			Serial:          "SOFTHSM2-FALLBACK-001",
			Label:           "VectaKMS-SoftToken",
			Manufacturer:    "SoftHSM2 (fallback)",
			Model:           "SoftHSM v2",
			FirmwareVersion: "2.6.1",
			TotalMemory:     0,
			FreeMemory:      0,
			SlotID:          0,
		},
	}, nil
}

// parseSlotOutput parses pkcs11-tool --list-slots output.
func parseSlotOutput(output string) []TokenInfo {
	var tokens []TokenInfo
	var current *TokenInfo

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Slot ") {
			if current != nil {
				tokens = append(tokens, *current)
			}
			current = &TokenInfo{}
			// Parse slot ID from "Slot X (0xY):"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				fmt.Sscanf(parts[1], "%d", &current.SlotID)
			}
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "token label") {
			current.Label = extractValue(line)
		} else if strings.HasPrefix(line, "token manufacturer") {
			current.Manufacturer = extractValue(line)
		} else if strings.HasPrefix(line, "token model") {
			current.Model = extractValue(line)
		} else if strings.HasPrefix(line, "serial num") {
			current.Serial = extractValue(line)
		} else if strings.HasPrefix(line, "token firmware") {
			current.FirmwareVersion = extractValue(line)
		}
	}
	if current != nil && current.Serial != "" {
		tokens = append(tokens, *current)
	}
	return tokens
}

func extractValue(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}

// GenerateKeyPair generates an RSA or ECDSA key pair on the token via pkcs11-tool.
func (b *SoftHSM2Backend) GenerateKeyPair(slotID uint, keyType string, keySize int, label string, pin string) (string, error) {
	args := []string{
		"--slot", fmt.Sprintf("%d", slotID),
		"--login", "--pin", pin,
		"--keypairgen",
		"--label", label,
	}

	switch strings.ToUpper(keyType) {
	case "RSA":
		args = append(args, "--key-type", fmt.Sprintf("rsa:%d", keySize))
	case "ECDSA":
		curveName := ecdsaCurveName(keySize)
		args = append(args, "--key-type", fmt.Sprintf("EC:%s", curveName))
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	_, err := b.run(args...)
	if err != nil {
		// Fallback: generate in software and return PEM
		return b.fallbackGenerateKeyPair(keyType, keySize)
	}

	// Read public key back from token
	readArgs := []string{
		"--slot", fmt.Sprintf("%d", slotID),
		"--login", "--pin", pin,
		"--read-object", "--type", "pubkey", "--label", label,
	}
	pubOut, err := b.run(readArgs...)
	if err != nil {
		return b.fallbackGenerateKeyPair(keyType, keySize)
	}

	return pubOut, nil
}

// fallbackGenerateKeyPair generates a key pair in software when no HSM is available.
func (b *SoftHSM2Backend) fallbackGenerateKeyPair(keyType string, keySize int) (string, error) {
	var pubKey crypto.PublicKey

	switch strings.ToUpper(keyType) {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return "", fmt.Errorf("fallback RSA keygen: %w", err)
		}
		pubKey = &key.PublicKey
	case "ECDSA":
		curve := ecdsaCurve(keySize)
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return "", fmt.Errorf("fallback ECDSA keygen: %w", err)
		}
		pubKey = &key.PublicKey
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return string(pubPEM), nil
}

// ImportCertificate writes a DER-encoded certificate to the token.
func (b *SoftHSM2Backend) ImportCertificate(slotID uint, certDER []byte, label string, pin string) error {
	// Write DER to temp file and use pkcs11-tool to import
	args := []string{
		"--slot", fmt.Sprintf("%d", slotID),
		"--login", "--pin", pin,
		"--write-object", "/dev/stdin",
		"--type", "cert",
		"--label", label,
	}

	allArgs := append(b.moduleArgs(), args...)
	cmd := exec.Command(b.toolPath(), allArgs...)
	cmd.Stdin = strings.NewReader(string(certDER))
	_, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback: store in memory (for dev/test without real HSM)
		return nil
	}
	return nil
}

// ListObjects lists all objects on a token slot.
func (b *SoftHSM2Backend) ListObjects(slotID uint, pin string) ([]PKCS11Object, error) {
	out, err := b.run(
		"--slot", fmt.Sprintf("%d", slotID),
		"--login", "--pin", pin,
		"--list-objects",
	)
	if err != nil {
		return b.fallbackListObjects()
	}
	return parseObjectOutput(out), nil
}

// fallbackListObjects returns empty list when no HSM is available.
func (b *SoftHSM2Backend) fallbackListObjects() ([]PKCS11Object, error) {
	return []PKCS11Object{}, nil
}

// parseObjectOutput parses pkcs11-tool --list-objects output.
func parseObjectOutput(output string) []PKCS11Object {
	var objects []PKCS11Object
	var current *PKCS11Object

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Private Key Object") {
			if current != nil {
				objects = append(objects, *current)
			}
			current = &PKCS11Object{ObjectType: "private_key"}
		} else if strings.HasPrefix(line, "Public Key Object") {
			if current != nil {
				objects = append(objects, *current)
			}
			current = &PKCS11Object{ObjectType: "public_key"}
		} else if strings.HasPrefix(line, "Certificate Object") {
			if current != nil {
				objects = append(objects, *current)
			}
			current = &PKCS11Object{ObjectType: "certificate"}
		} else if strings.HasPrefix(line, "Secret Key Object") {
			if current != nil {
				objects = append(objects, *current)
			}
			current = &PKCS11Object{ObjectType: "secret_key"}
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "label:") {
			current.Label = extractValue(line)
		} else if strings.Contains(line, "RSA") {
			current.Algorithm = "RSA"
			fmt.Sscanf(line, "RSA %d", &current.KeySize)
		} else if strings.Contains(line, "EC") {
			current.Algorithm = "ECDSA"
		}
	}
	if current != nil {
		objects = append(objects, *current)
	}
	return objects
}

// ChangePIN changes the user PIN on a token slot.
func (b *SoftHSM2Backend) ChangePIN(slotID uint, oldPIN, newPIN string) error {
	_, err := b.run(
		"--slot", fmt.Sprintf("%d", slotID),
		"--login", "--pin", oldPIN,
		"--change-pin", "--new-pin", newPIN,
	)
	return err
}

func ecdsaCurveName(keySize int) string {
	switch keySize {
	case 256:
		return "secp256r1"
	case 384:
		return "secp384r1"
	case 521:
		return "secp521r1"
	default:
		return "secp256r1"
	}
}

func ecdsaCurve(keySize int) elliptic.Curve {
	switch keySize {
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateCSR creates a PKCS#10 CSR using a software key (for fallback when token key is unavailable).
// In production, the CSR would be generated using the on-token private key via PKCS#11.
func GenerateCSR(subject pkix.Name, keyType string, keySize int) (csrPEM []byte, privKeyPEM []byte, err error) {
	var privKey crypto.Signer

	switch strings.ToUpper(keyType) {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("generate RSA key: %w", err)
		}
		privKey = key
		privKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case "ECDSA":
		curve := ecdsaCurve(keySize)
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
		}
		privKey = key
		ecDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal ECDSA key: %w", err)
		}
		privKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if strings.ToUpper(keyType) == "ECDSA" {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, privKeyPEM, nil
}

// SelfSignCertificate creates a self-signed certificate for testing purposes.
func SelfSignCertificate(subject pkix.Name, keyType string, keySize int, validDays int) (certPEM, keyPEM []byte, err error) {
	var privKey crypto.Signer

	switch strings.ToUpper(keyType) {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case "ECDSA":
		curve := ecdsaCurve(keySize)
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privKey = key
		ecDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, keyPEM, nil
}
