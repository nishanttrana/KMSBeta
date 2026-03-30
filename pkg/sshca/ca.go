package sshca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// CA is an SSH Certificate Authority that signs user and host certificates.
type CA struct {
	signer    ssh.Signer
	caPublicKey ssh.PublicKey
	store     Store
	audit     AuditPublisher
	logger    *log.Logger
}

// NewCA creates a new SSH CA from a PEM-encoded private key.
// Supports Ed25519 and RSA private keys.
func NewCA(privateKeyPEM []byte, store Store, audit AuditPublisher, logger *log.Logger) (*CA, error) {
	if logger == nil {
		logger = log.Default()
	}

	privKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("sshca: parse private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: create SSH signer: %w", err)
	}

	return &CA{
		signer:    signer,
		caPublicKey: signer.PublicKey(),
		store:     store,
		audit:     audit,
		logger:    logger,
	}, nil
}

// PublicKey returns the CA's public key in authorized_keys format.
func (ca *CA) PublicKey() []byte {
	return ssh.MarshalAuthorizedKey(ca.caPublicKey)
}

// SignUserCert signs a user SSH certificate.
func (ca *CA) SignUserCert(ctx context.Context, req UserCertRequest) (*ssh.Certificate, []byte, error) {
	if req.Username == "" {
		return nil, nil, fmt.Errorf("sshca: username is required")
	}
	if len(req.Principals) == 0 {
		return nil, nil, fmt.Errorf("sshca: at least one principal is required")
	}
	if req.TTL <= 0 {
		return nil, nil, fmt.Errorf("sshca: TTL must be positive")
	}

	pubKey, err := parsePublicKey(req.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: parse user public key: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: generate serial: %w", err)
	}

	now := time.Now()
	validAfter := now.Add(-30 * time.Second) // small clock skew allowance
	validBefore := now.Add(req.TTL)

	// Build extensions - default SSH permissions
	extensions := map[string]string{
		"permit-pty":              "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
	}
	// Merge caller-supplied extensions
	for k, v := range req.Extensions {
		extensions[k] = v
	}

	// Build critical options
	criticalOptions := make(map[string]string)
	if len(req.SourceAddresses) > 0 {
		criticalOptions["source-address"] = strings.Join(req.SourceAddresses, ",")
	}
	if req.ForceCommand != "" {
		criticalOptions["force-command"] = req.ForceCommand
	}

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           req.Username,
		Serial:          serial,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}

	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, nil, fmt.Errorf("sshca: sign user cert: %w", err)
	}

	marshaledCert := ssh.MarshalAuthorizedKey(cert)

	// Persist issued cert record
	fingerprint := fingerprintPublicKey(pubKey)
	issued := &IssuedCert{
		ID:          "sshcert_" + randomCertHex(16),
		TenantID:    req.TenantID,
		CertType:    "user",
		KeyID:       req.Username,
		Principals:  req.Principals,
		Serial:      serial,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
		Fingerprint: fingerprint,
		CreatedAt:   now,
	}
	if ca.store != nil {
		if err := ca.store.RecordCert(ctx, issued); err != nil {
			ca.logger.Printf("sshca: failed to record cert: %v", err)
		}
	}

	ca.publishAudit(ctx, "ssh_ca.user_cert_signed", map[string]string{
		"cert_id":     issued.ID,
		"tenant_id":   req.TenantID,
		"key_id":      req.Username,
		"serial":      fmt.Sprintf("%d", serial),
		"fingerprint": fingerprint,
	})

	return cert, marshaledCert, nil
}

// SignHostCert signs a host SSH certificate.
func (ca *CA) SignHostCert(ctx context.Context, req HostCertRequest) (*ssh.Certificate, []byte, error) {
	if len(req.Hostnames) == 0 {
		return nil, nil, fmt.Errorf("sshca: at least one hostname is required")
	}
	if req.TTL <= 0 {
		return nil, nil, fmt.Errorf("sshca: TTL must be positive")
	}

	pubKey, err := parsePublicKey(req.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: parse host public key: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: generate serial: %w", err)
	}

	now := time.Now()
	validAfter := now.Add(-30 * time.Second)
	validBefore := now.Add(req.TTL)

	keyID := strings.Join(req.Hostnames, ",")

	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             pubKey,
		KeyId:           keyID,
		Serial:          serial,
		ValidPrincipals: req.Hostnames,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}

	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, nil, fmt.Errorf("sshca: sign host cert: %w", err)
	}

	marshaledCert := ssh.MarshalAuthorizedKey(cert)

	fingerprint := fingerprintPublicKey(pubKey)
	issued := &IssuedCert{
		ID:          "sshcert_" + randomCertHex(16),
		TenantID:    req.TenantID,
		CertType:    "host",
		KeyID:       keyID,
		Principals:  req.Hostnames,
		Serial:      serial,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
		Fingerprint: fingerprint,
		CreatedAt:   now,
	}
	if ca.store != nil {
		if err := ca.store.RecordCert(ctx, issued); err != nil {
			ca.logger.Printf("sshca: failed to record host cert: %v", err)
		}
	}

	ca.publishAudit(ctx, "ssh_ca.host_cert_signed", map[string]string{
		"cert_id":     issued.ID,
		"tenant_id":   req.TenantID,
		"key_id":      keyID,
		"serial":      fmt.Sprintf("%d", serial),
		"fingerprint": fingerprint,
	})

	return cert, marshaledCert, nil
}

// parsePrivateKey decodes a PEM block and returns the private key (Ed25519 or RSA).
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first (handles both Ed25519 and RSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case ed25519.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type in PKCS8: %T", key)
		}
	}

	// Try RSA PKCS1
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	// Try OpenSSH format (common for Ed25519 keys generated by ssh-keygen)
	rawKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		switch k := rawKey.(type) {
		case *ed25519.PrivateKey:
			return *k, nil
		case ed25519.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type from OpenSSH format: %T", rawKey)
		}
	}

	return nil, fmt.Errorf("unable to parse private key (tried PKCS8, PKCS1, OpenSSH)")
}

// parsePublicKey parses an SSH public key from authorized_keys format or raw wire format.
func parsePublicKey(data []byte) (ssh.PublicKey, error) {
	// Try authorized_keys format first
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err == nil {
		return pubKey, nil
	}
	// Try raw wire format
	pubKey, err = ssh.ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse as authorized_keys or wire format: %w", err)
	}
	return pubKey, nil
}

// generateSerial creates a cryptographically random 64-bit serial number.
func generateSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// fingerprintPublicKey returns the SHA256 fingerprint of an SSH public key.
func fingerprintPublicKey(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + hex.EncodeToString(hash[:])
}

func randomCertHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (ca *CA) publishAudit(ctx context.Context, subject string, fields map[string]string) {
	if ca.audit == nil {
		return
	}
	payload := `{"event":"` + subject + `","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"`
	for k, v := range fields {
		payload += `,"` + k + `":"` + v + `"`
	}
	payload += `}`
	if err := ca.audit.Publish(ctx, "kms.audit."+subject, []byte(payload)); err != nil {
		ca.logger.Printf("sshca: audit publish failed for %s: %v", subject, err)
	}
}
