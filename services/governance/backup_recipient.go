package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// A scheduled backup runs with nobody there to take a software-mode key
// file, so the key is sealed to the root administrator's RSA public key
// instead (docs/SECURITY/BACKUP_KEYS.md, "Scheduled backups"). The sealed
// key file can be downloaded again at any time: only the private key, which
// never reaches the platform, opens it. Restore takes the key file once its
// holder has unsealed it (in the browser, or with openssl).

const (
	backupKeyModeRecipient = "recipient_sealed"
	backupKeyWrapRecipient = "rsa-oaep-sha256"
	// minRecipientBits: RSA under 3072 bits is not 128-bit strength.
	minRecipientBits = 3072
)

// backupRecipientLabel is the OAEP label: a sealed backup key opens only as
// one, not as a secret of another purpose sealed to the same key.
var backupRecipientLabel = []byte("vecta-kms backup key v1")

// backupRecipient is the administrator's public key as stored: its PKIX
// DER, PEM and fingerprint (pkg/crypto.RecipientKeyBinding).
type backupRecipient struct {
	DER         []byte
	PEM         string
	Fingerprint string
}

// parseBackupRecipient reads a PEM public key (BEGIN PUBLIC KEY). A private
// key, or an RSA key under minRecipientBits, is refused.
func parseBackupRecipient(raw string) (backupRecipient, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil || block.Type != "PUBLIC KEY" {
		return backupRecipient{}, errors.New("recipient_public_key must be a PEM public key (BEGIN PUBLIC KEY); never send a private key")
	}
	pub, err := pkgcrypto.ParseRecipientPublicKey(block.Bytes)
	if err != nil {
		return backupRecipient{}, err
	}
	if pub.N.BitLen() < minRecipientBits {
		return backupRecipient{}, fmt.Errorf("recipient_public_key must be RSA of at least %d bits", minRecipientBits)
	}
	return backupRecipient{
		DER:         block.Bytes,
		PEM:         string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})),
		Fingerprint: pkgcrypto.RecipientKeyBinding(block.Bytes),
	}, nil
}

// sealBackupKeyToRecipient is the key package of a backup whose key is
// sealed to the recipient with RSA-OAEP-SHA256 under backupRecipientLabel:
// stored as it is, since it holds no key the platform can use.
func sealBackupKeyToRecipient(backupKey []byte, to backupRecipient, requestTenantID, targetTenantID string, coverage backupCoverageSummary) (map[string]interface{}, error) {
	pub, err := pkgcrypto.ParseRecipientPublicKey(to.DER)
	if err != nil {
		return nil, err
	}
	wrapped, err := pkgcrypto.WrapKeyRSAOAEP(pub, backupKey, backupRecipientLabel)
	if err != nil {
		return nil, fmt.Errorf("seal the backup key: %w", err)
	}
	return map[string]interface{}{
		"version":              3,
		"mode":                 backupKeyModeRecipient,
		"algorithm":            "AES-256-GCM",
		"request_tenant_id":    requestTenantID,
		"target_tenant_id":     targetTenantID,
		"backup_key_sha256":    sha256Hex(string(backupKey)),
		"backup_coverage":      coverage,
		"key_retained":         false,
		"key_wrap":             backupKeyWrapRecipient,
		"oaep_label":           string(backupRecipientLabel),
		"recipient_key_sha256": to.Fingerprint,
		"wrapped_key_b64":      base64.StdEncoding.EncodeToString(wrapped),
		"note":                 "The backup key is sealed with RSA-OAEP-SHA256 (label in oaep_label) to the recipient public key the schedule names. Unseal it with the matching private key in the restore dialog, or with openssl pkeyutl (docs/SECURITY/BACKUP_KEYS.md), and put the base64 of the 32 bytes in backup_key_b64.",
	}, nil
}

// unsealedRecipientKey is the backup key from a sealed key file its holder
// has unsealed (backup_key_b64), checked against the fingerprint recorded
// when the backup was taken.
func unsealedRecipientKey(pkg map[string]interface{}) ([]byte, error) {
	raw := strings.TrimSpace(fmt.Sprint(pkg["backup_key_b64"]))
	if raw == "" || raw == "<nil>" {
		return nil, errors.New("this key file is sealed to the schedule's recipient key: unseal it with the matching private key (the restore dialog does this in the browser) before restoring")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("backup_key_b64 is not a 32-byte key")
	}
	if want := strings.TrimSpace(fmt.Sprint(pkg["backup_key_sha256"])); want == "" || sha256Hex(string(key)) != want {
		pkgcrypto.Zeroize(key)
		return nil, errors.New("the unsealed key is not this backup's key")
	}
	return key, nil
}
