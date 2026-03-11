package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	pkgmpc "vecta-kms/pkg/mpc"
)

const (
	defaultDeploymentPath    = "/etc/vecta/deployment.yaml"
	defaultNetworkPath       = "/etc/vecta/network.yaml"
	defaultFIPSPath          = "/etc/vecta/fips.yaml"
	defaultFDEPath           = "/etc/vecta/fde.yaml"
	defaultAuthPath          = "/etc/vecta/auth-bootstrap.yaml"
	defaultCertBootstrapPath = "/etc/vecta/certs-bootstrap.secret"
	defaultCertSealedKeyPath = "/var/lib/vecta/certs/crwk.sealed"
)

var (
	licenseKeyPattern = regexp.MustCompile(`^SEC-KMS-[A-Z]+-[0-9]{4}-[A-Z0-9-]+$`)
)

func outputPaths() map[string]string {
	return map[string]string{
		"deployment":     envOr("FIRSTBOOT_DEPLOYMENT_PATH", defaultDeploymentPath),
		"network":        envOr("FIRSTBOOT_NETWORK_PATH", defaultNetworkPath),
		"fips":           envOr("FIRSTBOOT_FIPS_PATH", defaultFIPSPath),
		"fde":            envOr("FIRSTBOOT_FDE_PATH", defaultFDEPath),
		"auth":           envOr("FIRSTBOOT_AUTH_PATH", defaultAuthPath),
		"cert_bootstrap": envOr("FIRSTBOOT_CERT_BOOTSTRAP_PATH", defaultCertBootstrapPath),
	}
}

func generateConfigs(req WizardRequest) (GeneratedConfigs, error) {
	if err := validateRequest(req); err != nil {
		return GeneratedConfigs{}, err
	}
	now := time.Now().UTC()
	paths := outputPaths()
	warnings := make([]string, 0)

	certSecurity := req.Spec.CertSecurity
	certStorageMode := strings.ToLower(strings.TrimSpace(certSecurity.CertStorageMode))
	if certStorageMode == "" {
		certStorageMode = "db_encrypted"
	}
	rootKeyMode := strings.ToLower(strings.TrimSpace(certSecurity.RootKeyMode))
	if rootKeyMode == "" {
		rootKeyMode = "software"
	}
	bootstrapPassphrase := strings.TrimSpace(certSecurity.BootstrapPassphrase)
	if rootKeyMode == "software" && bootstrapPassphrase == "" {
		bootstrapPassphrase = randomBootstrapSecret(32)
		warnings = append(warnings, "certificate bootstrap passphrase was auto-generated and written to cert bootstrap secret file")
	}
	sealedPath := firstNonEmpty(certSecurity.SealedKeyPath, defaultCertSealedKeyPath)
	passphraseFilePath := firstNonEmpty(certSecurity.PassphraseFilePath, paths["cert_bootstrap"])

	deployment := map[string]any{
		"apiVersion": "kms.vecta.io/v1",
		"kind":       "DeploymentConfig",
		"metadata": map[string]any{
			"appliance_id": req.Metadata.ApplianceID,
			"created_at":   now.Format(time.RFC3339),
		},
		"spec": map[string]any{
			"hsm_mode": req.Spec.HSMMode,
			"cert_security": map[string]any{
				"cert_storage_mode":    certStorageMode,
				"root_key_mode":        rootKeyMode,
				"sealed_key_path":      sealedPath,
				"passphrase_file_path": passphraseFilePath,
				"use_tpm_seal":         certSecurity.UseTPMSeal,
			},
			"core": map[string]bool{
				"auth":    true,
				"keycore": true,
				"audit":   true,
				"policy":  true,
			},
			"features": map[string]bool{
				"secrets":              req.Spec.Features.Secrets,
				"certs":                req.Spec.Features.Certs,
				"governance":           req.Spec.Features.Governance,
				"cloud_byok":           req.Spec.Features.CloudBYOK,
				"hyok_proxy":           req.Spec.Features.HYOKProxy,
				"kmip_server":          req.Spec.Features.KMIPServer,
				"qkd_interface":        req.Spec.Features.QKDInterface,
				"qrng_generator":       req.Spec.Features.QRNGGenerator,
				"ekm_database":         req.Spec.Features.EKMDatabase,
				"payment_crypto":       req.Spec.Features.PaymentCrypto,
				"compliance_dashboard": req.Spec.Features.ComplianceDashboard,
				"sbom_cbom":            req.Spec.Features.SBOMCBOM,
				"reporting_alerting":   req.Spec.Features.ReportingAlerting,
				"posture_management":   req.Spec.Features.PostureManagement,
				"ai_llm":               req.Spec.Features.AILLM,
				"pqc_migration":        req.Spec.Features.PQCMigration,
				"crypto_discovery":     req.Spec.Features.CryptoDiscovery,
				"mpc_engine":           req.Spec.Features.MPCEngine,
				"data_protection":      req.Spec.Features.DataProtection,
				"clustering":           req.Spec.Features.Clustering,
			},
			"license": map[string]any{
				"key":              req.Spec.License.Key,
				"max_keys":         req.Spec.License.MaxKeys,
				"max_tenants":      req.Spec.License.MaxTenants,
				"features_allowed": req.Spec.License.FeaturesAllowed,
				"activated_at":     now.Format(time.RFC3339),
				"status":           "active",
			},
		},
	}

	network := map[string]any{
		"management": req.Spec.Network.Management,
		"cluster":    req.Spec.Network.Cluster,
		"hsm":        req.Spec.Network.HSM,
		"tls":        req.Spec.Network.TLS,
		"ntp":        req.Spec.Network.NTP,
		"syslog":     req.Spec.Network.Syslog,
		"firewall":   req.Spec.Network.Firewall,
	}

	fips := map[string]any{
		"mode": req.Spec.FIPS.Mode,
		"strict": map[string]any{
			"block_non_fips_algorithms": true,
			"require_fips_tls":          true,
			"require_drbg":              true,
			"go_boringcrypto":           true,
			"reject_non_fips_imports":   true,
			"min_rsa_bits":              2048,
			"min_ec_bits":               224,
			"allowed_hashes":            []string{"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"},
			"allowed_symmetric":         []string{"AES-128", "AES-192", "AES-256", "3DES"},
			"allowed_tls_ciphers":       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		},
		"standard": map[string]any{
			"warn_non_fips_algorithms": true,
			"default_tls_version":      "1.2",
			"allow_legacy_algorithms":  true,
			"tag_non_fips_keys":        true,
		},
	}

	fde, shares, err := buildFDEConfig(req.Spec.FDE)
	if err != nil {
		return GeneratedConfigs{}, err
	}
	if req.Spec.HSMMode == "hardware" && !req.Spec.Network.HSM.Enabled {
		warnings = append(warnings, "hardware hsm mode selected but dedicated hsm interface is disabled")
	}
	if req.Spec.Network.Cluster.Enabled && !req.Spec.Features.Clustering {
		warnings = append(warnings, "cluster network enabled but clustering feature is disabled")
	}
	if req.Spec.FIPS.Mode == "strict" && req.Spec.Features.AILLM {
		warnings = append(warnings, "ai/llm enabled in strict fips mode; verify downstream model and tls settings")
	}

	authBootstrap := map[string]any{
		"tenant_id":             "root",
		"admin_username":        req.Spec.Admin.Username,
		"admin_password":        req.Spec.Admin.Password,
		"admin_email":           req.Spec.Admin.Email,
		"force_password_change": req.Spec.Admin.ForcePasswordChange,
	}

	deploymentYAML, err := yaml.Marshal(deployment)
	if err != nil {
		return GeneratedConfigs{}, err
	}
	networkYAML, err := yaml.Marshal(network)
	if err != nil {
		return GeneratedConfigs{}, err
	}
	fipsYAML, err := yaml.Marshal(fips)
	if err != nil {
		return GeneratedConfigs{}, err
	}
	fdeYAML, err := yaml.Marshal(fde)
	if err != nil {
		return GeneratedConfigs{}, err
	}
	authYAML, err := yaml.Marshal(authBootstrap)
	if err != nil {
		return GeneratedConfigs{}, err
	}

	var certBootstrap []byte
	if rootKeyMode == "software" {
		certBootstrap = []byte(bootstrapPassphrase + "\n")
	}

	return GeneratedConfigs{
		DeploymentYAML: deploymentYAML,
		NetworkYAML:    networkYAML,
		FIPSYAML:       fipsYAML,
		FDEYAML:        fdeYAML,
		AuthYAML:       authYAML,
		CertBootstrap:  certBootstrap,
		RecoveryShares: shares,
		GeneratedAt:    now,
		Warnings:       warnings,
		Paths:          paths,
	}, nil
}

func validateRequest(req WizardRequest) error {
	if strings.TrimSpace(req.Metadata.ApplianceID) == "" {
		return errors.New("metadata.appliance_id is required")
	}
	switch req.Spec.HSMMode {
	case "hardware", "software", "auto":
	default:
		return errors.New("spec.hsm_mode must be hardware, software, or auto")
	}
	storageMode := strings.ToLower(strings.TrimSpace(req.Spec.CertSecurity.CertStorageMode))
	if storageMode == "" {
		storageMode = "db_encrypted"
	}
	if storageMode != "db_encrypted" {
		return errors.New("spec.cert_security.cert_storage_mode must be db_encrypted")
	}
	rootMode := strings.ToLower(strings.TrimSpace(req.Spec.CertSecurity.RootKeyMode))
	if rootMode == "" {
		rootMode = "software"
	}
	switch rootMode {
	case "software", "hsm":
	default:
		return errors.New("spec.cert_security.root_key_mode must be software or hsm")
	}
	if strings.TrimSpace(req.Spec.CertSecurity.BootstrapPassphrase) != "" && len(strings.TrimSpace(req.Spec.CertSecurity.BootstrapPassphrase)) < 12 {
		return errors.New("spec.cert_security.bootstrap_passphrase must be at least 12 characters")
	}
	switch req.Spec.FIPS.Mode {
	case "strict", "standard":
	default:
		return errors.New("spec.fips.mode must be strict or standard")
	}
	if strings.TrimSpace(req.Spec.Network.Management.Interface) == "" {
		return errors.New("spec.network.management.interface is required")
	}
	if req.Spec.Network.Management.Mode != "dhcp" && req.Spec.Network.Management.Mode != "static" {
		return errors.New("spec.network.management.mode must be dhcp or static")
	}
	if req.Spec.Network.Management.Mode == "static" {
		if strings.TrimSpace(req.Spec.Network.Management.IPv4.Address) == "" {
			return errors.New("spec.network.management.ipv4.address is required for static mode")
		}
		if strings.TrimSpace(req.Spec.Network.Management.IPv4.Gateway) == "" {
			return errors.New("spec.network.management.ipv4.gateway is required for static mode")
		}
	}
	if len(req.Spec.Network.Management.IPv4.DNS) == 0 {
		return errors.New("spec.network.management.ipv4.dns requires at least one resolver")
	}
	switch req.Spec.Network.TLS.Mode {
	case "self-signed", "custom", "acme":
	default:
		return errors.New("spec.network.tls.mode must be self-signed, custom, or acme")
	}
	if req.Spec.Network.TLS.Mode == "custom" {
		if strings.TrimSpace(req.Spec.Network.TLS.CertPath) == "" || strings.TrimSpace(req.Spec.Network.TLS.KeyPath) == "" {
			return errors.New("spec.network.tls.cert_path and key_path are required in custom mode")
		}
	}
	if len(req.Spec.Network.NTP.Servers) == 0 {
		return errors.New("spec.network.ntp.servers requires at least one entry")
	}
	if req.Spec.License.MaxKeys <= 0 || req.Spec.License.MaxTenants <= 0 {
		return errors.New("spec.license.max_keys and spec.license.max_tenants must be positive")
	}
	if !licenseKeyPattern.MatchString(strings.TrimSpace(req.Spec.License.Key)) {
		return errors.New("spec.license.key has invalid format")
	}
	if len(req.Spec.License.FeaturesAllowed) == 0 {
		return errors.New("spec.license.features_allowed requires at least one feature or '*'")
	}
	if err := validateLicenseEntitlements(req.Spec.Features, req.Spec.License.FeaturesAllowed); err != nil {
		return err
	}
	if strings.TrimSpace(req.Spec.Admin.Username) == "" {
		return errors.New("spec.admin.username is required")
	}
	if strings.TrimSpace(req.Spec.Admin.Email) == "" {
		return errors.New("spec.admin.email is required")
	}
	if len(req.Spec.Admin.Password) < 12 {
		return errors.New("spec.admin.password must be at least 12 characters")
	}
	if req.Spec.FDE.Enabled {
		if strings.TrimSpace(req.Spec.FDE.Passphrase) == "" {
			return errors.New("spec.fde.passphrase is required when fde.enabled=true")
		}
		switch req.Spec.FDE.UnlockMethod {
		case "console", "usb", "tang", "rest_api":
		default:
			return errors.New("spec.fde.unlock_method must be console, usb, tang, or rest_api")
		}
		if req.Spec.FDE.RecoveryShares < 2 || req.Spec.FDE.RecoveryShares > 10 {
			return errors.New("spec.fde.recovery_shares must be between 2 and 10")
		}
		if req.Spec.FDE.RecoveryThreshold < 2 || req.Spec.FDE.RecoveryThreshold > req.Spec.FDE.RecoveryShares {
			return errors.New("spec.fde.recovery_threshold must be between 2 and recovery_shares")
		}
	}
	return nil
}

func validateLicenseEntitlements(features FeatureConfig, allowed []string) error {
	entitled := make(map[string]bool, len(allowed))
	for _, raw := range allowed {
		token := strings.TrimSpace(strings.ToLower(raw))
		if token == "" {
			continue
		}
		entitled[token] = true
	}
	if entitled["*"] {
		return nil
	}

	enabled := map[string]bool{
		"secrets":              features.Secrets,
		"certs":                features.Certs,
		"governance":           features.Governance,
		"cloud_byok":           features.CloudBYOK,
		"hyok_proxy":           features.HYOKProxy,
		"kmip_server":          features.KMIPServer,
		"qkd_interface":        features.QKDInterface,
		"qrng_generator":       features.QRNGGenerator,
		"ekm_database":         features.EKMDatabase,
		"payment_crypto":       features.PaymentCrypto,
		"compliance_dashboard": features.ComplianceDashboard,
		"sbom_cbom":            features.SBOMCBOM,
		"reporting_alerting":   features.ReportingAlerting,
		"posture_management":   features.PostureManagement,
		"ai_llm":               features.AILLM,
		"pqc_migration":        features.PQCMigration,
		"crypto_discovery":     features.CryptoDiscovery,
		"mpc_engine":           features.MPCEngine,
		"data_protection":      features.DataProtection,
		"clustering":           features.Clustering,
	}

	for feature, isEnabled := range enabled {
		if !isEnabled {
			continue
		}
		if !entitled[feature] {
			return fmt.Errorf("feature %q enabled but not permitted by license.features_allowed", feature)
		}
	}
	return nil
}

func buildFDEConfig(cfg FDEConfig) (map[string]any, []RecoveryShare, error) {
	if !cfg.Enabled {
		return map[string]any{
			"enabled": false,
		}, nil, nil
	}

	secretHash := sha256.Sum256([]byte(cfg.Passphrase))
	secretInt := new(big.Int).SetBytes(secretHash[:16])
	secretInt.Mod(secretInt, pkgmpc.Prime)
	shares, err := pkgmpc.Split(secretInt, cfg.RecoveryThreshold, cfg.RecoveryShares)
	if err != nil {
		return nil, nil, err
	}
	recovery := make([]RecoveryShare, 0, len(shares))
	for _, s := range shares {
		recovery = append(recovery, RecoveryShare{
			Index: int(s.X.Int64()),
			Value: hex.EncodeToString(s.Y.Bytes()),
		})
	}

	passphraseHash := sha256.Sum256([]byte(cfg.Passphrase))
	recoveryHash := passphraseHash
	if strings.TrimSpace(cfg.RecoveryPassphrase) != "" {
		recoveryHash = sha256.Sum256([]byte(cfg.RecoveryPassphrase))
	}

	doc := map[string]any{
		"enabled":                       true,
		"luks_version":                  "LUKS2",
		"algorithm":                     "AES-256-XTS",
		"key_derivation":                "Argon2id",
		"device":                        firstNonEmpty(cfg.LUKSDevice, "/dev/sda3"),
		"unlock_method":                 cfg.UnlockMethod,
		"operator_public_key":           cfg.OperatorPublicKey,
		"operator_passphrase_sha256":    hex.EncodeToString(passphraseHash[:]),
		"recovery_threshold":            cfg.RecoveryThreshold,
		"recovery_shares":               cfg.RecoveryShares,
		"recovery_passphrase_sha256":    hex.EncodeToString(recoveryHash[:]),
		"recovery_share_encoding":       "hex",
		"recovery_share_generation":     "shamir",
		"recovery_share_verification":   "required",
		"boot_unlock_listener_port":     9444,
		"boot_unlock_listener_protocol": "https",
		"tang_server":                   cfg.TangServer,
	}
	return doc, recovery, nil
}

func writeConfigFiles(g GeneratedConfigs) error {
	if err := validateDeploymentSchema(g.DeploymentYAML); err != nil {
		return fmt.Errorf("deployment schema validation failed: %w", err)
	}

	pairs := map[string][]byte{
		g.Paths["deployment"]: g.DeploymentYAML,
		g.Paths["network"]:    g.NetworkYAML,
		g.Paths["fips"]:       g.FIPSYAML,
		g.Paths["fde"]:        g.FDEYAML,
		g.Paths["auth"]:       g.AuthYAML,
	}
	for path, content := range pairs {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		if err := os.WriteFile(path, content, 0o640); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	if len(g.CertBootstrap) > 0 {
		secretPath := strings.TrimSpace(g.Paths["cert_bootstrap"])
		if secretPath == "" {
			secretPath = defaultCertBootstrapPath
		}
		if err := os.MkdirAll(filepath.Dir(secretPath), 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", secretPath, err)
		}
		if err := os.WriteFile(secretPath, g.CertBootstrap, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", secretPath, err)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func envOr(k string, d string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	return v
}

func randomBootstrapSecret(length int) string {
	if length < 16 {
		length = 16
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
	buf := make([]byte, length)
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("vecta-bootstrap-%d", time.Now().UTC().UnixNano())
	}
	for i := 0; i < length; i++ {
		buf[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(buf)
}
