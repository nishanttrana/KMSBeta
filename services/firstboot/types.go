package main

import "time"

type WizardRequest struct {
	Metadata WizardMetadata `json:"metadata"`
	Spec     WizardSpec     `json:"spec"`
}

type WizardMetadata struct {
	ApplianceID string `json:"appliance_id"`
}

type WizardSpec struct {
	HSMMode      string             `json:"hsm_mode"`
	CertSecurity CertSecurityConfig `json:"cert_security"`
	FDE          FDEConfig          `json:"fde"`
	FIPS         FIPSModeConfig     `json:"fips"`
	Network      NetworkConfig      `json:"network"`
	Features     FeatureConfig      `json:"features"`
	License      LicenseConfig      `json:"license"`
	Admin        AdminBootstrap     `json:"admin"`
	Timing       WizardApplyPlan    `json:"timing"`
}

type CertSecurityConfig struct {
	CertStorageMode     string `json:"cert_storage_mode"`
	RootKeyMode         string `json:"root_key_mode"`
	BootstrapPassphrase string `json:"bootstrap_passphrase,omitempty"`
	UseTPMSeal          bool   `json:"use_tpm_seal"`
	SealedKeyPath       string `json:"sealed_key_path,omitempty"`
	PassphraseFilePath  string `json:"passphrase_file_path,omitempty"`
}

type FDEConfig struct {
	Enabled            bool   `json:"enabled"`
	LUKSDevice         string `json:"luks_device"`
	Passphrase         string `json:"passphrase,omitempty"`
	UnlockMethod       string `json:"unlock_method"`
	RecoveryShares     int    `json:"recovery_shares"`
	RecoveryThreshold  int    `json:"recovery_threshold"`
	OperatorPublicKey  string `json:"operator_public_key,omitempty"`
	TangServer         string `json:"tang_server,omitempty"`
	RecoveryPassphrase string `json:"recovery_passphrase,omitempty"`
}

type FIPSModeConfig struct {
	Mode string `json:"mode"`
}

type NetworkConfig struct {
	Management InterfaceConfig `json:"management"`
	Cluster    ClusterConfig   `json:"cluster"`
	HSM        HSMInterface    `json:"hsm"`
	TLS        TLSConfig       `json:"tls"`
	NTP        NTPConfig       `json:"ntp"`
	Syslog     SyslogConfig    `json:"syslog"`
	Firewall   FirewallConfig  `json:"firewall"`
}

type InterfaceConfig struct {
	Interface string     `json:"interface"`
	Mode      string     `json:"mode"`
	IPv4      IPv4Config `json:"ipv4"`
	IPv6      IPv6Config `json:"ipv6"`
	Hostname  string     `json:"hostname"`
	Domain    string     `json:"domain"`
}

type ClusterConfig struct {
	Enabled   bool       `json:"enabled"`
	Interface string     `json:"interface"`
	IPv4      IPv4Config `json:"ipv4"`
	MTU       int        `json:"mtu"`
}

type HSMInterface struct {
	Enabled   bool       `json:"enabled"`
	Interface string     `json:"interface"`
	IPv4      IPv4Config `json:"ipv4"`
}

type IPv4Config struct {
	Address string   `json:"address"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type IPv6Config struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address,omitempty"`
}

type TLSConfig struct {
	Mode     string `json:"mode"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	CAPath   string `json:"ca_path,omitempty"`
}

type NTPConfig struct {
	Servers []string `json:"servers"`
}

type SyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Protocol string `json:"protocol"`
}

type FirewallConfig struct {
	Enabled      bool                      `json:"enabled"`
	AllowedPorts map[string][]int          `json:"allowed_ports"`
	Metadata     map[string]string         `json:"metadata,omitempty"`
	Overrides    map[string]map[string]any `json:"overrides,omitempty"`
}

type FeatureConfig struct {
	Secrets             bool `json:"secrets"`
	Certs               bool `json:"certs"`
	Governance          bool `json:"governance"`
	CloudBYOK           bool `json:"cloud_byok"`
	HYOKProxy           bool `json:"hyok_proxy"`
	KMIPServer          bool `json:"kmip_server"`
	QKDInterface        bool `json:"qkd_interface"`
	QRNGGenerator       bool `json:"qrng_generator"`
	EKMDatabase         bool `json:"ekm_database"`
	PaymentCrypto       bool `json:"payment_crypto"`
	ComplianceDashboard bool `json:"compliance_dashboard"`
	SBOMCBOM            bool `json:"sbom_cbom"`
	ReportingAlerting   bool `json:"reporting_alerting"`
	PostureManagement   bool `json:"posture_management"`
	AILLM               bool `json:"ai_llm"`
	PQCMigration        bool `json:"pqc_migration"`
	CryptoDiscovery     bool `json:"crypto_discovery"`
	MPCEngine           bool `json:"mpc_engine"`
	DataProtection      bool `json:"data_protection"`
	Clustering          bool `json:"clustering"`
}

type LicenseConfig struct {
	Key             string   `json:"key"`
	MaxKeys         int64    `json:"max_keys"`
	MaxTenants      int      `json:"max_tenants"`
	FeaturesAllowed []string `json:"features_allowed"`
}

type AdminBootstrap struct {
	Username            string `json:"username"`
	Password            string `json:"password,omitempty"`
	Email               string `json:"email"`
	ForcePasswordChange bool   `json:"force_password_change"`
}

type WizardApplyPlan struct {
	RequireReboot bool `json:"require_reboot"`
}

type GeneratedConfigs struct {
	DeploymentYAML []byte            `json:"-"`
	NetworkYAML    []byte            `json:"-"`
	FIPSYAML       []byte            `json:"-"`
	FDEYAML        []byte            `json:"-"`
	AuthYAML       []byte            `json:"-"`
	CertBootstrap  []byte            `json:"-"`
	RecoveryShares []RecoveryShare   `json:"recovery_shares,omitempty"`
	GeneratedAt    time.Time         `json:"generated_at"`
	Warnings       []string          `json:"warnings,omitempty"`
	Paths          map[string]string `json:"paths,omitempty"`
}

type RecoveryShare struct {
	Index int    `json:"index"`
	Value string `json:"value"`
}
