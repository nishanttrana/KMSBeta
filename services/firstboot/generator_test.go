package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateConfigs(t *testing.T) {
	req := WizardRequest{
		Metadata: WizardMetadata{ApplianceID: "kms-test-01"},
		Spec: WizardSpec{
			HSMMode: "software",
			FDE: FDEConfig{
				Enabled:           true,
				LUKSDevice:        "/dev/sda3",
				Passphrase:        "StrongPassphraseForFDE!",
				UnlockMethod:      "rest_api",
				RecoveryShares:    5,
				RecoveryThreshold: 3,
			},
			FIPS: FIPSModeConfig{Mode: "strict"},
			Network: NetworkConfig{
				Management: InterfaceConfig{
					Interface: "eth0",
					Mode:      "static",
					IPv4: IPv4Config{
						Address: "10.0.1.100/24",
						Gateway: "10.0.1.1",
						DNS:     []string{"10.0.1.2"},
					},
					IPv6:     IPv6Config{Enabled: false},
					Hostname: "kms-test-01",
					Domain:   "example.local",
				},
				Cluster: ClusterConfig{
					Enabled:   true,
					Interface: "eth1",
					IPv4:      IPv4Config{Address: "172.16.0.100/24"},
					MTU:       9000,
				},
				HSM: HSMInterface{
					Enabled:   false,
					Interface: "eth2",
					IPv4:      IPv4Config{},
				},
				TLS: TLSConfig{
					Mode:     "custom",
					CertPath: "/etc/vecta/tls/server.crt",
					KeyPath:  "/etc/vecta/tls/server.key",
					CAPath:   "/etc/vecta/tls/ca.crt",
				},
				NTP:      NTPConfig{Servers: []string{"pool.ntp.org"}},
				Syslog:   SyslogConfig{Enabled: true, Server: "syslog.example.local:514", Protocol: "tcp+tls"},
				Firewall: FirewallConfig{Enabled: true, AllowedPorts: map[string][]int{"management": {443, 9443}}},
			},
			Features: FeatureConfig{
				Secrets:             true,
				Certs:               true,
				Governance:          true,
				CloudBYOK:           false,
				HYOKProxy:           false,
				KMIPServer:          true,
				QKDInterface:        false,
				QRNGGenerator:       false,
				EKMDatabase:         false,
				PaymentCrypto:       true,
				ComplianceDashboard: true,
				SBOMCBOM:            true,
				ReportingAlerting:   true,
				PostureManagement:   true,
				AILLM:               false,
				PQCMigration:        true,
				CryptoDiscovery:     false,
				MPCEngine:           false,
				DataProtection:      true,
				Clustering:          true,
			},
			License: LicenseConfig{
				Key:             "SEC-KMS-ENT-2026-ABCD",
				MaxKeys:         5000000,
				MaxTenants:      50,
				FeaturesAllowed: []string{"*"},
			},
			Admin: AdminBootstrap{
				Username:            "admin",
				Password:            "VectaAdmin@2026",
				Email:               "admin@vecta.local",
				ForcePasswordChange: true,
			},
		},
	}
	got, err := generateConfigs(req)
	if err != nil {
		t.Fatalf("generateConfigs failed: %v", err)
	}
	if len(got.RecoveryShares) != 5 {
		t.Fatalf("expected 5 recovery shares, got %d", len(got.RecoveryShares))
	}
	if !strings.Contains(string(got.DeploymentYAML), "hsm_mode: software") {
		t.Fatalf("deployment output missing hsm_mode")
	}
	if !strings.Contains(string(got.NetworkYAML), "management:") {
		t.Fatalf("network output missing management block")
	}
	if !strings.Contains(string(got.FIPSYAML), "mode: strict") {
		t.Fatalf("fips output missing strict mode")
	}
	if !strings.Contains(string(got.FDEYAML), "luks_version: LUKS2") {
		t.Fatalf("fde output missing LUKS2 marker")
	}
}

func TestValidateRejectsInvalidLicense(t *testing.T) {
	req := WizardRequest{
		Metadata: WizardMetadata{ApplianceID: "kms-test-01"},
		Spec: WizardSpec{
			HSMMode: "software",
			FDE:     FDEConfig{Enabled: false},
			FIPS:    FIPSModeConfig{Mode: "strict"},
			Network: NetworkConfig{
				Management: InterfaceConfig{
					Interface: "eth0",
					Mode:      "dhcp",
					IPv4:      IPv4Config{DNS: []string{"8.8.8.8"}},
					IPv6:      IPv6Config{Enabled: false},
				},
				TLS: TLSConfig{
					Mode: "self-signed",
				},
				NTP: NTPConfig{Servers: []string{"pool.ntp.org"}},
			},
			License: LicenseConfig{
				Key:             "INVALID",
				MaxKeys:         100,
				MaxTenants:      10,
				FeaturesAllowed: []string{"*"},
			},
			Admin: AdminBootstrap{
				Username:            "admin",
				Password:            "VectaAdmin@2026",
				Email:               "admin@vecta.local",
				ForcePasswordChange: true,
			},
		},
	}
	if _, err := generateConfigs(req); err == nil {
		t.Fatal("expected invalid license key error")
	}
}

func TestValidateRejectsUnlicensedFeature(t *testing.T) {
	req := WizardRequest{
		Metadata: WizardMetadata{ApplianceID: "kms-test-01"},
		Spec: WizardSpec{
			HSMMode: "software",
			FDE:     FDEConfig{Enabled: false},
			FIPS:    FIPSModeConfig{Mode: "strict"},
			Network: NetworkConfig{
				Management: InterfaceConfig{
					Interface: "eth0",
					Mode:      "dhcp",
					IPv4:      IPv4Config{DNS: []string{"8.8.8.8"}},
					IPv6:      IPv6Config{Enabled: false},
				},
				TLS: TLSConfig{
					Mode: "self-signed",
				},
				NTP: NTPConfig{Servers: []string{"pool.ntp.org"}},
			},
			Features: FeatureConfig{
				Secrets: true,
			},
			License: LicenseConfig{
				Key:             "SEC-KMS-ENT-2026-ABCD",
				MaxKeys:         100,
				MaxTenants:      10,
				FeaturesAllowed: []string{"certs"},
			},
			Admin: AdminBootstrap{
				Username:            "admin",
				Password:            "VectaAdmin@2026",
				Email:               "admin@vecta.local",
				ForcePasswordChange: true,
			},
		},
	}
	if _, err := generateConfigs(req); err == nil {
		t.Fatal("expected unlicensed feature error")
	}
}

func TestValidateDeploymentSchema(t *testing.T) {
	schemaPath, err := filepath.Abs("../../infra/deployment/deployment.schema.json")
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	t.Setenv("FIRSTBOOT_DEPLOYMENT_SCHEMA_PATH", schemaPath)

	valid := []byte(`apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
metadata:
  appliance_id: kms-test-01
  created_at: "2026-02-19T00:00:00Z"
spec:
  hsm_mode: software
  core:
    auth: true
    keycore: true
    audit: true
    policy: true
  features:
    secrets: true
    certs: true
    governance: true
    cloud_byok: false
    hyok_proxy: false
    kmip_server: true
    qkd_interface: false
    qrng_generator: false
    ekm_database: false
    payment_crypto: true
    compliance_dashboard: true
    sbom_cbom: true
    reporting_alerting: true
    posture_management: true
    ai_llm: false
    pqc_migration: true
    crypto_discovery: false
    mpc_engine: false
    data_protection: true
    clustering: false
  license:
    key: SEC-KMS-ENT-2026-ABCD
    max_keys: 100
    max_tenants: 2
    features_allowed: ["*"]
`)
	if err := validateDeploymentSchema(valid); err != nil {
		t.Fatalf("expected valid deployment schema, got: %v", err)
	}

	invalid := []byte(`apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
metadata:
  appliance_id: kms-test-01
  created_at: "2026-02-19T00:00:00Z"
spec:
  hsm_mode: software
`)
	if err := validateDeploymentSchema(invalid); err == nil {
		t.Fatal("expected schema validation error for invalid deployment")
	}
}
