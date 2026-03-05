package main

import (
	"os"
	"strconv"
	"strings"
)

// ProviderConfig holds all environment-driven configuration for the PKCS#11 provider.
type ProviderConfig struct {
	BaseURL      string
	TenantID     string
	AuthToken    string
	MTLSCertPath string
	MTLSKeyPath  string
	MTLSCAPath   string
	APIKey       string
	JWTEndpoint  string
	KeyCacheTTL  int // seconds, 0 = disabled
	SlotLabel    string
}

func LoadProviderConfig() ProviderConfig {
	return ProviderConfig{
		BaseURL:      envStr("VECTA_BASE_URL", "https://localhost/svc/ekm"),
		TenantID:     envStr("VECTA_TENANT_ID", ""),
		AuthToken:    envStr("VECTA_AUTH_TOKEN", ""),
		MTLSCertPath: envStr("VECTA_MTLS_CERT", ""),
		MTLSKeyPath:  envStr("VECTA_MTLS_KEY", ""),
		MTLSCAPath:   envStr("VECTA_MTLS_CA", ""),
		APIKey:       envStr("VECTA_API_KEY", ""),
		JWTEndpoint:  envStr("VECTA_JWT_ENDPOINT", ""),
		KeyCacheTTL:  envInt("VECTA_KEY_CACHE_TTL", 300),
		SlotLabel:    envStr("VECTA_SLOT_LABEL", "Vecta KMS"),
	}
}

func envStr(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
