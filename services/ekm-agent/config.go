package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type AgentConfig struct {
	TenantID             string `json:"tenant_id"`
	AgentID              string `json:"agent_id"`
	AgentName            string `json:"agent_name"`
	Role                 string `json:"role"`
	DBEngine             string `json:"db_engine"`
	Host                 string `json:"host"`
	Version              string `json:"version"`
	APIBaseURL           string `json:"api_base_url"`
	RegisterPath         string `json:"register_path"`
	HeartbeatPath        string `json:"heartbeat_path"`
	RotatePath           string `json:"rotate_path"`
	AuthToken            string `json:"auth_token"`
	TLSSkipVerify        bool   `json:"tls_skip_verify"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	RotationCycleDays    int    `json:"rotation_cycle_days"`
	AutoProvisionTDE     bool   `json:"auto_provision_tde"`

	DBDSN      string `json:"db_dsn"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBName     string `json:"db_name"`
	DBPort     int    `json:"db_port"`

	PKCS11ModulePath string `json:"pkcs11_module_path"`
	PKCS11SlotID     int    `json:"pkcs11_slot_id"`
	PKCS11PINEnv     string `json:"pkcs11_pin_env"`

	ActiveKeyID      string `json:"active_key_id"`
	ActiveKeyVersion string `json:"active_key_version"`
	ConfigVersionAck int    `json:"config_version_ack"`
}

func LoadAgentConfig(path string) (AgentConfig, error) {
	var cfg AgentConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	applyEnvOverrides(&cfg)
	applyDefaults(&cfg)
	if err := validateConfig(cfg); err != nil {
		return AgentConfig{}, err
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *AgentConfig) {
	if cfg == nil {
		return
	}
	cfg.TenantID = envOr("TENANT_ID", cfg.TenantID)
	cfg.AgentID = envOr("AGENT_ID", cfg.AgentID)
	cfg.AgentName = envOr("AGENT_NAME", cfg.AgentName)
	cfg.Role = envOr("AGENT_ROLE", cfg.Role)
	cfg.DBEngine = envOr("DB_ENGINE", cfg.DBEngine)
	cfg.Host = envOr("AGENT_HOST", cfg.Host)
	cfg.Version = envOr("AGENT_VERSION", cfg.Version)
	cfg.APIBaseURL = envOr("EKM_API_BASE_URL", cfg.APIBaseURL)
	cfg.RegisterPath = envOr("EKM_REGISTER_PATH", cfg.RegisterPath)
	cfg.HeartbeatPath = envOr("EKM_HEARTBEAT_PATH", cfg.HeartbeatPath)
	cfg.RotatePath = envOr("EKM_ROTATE_PATH", cfg.RotatePath)
	cfg.AuthToken = envOr("EKM_AUTH_TOKEN", cfg.AuthToken)
	cfg.DBDSN = envOr("DB_DSN", cfg.DBDSN)
	cfg.DBUser = envOr("DB_USER", cfg.DBUser)
	cfg.DBPassword = envOr("DB_PASSWORD", cfg.DBPassword)
	cfg.DBName = envOr("DB_NAME", cfg.DBName)
	cfg.PKCS11ModulePath = envOr("PKCS11_MODULE_PATH", cfg.PKCS11ModulePath)
	cfg.PKCS11PINEnv = envOr("PKCS11_PIN_ENV", cfg.PKCS11PINEnv)
	cfg.ActiveKeyID = envOr("ACTIVE_KEY_ID", cfg.ActiveKeyID)
	cfg.ActiveKeyVersion = envOr("ACTIVE_KEY_VERSION", cfg.ActiveKeyVersion)

	cfg.DBPort = envIntOr("DB_PORT", cfg.DBPort)
	cfg.PKCS11SlotID = envIntOr("PKCS11_SLOT_ID", cfg.PKCS11SlotID)
	cfg.HeartbeatIntervalSec = envIntOr("HEARTBEAT_INTERVAL_SEC", cfg.HeartbeatIntervalSec)
	cfg.RotationCycleDays = envIntOr("ROTATION_CYCLE_DAYS", cfg.RotationCycleDays)
	cfg.ConfigVersionAck = envIntOr("CONFIG_VERSION_ACK", cfg.ConfigVersionAck)

	cfg.TLSSkipVerify = envBoolOr("TLS_SKIP_VERIFY", cfg.TLSSkipVerify)
	cfg.AutoProvisionTDE = envBoolOr("AUTO_PROVISION_TDE", cfg.AutoProvisionTDE)
}

func applyDefaults(cfg *AgentConfig) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.Role) == "" {
		cfg.Role = "ekm-agent"
	}
	cfg.DBEngine = normalizeDBEngine(cfg.DBEngine)
	if strings.TrimSpace(cfg.DBEngine) == "" {
		cfg.DBEngine = "mssql"
	}
	if strings.TrimSpace(cfg.APIBaseURL) == "" {
		cfg.APIBaseURL = "https://localhost/svc/ekm"
	}
	if strings.TrimSpace(cfg.RegisterPath) == "" {
		cfg.RegisterPath = "/ekm/agents/register"
	}
	if strings.TrimSpace(cfg.HeartbeatPath) == "" {
		cfg.HeartbeatPath = "/ekm/agents/{agent_id}/heartbeat"
	}
	if strings.TrimSpace(cfg.RotatePath) == "" {
		cfg.RotatePath = "/ekm/agents/{agent_id}/rotate"
	}
	if cfg.HeartbeatIntervalSec <= 0 {
		cfg.HeartbeatIntervalSec = 30
	}
	if cfg.RotationCycleDays <= 0 {
		cfg.RotationCycleDays = 90
	}
	if cfg.DBPort <= 0 {
		if cfg.DBEngine == "oracle" {
			cfg.DBPort = 1521
		} else {
			cfg.DBPort = 1433
		}
	}
	if strings.TrimSpace(cfg.AgentName) == "" {
		cfg.AgentName = cfg.AgentID
	}
}

func validateConfig(cfg AgentConfig) error {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(cfg.AgentID) == "" {
		return fmt.Errorf("agent_id is required")
	}
	if strings.TrimSpace(cfg.AgentName) == "" {
		return fmt.Errorf("agent_name is required")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return fmt.Errorf("host is required")
	}
	if strings.TrimSpace(cfg.APIBaseURL) == "" {
		return fmt.Errorf("api_base_url is required")
	}
	if cfg.DBEngine != "mssql" && cfg.DBEngine != "oracle" {
		return fmt.Errorf("db_engine must be mssql or oracle")
	}
	return nil
}

func envOr(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return strings.TrimSpace(fallback)
	}
	return v
}

func envIntOr(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func envBoolOr(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func normalizeDBEngine(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "mssql", "sqlserver", "sql-server":
		return "mssql"
	case "oracle":
		return "oracle"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}
