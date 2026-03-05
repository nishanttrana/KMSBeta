package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type HSMMode string

const (
	HSMModeHardware HSMMode = "hardware"
	HSMModeSoftware HSMMode = "software"
	HSMModeAuto     HSMMode = "auto"
)

type Config struct {
	Env              string
	PostgresDSN      string
	PostgresRODSN    string
	SQLitePath       string
	UseSQLite        bool
	NATSURL          string
	ConsulAddress    string
	OpsLimit         uint64
	MeteringWindow   time.Duration
	HSMMode          HSMMode
	HSMEndpoint      string
	TLSEnabled       bool
	JWTIssuer        string
	JWTAudience      string
	JWTPublicKeyPath string

	// Database pool tuning
	DBMaxOpen           int
	DBMaxIdle           int
	DBConnMaxIdleTimeSec int
	DBConnMaxLifetimeSec int

	// Rate limiting
	RateLimitRPS   float64
	RateLimitBurst int
}

func Load() Config {
	return Config{
		Env:              get("VECTA_ENV", "dev"),
		PostgresDSN:      get("POSTGRES_DSN", "postgres://postgres:postgres@localhost:5432/vecta?sslmode=disable"),
		PostgresRODSN:    get("POSTGRES_RO_DSN", ""),
		SQLitePath:       get("SQLITE_PATH", "vecta.db"),
		UseSQLite:        getBool("SQLITE_FALLBACK", false),
		NATSURL:          get("NATS_URL", "nats://localhost:4222"),
		ConsulAddress:    get("CONSUL_HTTP_ADDR", "127.0.0.1:8500"),
		OpsLimit:         uint64(getInt("OPS_LIMIT", 0)),
		MeteringWindow:   time.Duration(getInt("METERING_WINDOW_SECONDS", 3600)) * time.Second,
		HSMMode:          DetectHSMMode(get("HSM_MODE", string(HSMModeAuto)), get("HSM_ENDPOINT", "")),
		HSMEndpoint:      get("HSM_ENDPOINT", ""),
		TLSEnabled:       getBool("TLS_ENABLED", true),
		JWTIssuer:        get("JWT_ISSUER", "vecta-auth"),
		JWTAudience:      get("JWT_AUDIENCE", "vecta-services"),
		JWTPublicKeyPath: get("JWT_PUBLIC_KEY_PATH", "certs/jwt_public.pem"),

		DBMaxOpen:            getInt("DB_MAX_OPEN", 50),
		DBMaxIdle:            getInt("DB_MAX_IDLE", 25),
		DBConnMaxIdleTimeSec: getInt("DB_CONN_MAX_IDLE_TIME_SEC", 300),
		DBConnMaxLifetimeSec: getInt("DB_CONN_MAX_LIFETIME_SEC", 1800),

		RateLimitRPS:   getFloat("RATE_LIMIT_RPS", 100),
		RateLimitBurst: getInt("RATE_LIMIT_BURST", 200),
	}
}

func DetectHSMMode(raw string, endpoint string) HSMMode {
	m := HSMMode(strings.ToLower(strings.TrimSpace(raw)))
	switch m {
	case HSMModeHardware, HSMModeSoftware:
		return m
	default:
		if endpoint != "" {
			return HSMModeHardware
		}
		return HSMModeSoftware
	}
}

func get(key string, d string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return d
	}
	return v
}

func getBool(key string, d bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}

func getInt(key string, d int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return d
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return i
}

func getFloat(key string, d float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return d
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return d
	}
	return f
}
