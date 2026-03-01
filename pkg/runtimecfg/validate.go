package runtimecfg

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	pkgconfig "vecta-kms/pkg/config"
)

// ValidateServiceConfig performs strict startup validation for core runtime config.
// It is intentionally fail-fast to prevent partially misconfigured services from booting.
func ValidateServiceConfig(service string, cfg pkgconfig.Config) error {
	service = strings.TrimSpace(service)
	if service == "" {
		service = "unknown-service"
	}

	var errs []error
	if strings.TrimSpace(cfg.PostgresDSN) == "" && !cfg.UseSQLite {
		errs = append(errs, errors.New("POSTGRES_DSN is required when SQLITE_FALLBACK=false"))
	}
	if dsn := strings.TrimSpace(cfg.PostgresDSN); dsn != "" {
		if _, err := url.Parse(dsn); err != nil {
			errs = append(errs, fmt.Errorf("POSTGRES_DSN is invalid: %w", err))
		}
	}
	if strings.TrimSpace(cfg.SQLitePath) == "" && cfg.UseSQLite {
		errs = append(errs, errors.New("SQLITE_PATH is required when SQLITE_FALLBACK=true"))
	}
	if natsURL := strings.TrimSpace(cfg.NATSURL); natsURL == "" {
		errs = append(errs, errors.New("NATS_URL is required"))
	} else if !isValidURLWithSchemes(natsURL, "nats", "tls", "ws", "wss") {
		errs = append(errs, errors.New("NATS_URL must be a valid URL (nats://, tls://, ws://, or wss://)"))
	}
	if strings.TrimSpace(cfg.ConsulAddress) == "" {
		errs = append(errs, errors.New("CONSUL_HTTP_ADDR is required"))
	}
	if cfg.MeteringWindow <= 0 {
		errs = append(errs, errors.New("METERING_WINDOW_SECONDS must be greater than 0"))
	}
	if cfg.HSMMode == pkgconfig.HSMModeHardware && strings.TrimSpace(cfg.HSMEndpoint) == "" {
		errs = append(errs, errors.New("HSM_ENDPOINT is required when HSM_MODE=hardware"))
	}
	if cfg.TLSEnabled {
		if strings.TrimSpace(cfg.JWTIssuer) == "" {
			errs = append(errs, errors.New("JWT_ISSUER is required when TLS is enabled"))
		}
		if strings.TrimSpace(cfg.JWTAudience) == "" {
			errs = append(errs, errors.New("JWT_AUDIENCE is required when TLS is enabled"))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s runtime config validation failed: %w", service, errors.Join(errs...))
	}
	return nil
}

// ValidateHTTPPort ensures startup port bindings are numeric and valid.
func ValidateHTTPPort(portRaw string) error {
	portRaw = strings.TrimSpace(portRaw)
	if portRaw == "" {
		return errors.New("port is required")
	}
	if _, err := net.ResolveTCPAddr("tcp", ":"+portRaw); err != nil {
		return fmt.Errorf("invalid port %q: %w", portRaw, err)
	}
	return nil
}

// ValidateDurationFloor ensures scheduler/interval knobs are non-zero and sane.
func ValidateDurationFloor(name string, d time.Duration, min time.Duration) error {
	if d < min {
		return fmt.Errorf("%s must be >= %s", strings.TrimSpace(name), min.String())
	}
	return nil
}

func isValidURLWithSchemes(raw string, schemes ...string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	if len(schemes) == 0 {
		return true
	}
	needle := strings.ToLower(strings.TrimSpace(u.Scheme))
	for _, item := range schemes {
		if needle == strings.ToLower(strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}
