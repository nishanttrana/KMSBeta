package hsmconnector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A tenant's HSM profile is what the tenant administrator saved in the HSM
// tab (auth_hsm_provider_configs). The connector reads it; it never writes
// the database.

type TenantConfig struct {
	TenantID       string
	Provider       string
	Library        string
	SlotID         string
	PartitionLabel string
	TokenLabel     string
	PINEnvVar      string
	PIN            string
	ReadOnly       bool
}

var (
	ErrNotConfigured  = errors.New("no enabled HSM profile for this tenant")
	errLibraryRefused = errors.New("the PKCS#11 library is outside the allowed library directories")
	errPINMissing     = errors.New("the HSM PIN is not provided to the connector")
	pinVarRE          = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,62}PIN[A-Z0-9_]{0,62}$`)
)

// libraryRoots are the directories a PKCS#11 library may load from:
// HSM_LIBRARY_ROOTS (":"-separated), by default the provider workspace the
// hsm-integration container writes (mounted read-only here). A library is a
// native binary loaded into this process, so an arbitrary path would be
// arbitrary code.
func libraryRoots() []string {
	raw := strings.TrimSpace(os.Getenv("HSM_LIBRARY_ROOTS"))
	if raw == "" {
		raw = "/var/lib/vecta/hsm/providers"
	}
	var out []string
	for _, r := range strings.Split(raw, ":") {
		if r = strings.TrimSpace(r); r != "" {
			if abs, err := filepath.EvalSymlinks(r); err == nil {
				out = append(out, filepath.Clean(abs))
			}
		}
	}
	return out
}

// checkLibrary resolves path (symlinks included) and requires it under an
// allowed root.
func checkLibrary(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: library_path must be an absolute path", errLibraryRefused)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("PKCS#11 library %s: %w", path, err)
	}
	real = filepath.Clean(real)
	for _, root := range libraryRoots() {
		if strings.HasPrefix(real, root+string(filepath.Separator)) {
			return real, nil
		}
	}
	return "", errLibraryRefused
}

// pinFor reads the PIN from the environment variable the profile names (a
// name containing "PIN"), or from the file in <VAR>_FILE.
func pinFor(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "HSM_PIN"
	}
	if !pinVarRE.MatchString(name) {
		return "", fmt.Errorf("pin_env_var %q must be an upper-case variable name containing PIN", name)
	}
	if v := os.Getenv(name); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), nil
	}
	if f := strings.TrimSpace(os.Getenv(name + "_FILE")); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("reading %s_FILE: %w", name, err)
		}
		if v := strings.TrimSpace(string(raw)); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("%w: set %s (or %s_FILE) on the hsm-connector service", errPINMissing, name, name)
}

type ConfigSource interface {
	Load(ctx context.Context, tenant string) (TenantConfig, error)
}

// DBConfigs reads profiles, cached briefly so a burst of operations costs
// one query.
type DBConfigs struct {
	DB    *sql.DB
	mu    sync.Mutex
	cache map[string]cachedConfig
}

type cachedConfig struct {
	cfg TenantConfig
	err error
	at  time.Time
}

const configTTL = 15 * time.Second

func (d *DBConfigs) Load(ctx context.Context, tenant string) (TenantConfig, error) {
	d.mu.Lock()
	if c, ok := d.cache[tenant]; ok && time.Since(c.at) < configTTL {
		d.mu.Unlock()
		return c.cfg, c.err
	}
	d.mu.Unlock()
	cfg, err := d.query(ctx, tenant)
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string]cachedConfig{}
	}
	d.cache[tenant] = cachedConfig{cfg: cfg, err: err, at: time.Now()}
	d.mu.Unlock()
	return cfg, err
}

func (d *DBConfigs) query(ctx context.Context, tenant string) (TenantConfig, error) {
	cfg := TenantConfig{TenantID: tenant}
	var enabled bool
	err := d.DB.QueryRowContext(ctx, `
SELECT COALESCE(provider_name,''), COALESCE(library_path,''), COALESCE(slot_id,''), COALESCE(partition_label,''),
       COALESCE(token_label,''), COALESCE(pin_env_var,''), read_only, enabled
FROM auth_hsm_provider_configs WHERE tenant_id=$1`, tenant).Scan(
		&cfg.Provider, &cfg.Library, &cfg.SlotID, &cfg.PartitionLabel, &cfg.TokenLabel, &cfg.PINEnvVar, &cfg.ReadOnly, &enabled)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !enabled) {
		return cfg, ErrNotConfigured
	}
	if err != nil {
		return cfg, err
	}
	return Resolve(cfg)
}

// Resolve validates the library and reads the PIN.
func Resolve(cfg TenantConfig) (TenantConfig, error) {
	lib, err := checkLibrary(cfg.Library)
	if err != nil {
		return cfg, err
	}
	cfg.Library = lib
	if cfg.PIN, err = pinFor(cfg.PINEnvVar); err != nil {
		return cfg, err
	}
	return cfg, nil
}
