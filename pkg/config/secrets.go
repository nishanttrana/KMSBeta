package config

import (
	"log"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Secret-named env vars (same naming rule as scripts/conformance.sh rule 3).
var (
	secretEnvName = regexp.MustCompile(`^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSPHRASE|PASSWD|API_KEY|PRIVATE_KEY|_KEY_B64|_KEY_PEM|MEK|KEK)[A-Z0-9_]*$`)
	notSecretEnv  = regexp.MustCompile(`_(FILE|PATH|DIR|MODE|ENABLED|IN_HSM|CHANGE|ID|URL|TTL|HEADER)$`)
	// Values that only ever come from docs or example files.
	placeholderValue = regexp.MustCompile(`(?i)^your-|change-?me|change_me|replace-?me`)
	// Connection strings carry a password inside the URL.
	dsnEnvName = regexp.MustCompile(`(_DSN|DATABASE_URL)$`)
	// Vendor/tutorial default passwords, compared case-insensitively.
	defaultDBPasswords = map[string]bool{"postgres": true, "password": true, "admin": true, "root": true, "secret": true}
)

// weakDSNPassword reports whether a connection string embeds a default,
// placeholder, or username-equal password (for example postgres:postgres).
func weakDSNPassword(dsn string) bool {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || u.User == nil {
		return false
	}
	pw, ok := u.User.Password()
	if !ok {
		return false // no password in the URL (peer/trust auth or PGPASSWORD)
	}
	return pw == "" || strings.EqualFold(pw, u.User.Username()) || defaultDBPasswords[strings.ToLower(pw)] || placeholderValue.MatchString(pw)
}

// placeholderExempt is seeded with a forced password change on first login
// (docs/SECURITY/SECURE_DEFAULTS.md rule 5).
const placeholderExempt = "AUTH_BOOTSTRAP_ADMIN_PASSWORD"

// PlaceholderSecrets returns the names of secret-named variables in environ
// ("KEY=value" entries) whose value is a documentation placeholder, and of
// connection strings (*_DSN, *DATABASE_URL) that embed a default password.
func PlaceholderSecrets(environ []string) []string {
	var bad []string
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == placeholderExempt {
			continue
		}
		if dsnEnvName.MatchString(name) {
			if weakDSNPassword(value) {
				bad = append(bad, name)
			}
			continue
		}
		if !secretEnvName.MatchString(name) || notSecretEnv.MatchString(name) {
			continue
		}
		if placeholderValue.MatchString(strings.TrimSpace(value)) {
			bad = append(bad, name)
		}
	}
	sort.Strings(bad)
	return bad
}

var placeholderOnce sync.Once

// RejectPlaceholderSecrets stops the process when any secret in the
// environment is still a placeholder such as "your-..." or "change-me", or a
// connection string embeds a default password such as postgres:postgres:
// those values are public, so running with one is running without the secret. It
// runs once per process and is called from Load and NewHTTPServer, so every
// service gets it by construction.
func RejectPlaceholderSecrets() {
	placeholderOnce.Do(func() {
		if bad := PlaceholderSecrets(os.Environ()); len(bad) > 0 {
			log.Fatalf("refusing to start: placeholder or default credential in %s; generate real values (openssl rand -hex 32) — see docs/SECURITY/SECURE_DEFAULTS.md", strings.Join(bad, ", "))
		}
	})
}
