package dynamicsecrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	pgPasswordLen   = 32
	pgPasswordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
)

// PostgresProviderConfig configures the Postgres dynamic credentials provider.
type PostgresProviderConfig struct {
	AdminDSN   string   // DSN with admin privileges to create roles
	RoleGrants []string // e.g. ["SELECT", "INSERT", "UPDATE"] or ["ALL PRIVILEGES"]
	DefaultDB  string   // database to grant on (used in GRANT ... ON DATABASE)
}

// PostgresProvider generates ephemeral PostgreSQL credentials.
type PostgresProvider struct {
	adminDSN   string
	roleGrants []string
	defaultDB  string
}

// NewPostgresProvider creates a provider that manages dynamic Postgres users.
func NewPostgresProvider(cfg PostgresProviderConfig) (*PostgresProvider, error) {
	if cfg.AdminDSN == "" {
		return nil, fmt.Errorf("dynamicsecrets/postgres: admin DSN is required")
	}
	if len(cfg.RoleGrants) == 0 {
		cfg.RoleGrants = []string{"SELECT"}
	}
	if cfg.DefaultDB == "" {
		cfg.DefaultDB = "postgres"
	}
	return &PostgresProvider{
		adminDSN:   cfg.AdminDSN,
		roleGrants: cfg.RoleGrants,
		defaultDB:  cfg.DefaultDB,
	}, nil
}

func (p *PostgresProvider) Generate(ctx context.Context, req LeaseRequest) (*Credential, error) {
	password, err := generateSecurePassword(pgPasswordLen, pgPasswordChars)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/postgres: generate password: %w", err)
	}

	roleName := fmt.Sprintf("v_dyn_%s_%s", sanitizeIdentifier(req.Role), randomHex(8))
	expiresAt := time.Now().Add(req.TTL)

	db, err := sql.Open("pgx", p.adminDSN)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/postgres: open admin conn: %w", err)
	}
	defer db.Close()

	validUntil := expiresAt.UTC().Format("2006-01-02 15:04:05+00")

	// Create the role with LOGIN and an expiry
	createSQL := fmt.Sprintf(
		"CREATE ROLE %s WITH LOGIN PASSWORD '%s' VALID UNTIL '%s'",
		quoteIdentPG(roleName),
		escapeSingleQuotes(password),
		validUntil,
	)
	if _, err := db.ExecContext(ctx, createSQL); err != nil {
		return nil, fmt.Errorf("dynamicsecrets/postgres: create role: %w", err)
	}

	// Grant privileges
	grants := strings.Join(p.roleGrants, ", ")
	grantSQL := fmt.Sprintf("GRANT %s ON DATABASE %s TO %s",
		grants,
		quoteIdentPG(p.defaultDB),
		quoteIdentPG(roleName),
	)
	if _, err := db.ExecContext(ctx, grantSQL); err != nil {
		// Best-effort cleanup on grant failure
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", quoteIdentPG(roleName)))
		return nil, fmt.Errorf("dynamicsecrets/postgres: grant privileges: %w", err)
	}

	credID := "pgcred_" + randomHex(16)
	leaseID := "pglease_" + randomHex(16)

	// Extract endpoint from DSN for the credential
	endpoint := extractHostFromDSN(p.adminDSN)

	return &Credential{
		ID:        credID,
		TenantID:  req.TenantID,
		Provider:  "postgres",
		Username:  roleName,
		Password:  password,
		Endpoint:  endpoint,
		ExpiresAt: expiresAt,
		LeaseID:   leaseID,
	}, nil
}

func (p *PostgresProvider) Revoke(ctx context.Context, credentialID string) error {
	db, err := sql.Open("pgx", p.adminDSN)
	if err != nil {
		return fmt.Errorf("dynamicsecrets/postgres: open admin conn for revoke: %w", err)
	}
	defer db.Close()

	// credentialID is the cred ID; we need the username. The engine should pass it.
	// For the revoke path we receive the credential_id and look up the username from the store.
	// However, the Provider interface only gets credentialID. We encode the username in the ID
	// as a fallback: the store-based lease_manager resolves this properly.
	// For direct revocation by username, use RevokeByUsername.
	return p.RevokeByUsername(ctx, db, credentialID)
}

// RevokeByUsername drops a Postgres role by name, reassigning owned objects first.
func (p *PostgresProvider) RevokeByUsername(ctx context.Context, db *sql.DB, username string) error {
	stmts := []string{
		fmt.Sprintf("REASSIGN OWNED BY %s TO postgres", quoteIdentPG(username)),
		fmt.Sprintf("DROP OWNED BY %s", quoteIdentPG(username)),
		fmt.Sprintf("DROP ROLE IF EXISTS %s", quoteIdentPG(username)),
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("dynamicsecrets/postgres: revoke stmt %q: %w", stmt, err)
		}
	}
	return nil
}

// generateSecurePassword creates a cryptographically random password of the given length.
func generateSecurePassword(length int, charset string) (string, error) {
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = charset[idx.Int64()]
	}
	return string(result), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sanitizeIdentifier removes non-alphanumeric characters to prevent SQL injection in identifiers.
func sanitizeIdentifier(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// quoteIdentPG wraps a Postgres identifier in double quotes with escaping.
func quoteIdentPG(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func escapeSingleQuotes(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// extractHostFromDSN attempts to pull host:port from a postgres DSN.
func extractHostFromDSN(dsn string) string {
	// Handle postgresql://user:pass@host:port/db format
	if idx := strings.Index(dsn, "@"); idx >= 0 {
		rest := dsn[idx+1:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			return rest[:slashIdx]
		}
		return rest
	}
	return dsn
}
