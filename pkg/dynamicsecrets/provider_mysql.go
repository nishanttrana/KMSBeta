package dynamicsecrets

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	mysqlPasswordLen   = 32
	mysqlPasswordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
)

// MySQLProviderConfig configures the MySQL dynamic credentials provider.
type MySQLProviderConfig struct {
	AdminDSN string   // DSN with admin privileges (user:pass@tcp(host:port)/db)
	Grants   []string // e.g. ["SELECT", "INSERT", "UPDATE"]
	Database string   // target database to grant on
}

// MySQLProvider generates ephemeral MySQL credentials.
type MySQLProvider struct {
	adminDSN string
	grants   []string
	database string
}

// NewMySQLProvider creates a provider that manages dynamic MySQL users.
func NewMySQLProvider(cfg MySQLProviderConfig) (*MySQLProvider, error) {
	if cfg.AdminDSN == "" {
		return nil, fmt.Errorf("dynamicsecrets/mysql: admin DSN is required")
	}
	if len(cfg.Grants) == 0 {
		cfg.Grants = []string{"SELECT"}
	}
	if cfg.Database == "" {
		return nil, fmt.Errorf("dynamicsecrets/mysql: database name is required")
	}
	return &MySQLProvider{
		adminDSN: cfg.AdminDSN,
		grants:   cfg.Grants,
		database: cfg.Database,
	}, nil
}

func (p *MySQLProvider) Generate(ctx context.Context, req LeaseRequest) (*Credential, error) {
	password, err := generateSecurePassword(mysqlPasswordLen, mysqlPasswordChars)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/mysql: generate password: %w", err)
	}

	userName := fmt.Sprintf("v_dyn_%s_%s", sanitizeIdentifier(req.Role), randomHex(6))
	// MySQL username max length is 32 chars; truncate if needed
	if len(userName) > 32 {
		userName = userName[:32]
	}
	expiresAt := time.Now().Add(req.TTL)

	db, err := sql.Open("mysql", p.adminDSN)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/mysql: open admin conn: %w", err)
	}
	defer db.Close()

	// Create the user
	createSQL := fmt.Sprintf(
		"CREATE USER '%s'@'%%' IDENTIFIED BY '%s'",
		escapeMySQL(userName),
		escapeMySQL(password),
	)
	if _, err := db.ExecContext(ctx, createSQL); err != nil {
		return nil, fmt.Errorf("dynamicsecrets/mysql: create user: %w", err)
	}

	// Grant privileges on the target database
	grants := strings.Join(p.grants, ", ")
	grantSQL := fmt.Sprintf(
		"GRANT %s ON `%s`.* TO '%s'@'%%'",
		grants,
		escapeMySQL(p.database),
		escapeMySQL(userName),
	)
	if _, err := db.ExecContext(ctx, grantSQL); err != nil {
		// Best-effort cleanup
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", escapeMySQL(userName)))
		return nil, fmt.Errorf("dynamicsecrets/mysql: grant privileges: %w", err)
	}

	credID := "mysqlcred_" + randomHex(16)
	leaseID := "mysqllease_" + randomHex(16)
	endpoint := extractMySQLHost(p.adminDSN)

	return &Credential{
		ID:        credID,
		TenantID:  req.TenantID,
		Provider:  "mysql",
		Username:  userName,
		Password:  password,
		Endpoint:  endpoint,
		ExpiresAt: expiresAt,
		LeaseID:   leaseID,
	}, nil
}

func (p *MySQLProvider) Revoke(ctx context.Context, credentialID string) error {
	db, err := sql.Open("mysql", p.adminDSN)
	if err != nil {
		return fmt.Errorf("dynamicsecrets/mysql: open admin conn for revoke: %w", err)
	}
	defer db.Close()

	return p.RevokeByUsername(ctx, db, credentialID)
}

// RevokeByUsername drops a MySQL user by name.
func (p *MySQLProvider) RevokeByUsername(ctx context.Context, db *sql.DB, username string) error {
	dropSQL := fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%'", escapeMySQL(username))
	if _, err := db.ExecContext(ctx, dropSQL); err != nil {
		return fmt.Errorf("dynamicsecrets/mysql: drop user %q: %w", username, err)
	}
	return nil
}

// escapeMySQL escapes single quotes and backslashes for MySQL string literals.
func escapeMySQL(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

// extractMySQLHost pulls the host:port from a MySQL DSN (user:pass@tcp(host:port)/db).
func extractMySQLHost(dsn string) string {
	if idx := strings.Index(dsn, "tcp("); idx >= 0 {
		rest := dsn[idx+4:]
		if end := strings.Index(rest, ")"); end >= 0 {
			return rest[:end]
		}
	}
	return dsn
}
