package dbrotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresProvider implements DBProvider for PostgreSQL databases.
type PostgresProvider struct{}

// RotatePassword connects to PostgreSQL with admin credentials and changes the user's password.
func (p *PostgresProvider) RotatePassword(ctx context.Context, connectionString, username, newPassword string) error {
	db, err := sql.Open("pgx", connectionString)
	if err != nil {
		return fmt.Errorf("postgres: open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}

	// Sanitize username to prevent SQL injection (only allow alphanumeric and underscore)
	if !isValidIdentifier(username) {
		return fmt.Errorf("postgres: invalid username %q", username)
	}

	// Use ALTER ROLE to change the password. The password value is quoted as a string literal.
	query := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD '%s'", quoteIdentifier(username), escapeSQLString(newPassword))
	_, err = db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("postgres: alter role: %w", err)
	}

	return nil
}

// ValidateConnection verifies that the given credentials can connect and ping PostgreSQL.
func (p *PostgresProvider) ValidateConnection(ctx context.Context, connectionString, username, password string) error {
	// Build a DSN with the target user's credentials
	dsn := buildPostgresDSN(connectionString, username, password)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("postgres: validate open: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres: validate ping: %w", err)
	}
	return nil
}

// RevokePassword is a no-op for Postgres. The old password is simply overwritten by the rotation.
func (p *PostgresProvider) RevokePassword(ctx context.Context, connectionString, username, oldPassword string) error {
	// No separate revocation needed; ALTER ROLE already replaced the password
	return nil
}

// buildPostgresDSN constructs a PostgreSQL connection string with specified user and password.
// If the base connection string is a postgresql:// URL, we replace user/password.
// Otherwise we build a keyword=value DSN.
func buildPostgresDSN(baseConnStr, username, password string) string {
	if strings.HasPrefix(baseConnStr, "postgres://") || strings.HasPrefix(baseConnStr, "postgresql://") {
		// Parse and replace credentials in URL form
		// Find the host portion after ://
		prefix := baseConnStr[:strings.Index(baseConnStr, "://")+3]
		rest := baseConnStr[len(prefix):]

		// Strip existing credentials if present
		if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
			rest = rest[atIdx+1:]
		}

		return fmt.Sprintf("%s%s:%s@%s", prefix, username, password, rest)
	}

	// keyword=value format: replace or add user and password
	parts := strings.Fields(baseConnStr)
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.HasPrefix(part, "user=") || strings.HasPrefix(part, "password=") {
			continue
		}
		filtered = append(filtered, part)
	}
	filtered = append(filtered, fmt.Sprintf("user=%s", username))
	filtered = append(filtered, fmt.Sprintf("password=%s", password))
	return strings.Join(filtered, " ")
}

// isValidIdentifier checks that a string contains only safe characters for SQL identifiers.
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

// quoteIdentifier wraps a SQL identifier in double quotes.
func quoteIdentifier(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// escapeSQLString escapes single quotes in a string literal.
func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
