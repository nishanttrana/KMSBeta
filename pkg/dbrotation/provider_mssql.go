package dbrotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/microsoft/go-mssqldb"
)

// MSSQLProvider implements DBProvider for Microsoft SQL Server databases.
type MSSQLProvider struct{}

// RotatePassword connects to MSSQL and changes the login password.
func (p *MSSQLProvider) RotatePassword(ctx context.Context, connectionString, username, newPassword string) error {
	db, err := sql.Open("sqlserver", connectionString)
	if err != nil {
		return fmt.Errorf("mssql: open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("mssql: ping: %w", err)
	}

	if !isValidIdentifier(username) {
		return fmt.Errorf("mssql: invalid username %q", username)
	}

	// ALTER LOGIN to change the password using N'' for Unicode string
	query := fmt.Sprintf("ALTER LOGIN [%s] WITH PASSWORD = N'%s'",
		escapeMSSQLIdentifier(username), escapeMSSQLString(newPassword))
	_, err = db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("mssql: alter login: %w", err)
	}

	return nil
}

// ValidateConnection verifies credentials work against MSSQL.
func (p *MSSQLProvider) ValidateConnection(ctx context.Context, connectionString, username, password string) error {
	dsn := buildMSSQLDSN(connectionString, username, password)

	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return fmt.Errorf("mssql: validate open: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("mssql: validate ping: %w", err)
	}
	return nil
}

// RevokePassword is a no-op for MSSQL. The old password is replaced on rotation.
func (p *MSSQLProvider) RevokePassword(ctx context.Context, connectionString, username, oldPassword string) error {
	return nil
}

// buildMSSQLDSN constructs an MSSQL connection string with the given user and password.
// MSSQL uses URL format: sqlserver://user:password@host:port?database=dbname
func buildMSSQLDSN(baseConnStr, username, password string) string {
	if strings.HasPrefix(baseConnStr, "sqlserver://") {
		prefix := "sqlserver://"
		rest := baseConnStr[len(prefix):]

		// Strip existing credentials
		if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
			rest = rest[atIdx+1:]
		}
		return fmt.Sprintf("%s%s:%s@%s", prefix, username, password, rest)
	}

	// Key-value format: server=host;user id=user;password=pass;database=db
	parts := strings.Split(baseConnStr, ";")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		lower := strings.ToLower(strings.TrimSpace(part))
		if strings.HasPrefix(lower, "user id=") || strings.HasPrefix(lower, "password=") {
			continue
		}
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	filtered = append(filtered, fmt.Sprintf("user id=%s", username))
	filtered = append(filtered, fmt.Sprintf("password=%s", password))
	return strings.Join(filtered, ";")
}

// escapeMSSQLIdentifier escapes characters for bracket-quoted identifiers.
func escapeMSSQLIdentifier(s string) string {
	return strings.ReplaceAll(s, "]", "]]")
}

// escapeMSSQLString escapes single quotes in MSSQL string literals.
func escapeMSSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
