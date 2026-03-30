package dbrotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/sijms/go-ora/v2"
)

// OracleProvider implements DBProvider for Oracle databases.
type OracleProvider struct{}

// RotatePassword connects to Oracle and changes the user's password.
func (p *OracleProvider) RotatePassword(ctx context.Context, connectionString, username, newPassword string) error {
	db, err := sql.Open("oracle", connectionString)
	if err != nil {
		return fmt.Errorf("oracle: open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("oracle: ping: %w", err)
	}

	if !isValidIdentifier(username) {
		return fmt.Errorf("oracle: invalid username %q", username)
	}

	// ALTER USER to change the password (double-quoted password for special chars)
	query := fmt.Sprintf(`ALTER USER %s IDENTIFIED BY "%s"`,
		strings.ToUpper(username), escapeOracleString(newPassword))
	_, err = db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("oracle: alter user: %w", err)
	}

	return nil
}

// ValidateConnection verifies that the given credentials can connect to Oracle.
func (p *OracleProvider) ValidateConnection(ctx context.Context, connectionString, username, password string) error {
	dsn := buildOracleDSN(connectionString, username, password)

	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return fmt.Errorf("oracle: validate open: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("oracle: validate ping: %w", err)
	}
	return nil
}

// RevokePassword is a no-op for Oracle. The old password is replaced by the ALTER USER command.
func (p *OracleProvider) RevokePassword(ctx context.Context, connectionString, username, oldPassword string) error {
	return nil
}

// buildOracleDSN constructs an Oracle connection string with the given user and password.
// Oracle go-ora uses: oracle://user:password@host:port/service_name
func buildOracleDSN(baseConnStr, username, password string) string {
	if strings.HasPrefix(baseConnStr, "oracle://") {
		prefix := "oracle://"
		rest := baseConnStr[len(prefix):]

		// Strip existing credentials
		if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
			rest = rest[atIdx+1:]
		}
		return fmt.Sprintf("%s%s:%s@%s", prefix, username, password, rest)
	}

	// If it's just host:port/service, prepend credentials
	return fmt.Sprintf("oracle://%s:%s@%s", username, password, baseConnStr)
}

// escapeOracleString escapes double quotes in Oracle password strings.
func escapeOracleString(s string) string {
	return strings.ReplaceAll(s, `"`, `""`)
}
