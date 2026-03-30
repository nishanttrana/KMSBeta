package dbrotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// MySQLProvider implements DBProvider for MySQL databases.
type MySQLProvider struct{}

// RotatePassword connects to MySQL and changes the user's password.
func (p *MySQLProvider) RotatePassword(ctx context.Context, connectionString, username, newPassword string) error {
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return fmt.Errorf("mysql: open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("mysql: ping: %w", err)
	}

	if !isValidIdentifier(username) {
		return fmt.Errorf("mysql: invalid username %q", username)
	}

	// ALTER USER to change the password
	query := fmt.Sprintf("ALTER USER '%s'@'%%' IDENTIFIED BY '%s'",
		escapeMySQLString(username), escapeMySQLString(newPassword))
	_, err = db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("mysql: alter user: %w", err)
	}

	// Flush privileges to ensure the change takes effect immediately
	_, err = db.ExecContext(ctx, "FLUSH PRIVILEGES")
	if err != nil {
		return fmt.Errorf("mysql: flush privileges: %w", err)
	}

	return nil
}

// ValidateConnection verifies that the given credentials can connect and ping MySQL.
func (p *MySQLProvider) ValidateConnection(ctx context.Context, connectionString, username, password string) error {
	dsn := buildMySQLDSN(connectionString, username, password)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("mysql: validate open: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("mysql: validate ping: %w", err)
	}
	return nil
}

// RevokePassword is a no-op for MySQL. The old password is replaced on rotation.
func (p *MySQLProvider) RevokePassword(ctx context.Context, connectionString, username, oldPassword string) error {
	return nil
}

// buildMySQLDSN constructs a MySQL DSN with the specified user and password.
// MySQL DSN format: user:password@tcp(host:port)/dbname
func buildMySQLDSN(baseConnStr, username, password string) string {
	// If the DSN has a @ separator, strip existing credentials
	if atIdx := strings.Index(baseConnStr, "@"); atIdx >= 0 {
		hostPart := baseConnStr[atIdx:]
		return fmt.Sprintf("%s:%s%s", username, password, hostPart)
	}
	// If no credentials present, prepend them
	return fmt.Sprintf("%s:%s@%s", username, password, baseConnStr)
}

// escapeMySQLString escapes single quotes and backslashes for MySQL string literals.
func escapeMySQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", `\'`)
	return s
}
