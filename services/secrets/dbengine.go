package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/ssrfguard"
)

// Dynamic database credentials (13.34.0-beta). A role names a customer
// PostgreSQL database by its admin credential (type "database" in
// Playbooks → Credentials) and the SQL that creates and drops a login. Each
// request makes a new login with a random name and password, valid until
// its lease ends; the password is returned once and never stored. A lease
// is renewed up to the role's maximum and revoked on request or by the
// expiry sweep, which runs the revocation statements.
//
// Statements are templates. Placeholders are filled only with values the
// KMS generates, each quoted for its position:
//
//	{{name}}        the login, as a quoted identifier ("v_app_x2k...")
//	{{username}}    the login, as a string literal
//	{{password}}    the password, as a string literal
//	{{expiration}}  the lease end, as a timestamptz literal
//
// Every connection is TLS with the server's certificate and host verified
// (sslmode verify-full), dialled through pkg/ssrfguard with the credential's
// approved private ranges.

const (
	dbEngine           = "postgres"
	dbMinTTL           = 60 * time.Second
	dbMaxTTL           = 30 * 24 * time.Hour
	dbStatementTimeout = 15 * time.Second
)

var (
	dbRoleNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	dbPlaceholderRe = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)
	dbPlaceholders  = map[string]bool{"name": true, "username": true, "password": true, "expiration": true}
)

// Defaults a role starts from: a read-only login on the public schema.
var (
	defaultCreation = []string{
		`CREATE ROLE {{name}} WITH LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}};`,
		`GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};`,
	}
	defaultRevocation = []string{
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = {{username}};`,
		`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{name}};`,
		`DROP ROLE IF EXISTS {{name}};`,
	}
)

type DBRole struct {
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	ConnectionID         string    `json:"connection_id"`
	Engine               string    `json:"engine"`
	CreationStatements   []string  `json:"creation_statements"`
	RevocationStatements []string  `json:"revocation_statements"`
	DefaultTTLSeconds    int       `json:"default_ttl_seconds"`
	MaxTTLSeconds        int       `json:"max_ttl_seconds"`
	CreatedBy            string    `json:"created_by"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type DBLease struct {
	TenantID     string     `json:"tenant_id"`
	ID           string     `json:"id"`
	RoleName     string     `json:"role_name"`
	Username     string     `json:"username"`
	State        string     `json:"state"` // active, revoked, expired, revoke_failed
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	MaxExpiresAt time.Time  `json:"max_expires_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
}

// checkStatements validates a role's templates: only known placeholders, and
// a creation template that names the login and sets its password.
func checkStatements(creation, revocation []string) error {
	if len(creation) == 0 || len(revocation) == 0 {
		return errors.New("creation_statements and revocation_statements are required")
	}
	for _, list := range [][]string{creation, revocation} {
		for _, st := range list {
			if strings.TrimSpace(st) == "" {
				return errors.New("a statement is empty")
			}
			for _, m := range dbPlaceholderRe.FindAllStringSubmatch(st, -1) {
				if !dbPlaceholders[m[1]] {
					return fmt.Errorf("unknown placeholder {{%s}}", m[1])
				}
			}
			if strings.Count(st, "{{") != len(dbPlaceholderRe.FindAllString(st, -1)) {
				return errors.New("a statement has an unclosed placeholder")
			}
		}
	}
	joined := strings.Join(creation, "\n")
	if !strings.Contains(joined, "{{name}}") || !strings.Contains(joined, "{{password}}") {
		return errors.New("creation_statements must create {{name}} with {{password}}")
	}
	if !strings.Contains(strings.Join(revocation, "\n"), "{{name}}") && !strings.Contains(strings.Join(revocation, "\n"), "{{username}}") {
		return errors.New("revocation_statements must name the login")
	}
	return nil
}

// quoteIdent and quoteLiteral are PostgreSQL's quoting. The values are
// generated here ([a-z0-9_] names, base-62 passwords), so quoting is a
// second guard, not the only one.
func quoteIdent(s string) string   { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func quoteLiteral(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

func render(st, username, password string, expires time.Time) string {
	return dbPlaceholderRe.ReplaceAllStringFunc(st, func(m string) string {
		switch dbPlaceholderRe.FindStringSubmatch(m)[1] {
		case "name":
			return quoteIdent(username)
		case "username":
			return quoteLiteral(username)
		case "password":
			return quoteLiteral(password)
		case "expiration":
			return quoteLiteral(expires.UTC().Format("2006-01-02 15:04:05Z"))
		}
		return m
	})
}

const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randomFrom draws n characters uniformly from alphabet with the module's RNG.
func randomFrom(alphabet string, n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := pkgcrypto.RandomInt(max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

// newLogin makes a login name (v_<role>_<10 random>, at most 63 bytes, the
// PostgreSQL limit) and a 32-character password.
func newLogin(role string) (string, string, error) {
	r := strings.ReplaceAll(role, "-", "_")
	if len(r) > 40 {
		r = r[:40]
	}
	suffix, err := randomFrom("abcdefghijklmnopqrstuvwxyz0123456789", 10)
	if err != nil {
		return "", "", err
	}
	password, err := randomFrom(base62, 32)
	if err != nil {
		return "", "", err
	}
	return "v_" + r + "_" + suffix, password, nil
}

// dbTarget is a database credential's connection settings.
type dbTarget struct {
	Host, Port, Database, User, Password, CAPEM string
	PrivateRanges                               []string
}

func targetFrom(c credstore.Credential) (dbTarget, error) {
	if c.Type != "database" {
		return dbTarget{}, fmt.Errorf("credential %s is %s, not database", c.ID, c.Type)
	}
	t := dbTarget{
		Host: strings.TrimSpace(c.Fields["host"]), Port: strings.TrimSpace(c.Fields["port"]), Database: strings.TrimSpace(c.Fields["database"]),
		User: strings.TrimSpace(c.Fields["username"]), Password: c.Fields["password"], CAPEM: c.Fields["ca_pem"], PrivateRanges: c.PrivateRanges,
	}
	if t.Port == "" {
		t.Port = "5432"
	}
	if t.Host == "" || t.Database == "" || t.User == "" {
		return dbTarget{}, errors.New("the database credential needs host, database and username")
	}
	return t, nil
}

// pgConfig is the connection: verify-full TLS, ssrf-guarded dial.
func pgConfig(t dbTarget) (*pgx.ConnConfig, error) {
	port, err := strconv.Atoi(t.Port)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("port must be 1 to 65535")
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = t.Host, uint16(port), t.Database, t.User, t.Password
	cfg.ConnectTimeout = 10 * time.Second
	tlsCfg := &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(t.CAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(t.CAPEM)) {
			return nil, errors.New("ca_pem holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	cfg.TLSConfig = tlsCfg
	cfg.Fallbacks = nil // no plaintext retry
	allow, err := ssrfguard.ParseAllow(t.PrivateRanges)
	if err != nil {
		return nil, err
	}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return allow.DialContext(ctx, network, addr)
	}
	return cfg, nil
}

// connectDB opens a connection to the role's database. Tests replace it to
// reach a test server without TLS (dbengine_postgres_test.go).
var connectDB = func(ctx context.Context, t dbTarget) (*pgx.Conn, error) {
	cfg, err := pgConfig(t)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func (h *Handler) openTarget(ctx context.Context, tenantID, connectionID string) (*pgx.Conn, error) {
	if h.creds == nil {
		return nil, credstore.ErrNotDeployed
	}
	c, err := h.creds.Resolve(ctx, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	t, err := targetFrom(c)
	if err != nil {
		return nil, err
	}
	return connectDB(ctx, t)
}

// runStatements executes rendered statements in one transaction.
func runStatements(ctx context.Context, conn *pgx.Conn, statements []string, username, password string, expires time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, dbStatementTimeout)
	defer cancel()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for i, st := range statements {
		if _, err := tx.Exec(ctx, render(st, username, password, expires)); err != nil {
			// The error names the statement's position, never its text: the
			// rendered text holds the password.
			return fmt.Errorf("statement %d: %s", i+1, pgError(err))
		}
	}
	return tx.Commit(ctx)
}

// pgError is the server's message without the statement.
func pgError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, " (SQLSTATE"); i > 0 {
		return msg[:i]
	}
	return msg
}

func ttlWithin(requested, def, max int) (time.Duration, error) {
	ttl := time.Duration(def) * time.Second
	if requested > 0 {
		ttl = time.Duration(requested) * time.Second
	}
	if ttl < dbMinTTL || ttl > time.Duration(max)*time.Second {
		return 0, fmt.Errorf("ttl must be %d to %d seconds", int(dbMinTTL.Seconds()), max)
	}
	return ttl, nil
}

var errLeaseNotFound = errors.New("lease not found")

// issue creates a login for role and records its lease.
func (h *Handler) issue(ctx context.Context, tenantID string, role DBRole, ttlSeconds int, actor string) (DBLease, string, error) {
	ttl, err := ttlWithin(ttlSeconds, role.DefaultTTLSeconds, role.MaxTTLSeconds)
	if err != nil {
		return DBLease{}, "", errBadRequest(err.Error())
	}
	username, password, err := newLogin(role.Name)
	if err != nil {
		return DBLease{}, "", err
	}
	now := time.Now().UTC().Truncate(time.Second)
	lease := DBLease{
		TenantID: tenantID, RoleName: role.Name, Username: username, State: "active", CreatedBy: actor, CreatedAt: now,
		ExpiresAt: now.Add(ttl), MaxExpiresAt: now.Add(time.Duration(role.MaxTTLSeconds) * time.Second),
	}
	if lease.ID, err = randomFrom("abcdefghijklmnopqrstuvwxyz0123456789", 20); err != nil {
		return DBLease{}, "", err
	}
	lease.ID = "dbl_" + lease.ID
	conn, err := h.openTarget(ctx, tenantID, role.ConnectionID)
	if err != nil {
		return DBLease{}, "", errUnavailable("the database could not be reached: " + err.Error())
	}
	defer conn.Close(context.Background()) //nolint:errcheck
	if err := runStatements(ctx, conn, role.CreationStatements, username, password, lease.ExpiresAt); err != nil {
		return DBLease{}, "", errUnavailable("creating the login failed: " + err.Error())
	}
	if err := h.svc.store.CreateDBLease(ctx, lease); err != nil {
		// The login exists but has no lease: drop it now rather than leave
		// an untracked account behind.
		_ = runStatements(ctx, conn, role.RevocationStatements, username, "", lease.ExpiresAt)
		return DBLease{}, "", err
	}
	return lease, password, nil
}

// renew extends a lease, never past its maximum, and moves the login's
// expiry with it.
func (h *Handler) renew(ctx context.Context, tenantID, leaseID string, incrementSeconds int) (DBLease, error) {
	lease, err := h.svc.store.GetDBLease(ctx, tenantID, leaseID)
	if err != nil {
		return DBLease{}, err
	}
	if lease.State != "active" {
		return DBLease{}, errConflict("the lease is " + lease.State)
	}
	role, err := h.svc.store.GetDBRole(ctx, tenantID, lease.RoleName)
	if err != nil {
		return DBLease{}, err
	}
	inc := time.Duration(role.DefaultTTLSeconds) * time.Second
	if incrementSeconds > 0 {
		inc = time.Duration(incrementSeconds) * time.Second
	}
	next := time.Now().UTC().Truncate(time.Second).Add(inc)
	if next.After(lease.MaxExpiresAt) {
		next = lease.MaxExpiresAt
	}
	if !next.After(lease.ExpiresAt) {
		return DBLease{}, errConflict("the lease is at its maximum")
	}
	conn, err := h.openTarget(ctx, tenantID, role.ConnectionID)
	if err != nil {
		return DBLease{}, errUnavailable("the database could not be reached: " + err.Error())
	}
	defer conn.Close(context.Background()) //nolint:errcheck
	st := []string{`ALTER ROLE {{name}} VALID UNTIL {{expiration}};`}
	if err := runStatements(ctx, conn, st, lease.Username, "", next); err != nil {
		return DBLease{}, errUnavailable("extending the login failed: " + err.Error())
	}
	if err := h.svc.store.SetDBLeaseExpiry(ctx, tenantID, leaseID, next); err != nil {
		return DBLease{}, err
	}
	lease.ExpiresAt = next
	return lease, nil
}

// revoke drops the lease's login and ends the lease (state revoked, or
// expired from the sweep). A failure is recorded and retried by the sweep.
func (h *Handler) revoke(ctx context.Context, lease DBLease, endState string) (DBLease, error) {
	role, err := h.svc.store.GetDBRole(ctx, lease.TenantID, lease.RoleName)
	if err == nil {
		var conn *pgx.Conn
		if conn, err = h.openTarget(ctx, lease.TenantID, role.ConnectionID); err == nil {
			err = runStatements(ctx, conn, role.RevocationStatements, lease.Username, "", lease.ExpiresAt)
			conn.Close(context.Background()) //nolint:errcheck
		}
	}
	if err != nil {
		_ = h.svc.store.EndDBLease(ctx, lease.TenantID, lease.ID, "revoke_failed", err.Error(), nil)
		lease.State, lease.LastError = "revoke_failed", err.Error()
		return lease, errUnavailable("dropping the login failed: " + err.Error())
	}
	now := time.Now().UTC()
	if err := h.svc.store.EndDBLease(ctx, lease.TenantID, lease.ID, endState, "", &now); err != nil {
		return DBLease{}, err
	}
	lease.State, lease.EndedAt, lease.LastError = endState, &now, ""
	return lease, nil
}

// errBadRequest, errConflict and errUnavailable carry an HTTP status for
// the route.
type dbError struct {
	status int
	code   string
	msg    string
}

func (e dbError) Error() string       { return e.msg }
func errBadRequest(msg string) error  { return dbError{400, "bad_request", msg} }
func errConflict(msg string) error    { return dbError{409, "conflict", msg} }
func errUnavailable(msg string) error { return dbError{502, "database_unavailable", msg} }
