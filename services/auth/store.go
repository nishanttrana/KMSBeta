package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateTenant(ctx context.Context, t Tenant) error
	ListTenants(ctx context.Context) ([]Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (Tenant, error)
	UpdateTenant(ctx context.Context, t Tenant) error

	CreateTenantRole(ctx context.Context, role TenantRole) error
	UpdateTenantRole(ctx context.Context, role TenantRole) error
	DeleteTenantRole(ctx context.Context, tenantID string, roleName string) error
	GetRolePermissions(ctx context.Context, tenantID string, roleName string) ([]string, error)

	CreateUser(ctx context.Context, u User) error
	GetUserByUsername(ctx context.Context, tenantID string, username string) (User, error)
	GetUserByID(ctx context.Context, tenantID string, userID string) (User, error)
	ListUsers(ctx context.Context, tenantID string) ([]User, error)
	UpdateUserRole(ctx context.Context, tenantID string, userID string, role string) error
	UpdateUserStatus(ctx context.Context, tenantID string, userID string, status string) error
	UpdateUserPassword(ctx context.Context, tenantID string, userID string, pwdHash []byte, mustChangePassword bool) error

	CreateClientRegistration(ctx context.Context, reg ClientRegistration) error
	GetClientRegistration(ctx context.Context, tenantID string, registrationID string) (ClientRegistration, error)
	ListClientRegistrations(ctx context.Context, tenantID string) ([]ClientRegistration, error)
	UpdateClientRegistrationSettings(ctx context.Context, tenantID string, registrationID string, whitelist []string, rateLimit int) error
	ActivateClientRegistration(ctx context.Context, tenantID string, registrationID string, apiKey APIKey, approver string, approvalID string) error
	RevokeClientRegistration(ctx context.Context, tenantID string, registrationID string) error
	RotateClientAPIKey(ctx context.Context, tenantID string, registrationID string, keyHash []byte, keyPrefix string) error

	CreateAPIKey(ctx context.Context, k APIKey) error
	DeleteAPIKey(ctx context.Context, tenantID string, keyID string) error

	CreateSession(ctx context.Context, s Session) error
	DeleteSession(ctx context.Context, tenantID string, sessionID string) error

	GetPasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error)
	UpsertPasswordPolicy(ctx context.Context, policy PasswordPolicy) (PasswordPolicy, error)
	GetSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error)
	UpsertSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type TenantRole struct {
	TenantID    string   `json:"tenant_id"`
	RoleName    string   `json:"role_name"`
	Permissions []string `json:"permissions"`
}

type User struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	Password           []byte    `json:"-"`
	TOTPSecret         []byte    `json:"-"`
	Role               string    `json:"role"`
	Status             string    `json:"status"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}

type ClientRegistration struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ClientName    string    `json:"client_name"`
	ClientType    string    `json:"client_type"`
	Description   string    `json:"description"`
	ContactEmail  string    `json:"contact_email"`
	RequestedRole string    `json:"requested_role"`
	Status        string    `json:"status"`
	ApprovalID    string    `json:"approval_id"`
	IPWhitelist   []string  `json:"ip_whitelist"`
	RateLimit     int       `json:"rate_limit"`
	APIKeyPrefix  string    `json:"api_key_prefix"`
	ApprovedAt    time.Time `json:"approved_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type APIKey struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	UserID      string     `json:"user_id"`
	ClientID    string     `json:"client_id"`
	KeyHash     []byte     `json:"-"`
	KeyPrefix   string     `json:"api_key_prefix"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	TokenHash []byte    `json:"-"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type PasswordPolicy struct {
	TenantID       string    `json:"tenant_id"`
	MinLength      int       `json:"min_length"`
	MaxLength      int       `json:"max_length"`
	RequireUpper   bool      `json:"require_upper"`
	RequireLower   bool      `json:"require_lower"`
	RequireDigit   bool      `json:"require_digit"`
	RequireSpecial bool      `json:"require_special"`
	RequireNoSpace bool      `json:"require_no_whitespace"`
	DenyUsername   bool      `json:"deny_username"`
	DenyEmailLocal bool      `json:"deny_email_local_part"`
	MinUniqueChars int       `json:"min_unique_chars"`
	UpdatedBy      string    `json:"updated_by"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SecurityPolicy struct {
	TenantID           string    `json:"tenant_id"`
	MaxFailedAttempts  int       `json:"max_failed_attempts"`
	LockoutMinutes     int       `json:"lockout_minutes"`
	IdleTimeoutMinutes int       `json:"idle_timeout_minutes"`
	UpdatedBy          string    `json:"updated_by"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (s *SQLStore) CreateTenant(ctx context.Context, t Tenant) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_tenants (id, name, status, created_at, updated_at)
VALUES ($1,$2,$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, t.ID, t.Name, t.Status)
	return err
}

func (s *SQLStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT id,name,status,created_at FROM auth_tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Status, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var t Tenant
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id,name,status,created_at FROM auth_tenants WHERE id=$1
`, tenantID).Scan(&t.ID, &t.Name, &t.Status, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, errNotFound
	}
	return t, err
}

func (s *SQLStore) UpdateTenant(ctx context.Context, t Tenant) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_tenants SET name=$1, status=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3
`, t.Name, t.Status, t.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateTenantRole(ctx context.Context, role TenantRole) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_tenant_roles (tenant_id, role_name, permissions, created_at, updated_at)
VALUES ($1,$2,$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, role.TenantID, role.RoleName, perms)
	return err
}

func (s *SQLStore) UpdateTenantRole(ctx context.Context, role TenantRole) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_tenant_roles SET permissions=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND role_name=$3
`, perms, role.TenantID, role.RoleName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteTenantRole(ctx context.Context, tenantID string, roleName string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM auth_tenant_roles WHERE tenant_id=$1 AND role_name=$2
`, tenantID, roleName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetRolePermissions(ctx context.Context, tenantID string, roleName string) ([]string, error) {
	var raw []byte
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT permissions FROM auth_tenant_roles
WHERE tenant_id=$1 AND role_name=$2
`, tenantID, roleName).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

func (s *SQLStore) CreateUser(ctx context.Context, u User) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_users (
    id, tenant_id, username, email, pwd_hash, totp_secret, role, status, must_change_password, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, u.ID, u.TenantID, u.Username, u.Email, u.Password, nullableBytes(u.TOTPSecret), u.Role, u.Status, u.MustChangePassword)
	return err
}

func (s *SQLStore) GetUserByUsername(ctx context.Context, tenantID string, username string) (User, error) {
	var u User
	var totp sql.NullString
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, username, email, pwd_hash, totp_secret, role, status, must_change_password, created_at
FROM auth_users
WHERE tenant_id=$1 AND username=$2
`, tenantID, username).Scan(
		&u.ID, &u.TenantID, &u.Username, &u.Email, &u.Password, &totp, &u.Role, &u.Status, &u.MustChangePassword, &u.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, errNotFound
	}
	if err != nil {
		return User{}, err
	}
	if totp.Valid {
		u.TOTPSecret = []byte(totp.String)
	}
	return u, nil
}

func (s *SQLStore) GetUserByID(ctx context.Context, tenantID string, userID string) (User, error) {
	var u User
	var totp sql.NullString
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, username, email, pwd_hash, totp_secret, role, status, must_change_password, created_at
FROM auth_users
WHERE tenant_id=$1 AND id=$2
`, tenantID, userID).Scan(
		&u.ID, &u.TenantID, &u.Username, &u.Email, &u.Password, &totp, &u.Role, &u.Status, &u.MustChangePassword, &u.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, errNotFound
	}
	if err != nil {
		return User{}, err
	}
	if totp.Valid {
		u.TOTPSecret = []byte(totp.String)
	}
	return u, nil
}

func (s *SQLStore) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, username, email, role, status, must_change_password, created_at
FROM auth_users
WHERE tenant_id=$1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.Role, &u.Status, &u.MustChangePassword, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateUserRole(ctx context.Context, tenantID string, userID string, role string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_users SET role=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, role, tenantID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateUserStatus(ctx context.Context, tenantID string, userID string, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_users SET status=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, status, tenantID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateUserPassword(ctx context.Context, tenantID string, userID string, pwdHash []byte, mustChangePassword bool) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_users SET pwd_hash=$1, must_change_password=$2, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, pwdHash, mustChangePassword, tenantID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateClientRegistration(ctx context.Context, reg ClientRegistration) error {
	wl, err := json.Marshal(reg.IPWhitelist)
	if err != nil {
		return err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_client_registrations (
    id, tenant_id, client_name, client_type, description, contact_email, requested_role,
    status, approval_id, ip_whitelist, rate_limit, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP)
`, reg.ID, reg.TenantID, reg.ClientName, reg.ClientType, reg.Description, reg.ContactEmail, reg.RequestedRole, reg.Status, reg.ApprovalID, wl, reg.RateLimit)
	return err
}

func (s *SQLStore) GetClientRegistration(ctx context.Context, tenantID string, registrationID string) (ClientRegistration, error) {
	var reg ClientRegistration
	var raw []byte
	var approvedAt sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, client_name, client_type, description, contact_email, requested_role,
       status, approval_id, ip_whitelist, rate_limit, api_key_prefix, approved_at, created_at
FROM auth_client_registrations
WHERE tenant_id=$1 AND id=$2
`, tenantID, registrationID).Scan(
		&reg.ID, &reg.TenantID, &reg.ClientName, &reg.ClientType, &reg.Description, &reg.ContactEmail, &reg.RequestedRole,
		&reg.Status, &reg.ApprovalID, &raw, &reg.RateLimit, &reg.APIKeyPrefix, &approvedAt, &reg.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientRegistration{}, errNotFound
	}
	if err != nil {
		return ClientRegistration{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &reg.IPWhitelist); err != nil {
			return ClientRegistration{}, err
		}
	}
	if approvedAt.Valid {
		reg.ApprovedAt = approvedAt.Time
	}
	return reg, nil
}

func (s *SQLStore) ListClientRegistrations(ctx context.Context, tenantID string) ([]ClientRegistration, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, client_name, client_type, description, contact_email, requested_role,
       status, approval_id, ip_whitelist, rate_limit, api_key_prefix, created_at
FROM auth_client_registrations
WHERE tenant_id=$1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ClientRegistration
	for rows.Next() {
		var reg ClientRegistration
		var raw []byte
		if err := rows.Scan(
			&reg.ID, &reg.TenantID, &reg.ClientName, &reg.ClientType, &reg.Description, &reg.ContactEmail, &reg.RequestedRole,
			&reg.Status, &reg.ApprovalID, &raw, &reg.RateLimit, &reg.APIKeyPrefix, &reg.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &reg.IPWhitelist); err != nil {
				return nil, err
			}
		}
		out = append(out, reg)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateClientRegistrationSettings(ctx context.Context, tenantID string, registrationID string, whitelist []string, rateLimit int) error {
	wl, err := json.Marshal(whitelist)
	if err != nil {
		return err
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_client_registrations
SET ip_whitelist=$1, rate_limit=$2
WHERE tenant_id=$3 AND id=$4
`, wl, rateLimit, tenantID, registrationID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ActivateClientRegistration(ctx context.Context, tenantID string, registrationID string, apiKey APIKey, approver string, approvalID string) error {
	if err := s.db.WithTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `
SELECT status FROM auth_client_registrations WHERE tenant_id=$1 AND id=$2
`, tenantID, registrationID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if status != "pending" {
			return fmt.Errorf("registration is %s", status)
		}

		approversJSON, _ := json.Marshal([]string{approver})
		_, err = tx.ExecContext(ctx, `
UPDATE auth_client_registrations
SET status='approved', api_key_hash=$1, api_key_prefix=$2, approved_by=$3, approval_id=$4, approved_at=CURRENT_TIMESTAMP
WHERE tenant_id=$5 AND id=$6
`, apiKey.KeyHash, apiKey.KeyPrefix, approversJSON, approvalID, tenantID, registrationID)
		if err != nil {
			return err
		}

		perms, _ := json.Marshal(apiKey.Permissions)
		_, err = tx.ExecContext(ctx, `
INSERT INTO auth_api_keys (
    id, tenant_id, user_id, client_id, key_hash, name, permissions, expires_at, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
`, apiKey.ID, tenantID, nullableString(apiKey.UserID), registrationID, apiKey.KeyHash, apiKey.Name, perms, apiKey.ExpiresAt)
		return err
	}); err != nil {
		return err
	}
	return nil
}

func (s *SQLStore) RevokeClientRegistration(ctx context.Context, tenantID string, registrationID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_client_registrations SET status='revoked' WHERE tenant_id=$1 AND id=$2
`, tenantID, registrationID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) RotateClientAPIKey(ctx context.Context, tenantID string, registrationID string, keyHash []byte, keyPrefix string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_client_registrations
SET api_key_hash=$1, api_key_prefix=$2, last_used=NULL
WHERE tenant_id=$3 AND id=$4
`, keyHash, keyPrefix, tenantID, registrationID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateAPIKey(ctx context.Context, k APIKey) error {
	perms, err := json.Marshal(k.Permissions)
	if err != nil {
		return err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_api_keys (
    id, tenant_id, user_id, client_id, key_hash, name, permissions, expires_at, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
`, k.ID, k.TenantID, nullableString(k.UserID), nullableString(k.ClientID), k.KeyHash, k.Name, perms, k.ExpiresAt)
	return err
}

func (s *SQLStore) DeleteAPIKey(ctx context.Context, tenantID string, keyID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM auth_api_keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateSession(ctx context.Context, session Session) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_sessions (
    id, tenant_id, user_id, token_hash, ip_address, user_agent, expires_at, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
`, session.ID, session.TenantID, session.UserID, session.TokenHash, session.IPAddress, session.UserAgent, session.ExpiresAt)
	return err
}

func (s *SQLStore) DeleteSession(ctx context.Context, tenantID string, sessionID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM auth_sessions WHERE tenant_id=$1 AND id=$2
`, tenantID, sessionID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetPasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error) {
	var out PasswordPolicy
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, min_length, max_length, require_upper, require_lower, require_digit,
       require_special, require_no_whitespace, deny_username, deny_email_local_part,
       min_unique_chars, updated_by, updated_at
FROM auth_password_policies
WHERE tenant_id=$1
`, tenantID).Scan(
		&out.TenantID,
		&out.MinLength,
		&out.MaxLength,
		&out.RequireUpper,
		&out.RequireLower,
		&out.RequireDigit,
		&out.RequireSpecial,
		&out.RequireNoSpace,
		&out.DenyUsername,
		&out.DenyEmailLocal,
		&out.MinUniqueChars,
		&out.UpdatedBy,
		&out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PasswordPolicy{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) UpsertPasswordPolicy(ctx context.Context, policy PasswordPolicy) (PasswordPolicy, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_password_policies (
    tenant_id, min_length, max_length, require_upper, require_lower, require_digit,
    require_special, require_no_whitespace, deny_username, deny_email_local_part,
    min_unique_chars, updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_length = EXCLUDED.max_length,
    require_upper = EXCLUDED.require_upper,
    require_lower = EXCLUDED.require_lower,
    require_digit = EXCLUDED.require_digit,
    require_special = EXCLUDED.require_special,
    require_no_whitespace = EXCLUDED.require_no_whitespace,
    deny_username = EXCLUDED.deny_username,
    deny_email_local_part = EXCLUDED.deny_email_local_part,
    min_unique_chars = EXCLUDED.min_unique_chars,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
`, policy.TenantID, policy.MinLength, policy.MaxLength, policy.RequireUpper, policy.RequireLower, policy.RequireDigit, policy.RequireSpecial, policy.RequireNoSpace, policy.DenyUsername, policy.DenyEmailLocal, policy.MinUniqueChars, policy.UpdatedBy)
	if err != nil {
		return PasswordPolicy{}, err
	}
	return s.GetPasswordPolicy(ctx, policy.TenantID)
}

func (s *SQLStore) GetSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error) {
	var out SecurityPolicy
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, max_failed_attempts, lockout_minutes, idle_timeout_minutes, updated_by, updated_at
FROM auth_security_policies
WHERE tenant_id=$1
	`, tenantID).Scan(
		&out.TenantID,
		&out.MaxFailedAttempts,
		&out.LockoutMinutes,
		&out.IdleTimeoutMinutes,
		&out.UpdatedBy,
		&out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityPolicy{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) UpsertSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_security_policies (
    tenant_id, max_failed_attempts, lockout_minutes, idle_timeout_minutes, updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET
    max_failed_attempts = EXCLUDED.max_failed_attempts,
    lockout_minutes = EXCLUDED.lockout_minutes,
    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
`, policy.TenantID, policy.MaxFailedAttempts, policy.LockoutMinutes, policy.IdleTimeoutMinutes, policy.UpdatedBy)
	if err != nil {
		return SecurityPolicy{}, err
	}
	return s.GetSecurityPolicy(ctx, policy.TenantID)
}

func nullableString(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

func nullableBytes(v []byte) interface{} {
	if len(v) == 0 {
		return nil
	}
	return string(v)
}
