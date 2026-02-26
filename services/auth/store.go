package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateTenant(ctx context.Context, t Tenant) error
	ListTenants(ctx context.Context) ([]Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (Tenant, error)
	UpdateTenant(ctx context.Context, t Tenant) error
	DeleteTenant(ctx context.Context, tenantID string) (TenantDeleteSummary, error)
	GetTenantDeleteReadiness(ctx context.Context, tenantID string) (TenantDeleteReadiness, error)
	DisableTenant(ctx context.Context, tenantID string) (TenantDeleteReadiness, error)
	IsPlatformQuorumRequired(ctx context.Context, tenantID string, action string) (bool, error)
	IsGovernanceRequestApproved(ctx context.Context, tenantID string, requestID string, action string, targetType string, targetID string) (bool, error)
	ListGroupRoleBindings(ctx context.Context, tenantID string) ([]GroupRoleBinding, error)
	UpsertGroupRoleBinding(ctx context.Context, binding GroupRoleBinding) (GroupRoleBinding, error)
	DeleteGroupRoleBinding(ctx context.Context, tenantID string, groupID string) error
	ListGroupRolesForUser(ctx context.Context, tenantID string, userID string) ([]string, error)

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
	GetAPIKeyByHash(ctx context.Context, tenantID string, keyHash []byte) (APIKey, error)

	CreateAPIKey(ctx context.Context, k APIKey) error
	DeleteAPIKey(ctx context.Context, tenantID string, keyID string) error

	CreateSession(ctx context.Context, s Session) error
	DeleteSession(ctx context.Context, tenantID string, sessionID string) error

	GetPasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error)
	UpsertPasswordPolicy(ctx context.Context, policy PasswordPolicy) (PasswordPolicy, error)
	GetSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error)
	UpsertSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error)
	GetHSMProviderConfig(ctx context.Context, tenantID string) (HSMProviderConfig, error)
	UpsertHSMProviderConfig(ctx context.Context, cfg HSMProviderConfig) (HSMProviderConfig, error)
	ListIdentityProviderConfigs(ctx context.Context, tenantID string) ([]IdentityProviderConfig, error)
	GetIdentityProviderConfig(ctx context.Context, tenantID string, provider string) (IdentityProviderConfig, error)
	UpsertIdentityProviderConfig(ctx context.Context, cfg IdentityProviderConfig) (IdentityProviderConfig, error)
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
	InterfaceName string    `json:"interface_name"`
	SubjectID     string    `json:"subject_id"`
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

type HSMProviderConfig struct {
	TenantID           string         `json:"tenant_id"`
	ProviderName       string         `json:"provider_name"`
	IntegrationService string         `json:"integration_service"`
	LibraryPath        string         `json:"library_path"`
	SlotID             string         `json:"slot_id"`
	PartitionLabel     string         `json:"partition_label"`
	TokenLabel         string         `json:"token_label"`
	PINEnvVar          string         `json:"pin_env_var"`
	ReadOnly           bool           `json:"read_only"`
	Enabled            bool           `json:"enabled"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	UpdatedBy          string         `json:"updated_by"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type IdentityProviderConfig struct {
	TenantID  string         `json:"tenant_id"`
	Provider  string         `json:"provider"`
	Enabled   bool           `json:"enabled"`
	Config    map[string]any `json:"config,omitempty"`
	Secrets   map[string]any `json:"secrets,omitempty"`
	UpdatedBy string         `json:"updated_by"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type TenantDeleteSummary struct {
	TenantID       string           `json:"tenant_id"`
	TablesPurged   int              `json:"tables_purged"`
	RowsPurged     int64            `json:"rows_purged"`
	DeletedByTable map[string]int64 `json:"deleted_by_table,omitempty"`
}

type GroupRoleBinding struct {
	TenantID  string    `json:"tenant_id"`
	GroupID   string    `json:"group_id"`
	RoleName  string    `json:"role_name"`
	UpdatedAt time.Time `json:"updated_at"`
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

func (s *SQLStore) DeleteTenant(ctx context.Context, tenantID string) (TenantDeleteSummary, error) {
	summary := TenantDeleteSummary{
		TenantID:       tenantID,
		DeletedByTable: map[string]int64{},
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return summary, errors.New("tenant id is required")
	}

	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return summary, err
	}
	defer tx.Rollback() //nolint:errcheck

	var exists string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM auth_tenants WHERE id=$1`, tenantID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return summary, errNotFound
	} else if err != nil {
		return summary, err
	}

	tables, err := discoverTenantTables(ctx, tx)
	if err != nil {
		return summary, err
	}
	auditTriggerDisabled := []string{}
	for _, table := range tables {
		if !isAuditEventsTable(table) {
			continue
		}
		if disableErr := disableTableUserTriggers(ctx, tx, table); disableErr != nil {
			return summary, disableErr
		}
		auditTriggerDisabled = append(auditTriggerDisabled, table)
	}
	pending := append([]string(nil), tables...)
	for attempts := 0; attempts < len(tables); attempts++ {
		if len(pending) == 0 {
			break
		}
		progress := false
		next := make([]string, 0, len(pending))
		for _, table := range pending {
			stmt := buildTenantDeleteStatement(table)
			res, execErr := tx.ExecContext(ctx, stmt, tenantID)
			if execErr != nil {
				if isForeignKeyDeleteError(execErr) {
					next = append(next, table)
					continue
				}
				return summary, execErr
			}
			n, _ := res.RowsAffected()
			summary.RowsPurged += n
			if n > 0 {
				summary.DeletedByTable[table] += n
			}
			summary.TablesPurged++
			progress = true
		}
		if len(next) == 0 {
			pending = next
			break
		}
		if !progress {
			return summary, fmt.Errorf("tenant purge blocked by relational constraints for tables: %s", strings.Join(next, ", "))
		}
		pending = next
	}
	for _, table := range auditTriggerDisabled {
		if enableErr := enableTableUserTriggers(ctx, tx, table); enableErr != nil {
			return summary, enableErr
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM auth_tenants WHERE id=$1`, tenantID)
	if err != nil {
		return summary, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return summary, errNotFound
	}
	summary.RowsPurged += n
	summary.DeletedByTable["auth_tenants"] += n

	if err := tx.Commit(); err != nil {
		return summary, err
	}
	return summary, nil
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

func (s *SQLStore) ListGroupRoleBindings(ctx context.Context, tenantID string) ([]GroupRoleBinding, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, group_id, role_name, updated_at
FROM auth_group_role_bindings
WHERE tenant_id=$1
ORDER BY group_id
`, tenantID)
	if err != nil {
		if isGroupRoleSchemaMissing(err) {
			return []GroupRoleBinding{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]GroupRoleBinding, 0)
	for rows.Next() {
		var item GroupRoleBinding
		if scanErr := rows.Scan(&item.TenantID, &item.GroupID, &item.RoleName, &item.UpdatedAt); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertGroupRoleBinding(ctx context.Context, binding GroupRoleBinding) (GroupRoleBinding, error) {
	if strings.TrimSpace(binding.TenantID) == "" || strings.TrimSpace(binding.GroupID) == "" || strings.TrimSpace(binding.RoleName) == "" {
		return GroupRoleBinding{}, errors.New("tenant_id, group_id and role_name are required")
	}
	if _, err := s.GetRolePermissions(ctx, binding.TenantID, binding.RoleName); err != nil {
		if errors.Is(err, errNotFound) {
			return GroupRoleBinding{}, fmt.Errorf("role %s is not configured", strings.TrimSpace(binding.RoleName))
		}
		return GroupRoleBinding{}, err
	}
	var out GroupRoleBinding
	err := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO auth_group_role_bindings (tenant_id, group_id, role_name, created_at, updated_at)
VALUES ($1,$2,$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, group_id) DO UPDATE SET
    role_name=EXCLUDED.role_name,
    updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, group_id, role_name, updated_at
`, strings.TrimSpace(binding.TenantID), strings.TrimSpace(binding.GroupID), strings.TrimSpace(binding.RoleName)).
		Scan(&out.TenantID, &out.GroupID, &out.RoleName, &out.UpdatedAt)
	if err != nil {
		if isGroupRoleSchemaMissing(err) {
			return GroupRoleBinding{}, errors.New("group role schema is not initialized")
		}
		return GroupRoleBinding{}, err
	}
	return out, nil
}

func (s *SQLStore) DeleteGroupRoleBinding(ctx context.Context, tenantID string, groupID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM auth_group_role_bindings
WHERE tenant_id=$1 AND group_id=$2
`, tenantID, groupID)
	if err != nil {
		if isGroupRoleSchemaMissing(err) {
			return errNotFound
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListGroupRolesForUser(ctx context.Context, tenantID string, userID string) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT gr.role_name
FROM auth_group_role_bindings gr
JOIN key_access_group_members gm
  ON gm.tenant_id = gr.tenant_id AND gm.group_id = gr.group_id
WHERE gr.tenant_id=$1 AND gm.user_id=$2
ORDER BY gr.role_name
`, tenantID, userID)
	if err != nil {
		if isGroupRoleSchemaMissing(err) || isGroupMembershipSchemaMissing(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]string, 0, 4)
	for rows.Next() {
		var role string
		if scanErr := rows.Scan(&role); scanErr != nil {
			return nil, scanErr
		}
		role = strings.TrimSpace(role)
		if role != "" {
			out = append(out, role)
		}
	}
	return out, rows.Err()
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
    id, tenant_id, client_name, client_type, interface_name, subject_id, description, contact_email, requested_role,
    status, approval_id, ip_whitelist, rate_limit, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP)
`, reg.ID, reg.TenantID, reg.ClientName, reg.ClientType, reg.InterfaceName, reg.SubjectID, reg.Description, reg.ContactEmail, reg.RequestedRole, reg.Status, reg.ApprovalID, wl, reg.RateLimit)
	return err
}

func (s *SQLStore) GetClientRegistration(ctx context.Context, tenantID string, registrationID string) (ClientRegistration, error) {
	var reg ClientRegistration
	var raw []byte
	var approvedAt sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, client_name, client_type, interface_name, subject_id, description, contact_email, requested_role,
       status, approval_id, ip_whitelist, rate_limit, api_key_prefix, approved_at, created_at
FROM auth_client_registrations
WHERE tenant_id=$1 AND id=$2
`, tenantID, registrationID).Scan(
		&reg.ID, &reg.TenantID, &reg.ClientName, &reg.ClientType, &reg.InterfaceName, &reg.SubjectID, &reg.Description, &reg.ContactEmail, &reg.RequestedRole,
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
SELECT id, tenant_id, client_name, client_type, interface_name, subject_id, description, contact_email, requested_role,
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
			&reg.ID, &reg.TenantID, &reg.ClientName, &reg.ClientType, &reg.InterfaceName, &reg.SubjectID, &reg.Description, &reg.ContactEmail, &reg.RequestedRole,
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

func (s *SQLStore) GetAPIKeyByHash(ctx context.Context, tenantID string, keyHash []byte) (APIKey, error) {
	var out APIKey
	var userID sql.NullString
	var clientID sql.NullString
	var permsRaw []byte
	var expiresAt sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, user_id, client_id, key_hash, name, permissions, expires_at, created_at
FROM auth_api_keys
WHERE tenant_id=$1 AND key_hash=$2
`, tenantID, keyHash).Scan(
		&out.ID,
		&out.TenantID,
		&userID,
		&clientID,
		&out.KeyHash,
		&out.Name,
		&permsRaw,
		&expiresAt,
		&out.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, errNotFound
	}
	if err != nil {
		return APIKey{}, err
	}
	if userID.Valid {
		out.UserID = userID.String
	}
	if clientID.Valid {
		out.ClientID = clientID.String
	}
	if len(permsRaw) > 0 {
		if err := json.Unmarshal(permsRaw, &out.Permissions); err != nil {
			return APIKey{}, err
		}
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		out.ExpiresAt = &t
	}
	return out, nil
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

func (s *SQLStore) GetHSMProviderConfig(ctx context.Context, tenantID string) (HSMProviderConfig, error) {
	var out HSMProviderConfig
	var metadataRaw []byte
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, provider_name, integration_service, library_path, slot_id, partition_label,
       token_label, pin_env_var, read_only, enabled, metadata_json, updated_by, created_at, updated_at
FROM auth_hsm_provider_configs
WHERE tenant_id=$1
`, tenantID).Scan(
		&out.TenantID,
		&out.ProviderName,
		&out.IntegrationService,
		&out.LibraryPath,
		&out.SlotID,
		&out.PartitionLabel,
		&out.TokenLabel,
		&out.PINEnvVar,
		&out.ReadOnly,
		&out.Enabled,
		&metadataRaw,
		&out.UpdatedBy,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return HSMProviderConfig{}, errNotFound
	}
	if err != nil {
		return HSMProviderConfig{}, err
	}
	out.Metadata = map[string]any{}
	if len(metadataRaw) > 0 {
		_ = json.Unmarshal(metadataRaw, &out.Metadata)
	}
	return out, nil
}

func (s *SQLStore) UpsertHSMProviderConfig(ctx context.Context, cfg HSMProviderConfig) (HSMProviderConfig, error) {
	metadataRaw, err := json.Marshal(cfg.Metadata)
	if err != nil {
		return HSMProviderConfig{}, err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_hsm_provider_configs (
    tenant_id, provider_name, integration_service, library_path, slot_id, partition_label,
    token_label, pin_env_var, read_only, enabled, metadata_json, updated_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET
    provider_name = EXCLUDED.provider_name,
    integration_service = EXCLUDED.integration_service,
    library_path = EXCLUDED.library_path,
    slot_id = EXCLUDED.slot_id,
    partition_label = EXCLUDED.partition_label,
    token_label = EXCLUDED.token_label,
    pin_env_var = EXCLUDED.pin_env_var,
    read_only = EXCLUDED.read_only,
    enabled = EXCLUDED.enabled,
    metadata_json = EXCLUDED.metadata_json,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
`, cfg.TenantID, cfg.ProviderName, cfg.IntegrationService, cfg.LibraryPath, cfg.SlotID, cfg.PartitionLabel, cfg.TokenLabel, cfg.PINEnvVar, cfg.ReadOnly, cfg.Enabled, metadataRaw, cfg.UpdatedBy)
	if err != nil {
		return HSMProviderConfig{}, err
	}
	return s.GetHSMProviderConfig(ctx, cfg.TenantID)
}

func (s *SQLStore) ListIdentityProviderConfigs(ctx context.Context, tenantID string) ([]IdentityProviderConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, provider, enabled, config_json, secret_json, updated_by, created_at, updated_at
FROM auth_identity_provider_configs
WHERE tenant_id=$1
ORDER BY provider
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]IdentityProviderConfig, 0, 4)
	for rows.Next() {
		var cfg IdentityProviderConfig
		var configRaw []byte
		var secretRaw []byte
		if err := rows.Scan(
			&cfg.TenantID,
			&cfg.Provider,
			&cfg.Enabled,
			&configRaw,
			&secretRaw,
			&cfg.UpdatedBy,
			&cfg.CreatedAt,
			&cfg.UpdatedAt,
		); err != nil {
			return nil, err
		}
		cfg.Config = map[string]any{}
		cfg.Secrets = map[string]any{}
		if len(configRaw) > 0 {
			_ = json.Unmarshal(configRaw, &cfg.Config)
		}
		if len(secretRaw) > 0 {
			_ = json.Unmarshal(secretRaw, &cfg.Secrets)
		}
		out = append(out, cfg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLStore) GetIdentityProviderConfig(ctx context.Context, tenantID string, provider string) (IdentityProviderConfig, error) {
	var out IdentityProviderConfig
	var configRaw []byte
	var secretRaw []byte
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, provider, enabled, config_json, secret_json, updated_by, created_at, updated_at
FROM auth_identity_provider_configs
WHERE tenant_id=$1 AND provider=$2
`, tenantID, provider).Scan(
		&out.TenantID,
		&out.Provider,
		&out.Enabled,
		&configRaw,
		&secretRaw,
		&out.UpdatedBy,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return IdentityProviderConfig{}, errNotFound
	}
	if err != nil {
		return IdentityProviderConfig{}, err
	}
	out.Config = map[string]any{}
	out.Secrets = map[string]any{}
	if len(configRaw) > 0 {
		_ = json.Unmarshal(configRaw, &out.Config)
	}
	if len(secretRaw) > 0 {
		_ = json.Unmarshal(secretRaw, &out.Secrets)
	}
	return out, nil
}

func (s *SQLStore) UpsertIdentityProviderConfig(ctx context.Context, cfg IdentityProviderConfig) (IdentityProviderConfig, error) {
	configRaw, err := json.Marshal(cfg.Config)
	if err != nil {
		return IdentityProviderConfig{}, err
	}
	secretRaw, err := json.Marshal(cfg.Secrets)
	if err != nil {
		return IdentityProviderConfig{}, err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_identity_provider_configs (
    tenant_id, provider, enabled, config_json, secret_json, updated_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    config_json = EXCLUDED.config_json,
    secret_json = EXCLUDED.secret_json,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
`, cfg.TenantID, cfg.Provider, cfg.Enabled, configRaw, secretRaw, cfg.UpdatedBy)
	if err != nil {
		return IdentityProviderConfig{}, err
	}
	return s.GetIdentityProviderConfig(ctx, cfg.TenantID, cfg.Provider)
}

func discoverTenantTables(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT table_schema, table_name
FROM information_schema.columns
WHERE column_name='tenant_id'
  AND table_schema NOT IN ('pg_catalog','information_schema')
`)
	if err == nil {
		defer rows.Close() //nolint:errcheck
		out := make([]string, 0, 64)
		seen := map[string]struct{}{}
		for rows.Next() {
			var schema string
			var table string
			if scanErr := rows.Scan(&schema, &table); scanErr != nil {
				return nil, scanErr
			}
			name := fmt.Sprintf("%s.%s", schema, table)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return nil, rowsErr
		}
		sort.Strings(out)
		return out, nil
	}

	// SQLite fallback.
	sqliteRows, sqliteErr := tx.QueryContext(ctx, `
SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
`)
	if sqliteErr != nil {
		return nil, err
	}
	defer sqliteRows.Close() //nolint:errcheck
	out := make([]string, 0, 64)
	for sqliteRows.Next() {
		var table string
		if scanErr := sqliteRows.Scan(&table); scanErr != nil {
			return nil, scanErr
		}
		if strings.TrimSpace(table) == "" {
			continue
		}
		hasTenant, hasErr := sqliteTableHasTenantID(ctx, tx, table)
		if hasErr != nil {
			return nil, hasErr
		}
		if hasTenant {
			out = append(out, table)
		}
	}
	if rowsErr := sqliteRows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	sort.Strings(out)
	return out, nil
}

func sqliteTableHasTenantID(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	query := fmt.Sprintf(`PRAGMA table_info("%s")`, sqlQuoteIdentifier(table))
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return false, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var defaultVal sql.NullString
		var pk int
		if scanErr := rows.Scan(&cid, &name, &dataType, &notNull, &defaultVal, &pk); scanErr != nil {
			return false, scanErr
		}
		if strings.EqualFold(strings.TrimSpace(name), "tenant_id") {
			return true, nil
		}
	}
	return false, rows.Err()
}

func buildTenantDeleteStatement(table string) string {
	parts := strings.SplitN(strings.TrimSpace(table), ".", 2)
	if len(parts) == 2 {
		return fmt.Sprintf(`DELETE FROM "%s"."%s" WHERE tenant_id=$1`, sqlQuoteIdentifier(parts[0]), sqlQuoteIdentifier(parts[1]))
	}
	return fmt.Sprintf(`DELETE FROM "%s" WHERE tenant_id=$1`, sqlQuoteIdentifier(parts[0]))
}

func sqlQuoteIdentifier(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), `"`, `""`)
}

func isForeignKeyDeleteError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "foreign key") || strings.Contains(msg, "constraint failed")
}

func isAuditEventsTable(table string) bool {
	name := strings.ToLower(strings.TrimSpace(table))
	if name == "" {
		return false
	}
	return strings.HasSuffix(name, ".audit_events") ||
		strings.Contains(name, ".audit_events_") ||
		name == "audit_events" ||
		strings.HasPrefix(name, "audit_events_")
}

func disableTableUserTriggers(ctx context.Context, tx *sql.Tx, table string) error {
	stmt := buildDisableTableUserTriggersStatement(table)
	if strings.TrimSpace(stmt) == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, stmt)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "does not exist") {
		return nil
	}
	return err
}

func enableTableUserTriggers(ctx context.Context, tx *sql.Tx, table string) error {
	stmt := buildEnableTableUserTriggersStatement(table)
	if strings.TrimSpace(stmt) == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, stmt)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "does not exist") {
		return nil
	}
	return err
}

func buildDisableTableUserTriggersStatement(table string) string {
	parts := strings.SplitN(strings.TrimSpace(table), ".", 2)
	if len(parts) == 2 {
		return fmt.Sprintf(`ALTER TABLE "%s"."%s" DISABLE TRIGGER USER`, sqlQuoteIdentifier(parts[0]), sqlQuoteIdentifier(parts[1]))
	}
	return fmt.Sprintf(`ALTER TABLE "%s" DISABLE TRIGGER USER`, sqlQuoteIdentifier(parts[0]))
}

func buildEnableTableUserTriggersStatement(table string) string {
	parts := strings.SplitN(strings.TrimSpace(table), ".", 2)
	if len(parts) == 2 {
		return fmt.Sprintf(`ALTER TABLE "%s"."%s" ENABLE TRIGGER USER`, sqlQuoteIdentifier(parts[0]), sqlQuoteIdentifier(parts[1]))
	}
	return fmt.Sprintf(`ALTER TABLE "%s" ENABLE TRIGGER USER`, sqlQuoteIdentifier(parts[0]))
}

func isGroupRoleSchemaMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "auth_group_role_bindings") &&
		(strings.Contains(msg, "no such table") || strings.Contains(msg, "does not exist"))
}

func isGroupMembershipSchemaMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "key_access_group_members") &&
		(strings.Contains(msg, "no such table") || strings.Contains(msg, "does not exist"))
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
