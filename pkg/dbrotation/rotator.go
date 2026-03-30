package dbrotation

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DBType identifies the target database engine.
type DBType string

const (
	DBTypePostgres DBType = "postgres"
	DBTypeMySQL    DBType = "mysql"
	DBTypeOracle   DBType = "oracle"
	DBTypeMSSQL    DBType = "mssql"
)

// RotationStatus tracks the state of a rotation target.
type RotationStatus string

const (
	StatusActive    RotationStatus = "active"
	StatusRotating  RotationStatus = "rotating"
	StatusFailed    RotationStatus = "failed"
	StatusDisabled  RotationStatus = "disabled"
)

// RotationTarget represents a database credential to be rotated.
type RotationTarget struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	DBType           DBType         `json:"db_type"`
	ConnectionString string         `json:"connection_string"` // encrypted at rest
	Username         string         `json:"username"`
	CurrentPassword  string         `json:"current_password"` // encrypted at rest
	PreviousPassword string         `json:"previous_password"` // for grace period
	RotationInterval time.Duration  `json:"rotation_interval"`
	GracePeriod      time.Duration  `json:"grace_period"`
	LastRotated      time.Time      `json:"last_rotated"`
	NextRotation     time.Time      `json:"next_rotation"`
	Status           RotationStatus `json:"status"`
	FailureCount     int            `json:"failure_count"`
	LastError        string         `json:"last_error"`
}

// DBProvider defines the interface for database-specific password rotation.
type DBProvider interface {
	RotatePassword(ctx context.Context, connectionString, username, newPassword string) error
	ValidateConnection(ctx context.Context, connectionString, username, password string) error
	RevokePassword(ctx context.Context, connectionString, username, oldPassword string) error
}

// RotationEvent captures the result of a rotation attempt.
type RotationEvent struct {
	TargetID    string    `json:"target_id"`
	TenantID    string    `json:"tenant_id"`
	DBType      DBType    `json:"db_type"`
	Username    string    `json:"username"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	RotatedAt   time.Time `json:"rotated_at"`
	Duration    time.Duration `json:"duration"`
}

// Rotator manages database credential rotation across registered targets.
type Rotator struct {
	providers map[DBType]DBProvider
	store     *Store
	auditFn   func(ctx context.Context, event RotationEvent)
}

// NewRotator creates a Rotator with the given store and optional audit callback.
func NewRotator(store *Store, auditFn func(ctx context.Context, event RotationEvent)) *Rotator {
	if auditFn == nil {
		auditFn = func(context.Context, RotationEvent) {}
	}
	return &Rotator{
		providers: make(map[DBType]DBProvider),
		store:     store,
		auditFn:   auditFn,
	}
}

// RegisterProvider registers a DBProvider for a specific database type.
func (r *Rotator) RegisterProvider(dbType DBType, provider DBProvider) {
	r.providers[dbType] = provider
}

// RegisterDefaults registers the built-in providers for all supported DB types.
func (r *Rotator) RegisterDefaults() {
	r.providers[DBTypePostgres] = &PostgresProvider{}
	r.providers[DBTypeMySQL] = &MySQLProvider{}
	r.providers[DBTypeMSSQL] = &MSSQLProvider{}
	r.providers[DBTypeOracle] = &OracleProvider{}
}

// AddTarget registers a new rotation target.
func (r *Rotator) AddTarget(ctx context.Context, target *RotationTarget) error {
	if target.ID == "" {
		target.ID = generateTargetID()
	}
	if target.RotationInterval <= 0 {
		target.RotationInterval = 24 * time.Hour
	}
	if target.GracePeriod <= 0 {
		target.GracePeriod = 5 * time.Minute
	}
	if target.Status == "" {
		target.Status = StatusActive
	}
	if target.NextRotation.IsZero() {
		target.NextRotation = time.Now().UTC().Add(target.RotationInterval)
	}

	if r.store != nil {
		return r.store.SaveTarget(ctx, target)
	}
	return nil
}

// RotateTarget performs a credential rotation for a specific target.
func (r *Rotator) RotateTarget(ctx context.Context, targetID string) (*RotationEvent, error) {
	target, err := r.store.GetTarget(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("dbrotation: get target: %w", err)
	}

	provider, ok := r.providers[target.DBType]
	if !ok {
		return nil, fmt.Errorf("dbrotation: no provider for db_type %q", target.DBType)
	}

	start := time.Now()
	event := RotationEvent{
		TargetID: target.ID,
		TenantID: target.TenantID,
		DBType:   target.DBType,
		Username: target.Username,
	}

	// Generate a new password
	newPassword, err := GeneratePassword(32)
	if err != nil {
		event.Success = false
		event.Error = fmt.Sprintf("generate password: %v", err)
		event.Duration = time.Since(start)
		event.RotatedAt = time.Now().UTC()
		r.auditFn(ctx, event)
		return &event, fmt.Errorf("dbrotation: generate password: %w", err)
	}

	// Update status to rotating
	target.Status = StatusRotating
	_ = r.store.UpdateTargetStatus(ctx, target.ID, target.Status, "")

	// Rotate the password on the target database
	if err := provider.RotatePassword(ctx, target.ConnectionString, target.Username, newPassword); err != nil {
		// Rotation failed, keep old credentials
		target.Status = StatusFailed
		target.FailureCount++
		target.LastError = err.Error()
		_ = r.store.UpdateTargetStatus(ctx, target.ID, target.Status, err.Error())

		event.Success = false
		event.Error = err.Error()
		event.Duration = time.Since(start)
		event.RotatedAt = time.Now().UTC()
		r.auditFn(ctx, event)
		return &event, fmt.Errorf("dbrotation: rotate password: %w", err)
	}

	// Validate the new password works
	if err := provider.ValidateConnection(ctx, target.ConnectionString, target.Username, newPassword); err != nil {
		// New password doesn't work, attempt rollback
		rollbackErr := provider.RotatePassword(ctx, target.ConnectionString, target.Username, target.CurrentPassword)
		target.Status = StatusFailed
		target.FailureCount++
		errMsg := fmt.Sprintf("validation failed: %v", err)
		if rollbackErr != nil {
			errMsg += fmt.Sprintf("; rollback also failed: %v", rollbackErr)
		}
		target.LastError = errMsg
		_ = r.store.UpdateTargetStatus(ctx, target.ID, target.Status, errMsg)

		event.Success = false
		event.Error = errMsg
		event.Duration = time.Since(start)
		event.RotatedAt = time.Now().UTC()
		r.auditFn(ctx, event)
		return &event, errors.New("dbrotation: " + errMsg)
	}

	// Rotation succeeded: store old password for grace period, update current
	now := time.Now().UTC()
	target.PreviousPassword = target.CurrentPassword
	target.CurrentPassword = newPassword
	target.LastRotated = now
	target.NextRotation = now.Add(target.RotationInterval)
	target.Status = StatusActive
	target.FailureCount = 0
	target.LastError = ""

	if err := r.store.SaveTarget(ctx, target); err != nil {
		event.Success = false
		event.Error = fmt.Sprintf("save target: %v", err)
		event.Duration = time.Since(start)
		event.RotatedAt = now
		r.auditFn(ctx, event)
		return &event, fmt.Errorf("dbrotation: save target: %w", err)
	}

	// Schedule grace period expiry for the old password
	if target.PreviousPassword != "" && target.GracePeriod > 0 {
		go r.revokeAfterGracePeriod(target.ID, target.GracePeriod)
	}

	event.Success = true
	event.Duration = time.Since(start)
	event.RotatedAt = now
	r.auditFn(ctx, event)

	return &event, nil
}

// revokeAfterGracePeriod waits for the grace period then clears the previous password.
func (r *Rotator) revokeAfterGracePeriod(targetID string, gracePeriod time.Duration) {
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()
	<-timer.C

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target, err := r.store.GetTarget(ctx, targetID)
	if err != nil {
		return
	}
	if target.PreviousPassword == "" {
		return
	}

	// Revoke old password if the provider supports it
	if provider, ok := r.providers[target.DBType]; ok {
		_ = provider.RevokePassword(ctx, target.ConnectionString, target.Username, target.PreviousPassword)
	}

	target.PreviousPassword = ""
	_ = r.store.SaveTarget(ctx, target)
}

// ListTargets returns all targets for a tenant.
func (r *Rotator) ListTargets(ctx context.Context, tenantID string) ([]*RotationTarget, error) {
	return r.store.ListTargets(ctx, tenantID)
}

// GetTarget returns a single target.
func (r *Rotator) GetTarget(ctx context.Context, targetID string) (*RotationTarget, error) {
	return r.store.GetTarget(ctx, targetID)
}

// RemoveTarget deletes a rotation target.
func (r *Rotator) RemoveTarget(ctx context.Context, targetID string) error {
	return r.store.DeleteTarget(ctx, targetID)
}

// GeneratePassword creates a cryptographically random password of the specified length.
// Uses alphanumeric characters plus special characters: !@#$%^&*()-_=+
func GeneratePassword(length int) (string, error) {
	if length < 8 {
		length = 8
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	charsetLen := big.NewInt(int64(len(charset)))

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		password[i] = charset[idx.Int64()]
	}

	// Ensure at least one of each category
	categories := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"!@#$%^&*()-_=+",
	}
	for i, cat := range categories {
		if i >= length {
			break
		}
		catLen := big.NewInt(int64(len(cat)))
		idx, err := rand.Int(rand.Reader, catLen)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		// Place required character at a random position
		pos, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		password[pos.Int64()] = cat[idx.Int64()]
	}

	return string(password), nil
}

func generateTargetID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("dbtgt_%x", b)
}
