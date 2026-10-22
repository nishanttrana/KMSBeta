package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/servicetoken"
)

// Scheduled encrypted backups (13.43.0-beta; docs/SECURITY/BACKUP_KEYS.md,
// "Scheduled backups"). A schedule takes a governance backup every
// interval_hours and keeps the newest retain_count it took. It runs as the
// governance service with nobody present, so:
//   - it acts on the authority of the root administrator who saved it, asked
//     of auth before every run; when they are no longer active or no longer
//     hold auth.tenant.write the schedule pauses, audited, until someone who
//     does saves it again (docs/PLATFORM_CONTRACT.md);
//   - the backup key is never a software key file nobody receives: it is
//     wrapped in the tenant's HSM (key_protection "hsm", refused when the HSM
//     is not enabled) or sealed to the administrator's RSA public key
//     (key_protection "recipient");
//   - it runs on the primary only (the schedules table is replicated).
// Every run is audited: scheduled_backup_taken, scheduled_backup_failed
// (the backup was refused) and scheduled_backup_refused (authority).

const (
	backupSchedulePermission = "auth.tenant.write"
	maxBackupIntervalHours   = 30 * 24
	maxBackupRetain          = 90
	// backupScheduleRetry: how long a run waits after auth could not be
	// asked, or after a failed backup when the interval is longer.
	backupScheduleRetry = 15 * time.Minute
	// backupRunTimeout bounds one scheduled backup.
	backupRunTimeout = 30 * time.Minute

	keyProtectionHSM       = "hsm"
	keyProtectionRecipient = "recipient"
)

var errInvalidBackupSchedule = errors.New("invalid backup schedule")

// BackupSchedule is a saved schedule. The recipient key is a public key and
// is returned as stored.
type BackupSchedule struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	Name               string     `json:"name"`
	Enabled            bool       `json:"enabled"`
	Scope              string     `json:"scope"`
	TargetTenantID     string     `json:"target_tenant_id,omitempty"`
	IntervalHours      int        `json:"interval_hours"`
	RetainCount        int        `json:"retain_count"`
	KeyProtection      string     `json:"key_protection"`
	RecipientPublicKey string     `json:"recipient_public_key,omitempty"`
	RecipientKeySHA256 string     `json:"recipient_key_sha256,omitempty"`
	AuthorizedBy       string     `json:"authorized_by"`
	PausedReason       string     `json:"paused_reason,omitempty"`
	NextRunAt          *time.Time `json:"next_run_at,omitempty"`
	LastRunAt          *time.Time `json:"last_run_at,omitempty"`
	LastResult         string     `json:"last_result,omitempty"`
	LastBackupID       string     `json:"last_backup_id,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// BackupScheduleInput is what a create or update sends.
type BackupScheduleInput struct {
	Name               string `json:"name"`
	Enabled            *bool  `json:"enabled"`
	Scope              string `json:"scope"`
	TargetTenantID     string `json:"target_tenant_id"`
	IntervalHours      int    `json:"interval_hours"`
	RetainCount        int    `json:"retain_count"`
	KeyProtection      string `json:"key_protection"`
	RecipientPublicKey string `json:"recipient_public_key"`
}

// backupAuthority asks auth whether a person is still active and still
// holds permissions, now.
type backupAuthority interface {
	Authority(ctx context.Context, tenantID, userID string, perms []string) (active bool, missing []string, err error)
}

// backupScheduleRunner serialises runs: the tick and "run now" never take
// two backups of one schedule at once.
var backupScheduleRunner sync.Mutex

func (s *Service) clockNow() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// SaveBackupSchedule creates (id "") or replaces a schedule on userID's
// authority, which the route kernel has verified, and clears a pause. The
// first run is one interval from now.
func (s *Service) SaveBackupSchedule(ctx context.Context, tenantID, id string, in BackupScheduleInput, userID string) (BackupSchedule, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil {
		return BackupSchedule{}, errors.New("backup store is unavailable")
	}
	bad := func(format string, a ...interface{}) error {
		return fmt.Errorf("%w: %s", errInvalidBackupSchedule, fmt.Sprintf(format, a...))
	}
	sch := BackupSchedule{ID: strings.TrimSpace(id), TenantID: tenantID, Name: strings.TrimSpace(in.Name), Enabled: in.Enabled == nil || *in.Enabled,
		IntervalHours: in.IntervalHours, RetainCount: in.RetainCount, AuthorizedBy: strings.TrimSpace(userID)}
	if sch.Name == "" || len(sch.Name) > 120 {
		return BackupSchedule{}, bad("name is required (at most 120 characters)")
	}
	if sch.IntervalHours < 1 || sch.IntervalHours > maxBackupIntervalHours {
		return BackupSchedule{}, bad("interval_hours must be 1 to %d", maxBackupIntervalHours)
	}
	if sch.RetainCount < 1 || sch.RetainCount > maxBackupRetain {
		return BackupSchedule{}, bad("retain_count must be 1 to %d", maxBackupRetain)
	}
	if sch.AuthorizedBy == "" {
		return BackupSchedule{}, bad("the saving administrator is unknown")
	}
	switch sch.Scope = normalizeBackupScope(in.Scope); sch.Scope {
	case backupScopeSystem:
	case backupScopeTenant:
		if sch.TargetTenantID = strings.TrimSpace(in.TargetTenantID); sch.TargetTenantID == "" {
			return BackupSchedule{}, bad("target_tenant_id is required for a tenant backup")
		}
	default:
		return BackupSchedule{}, bad("scope must be system or tenant")
	}
	switch sch.KeyProtection = strings.TrimSpace(in.KeyProtection); sch.KeyProtection {
	case keyProtectionHSM:
		if strings.TrimSpace(in.RecipientPublicKey) != "" {
			return BackupSchedule{}, bad("recipient_public_key applies to key_protection recipient")
		}
		hsmTenant := tenantID
		if sch.Scope == backupScopeTenant {
			hsmTenant = sch.TargetTenantID
		}
		if !store.loadHSMBinding(ctx, hsmTenant).Enabled {
			return BackupSchedule{}, bad("key_protection hsm needs an enabled HSM profile for tenant %s (HSM tab); use recipient otherwise", hsmTenant)
		}
	case keyProtectionRecipient:
		rk, err := parseBackupRecipient(in.RecipientPublicKey)
		if err != nil {
			return BackupSchedule{}, bad("%v", err)
		}
		sch.RecipientPublicKey, sch.RecipientKeySHA256 = rk.PEM, rk.Fingerprint
	default:
		return BackupSchedule{}, bad("key_protection must be hsm or recipient: nobody is present to take a software key file")
	}
	now := s.clockNow()
	if sch.ID == "" {
		sch.ID = newID("bks")
		sch.CreatedAt = now
	} else {
		prev, err := store.getBackupSchedule(ctx, tenantID, sch.ID)
		if err != nil {
			return BackupSchedule{}, err
		}
		sch.CreatedAt, sch.LastRunAt, sch.LastResult, sch.LastBackupID, sch.LastError = prev.CreatedAt, prev.LastRunAt, prev.LastResult, prev.LastBackupID, prev.LastError
	}
	if sch.Enabled {
		next := now.Add(time.Duration(sch.IntervalHours) * time.Hour)
		sch.NextRunAt = &next
	}
	sch.UpdatedAt = now
	if err := store.putBackupSchedule(ctx, sch); err != nil {
		return BackupSchedule{}, err
	}
	return sch, nil
}

func (s *Service) ListBackupSchedules(ctx context.Context, tenantID string) ([]BackupSchedule, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil {
		return nil, errors.New("backup store is unavailable")
	}
	return store.listBackupSchedules(ctx, tenantID)
}

// DeleteBackupSchedule removes a schedule; the backups it took stay.
func (s *Service) DeleteBackupSchedule(ctx context.Context, tenantID, id string) error {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil {
		return errors.New("backup store is unavailable")
	}
	return store.deleteBackupSchedule(ctx, tenantID, id)
}

// RunBackupSchedulesLoop runs due schedules every interval on the primary
// until ctx ends.
func (s *Service) RunBackupSchedulesLoop(ctx context.Context, primary func(context.Context) bool, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if primary(ctx) {
				s.RunDueBackupSchedules(ctx)
			}
		}
	}
}

// RunDueBackupSchedules runs every enabled, unpaused schedule whose time has
// come and returns how many backups it took.
func (s *Service) RunDueBackupSchedules(ctx context.Context) int {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil {
		return 0
	}
	due, err := store.dueBackupSchedules(ctx, s.clockNow())
	if err != nil {
		logger.Printf("backup schedules: %v", err)
		return 0
	}
	taken := 0
	for _, sch := range due {
		if _, err := s.RunBackupSchedule(ctx, sch); err == nil {
			taken++
		}
	}
	return taken
}

// RunBackupSchedule takes one backup for sch now: the tick, or "run now".
func (s *Service) RunBackupSchedule(ctx context.Context, sch BackupSchedule) (BackupJob, error) {
	backupScheduleRunner.Lock()
	defer backupScheduleRunner.Unlock()
	store := s.store.(*SQLStore)
	now := s.clockNow()
	audit := func(subject, result, reason string, extra map[string]interface{}) {
		d := map[string]interface{}{"schedule_id": sch.ID, "schedule_name": sch.Name, "scope": sch.Scope, "target_tenant_id": sch.TargetTenantID,
			"key_protection": sch.KeyProtection, "authorized_by": sch.AuthorizedBy, "actor_id": "kms-governance", "result": result}
		if reason != "" {
			d["reason"], d["severity"] = reason, "high"
		}
		for k, v := range extra {
			d[k] = v
		}
		_ = s.publishAudit(ctx, subject, sch.TenantID, d)
	}
	finish := func(result, errText, backupID string, next time.Time) {
		sch.LastRunAt, sch.LastResult, sch.LastError = &now, result, errText
		if backupID != "" {
			sch.LastBackupID = backupID
		}
		if sch.PausedReason == "" {
			sch.NextRunAt = &next
		}
		sch.UpdatedAt = now
		if err := store.putBackupSchedule(ctx, sch); err != nil {
			logger.Printf("backup schedule %s: %v", sch.ID, err)
		}
	}
	retry := now.Add(backupScheduleRetry)
	if s.authority == nil {
		finish("refused", "auth could not be asked", "", retry)
		audit("audit.governance.scheduled_backup_refused", "refused", "authority_unknown", nil)
		return BackupJob{}, errors.New("authority unknown")
	}
	active, missing, err := s.authority.Authority(ctx, sch.TenantID, sch.AuthorizedBy, []string{backupSchedulePermission})
	switch {
	case err != nil:
		// Auth didn't answer: neither run on unverified authority nor
		// pause a schedule that may still be valid.
		finish("refused", "auth could not be asked: "+err.Error(), "", retry)
		audit("audit.governance.scheduled_backup_refused", "refused", "authority_unknown", nil)
		return BackupJob{}, err
	case !active || len(missing) > 0:
		sch.PausedReason = "the administrator who saved this schedule is no longer active or no longer holds " + backupSchedulePermission + "; save it again to resume"
		finish("refused", sch.PausedReason, "", retry)
		audit("audit.governance.scheduled_backup_refused", "refused", "authority_revoked", nil)
		return BackupJob{}, errors.New(sch.PausedReason)
	}

	in := CreateBackupInput{TenantID: sch.TenantID, Scope: sch.Scope, TargetTenantID: sch.TargetTenantID, CreatedBy: sch.AuthorizedBy, ScheduleID: sch.ID}
	if sch.KeyProtection == keyProtectionRecipient {
		rk, perr := parseBackupRecipient(sch.RecipientPublicKey)
		if err = perr; err != nil {
			finish("failed", err.Error(), "", now.Add(time.Duration(sch.IntervalHours)*time.Hour))
			audit("audit.governance.scheduled_backup_failed", "failure", "recipient_key_invalid", nil)
			return BackupJob{}, err
		}
		in.Recipient = &rk
	} else {
		in.RequireHSM = true
	}
	runCtx, cancel := context.WithTimeout(ctx, backupRunTimeout)
	defer cancel()
	job, _, err := s.CreateBackup(runCtx, in)
	if err != nil {
		next := now.Add(time.Duration(sch.IntervalHours) * time.Hour)
		if hour := now.Add(time.Hour); hour.Before(next) {
			next = hour // a failed backup is tried again within the hour
		}
		finish("failed", err.Error(), "", next)
		audit("audit.governance.scheduled_backup_failed", "failure", "backup_refused", map[string]interface{}{"error": err.Error()})
		return BackupJob{}, err
	}
	removed := s.pruneScheduledBackups(ctx, store, sch)
	finish("succeeded", "", job.ID, now.Add(time.Duration(sch.IntervalHours)*time.Hour))
	audit("audit.governance.scheduled_backup_taken", "success", "", map[string]interface{}{"backup_id": job.ID, "pruned": removed, "artifact_size_bytes": job.ArtifactSizeBytes})
	return job, nil
}

// pruneScheduledBackups deletes this schedule's own backups beyond the
// newest retain_count, each audited as backup_deleted.
func (s *Service) pruneScheduledBackups(ctx context.Context, store *SQLStore, sch BackupSchedule) int {
	ids, err := store.scheduledBackupIDs(ctx, sch.TenantID, sch.ID)
	if err != nil {
		logger.Printf("backup schedule %s: retention: %v", sch.ID, err)
		return 0
	}
	removed := 0
	for i := sch.RetainCount; i < len(ids); i++ {
		if err := s.DeleteBackup(ctx, sch.TenantID, ids[i], "schedule:"+sch.ID); err != nil {
			logger.Printf("backup schedule %s: delete %s: %v", sch.ID, ids[i], err)
			continue
		}
		removed++
	}
	return removed
}

// ── store ────────────────────────────────────────────────────────────

const backupScheduleColumns = `id, tenant_id, name, enabled, scope, target_tenant_id, interval_hours, retain_count, key_protection,
       recipient_public_key, recipient_key_sha256, authorized_by, paused_reason, next_run_at, last_run_at,
       last_result, last_backup_id, last_error, created_at, updated_at`

func scanBackupSchedule(row interface{ Scan(...interface{}) error }) (BackupSchedule, error) {
	var sch BackupSchedule
	var next, last, created, updated interface{}
	if err := row.Scan(&sch.ID, &sch.TenantID, &sch.Name, &sch.Enabled, &sch.Scope, &sch.TargetTenantID, &sch.IntervalHours, &sch.RetainCount,
		&sch.KeyProtection, &sch.RecipientPublicKey, &sch.RecipientKeySHA256, &sch.AuthorizedBy, &sch.PausedReason, &next, &last,
		&sch.LastResult, &sch.LastBackupID, &sch.LastError, &created, &updated); err != nil {
		return BackupSchedule{}, err
	}
	if t := parseTimeValue(next); !t.IsZero() {
		sch.NextRunAt = &t
	}
	if t := parseTimeValue(last); !t.IsZero() {
		sch.LastRunAt = &t
	}
	sch.CreatedAt, sch.UpdatedAt = parseTimeValue(created), parseTimeValue(updated)
	return sch, nil
}

func (s *SQLStore) queryBackupSchedules(ctx context.Context, where string, args ...interface{}) ([]BackupSchedule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+backupScheduleColumns+` FROM governance_backup_schedules `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []BackupSchedule{}
	for rows.Next() {
		sch, err := scanBackupSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *SQLStore) listBackupSchedules(ctx context.Context, tenantID string) ([]BackupSchedule, error) {
	return s.queryBackupSchedules(ctx, `WHERE tenant_id=$1 ORDER BY created_at, id`, tenantID)
}

func (s *SQLStore) getBackupSchedule(ctx context.Context, tenantID, id string) (BackupSchedule, error) {
	sch, err := scanBackupSchedule(s.db.SQL().QueryRowContext(ctx, `SELECT `+backupScheduleColumns+` FROM governance_backup_schedules WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return BackupSchedule{}, errNotFound
	}
	return sch, err
}

func (s *SQLStore) dueBackupSchedules(ctx context.Context, now time.Time) ([]BackupSchedule, error) {
	return s.queryBackupSchedules(ctx, `WHERE enabled=$1 AND paused_reason='' AND next_run_at IS NOT NULL AND next_run_at <= $2 ORDER BY next_run_at, id`, true, now.UTC())
}

func (s *SQLStore) putBackupSchedule(ctx context.Context, sch BackupSchedule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO governance_backup_schedules (`+backupScheduleColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
ON CONFLICT (id) DO UPDATE SET
    name=EXCLUDED.name, enabled=EXCLUDED.enabled, scope=EXCLUDED.scope, target_tenant_id=EXCLUDED.target_tenant_id,
    interval_hours=EXCLUDED.interval_hours, retain_count=EXCLUDED.retain_count, key_protection=EXCLUDED.key_protection,
    recipient_public_key=EXCLUDED.recipient_public_key, recipient_key_sha256=EXCLUDED.recipient_key_sha256,
    authorized_by=EXCLUDED.authorized_by, paused_reason=EXCLUDED.paused_reason, next_run_at=EXCLUDED.next_run_at,
    last_run_at=EXCLUDED.last_run_at, last_result=EXCLUDED.last_result, last_backup_id=EXCLUDED.last_backup_id,
    last_error=EXCLUDED.last_error, updated_at=EXCLUDED.updated_at
WHERE governance_backup_schedules.tenant_id=EXCLUDED.tenant_id`,
		sch.ID, sch.TenantID, sch.Name, sch.Enabled, sch.Scope, sch.TargetTenantID, sch.IntervalHours, sch.RetainCount, sch.KeyProtection,
		sch.RecipientPublicKey, sch.RecipientKeySHA256, sch.AuthorizedBy, sch.PausedReason, nullableTimePtr(sch.NextRunAt), nullableTimePtr(sch.LastRunAt),
		sch.LastResult, sch.LastBackupID, sch.LastError, sch.CreatedAt.UTC(), sch.UpdatedAt.UTC())
	return err
}

func (s *SQLStore) deleteBackupSchedule(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM governance_backup_schedules WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// scheduledBackupIDs are the schedule's backups, newest first.
func (s *SQLStore) scheduledBackupIDs(ctx context.Context, tenantID, scheduleID string) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT id FROM governance_backup_jobs WHERE tenant_id=$1 AND schedule_id=$2 ORDER BY created_at DESC, id DESC`, tenantID, scheduleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func nullableTimePtr(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

// ── routes ───────────────────────────────────────────────────────────

// backupScheduleRouter: the schedules are the root tenant's, for platform
// administrators (auth.tenant.read / write), as backups are.
func (h *Handler) backupScheduleRouter() *route.Router {
	r := route.New("governance", kernelEmitter{h}, nil)
	read := route.Spec{Action: "backup_schedules_listed", Permission: "auth.tenant.read", Resource: "backup_schedule"}
	write := func(action string) route.Spec {
		return route.Spec{Action: action, Permission: backupSchedulePermission, Resource: "backup_schedule", TargetParam: "id", Severity: "warning"}
	}
	r.Handle("GET /governance/backups/schedules", read, h.listBackupSchedules)
	r.Handle("POST /governance/backups/schedules", route.Spec{Action: "backup_schedule_created", Permission: backupSchedulePermission, Resource: "backup_schedule", Severity: "warning"}, h.saveBackupSchedule)
	r.Handle("PUT /governance/backups/schedules/{id}", write("backup_schedule_updated"), h.saveBackupSchedule)
	r.Handle("DELETE /governance/backups/schedules/{id}", write("backup_schedule_deleted"), h.deleteBackupSchedule)
	r.Handle("POST /governance/backups/schedules/{id}/run", write("backup_schedule_run_requested"), h.runBackupSchedule)
	return r
}

// rootOnly refuses a caller outside the root tenant: backups are system
// administration.
func rootOnly(c *route.Call) bool {
	if !strings.EqualFold(c.Tenant, "root") || c.Claims == nil || !strings.EqualFold(strings.TrimSpace(c.Claims.TenantID), "root") {
		c.Refuse(http.StatusForbidden, "not_root_tenant", "backup schedules belong to the root tenant's administrators")
		return false
	}
	return true
}

func (h *Handler) listBackupSchedules(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	items, err := h.svc.ListBackupSchedules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "schedules_unavailable", "backup schedules could not be read")
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) saveBackupSchedule(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var in BackupScheduleInput
	if !c.Decode(&in) {
		return
	}
	id := c.R.PathValue("id")
	sch, err := h.svc.SaveBackupSchedule(c.R.Context(), c.Tenant, id, in, c.Actor())
	switch {
	case errors.Is(err, errInvalidBackupSchedule):
		c.Refuse(http.StatusBadRequest, "invalid_schedule", err.Error())
		return
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "no such backup schedule")
		return
	case err != nil:
		c.Error(http.StatusInternalServerError, "schedule_save_failed", "the backup schedule could not be saved")
		return
	}
	c.Target(sch.ID)
	c.Detail("scope", sch.Scope)
	c.Detail("interval_hours", sch.IntervalHours)
	c.Detail("retain_count", sch.RetainCount)
	c.Detail("key_protection", sch.KeyProtection)
	c.Detail("enabled", sch.Enabled)
	if sch.RecipientKeySHA256 != "" {
		c.Detail("recipient_key_sha256", sch.RecipientKeySHA256)
	}
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	c.JSON(status, map[string]interface{}{"schedule": sch})
}

func (h *Handler) deleteBackupSchedule(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	err := h.svc.DeleteBackupSchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "no such backup schedule")
	case err != nil:
		c.Error(http.StatusInternalServerError, "schedule_delete_failed", "the backup schedule could not be deleted")
	default:
		c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
	}
}

// runBackupSchedule takes the schedule's backup now, on the schedule's
// authority, as the tick would.
func (h *Handler) runBackupSchedule(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	store, ok := h.svc.store.(*SQLStore)
	if !ok {
		c.Error(http.StatusInternalServerError, "store_unavailable", "backup store is unavailable")
		return
	}
	sch, err := store.getBackupSchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "no such backup schedule")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "schedule_unavailable", "the backup schedule could not be read")
		return
	}
	if sch.PausedReason != "" {
		c.Refuse(http.StatusConflict, "schedule_paused", sch.PausedReason)
		return
	}
	job, err := h.svc.RunBackupSchedule(c.R.Context(), sch)
	if err != nil {
		c.Refuse(http.StatusConflict, "backup_not_taken", err.Error())
		return
	}
	c.Detail("backup_id", job.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"job": job})
}

// ── auth ─────────────────────────────────────────────────────────────

// authAuthority asks auth (POST /auth/delegated/authority) as
// kms-governance, which auth admits as a caller of that route.
type authAuthority struct {
	url  string
	http *http.Client
}

func newAuthAuthority(authURL string) authAuthority {
	return authAuthority{url: strings.TrimRight(authURL, "/"), http: &http.Client{Timeout: 10 * time.Second}}
}

func (a authAuthority) Authority(ctx context.Context, tenantID, userID string, perms []string) (bool, []string, error) {
	raw, err := json.Marshal(map[string]interface{}{"tenant_id": tenantID, "user_id": userID, "permissions": perms})
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url+"/auth/delegated/authority?tenant_id="+neturl.QueryEscape(tenantID), bytes.NewReader(raw))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := a.http.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("%s unreachable: %w", req.URL.Hostname(), err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("%s HTTP %d", req.URL.Hostname(), resp.StatusCode)
	}
	var out struct {
		Active  bool     `json:"active"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false, nil, fmt.Errorf("%s answered without an authority", req.URL.Hostname())
	}
	return out.Active, out.Missing, nil
}
