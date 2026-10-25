package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/route"
)

// Secret rotation schedules (13.66.0-beta, docs/SCHEDULING.md). A secret the
// KMS generated (an SSH key or a key pair) can be rotated on an interval:
// fresh material of the same kind becomes its next version, so readers of
// the latest version get it. A secret whose value came from outside can't
// be rotated by the KMS, so it can't have a schedule.
//
// A run acts on the authority of the person who saved the schedule: auth
// says they are active and hold secrets.write, and the vault's access rules
// allow them to write the secret's path. Otherwise the schedule pauses.

const (
	reasonNotGenerated         = "not_generated"
	maxSecretRotationInterval  = 24 * 365
	secretRotationRetry        = 15 * time.Minute
	secretRotationSchedulerTag = "kms-secrets-rotation-scheduler"
)

type SecretRotationSchedule struct {
	TenantID      string     `json:"tenant_id"`
	SecretID      string     `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	SecretPath    string     `json:"secret_path"`
	SecretType    string     `json:"secret_type"`
	IntervalHours int        `json:"interval_hours"`
	Enabled       bool       `json:"enabled"`
	AuthorizedBy  string     `json:"authorized_by"`
	PausedReason  string     `json:"paused_reason,omitempty"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	// LastResult: rotated, refused (the run did not happen) or failed; ""
	// before the first run. LastVersion is the version the last rotation made.
	LastResult  string    `json:"last_result,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastVersion int       `json:"last_version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// regenerable reports how a secret's material is made again: its key type,
// or "" when the KMS did not generate it.
func regenerable(s Secret) string {
	if generated, _ := s.Metadata["generated"].(bool); !generated {
		return ""
	}
	if kt, _ := s.Metadata["key_type"].(string); kt != "" {
		return kt
	}
	// POST /secrets/generate/ssh_key records only the algorithm (ed25519).
	if alg, _ := s.Metadata["algorithm"].(string); alg == "ed25519" && s.SecretType == "ssh_private_key" {
		return "ed25519"
	}
	return ""
}

// regenerate makes fresh material of the secret's kind: the private value
// and the public half.
func regenerate(keyType, name string) (string, string, error) {
	switch keyType {
	case "ed25519", "rsa-4096", "ecdsa-p384":
		return generateSSHKeyPair(keyType)
	case "pgp-rsa-4096":
		return generateOpenPGPKeyPair(name)
	case "wireguard-curve25519":
		return generateWireGuardKeyPair()
	case "age-x25519":
		return generateAgeX25519KeyPair()
	}
	return "", "", fmt.Errorf("key type %q cannot be generated again", keyType)
}

// RotateGenerated writes fresh material of the secret's kind as its next
// version, conditional on the version read, and records the new public key.
func (s *Service) RotateGenerated(ctx context.Context, secret Secret, actor string) (Secret, error) {
	kt := regenerable(secret)
	if kt == "" {
		return Secret{}, errNotGenerated
	}
	private, public, err := regenerate(kt, secret.Name)
	if err != nil {
		return Secret{}, err
	}
	meta := map[string]interface{}{}
	for k, v := range secret.Metadata {
		meta[k] = v
	}
	meta["public_key"] = public
	meta["rotated_at"] = time.Now().UTC().Format(time.RFC3339)
	expected := secret.CurrentVersion
	return s.UpdateSecret(ctx, secret.TenantID, secret.ID, UpdateSecretRequest{
		Value: &private, Metadata: &meta, UpdatedBy: actor, ExpectedVersion: &expected,
		changeAction: "rotated", changeDetail: fmt.Sprintf("Scheduled rotation: new %s material as version %d", kt, expected+1),
	})
}

var errNotGenerated = errors.New("only a secret the KMS generated (an SSH key or a key pair) can be rotated on a schedule; its value is made outside the KMS")

// ── store ────────────────────────────────────────────────────────────

const rotationScheduleColumns = `r.tenant_id, r.secret_id, s.name, s.labels, s.secret_type, r.interval_hours, r.enabled, r.authorized_by,
       r.paused_reason, r.next_run_at, r.last_run_at, r.last_result, r.last_error, r.last_version, r.created_at, r.updated_at`

func (s *SQLStore) queryRotationSchedules(ctx context.Context, where string, args ...any) ([]SecretRotationSchedule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+rotationScheduleColumns+`
FROM secret_rotation_schedules r JOIN secrets s ON s.tenant_id = r.tenant_id AND s.id = r.secret_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SecretRotationSchedule{}
	for rows.Next() {
		var (
			r          SecretRotationSchedule
			labelsJSON []byte
			next, last sql.NullTime
		)
		if err := rows.Scan(&r.TenantID, &r.SecretID, &r.SecretName, &labelsJSON, &r.SecretType, &r.IntervalHours, &r.Enabled,
			&r.AuthorizedBy, &r.PausedReason, &next, &last, &r.LastResult, &r.LastError, &r.LastVersion, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		labels := map[string]string{}
		_ = json.Unmarshal(labelsJSON, &labels)
		r.SecretPath = secretPath(labels, r.SecretName)
		if next.Valid {
			t := next.Time.UTC()
			r.NextRunAt = &t
		}
		if last.Valid {
			t := last.Time.UTC()
			r.LastRunAt = &t
		}
		r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListRotationSchedules(ctx context.Context, tenantID string) ([]SecretRotationSchedule, error) {
	return s.queryRotationSchedules(ctx, `WHERE r.tenant_id = $1 ORDER BY s.name, r.secret_id`, tenantID)
}

func (s *SQLStore) GetRotationSchedule(ctx context.Context, tenantID, secretID string) (SecretRotationSchedule, error) {
	items, err := s.queryRotationSchedules(ctx, `WHERE r.tenant_id = $1 AND r.secret_id = $2`, tenantID, secretID)
	if err != nil {
		return SecretRotationSchedule{}, err
	}
	if len(items) == 0 {
		return SecretRotationSchedule{}, errNotFound
	}
	return items[0], nil
}

// ListDueRotationSchedules returns enabled, unpaused schedules whose time
// has come, across tenants.
func (s *SQLStore) ListDueRotationSchedules(ctx context.Context, now time.Time, limit int) ([]SecretRotationSchedule, error) {
	return s.queryRotationSchedules(ctx, `WHERE r.enabled = TRUE AND r.paused_reason = '' AND r.next_run_at IS NOT NULL AND r.next_run_at <= $1
ORDER BY r.next_run_at, r.secret_id LIMIT $2`, now.UTC(), limit)
}

func (s *SQLStore) PutRotationSchedule(ctx context.Context, r SecretRotationSchedule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO secret_rotation_schedules (tenant_id, secret_id, interval_hours, enabled, authorized_by, paused_reason,
    next_run_at, last_run_at, last_result, last_error, last_version, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id, secret_id) DO UPDATE SET
    interval_hours=EXCLUDED.interval_hours, enabled=EXCLUDED.enabled, authorized_by=EXCLUDED.authorized_by,
    paused_reason=EXCLUDED.paused_reason, next_run_at=EXCLUDED.next_run_at, last_run_at=EXCLUDED.last_run_at,
    last_result=EXCLUDED.last_result, last_error=EXCLUDED.last_error, last_version=EXCLUDED.last_version,
    updated_at=EXCLUDED.updated_at`,
		r.TenantID, r.SecretID, r.IntervalHours, r.Enabled, r.AuthorizedBy, r.PausedReason,
		nullTime(r.NextRunAt), nullTime(r.LastRunAt), r.LastResult, r.LastError, r.LastVersion, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *SQLStore) DeleteRotationSchedule(ctx context.Context, tenantID, secretID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM secret_rotation_schedules WHERE tenant_id=$1 AND secret_id=$2`, tenantID, secretID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// ── running ──────────────────────────────────────────────────────────

// runRotation runs one schedule now: the authority, the access rule, the
// rotation; the outcome is stored and audited. by is "schedule" or
// "manual:<actor>".
func (h *Handler) runRotation(ctx context.Context, r SecretRotationSchedule, by string) SecretRotationSchedule {
	now := time.Now().UTC()
	reason, detail := h.rotationAuthority(ctx, r)
	if reason == "" {
		secret, err := h.svc.GetSecret(ctx, r.TenantID, r.SecretID)
		switch {
		case err != nil || secret.Status != SecretStatusActive:
			reason, detail = authority.ReasonRevoked, "the secret is deleted"
		default:
			out, err := h.svc.RotateGenerated(ctx, secret, r.AuthorizedBy)
			if err != nil {
				r.LastResult, r.LastError = "failed", err.Error()
			} else {
				r.LastResult, r.LastError, r.LastVersion = "rotated", "", out.CurrentVersion
			}
			next := now.Add(time.Duration(r.IntervalHours) * time.Hour)
			r.NextRunAt = &next
		}
	}
	if reason != "" {
		r.LastResult, r.LastError = "refused", detail
		retry := now.Add(secretRotationRetry)
		r.NextRunAt = &retry
		if reason != authority.ReasonUnknown {
			r.PausedReason = detail
		}
	}
	r.LastRunAt, r.UpdatedAt = &now, now
	if err := h.svc.store.PutRotationSchedule(ctx, r); err != nil {
		h.logf("secret rotation schedule %s: %v", r.SecretID, err)
	}
	if h.audit != nil {
		result := map[string]string{"rotated": "success", "failed": "failure", "refused": "refused"}[r.LastResult]
		details := map[string]interface{}{"path": r.SecretPath, "authorized_by": r.AuthorizedBy, "triggered_by": by,
			"interval_hours": r.IntervalHours}
		switch r.LastResult {
		case "rotated":
			details["new_version"] = r.LastVersion
		case "refused":
			details["reason"], details["description"], details["severity"] = reason, detail, "warning"
		case "failed":
			details["description"], details["severity"] = r.LastError, "warning"
		}
		emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = h.audit.Emit(emitCtx, "rotation_schedule_run", pkgaudit.Event{
			TenantID: r.TenantID, ActorID: secretRotationSchedulerTag, ActorType: "service",
			TargetType: "secret", TargetID: r.SecretID, Result: result, Details: details,
		})
		cancel()
	}
	return r
}

// rotationAuthority asks auth about the saver, then applies the vault's
// access rules to them for write on the secret's path.
func (h *Handler) rotationAuthority(ctx context.Context, r SecretRotationSchedule) (string, string) {
	a, reason, detail := authority.Check(ctx, h.authority, r.TenantID, r.AuthorizedBy, []string{permWrite})
	if reason != "" {
		return reason, detail
	}
	rules, err := h.svc.AccessRules(ctx, r.TenantID)
	if err != nil {
		return authority.ReasonUnknown, "access rules unavailable: " + err.Error()
	}
	settings, err := h.svc.Settings(ctx, r.TenantID)
	if err != nil {
		return authority.ReasonUnknown, "vault settings unavailable: " + err.Error()
	}
	who := &caller{claims: &pkgauth.Claims{UserID: r.AuthorizedBy, TenantID: r.TenantID, Role: a.Role, Permissions: []string{permWrite}}}
	who.groups = func() ([]string, error) {
		if h.groups == nil {
			return nil, errors.New("no access group source is configured")
		}
		return h.groups.GroupsOf(ctx, r.TenantID, r.AuthorizedBy)
	}
	switch d := decide(rules, settings.DefaultDeny, who, r.SecretPath, capWrite); d {
	case "":
		return "", ""
	case reasonGroupsUnavailable:
		return authority.ReasonUnknown, "group membership could not be read for an access rule on " + r.SecretPath
	default:
		return d, "an access rule on " + r.SecretPath + " no longer lets " + r.AuthorizedBy + " write it (" + d + ")"
	}
}

// runRotationSchedules runs due schedules every interval, primary only.
func (h *Handler) runRotationSchedules(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h.rotateDue(ctx, time.Now().UTC())
		}
	}
}

func (h *Handler) rotateDue(ctx context.Context, now time.Time) int {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	due, err := h.svc.store.ListDueRotationSchedules(ctx, now, 100)
	if err != nil {
		h.logf("secret rotation schedules: %v", err)
		return 0
	}
	for _, r := range due {
		h.runRotation(ctx, r, "schedule")
	}
	return len(due)
}

// ── routes ───────────────────────────────────────────────────────────

func (h *Handler) rotationScheduleRoutes() {
	r := h.router
	spec := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "secret_rotation_schedule", TargetParam: "id"}
	}
	r.Handle("GET /secrets/rotation-schedules", route.Spec{Action: "rotation_schedules_listed", Permission: permRead, Resource: "secret_rotation_schedule"}, h.listRotationSchedules)
	r.Handle("PUT /secrets/rotation-schedules/{id}", spec("rotation_schedule_saved", permWrite), h.putRotationSchedule)
	del := spec("rotation_schedule_deleted", permWrite)
	del.Severity = "warning"
	r.Handle("DELETE /secrets/rotation-schedules/{id}", del, h.deleteRotationSchedule)
	run := spec("rotation_schedule_run_requested", permWrite)
	run.Severity = "warning"
	r.Handle("POST /secrets/rotation-schedules/{id}/run", run, h.runRotationNow)
}

// listRotationSchedules lists the schedules of the secrets the caller may read.
func (h *Handler) listRotationSchedules(c *route.Call) {
	items, err := h.svc.store.ListRotationSchedules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_failed", "failed to list rotation schedules")
		return
	}
	p, ok := h.policy(c)
	if !ok {
		return
	}
	out := []SecretRotationSchedule{}
	for _, it := range items {
		if p.decide(it.SecretPath, capRead) == "" {
			out = append(out, it)
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": out})
}

func (h *Handler) putRotationSchedule(c *route.Call) {
	var in struct {
		IntervalHours int   `json:"interval_hours"`
		Enabled       *bool `json:"enabled"`
	}
	if !c.Decode(&in) {
		return
	}
	secret, ok := h.secretFor(c, capWrite)
	if !ok {
		return
	}
	if regenerable(secret) == "" {
		c.Refuse(http.StatusConflict, reasonNotGenerated, errNotGenerated.Error())
		return
	}
	if in.IntervalHours < 1 || in.IntervalHours > maxSecretRotationInterval {
		c.Refuse(http.StatusBadRequest, "invalid_schedule", "interval_hours must be 1 to 8760")
		return
	}
	ctx := c.R.Context()
	now := time.Now().UTC()
	r, err := h.svc.store.GetRotationSchedule(ctx, c.Tenant, secret.ID)
	switch {
	case errors.Is(err, errNotFound):
		r = SecretRotationSchedule{TenantID: c.Tenant, SecretID: secret.ID, CreatedAt: now}
	case err != nil:
		c.Error(http.StatusInternalServerError, "lookup_failed", "failed to read the rotation schedule")
		return
	}
	if r.PausedReason != "" {
		c.Detail("resumed", r.PausedReason)
	}
	intervalChanged := r.IntervalHours != in.IntervalHours
	r.SecretName, r.SecretPath, r.SecretType = secret.Name, secret.Path, secret.SecretType
	r.IntervalHours, r.Enabled = in.IntervalHours, in.Enabled == nil || *in.Enabled
	// Saving makes the caller the schedule's authority and resumes a pause.
	r.AuthorizedBy, r.PausedReason, r.UpdatedAt = c.Actor(), "", now
	if r.NextRunAt == nil || intervalChanged {
		base := now
		if r.LastRunAt != nil {
			base = *r.LastRunAt
		}
		next := base.Add(time.Duration(r.IntervalHours) * time.Hour)
		if next.Before(now) {
			next = now
		}
		r.NextRunAt = &next
	}
	if err := h.svc.store.PutRotationSchedule(ctx, r); err != nil {
		c.Error(http.StatusInternalServerError, "save_failed", "failed to save the rotation schedule")
		return
	}
	c.Detail("path", r.SecretPath)
	c.Detail("interval_hours", r.IntervalHours)
	c.Detail("enabled", r.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"schedule": r})
}

func (h *Handler) deleteRotationSchedule(c *route.Call) {
	if _, ok := h.secretFor(c, capWrite); !ok {
		return
	}
	err := h.svc.store.DeleteRotationSchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "no rotation schedule for this secret")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "delete_failed", "failed to delete the rotation schedule")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
}

// runRotationNow runs the schedule at once, on the saved person's authority
// as the tick would; the caller needs write on the secret too.
func (h *Handler) runRotationNow(c *route.Call) {
	if _, ok := h.secretFor(c, capWrite); !ok {
		return
	}
	r, err := h.svc.store.GetRotationSchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "no rotation schedule for this secret")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "lookup_failed", "failed to read the rotation schedule")
		return
	}
	if r.PausedReason != "" {
		c.Refuse(http.StatusConflict, "schedule_paused", r.PausedReason)
		return
	}
	r = h.runRotation(c.R.Context(), r, "manual:"+c.Actor())
	c.Detail("result", r.LastResult)
	c.Detail("new_version", r.LastVersion)
	c.JSON(http.StatusOK, map[string]interface{}{"schedule": r})
}
