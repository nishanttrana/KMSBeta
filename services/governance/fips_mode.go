package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgfips "vecta-kms/pkg/fips"
)

// Platform FIPS mode control: a root administrator changes the mode in the KMS
// UI; services apply it with a staggered restart (pkg/config.RequireFIPSRuntime).

type PlatformFIPSMode struct {
	Mode        string    `json:"mode"`
	Previous    string    `json:"previous"`
	Reason      string    `json:"reason"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

type FIPSObservedService struct {
	Service       string    `json:"service"`
	Instance      string    `json:"instance"`
	Mode          string    `json:"mode"`
	ModuleVersion string    `json:"module_version"`
	Validated     bool      `json:"validated"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type FIPSModeImpact struct {
	From          string           `json:"from"`
	To            string           `json:"to"`
	Downgrade     bool             `json:"downgrade"`
	Stops         []pkgfips.Impact `json:"stops"`
	Starts        []pkgfips.Impact `json:"starts"`
	Notes         []string         `json:"notes"`
	Restarts      []string         `json:"restarts"`
	EstimatedSecs int              `json:"estimated_seconds"`
}

type FIPSModeStatus struct {
	Desired   *PlatformFIPSMode     `json:"desired"`
	Effective string                `json:"effective"`
	Services  []FIPSObservedService `json:"services"`
	Converged bool                  `json:"converged"`
	Pending   int                   `json:"pending"`
}

var errFIPSModeConfirm = errors.New("confirm must repeat the target mode")

func (s *SQLStore) GetPlatformFIPSMode(ctx context.Context) (*PlatformFIPSMode, error) {
	var (
		out PlatformFIPSMode
		at  interface{}
	)
	err := s.db.SQL().QueryRowContext(ctx, `SELECT mode, previous, reason, requested_by, requested_at FROM platform_fips_mode WHERE id = 1`).
		Scan(&out.Mode, &out.Previous, &out.Reason, &out.RequestedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out.RequestedAt = parseTimeValue(at)
	return &out, nil
}

func (s *SQLStore) SetPlatformFIPSMode(ctx context.Context, m PlatformFIPSMode) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO platform_fips_mode (id, mode, previous, reason, requested_by, requested_at)
VALUES (1,$1,$2,$3,$4,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET mode = EXCLUDED.mode, previous = EXCLUDED.previous, reason = EXCLUDED.reason,
	requested_by = EXCLUDED.requested_by, requested_at = CURRENT_TIMESTAMP, completed_at = NULL
`, m.Mode, m.Previous, m.Reason, m.RequestedBy)
	return err
}

func (s *SQLStore) ListPlatformFIPSObserved(ctx context.Context) ([]FIPSObservedService, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT service, instance, mode, module_version, validated, started_at, updated_at FROM platform_fips_observed ORDER BY service, instance`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []FIPSObservedService{}
	for rows.Next() {
		var (
			item         FIPSObservedService
			started, upd interface{}
		)
		if err := rows.Scan(&item.Service, &item.Instance, &item.Mode, &item.ModuleVersion, &item.Validated, &started, &upd); err != nil {
			return nil, err
		}
		item.StartedAt, item.UpdatedAt = parseTimeValue(started), parseTimeValue(upd)
		out = append(out, item)
	}
	return out, rows.Err()
}

// effectiveFIPSMode is the administrator's setting, or this process's running
// mode when none was ever set (the deployment seed).
func effectiveFIPSMode(desired *PlatformFIPSMode) string {
	if desired != nil && pkgfips.ValidMode(desired.Mode) {
		return desired.Mode
	}
	return pkgfips.Mode()
}

func (s *Service) FIPSModeStatus(ctx context.Context) (FIPSModeStatus, error) {
	desired, err := s.store.GetPlatformFIPSMode(ctx)
	if err != nil {
		return FIPSModeStatus{}, err
	}
	services, err := s.store.ListPlatformFIPSObserved(ctx)
	if err != nil {
		return FIPSModeStatus{}, err
	}
	out := FIPSModeStatus{Desired: desired, Effective: effectiveFIPSMode(desired), Services: services}
	for _, svc := range services {
		if svc.Mode != out.Effective {
			out.Pending++
		}
	}
	out.Converged = out.Pending == 0
	return out, nil
}

func (s *Service) FIPSModeImpact(ctx context.Context, target string) (FIPSModeImpact, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if !pkgfips.ValidMode(target) {
		return FIPSModeImpact{}, fmt.Errorf("mode must be on, only or off")
	}
	status, err := s.FIPSModeStatus(ctx)
	if err != nil {
		return FIPSModeImpact{}, err
	}
	stops, starts, notes := pkgfips.TransitionImpact(status.Effective, target)
	out := FIPSModeImpact{
		From: status.Effective, To: target, Stops: stops, Starts: starts, Notes: notes,
		Downgrade: pkgfips.ModeRank(target) < pkgfips.ModeRank(status.Effective),
		Restarts:  []string{},
	}
	seen := map[string]bool{}
	for _, svc := range status.Services {
		if !seen[svc.Service] {
			seen[svc.Service] = true
			out.Restarts = append(out.Restarts, svc.Service)
			if d := int(pkgfips.RestartDelay(svc.Service)/time.Second) + 30; d > out.EstimatedSecs {
				out.EstimatedSecs = d // tier delay + poll interval + restart
			}
		}
	}
	return out, nil
}

// SetFIPSMode records the administrator's choice; services pick it up within
// one poll interval and restart in tiers. confirm must repeat the mode.
func (s *Service) SetFIPSMode(ctx context.Context, target, confirm, reason, actor string) (FIPSModeImpact, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if strings.ToLower(strings.TrimSpace(confirm)) != target {
		return FIPSModeImpact{}, errFIPSModeConfirm
	}
	impact, err := s.FIPSModeImpact(ctx, target)
	if err != nil {
		return FIPSModeImpact{}, err
	}
	if impact.From == target {
		return impact, nil
	}
	if err := s.store.SetPlatformFIPSMode(ctx, PlatformFIPSMode{Mode: target, Previous: impact.From, Reason: strings.TrimSpace(reason), RequestedBy: actor}); err != nil {
		return FIPSModeImpact{}, err
	}
	severity := "warning"
	if impact.Downgrade {
		severity = "critical"
	}
	stopped := make([]string, 0, len(impact.Stops))
	for _, i := range impact.Stops {
		stopped = append(stopped, i.Service+": "+i.Feature)
	}
	_ = s.publishAudit(ctx, "audit.governance.fips_mode_changed", "root", map[string]interface{}{
		"from":              impact.From,
		"to":                target,
		"downgrade":         impact.Downgrade,
		"reason":            strings.TrimSpace(reason),
		"actor":             actor,
		"features_stopped":  stopped,
		"services_restart":  impact.Restarts,
		"estimated_seconds": impact.EstimatedSecs,
		"severity":          severity,
		"description":       fmt.Sprintf("platform FIPS 140-3 mode changed %s -> %s; services restart in tiers to apply it", impact.From, target),
	})
	return impact, nil
}

// ---- Rollout audit ----
//
// Services apply a mode change by restarting (pkg/config); they have no audit
// pipeline that early, so governance audits what they report: one event per
// service instance started in a mode, and one when every service reached the
// desired mode. Markers in the tables make this restart-safe.

// ClaimUnauditedFIPSObserved atomically marks every service start not yet
// audited and returns those rows, so concurrent or repeated runs never emit the
// same start twice.
func (s *SQLStore) ClaimUnauditedFIPSObserved(ctx context.Context) ([]FIPSObservedService, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
UPDATE platform_fips_observed SET audited_started_at = started_at
WHERE audited_started_at IS NULL OR audited_started_at <> started_at
RETURNING service, instance, mode, module_version, validated, started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []FIPSObservedService{}
	for rows.Next() {
		var (
			item    FIPSObservedService
			started interface{}
		)
		if err := rows.Scan(&item.Service, &item.Instance, &item.Mode, &item.ModuleVersion, &item.Validated, &started); err != nil {
			return nil, err
		}
		item.StartedAt = parseTimeValue(started)
		out = append(out, item)
	}
	return out, rows.Err()
}

// MarkFIPSRolloutCompleted sets completed_at once per requested change; it
// reports whether this call did it.
func (s *SQLStore) MarkFIPSRolloutCompleted(ctx context.Context) (bool, error) {
	res, err := s.db.SQL().ExecContext(ctx, `UPDATE platform_fips_mode SET completed_at = CURRENT_TIMESTAMP WHERE id = 1 AND completed_at IS NULL`)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// AuditFIPSRollout emits pending rollout audit events. Called periodically.
func (s *Service) AuditFIPSRollout(ctx context.Context) error {
	pending, err := s.store.ClaimUnauditedFIPSObserved(ctx)
	if err != nil {
		return err
	}
	desired, err := s.store.GetPlatformFIPSMode(ctx)
	if err != nil {
		return err
	}
	effective := effectiveFIPSMode(desired)
	for _, p := range pending {
		severity := "info"
		if p.Mode != effective {
			severity = "warning" // started in a mode other than the platform setting
		}
		_ = s.publishAudit(ctx, "audit.governance.fips_mode_applied", "root", map[string]interface{}{
			"service":        p.Service,
			"instance":       p.Instance,
			"mode":           p.Mode,
			"platform_mode":  effective,
			"module_version": p.ModuleVersion,
			"validated":      p.Validated,
			"started_at":     p.StartedAt,
			"severity":       severity,
			"actor":          "system:" + p.Service,
			"description":    fmt.Sprintf("%s started in FIPS mode %s (platform mode %s)", p.Service, p.Mode, effective),
		})
	}
	if desired == nil {
		return nil
	}
	status, err := s.FIPSModeStatus(ctx)
	if err != nil || !status.Converged || len(status.Services) == 0 {
		return err
	}
	done, err := s.store.MarkFIPSRolloutCompleted(ctx)
	if err != nil || !done {
		return err
	}
	_ = s.publishAudit(ctx, "audit.governance.fips_mode_rollout_completed", "root", map[string]interface{}{
		"mode":         desired.Mode,
		"previous":     desired.Previous,
		"requested_by": desired.RequestedBy,
		"requested_at": desired.RequestedAt,
		"services":     len(status.Services),
		"severity":     "info",
		"description":  fmt.Sprintf("every service now runs FIPS mode %s", desired.Mode),
	})
	return nil
}
