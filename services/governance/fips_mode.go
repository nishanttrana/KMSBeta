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
	requested_by = EXCLUDED.requested_by, requested_at = CURRENT_TIMESTAMP
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
