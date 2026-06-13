package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Threat detection runs honest, explainable rules over the key usage trail
// (key_usage_events) rather than claiming ML. Three rules plus canary trips:
//
//   new_actor             an actor used a key it has never used before, on a
//                         key that already has an established usage history
//   volume_spike          ops on a key in the last hour exceed 4x its hourly
//                         baseline over the prior 7 days (min 20 ops)
//   dormant_key_activity  a key untouched for 14+ days was suddenly used
//   canary_tripped        any API reference to a canary key id (recorded at
//                         the GetKey choke point, so real attacker traffic
//                         trips it — not just the manual /trip endpoint)
//
// Sweeps are evaluated on read (GET /threat/signals or /threat/dashboard) and
// rate-limited per tenant; canary trips raise signals at trip time.

type ThreatSignal struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	SignalType     string         `json:"signal_type"`
	KeyID          string         `json:"key_id,omitempty"`
	ActorID        string         `json:"actor_id,omitempty"`
	Severity       string         `json:"severity"`
	Description    string         `json:"description"`
	DedupeKey      string         `json:"-"`
	DetectedAt     time.Time      `json:"detected_at"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string         `json:"acknowledged_by,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type KeyUsageEvent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	KeyID      string    `json:"key_id"`
	Operation  string    `json:"operation"`
	ActorID    string    `json:"actor_id"`
	ActorIP    string    `json:"actor_ip"`
	Interface  string    `json:"interface"`
	OccurredAt time.Time `json:"occurred_at"`
}

type ThreatDashboard struct {
	ActiveBySeverity     map[string]int `json:"active_by_severity"`
	ActiveTotal          int            `json:"active_total"`
	AcknowledgedTotal    int            `json:"acknowledged_total"`
	CanaryKeys           int            `json:"canary_keys"`
	CanaryTrips          int            `json:"canary_trips"`
	OpenCompromiseEvents int            `json:"open_compromise_events"`
	RecentSignals        []ThreatSignal `json:"recent_signals"`
	GeneratedAt          time.Time      `json:"generated_at"`
}

const (
	threatSweepMinInterval  = time.Minute
	usageRetention          = 30 * 24 * time.Hour
	newActorHistoryMin      = 5
	newActorAlertWindow     = time.Hour
	volumeSpikeMinOps       = 20
	volumeSpikeFactor       = 4.0
	dormantThreshold        = 14 * 24 * time.Hour
	threatSweepWindow       = 24 * time.Hour
	threatSweepMaxCandidates = 200
)

var threatSweepLast sync.Map // tenantID -> time.Time

// runCryptoTx wraps the store crypto transaction and records a usage event on
// success so the detection rules have a trail to run over. Recording is
// best-effort and off the request's critical path.
func (s *Service) runCryptoTx(ctx context.Context, tenantID, keyID, operation string, fn func(Key, KeyVersion) (CryptoTxResult, error)) (CryptoTxResult, error) {
	result, err := s.store.RunCryptoTx(ctx, tenantID, keyID, operation, fn)
	if err == nil {
		s.recordKeyUsage(ctx, tenantID, keyID, operation)
	}
	return result, err
}

func (s *Service) recordKeyUsage(ctx context.Context, tenantID, keyID, operation string) {
	actor := accessActorFromContext(ctx)
	event := KeyUsageEvent{
		ID:         newID("kue"),
		TenantID:   tenantID,
		KeyID:      keyID,
		Operation:  operation,
		ActorID:    firstNonEmpty(actor.UserID, actor.Username, actor.SubjectID, actor.ClientID),
		ActorIP:    actor.SourceIP,
		Interface:  actor.InterfaceName,
		OccurredAt: time.Now().UTC(),
	}
	go func() {
		insertCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.InsertKeyUsageEvent(insertCtx, event)
	}()
}

// noteCanaryProbe is called from GetKey's not-found branch: if the requested
// id is an active canary, the probe is recorded as a trip and a critical
// threat signal is raised. The caller still returns not-found so the probe
// learns nothing.
func (s *Service) noteCanaryProbe(ctx context.Context, tenantID, keyID string) {
	canary, err := s.store.GetCanaryKey(ctx, tenantID, keyID)
	if err != nil || !canary.Active {
		return
	}
	actor := accessActorFromContext(ctx)
	actorID := firstNonEmpty(actor.UserID, actor.Username, actor.SubjectID, actor.ClientID, "unknown")
	now := time.Now().UTC()
	_ = s.store.RecordCanaryTrip(ctx, CanaryTripEvent{
		ID:         newID("ctrip"),
		CanaryID:   canary.ID,
		TenantID:   tenantID,
		ActorID:    actorID,
		ActorIP:    actor.SourceIP,
		TrippedAt:  now,
		Severity:   "critical",
		RawRequest: "key API reference to canary id " + keyID,
	})
	_, _ = s.store.CreateThreatSignal(ctx, ThreatSignal{
		ID:          newID("tsig"),
		TenantID:    tenantID,
		SignalType:  "canary_tripped",
		KeyID:       canary.ID,
		ActorID:     actorID,
		Severity:    "critical",
		Description: fmt.Sprintf("Canary key %q was referenced through the key API by actor %q — treat as active credential compromise", canary.Name, actorID),
		DedupeKey:   strings.Join([]string{"canary_tripped", canary.ID, actorID, now.Format("2006-01-02T15")}, "|"),
		DetectedAt:  now,
	})
	_ = s.publishAudit(ctx, "audit.keycore.canary_tripped", tenantID, map[string]any{
		"canary_id": canary.ID,
		"actor_id":  actorID,
		"actor_ip":  actor.SourceIP,
		"severity":  "critical",
		"source":    "key_api_probe",
	})
}

// sweepThreatSignals evaluates the detection rules for a tenant, at most once
// per threatSweepMinInterval. Safe to call on every read.
func (s *Service) sweepThreatSignals(ctx context.Context, tenantID string) {
	if last, ok := threatSweepLast.Load(tenantID); ok {
		if time.Since(last.(time.Time)) < threatSweepMinInterval {
			return
		}
	}
	threatSweepLast.Store(tenantID, time.Now())

	now := time.Now().UTC()
	_ = s.store.PruneKeyUsageEvents(ctx, tenantID, now.Add(-usageRetention))

	s.detectNewActors(ctx, tenantID, now)
	s.detectVolumeSpikes(ctx, tenantID, now)
	s.detectDormantActivity(ctx, tenantID, now)
}

func (s *Service) detectNewActors(ctx context.Context, tenantID string, now time.Time) {
	alertSince := now.Add(-newActorAlertWindow)
	pairs, err := s.store.ListRecentKeyActorPairs(ctx, tenantID, alertSince, threatSweepMaxCandidates)
	if err != nil {
		return
	}
	for _, p := range pairs {
		if p.ActorID == "" {
			continue
		}
		// The actor must be genuinely new to this key — their first-ever use
		// falls inside the alert window.
		firstUse, err := s.store.KeyActorFirstUse(ctx, tenantID, p.KeyID, p.ActorID)
		if err != nil || firstUse.IsZero() || firstUse.Before(alertSince) {
			continue
		}
		// And the key must already have an established history by others
		// before this actor showed up (else it's just a young key).
		priorByOthers, err := s.store.CountKeyUsageBetween(ctx, tenantID, p.KeyID, time.Time{}, firstUse)
		if err != nil || priorByOthers < newActorHistoryMin {
			continue
		}
		s.raiseSignal(ctx, ThreatSignal{
			TenantID:    tenantID,
			SignalType:  "new_actor",
			KeyID:       p.KeyID,
			ActorID:     p.ActorID,
			Severity:    "high",
			Description: fmt.Sprintf("Actor %q used key %s for the first time; the key has an established history of %d+ operations by other actors", p.ActorID, p.KeyID, priorByOthers),
			DedupeKey:   strings.Join([]string{"new_actor", p.KeyID, p.ActorID, now.Format("2006-01-02")}, "|"),
			DetectedAt:  now,
		})
	}
}

func (s *Service) detectVolumeSpikes(ctx context.Context, tenantID string, now time.Time) {
	keyIDs, err := s.store.ListRecentlyUsedKeyIDs(ctx, tenantID, now.Add(-time.Hour), threatSweepMaxCandidates)
	if err != nil {
		return
	}
	baselineStart := now.Add(-7 * 24 * time.Hour)
	baselineEnd := now.Add(-time.Hour)
	baselineHours := baselineEnd.Sub(baselineStart).Hours()
	for _, keyID := range keyIDs {
		lastHour, err := s.store.CountKeyUsageBetween(ctx, tenantID, keyID, now.Add(-time.Hour), now)
		if err != nil || lastHour < volumeSpikeMinOps {
			continue
		}
		baseline, err := s.store.CountKeyUsageBetween(ctx, tenantID, keyID, baselineStart, baselineEnd)
		if err != nil {
			continue
		}
		avgHourly := float64(baseline) / baselineHours
		if baseline > 0 && float64(lastHour) <= avgHourly*volumeSpikeFactor {
			continue
		}
		if baseline == 0 {
			// No baseline at all: covered by new_actor/dormant rules instead.
			continue
		}
		s.raiseSignal(ctx, ThreatSignal{
			TenantID:    tenantID,
			SignalType:  "volume_spike",
			KeyID:       keyID,
			Severity:    "high",
			Description: fmt.Sprintf("Key %s served %d ops in the last hour vs a %.1f/hour 7-day baseline", keyID, lastHour, avgHourly),
			DedupeKey:   strings.Join([]string{"volume_spike", keyID, now.Format("2006-01-02T15")}, "|"),
			DetectedAt:  now,
		})
	}
}

func (s *Service) detectDormantActivity(ctx context.Context, tenantID string, now time.Time) {
	keyIDs, err := s.store.ListRecentlyUsedKeyIDs(ctx, tenantID, now.Add(-threatSweepWindow), threatSweepMaxCandidates)
	if err != nil {
		return
	}
	for _, keyID := range keyIDs {
		previous, err := s.store.LastKeyUsageBefore(ctx, tenantID, keyID, now.Add(-threatSweepWindow))
		if err != nil || previous.IsZero() {
			continue
		}
		gap := now.Add(-threatSweepWindow).Sub(previous)
		if gap < dormantThreshold {
			continue
		}
		s.raiseSignal(ctx, ThreatSignal{
			TenantID:    tenantID,
			SignalType:  "dormant_key_activity",
			KeyID:       keyID,
			Severity:    "medium",
			Description: fmt.Sprintf("Key %s was used after %.0f days of inactivity", keyID, gap.Hours()/24),
			DedupeKey:   strings.Join([]string{"dormant_key_activity", keyID, now.Format("2006-01-02")}, "|"),
			DetectedAt:  now,
		})
	}
}

func (s *Service) raiseSignal(ctx context.Context, sig ThreatSignal) {
	sig.ID = newID("tsig")
	created, err := s.store.CreateThreatSignal(ctx, sig)
	if err != nil || !created {
		return
	}
	_ = s.publishAudit(ctx, "audit.threat.signal_raised", sig.TenantID, map[string]any{
		"signal_id":   sig.ID,
		"signal_type": sig.SignalType,
		"key_id":      sig.KeyID,
		"actor_id":    sig.ActorID,
		"severity":    sig.Severity,
	})
}

func (s *Service) GetThreatDashboard(ctx context.Context, tenantID string) (ThreatDashboard, error) {
	s.sweepThreatSignals(ctx, tenantID)
	signals, err := s.store.ListThreatSignals(ctx, tenantID, 200)
	if err != nil {
		return ThreatDashboard{}, err
	}
	dash := ThreatDashboard{
		ActiveBySeverity: map[string]int{},
		GeneratedAt:      time.Now().UTC(),
	}
	for _, sig := range signals {
		if sig.AcknowledgedAt == nil {
			dash.ActiveBySeverity[sig.Severity]++
			dash.ActiveTotal++
		} else {
			dash.AcknowledgedTotal++
		}
	}
	if len(signals) > 10 {
		signals = signals[:10]
	}
	dash.RecentSignals = signals
	if canaries, err := s.store.ListCanaryKeys(ctx, tenantID); err == nil {
		dash.CanaryKeys = len(canaries)
		for _, c := range canaries {
			dash.CanaryTrips += c.TripCount
		}
	}
	if events, err := s.store.ListCompromiseEvents(ctx, tenantID, "", "", 500); err == nil {
		for _, e := range events {
			if !strings.EqualFold(e.Status, "resolved") && !strings.EqualFold(e.Status, "closed") {
				dash.OpenCompromiseEvents++
			}
		}
	}
	return dash, nil
}
