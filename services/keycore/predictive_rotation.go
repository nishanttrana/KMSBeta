package main

import (
	"time"
)

// RotationForecaster estimates when a key will exhaust its ops_limit
// based on the last N usage samples. The forecaster is intentionally
// simple — a linear extrapolation from recent velocity — because the
// goal is "warn early," not "predict precisely."
type RotationForecaster struct{}

// Forecast returns the predicted time when the key's ops counter will
// hit its limit. Returns the zero time when there is insufficient signal
// (no limit set, no recent usage). PrepareAt is 24 hours before the
// predicted exhaustion: the reconciler pre-creates a successor key at
// PrepareAt and hot-swaps at SwapAt.
type Forecast struct {
	HasSignal bool
	OpsPerHour float64
	ExhaustAt time.Time
	PrepareAt time.Time
	SwapAt    time.Time
}

// Forecast computes the upcoming exhaustion. The inputs are:
//   - opsTotal:      current cumulative count
//   - opsLimit:      configured ceiling (zero = no forecast)
//   - sampledOps:    ops counter at sampleTime (for velocity)
//   - sampleTime:    timestamp the sample was taken
//
// The "prepare 24h early" buffer matches typical downstream cache TTLs:
// a successor created 24h ahead has time to propagate before traffic
// hits it.
func (RotationForecaster) Forecast(opsTotal, opsLimit, sampledOps int64, sampleTime time.Time) Forecast {
	if opsLimit <= 0 || sampleTime.IsZero() {
		return Forecast{}
	}
	delta := opsTotal - sampledOps
	if delta <= 0 {
		return Forecast{}
	}
	elapsed := time.Since(sampleTime)
	if elapsed <= 0 {
		return Forecast{}
	}
	rate := float64(delta) / elapsed.Hours()
	if rate <= 0 {
		return Forecast{}
	}
	remaining := opsLimit - opsTotal
	if remaining <= 0 {
		now := time.Now().UTC()
		return Forecast{
			HasSignal:  true,
			OpsPerHour: rate,
			ExhaustAt:  now,
			PrepareAt:  now,
			SwapAt:     now,
		}
	}
	hoursLeft := float64(remaining) / rate
	exhaust := time.Now().UTC().Add(time.Duration(hoursLeft * float64(time.Hour)))
	prepare := exhaust.Add(-24 * time.Hour)
	if prepare.Before(time.Now().UTC()) {
		prepare = time.Now().UTC()
	}
	return Forecast{
		HasSignal:  true,
		OpsPerHour: rate,
		ExhaustAt:  exhaust,
		PrepareAt:  prepare,
		SwapAt:     exhaust,
	}
}
