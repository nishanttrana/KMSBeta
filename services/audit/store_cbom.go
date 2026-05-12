package main

import (
	"context"
	"strings"
	"time"
)

// CBOMSample is the minimal projection used to build a CBOM inventory.
// It is generated from the immutable audit chain so the inventory is
// tamper-evident by construction.
type CBOMSample struct {
	Algorithm   string
	Parameters  string
	KeyCount    int
	FirstSeenAt time.Time
	LastUsedAt  time.Time
}

// CBOMSamples returns the algorithm/parameter aggregates for one tenant.
// The implementation walks the most recent N audit events and groups by
// the algorithm/parameters fields embedded in event details.
//
// Note: this is a default implementation built on top of the existing
// event query API. A future revision can replace it with a materialised
// view if scan cost becomes a bottleneck — but until then, freshness
// outweighs the projection overhead.
func (s *SQLStore) CBOMSamples(ctx context.Context, tenantID string) ([]CBOMSample, error) {
	const horizon = 10_000
	events, err := s.QueryEvents(ctx, tenantID, EventQuery{Limit: horizon})
	if err != nil {
		return nil, err
	}
	type aggKey struct{ alg, params string }
	agg := make(map[aggKey]*CBOMSample, 16)
	for _, ev := range events {
		alg, params := extractCBOMAlgorithm(ev)
		if alg == "" {
			continue
		}
		k := aggKey{alg: strings.ToUpper(alg), params: strings.ToUpper(params)}
		sample, ok := agg[k]
		if !ok {
			sample = &CBOMSample{
				Algorithm:   k.alg,
				Parameters:  k.params,
				FirstSeenAt: ev.Timestamp,
				LastUsedAt:  ev.Timestamp,
			}
			agg[k] = sample
		}
		sample.KeyCount++
		if ev.Timestamp.Before(sample.FirstSeenAt) {
			sample.FirstSeenAt = ev.Timestamp
		}
		if ev.Timestamp.After(sample.LastUsedAt) {
			sample.LastUsedAt = ev.Timestamp
		}
	}
	out := make([]CBOMSample, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	return out, nil
}

// extractCBOMAlgorithm pulls the algorithm/parameter set out of an event's
// details payload. Several producers (keycore, KMIP) write the same logical
// information under slightly different keys; this normaliser papers over
// the differences.
func extractCBOMAlgorithm(ev AuditEvent) (string, string) {
	if ev.Details == nil {
		return "", ""
	}
	candidates := []string{"algorithm", "alg", "key_algorithm"}
	paramKeys := []string{"parameters", "params", "key_params", "kdf_algorithm"}
	alg := ""
	for _, k := range candidates {
		if v, ok := ev.Details[k].(string); ok && strings.TrimSpace(v) != "" {
			alg = strings.TrimSpace(v)
			break
		}
	}
	params := ""
	for _, k := range paramKeys {
		if v, ok := ev.Details[k].(string); ok && strings.TrimSpace(v) != "" {
			params = strings.TrimSpace(v)
			break
		}
	}
	return alg, params
}
