package keyrisk

import (
	"context"
	"sort"
)

// ScoreAllKeys computes risk scores for a batch of keys.
func (s *Scorer) ScoreAllKeys(ctx context.Context, keys []KeyMetadata) []KeyRiskScore {
	scores := make([]KeyRiskScore, 0, len(keys))
	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		scores = append(scores, s.ScoreKey(ctx, key))
	}
	return scores
}

// TopRiskKeys returns the top N keys sorted by overall risk score descending.
func (s *Scorer) TopRiskKeys(ctx context.Context, keys []KeyMetadata, limit int) []KeyRiskScore {
	scores := s.ScoreAllKeys(ctx, keys)

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].OverallScore > scores[j].OverallScore
	})

	if limit > 0 && limit < len(scores) {
		scores = scores[:limit]
	}
	return scores
}
