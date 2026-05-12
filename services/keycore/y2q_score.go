package main

import (
	"strconv"
	"strings"

	"vecta-kms/pkg/migration"
)

// Y2QInputs are the operator-controlled signals that feed the Y2Q risk
// computation. Sensitivity is on a 0..1 scale (top-secret = 1); the
// decryption window is in years. Both are stored on the key's label
// dictionary so the score is reproducible without runtime context.
type Y2QInputs struct {
	Sensitivity           float64
	DecryptionWindowYears float64
}

// Y2QScore proxies to the pure helper in pkg/migration so the
// computation lives in one place. Returning through this keycore-local
// wrapper means later changes to the formula propagate automatically.
func Y2QScore(in Y2QInputs) float64 {
	return migration.Y2QScore(in.Sensitivity, in.DecryptionWindowYears)
}

// Y2QFromLabels reads the labels written by the dashboard / KMIP
// registrar and returns the corresponding score. Missing labels yield
// the most conservative default (sensitivity 0.5 * 10y window = 5.0) so
// untagged keys still appear in migration plans rather than disappearing
// off the list.
func Y2QFromLabels(labels KeyLabels) float64 {
	if labels == nil {
		return migration.Y2QScore(0.5, 10)
	}
	s := readLabelFloat(labels, "sensitivity", 0.5)
	w := readLabelFloat(labels, "y2q_window_years", 10)
	return migration.Y2QScore(s, w)
}

func readLabelFloat(labels KeyLabels, key string, fallback float64) float64 {
	for _, candidate := range []string{key, strings.ToLower(key), strings.ToUpper(key)} {
		raw, ok := labels[candidate]
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err == nil {
			return v
		}
	}
	return fallback
}
