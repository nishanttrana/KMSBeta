package audit

import (
	"regexp"
	"time"
)

// MeteredOp is the details key that marks an audit event as one
// cryptographic operation. The audit service builds the Operations metrics
// (throughput, latency, errors) from every persisted event that carries it,
// using the event's service, its duration_ms and its result (success,
// refused or failure). An event without it is never counted, so a metric
// exists only for an operation whose own event says it ran, was refused or
// failed.
const MeteredOp = "metered_op"

var meteredOpName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// ValidMeteredOp reports whether op is a well-formed operation name
// (lower-case, digits and underscores, at most 40 characters).
func ValidMeteredOp(op string) bool { return meteredOpName.MatchString(op) }

// Metered marks details as the event of operation op that started at start:
// it sets MeteredOp and the measured duration_ms (microsecond resolution).
func Metered(details map[string]any, op string, start time.Time) map[string]any {
	if details == nil {
		details = map[string]any{}
	}
	details[MeteredOp] = op
	details["duration_ms"] = DurationMS(start)
	return details
}

// DurationMS is the time since start in milliseconds, to the microsecond.
func DurationMS(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}
