// Package timebucket splits an analytics window into chart buckets. Every
// service uses it, so a dashboard window (last day, week, month, 6 months,
// year, or since uptime) has the same buckets on every chart.
package timebucket

import "time"

// MaxBuckets bounds the points on one chart.
const MaxBuckets = 60

const day = 24 * time.Hour

// Width is the bucket width for a window: hourly for a day, 6-hourly for a
// week, daily for a month, weekly up to a year, then whole days sized to stay
// within MaxBuckets.
func Width(from, to time.Time) time.Duration {
	span := to.Sub(from)
	switch {
	case span <= 25*time.Hour:
		return time.Hour
	case span <= 8*day:
		return 6 * time.Hour
	case span <= 32*day:
		return day
	case span <= 400*day:
		return 7 * day
	default:
		return time.Duration(int64(span/day)/MaxBuckets+1) * day
	}
}

// Buckets returns the bucket starts covering [from, to] in UTC, aligned to the
// width (weekly buckets start on Monday), and the width.
func Buckets(from, to time.Time) ([]time.Time, time.Duration) {
	from, to = from.UTC(), to.UTC()
	if to.Before(from) {
		return nil, 0
	}
	w := Width(from, to)
	var out []time.Time
	for t := from.Truncate(w); !t.After(to); t = t.Add(w) {
		out = append(out, t)
	}
	return out, w
}

// Index is the bucket holding t, or -1 when t is outside the buckets.
func Index(starts []time.Time, w time.Duration, t time.Time) int {
	if len(starts) == 0 || t.Before(starts[0]) {
		return -1
	}
	i := int(t.Sub(starts[0]) / w)
	if i >= len(starts) {
		return -1
	}
	return i
}
