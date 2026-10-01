package main

import (
	"math"
	"time"
)

// The posture baseline (docs/SECURITY/POSTURE_BASELINE.md).
//
// A baseline is the tenant's own history: one signal summary per complete UTC
// day, from audit events posture has read in full. "Unusual" is judged
// against it with a significance test, never against a single previous day.
//
//   - MinBaselineDays of history are needed before any comparison is made or
//     a risk score is given: two weekly cycles, so weekday and weekend
//     behaviour are both in the sample. Before that posture reports
//     "baseline building" and the score is not assessed.
//   - StableBaselineDays is the window the baseline covers once available.
//   - A count (failed logins a day) is unusual when the chance of seeing that
//     many or more, given the baseline's mean and day-to-day variance, is
//     below SpikeAlpha, and the count also reaches the signal's floor (a
//     statistically rare 3 failed logins is not an incident).
//   - A failure rate needs MinRateEvents baseline events: with fewer, the
//     95% margin of error on the rate is wider than ±5 points, so the rate
//     is shown but not judged.
const (
	MinBaselineDays    = 14
	StableBaselineDays = 28
	SpikeAlpha         = 0.001
	MinRateEvents      = 385
)

// Baseline is the tenant's finalized days, oldest first.
type Baseline struct {
	Days          []SignalDay
	From          time.Time // observation of this tenant starts here
	SyncedThrough time.Time // audit events are read in full up to here
}

type SignalDay struct {
	Day     string // UTC, 2006-01-02
	Summary SignalSummary
}

func (b Baseline) Ready() bool  { return len(b.Days) >= MinBaselineDays }
func (b Baseline) Stable() bool { return len(b.Days) >= StableBaselineDays }

// CountTest is the outcome of judging a 24h count against the baseline.
type CountTest struct {
	Assessed bool    `json:"assessed"`
	Unusual  bool    `json:"unusual"`
	Current  int     `json:"current_24h"`
	Mean     float64 `json:"baseline_daily_mean"`
	StdDev   float64 `json:"baseline_daily_stddev"`
	Days     int     `json:"baseline_days"`
	P        float64 `json:"p_value"`
	Floor    int     `json:"floor"`
}

// Count judges current against the daily values pick selects. It is unusual
// only when the baseline is ready, current reaches floor, and the upper-tail
// probability is below SpikeAlpha.
func (b Baseline) Count(current int, floor int, pick func(SignalSummary) int) CountTest {
	out := CountTest{Current: current, Days: len(b.Days), Floor: floor, P: 1}
	if !b.Ready() {
		return out
	}
	var sum, sumSq float64
	for _, d := range b.Days {
		v := float64(pick(d.Summary))
		sum += v
		sumSq += v * v
	}
	n := float64(len(b.Days))
	// Half an event of prior weight keeps an all-zero history from claiming
	// certainty that the rate is exactly zero.
	mean := (sum + 0.5) / n
	variance := 0.0
	if n > 1 {
		variance = math.Max(0, (sumSq-sum*sum/n)/(n-1))
	}
	out.Assessed, out.Mean, out.StdDev = true, sum/n, math.Sqrt(variance)
	out.P = upperTail(current, mean, variance)
	out.Unusual = current >= floor && out.P < SpikeAlpha
	return out
}

// RateTest is the outcome of judging a 24h failure rate against the baseline.
type RateTest struct {
	Assessed       bool    `json:"assessed"`
	Unusual        bool    `json:"unusual"`
	Events         int     `json:"events_24h"`
	Failures       int     `json:"failures_24h"`
	Rate           float64 `json:"failure_rate_24h"`
	BaselineEvents int     `json:"baseline_events"`
	BaselineRate   float64 `json:"baseline_failure_rate"`
	Days           int     `json:"baseline_days"`
	P              float64 `json:"p_value"`
	RequiredEvents int     `json:"required_baseline_events"`
}

// rateFloor is the fewest failures in 24h that can make a rate unusual.
const rateFloor = 3

// Rate judges failures out of events against the baseline's pooled failure
// rate with a one-sided binomial test. It is not assessed until the baseline
// is ready and holds MinRateEvents events for this signal.
func (b Baseline) Rate(events, failures int, pickEvents, pickFailures func(SignalSummary) int) RateTest {
	out := RateTest{Events: events, Failures: failures, Days: len(b.Days), P: 1, RequiredEvents: MinRateEvents}
	if events > 0 {
		out.Rate = float64(failures) / float64(events)
	}
	var n, f int
	for _, d := range b.Days {
		n += pickEvents(d.Summary)
		f += pickFailures(d.Summary)
	}
	out.BaselineEvents = n
	if n > 0 {
		out.BaselineRate = float64(f) / float64(n)
	}
	if !b.Ready() || n < MinRateEvents {
		return out
	}
	out.Assessed = true
	if events <= 0 || failures <= 0 {
		return out
	}
	p0 := (float64(f) + 0.5) / (float64(n) + 1)
	out.P = binomialUpperTail(failures, events, p0)
	out.Unusual = failures >= rateFloor && out.P < SpikeAlpha
	return out
}

// Mean is the baseline's mean of the daily values pick selects, over days
// where it is positive (a latency average on days the component was used),
// and how many such days there were.
func (b Baseline) Mean(pick func(SignalSummary) float64) (float64, int) {
	var sum float64
	n := 0
	for _, d := range b.Days {
		if v := pick(d.Summary); v > 0 {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return sum / float64(n), n
}

// SumLast sums pick over the newest n days, skipping the newest skip days.
func (b Baseline) SumLast(skip, n int, pick func(SignalSummary) int) int {
	total := 0
	end := len(b.Days) - skip
	for i := max(0, end-n); i < end; i++ {
		total += pick(b.Days[i].Summary)
	}
	return total
}

// exactTailLimit bounds the exact summations; beyond it the normal
// approximation is accurate to far better than SpikeAlpha needs.
const exactTailLimit = 20000

// upperTail is P(X >= x) for a daily count with the given mean and variance:
// Poisson when the variance does not exceed the mean, negative binomial
// (which allows day-to-day swings such as weekdays against weekends) when it
// does.
func upperTail(x int, mean, variance float64) float64 {
	if x <= 0 {
		return 1
	}
	if mean <= 0 {
		return 0
	}
	if x > exactTailLimit {
		return normalUpperTail((float64(x) - 0.5 - mean) / math.Sqrt(math.Max(variance, mean)))
	}
	logPMF := func(k int) float64 { // Poisson
		lg, _ := math.Lgamma(float64(k) + 1)
		return float64(k)*math.Log(mean) - mean - lg
	}
	if variance > mean*1.0001 {
		r := mean * mean / (variance - mean)
		p := r / (r + mean)
		lgR, _ := math.Lgamma(r)
		logPMF = func(k int) float64 {
			a, _ := math.Lgamma(float64(k) + r)
			c, _ := math.Lgamma(float64(k) + 1)
			return a - c - lgR + r*math.Log(p) + float64(k)*math.Log1p(-p)
		}
	}
	cdf := 0.0
	for k := 0; k < x; k++ {
		cdf += math.Exp(logPMF(k))
	}
	return clamp01(1 - cdf)
}

// binomialUpperTail is P(X >= f) for X ~ Binomial(n, p).
func binomialUpperTail(f, n int, p float64) float64 {
	switch {
	case f <= 0:
		return 1
	case f > n || p <= 0:
		return 0
	case p >= 1:
		return 1
	}
	if n > exactTailLimit {
		mean := float64(n) * p
		return normalUpperTail((float64(f) - 0.5 - mean) / math.Sqrt(mean*(1-p)))
	}
	lgN, _ := math.Lgamma(float64(n) + 1)
	tail := 0.0
	for k := f; k <= n; k++ {
		a, _ := math.Lgamma(float64(k) + 1)
		c, _ := math.Lgamma(float64(n-k) + 1)
		tail += math.Exp(lgN - a - c + float64(k)*math.Log(p) + float64(n-k)*math.Log1p(-p))
	}
	return clamp01(tail)
}

func normalUpperTail(z float64) float64 { return 0.5 * math.Erfc(z/math.Sqrt2) }

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// BaselineStatus is what the dashboard shows while the baseline builds and
// after: how much history exists against what is needed, per signal.
type BaselineStatus struct {
	Ready         bool             `json:"ready"`
	Stable        bool             `json:"stable"`
	Days          int              `json:"days"`
	RequiredDays  int              `json:"required_days"`
	StableDays    int              `json:"stable_days"`
	From          *time.Time       `json:"from,omitempty"`
	SyncedThrough *time.Time       `json:"synced_through,omitempty"`
	SpikeAlpha    float64          `json:"spike_alpha"`
	Signals       []BaselineSignal `json:"signals"`
}

// BaselineSignal is one signal's standing. Status is "building" (fewer than
// MinBaselineDays), "needs_events" (a rate with too few baseline events to
// judge) or "ready".
type BaselineSignal struct {
	Key            string  `json:"key"`
	Label          string  `json:"label"`
	Kind           string  `json:"kind"` // count | rate
	Status         string  `json:"status"`
	Current24h     int     `json:"current_24h"`
	DailyMean      float64 `json:"baseline_daily_mean"`
	Floor          int     `json:"floor,omitempty"`
	Events24h      int     `json:"events_24h,omitempty"`
	BaselineEvents int     `json:"baseline_events,omitempty"`
	RequiredEvents int     `json:"required_baseline_events,omitempty"`
	BaselineRate   float64 `json:"baseline_failure_rate,omitempty"`
	Unusual        bool    `json:"unusual"`
	P              float64 `json:"p_value"`
}

// countSignals and rateSignals are the signals judged against the baseline,
// with the floors and picks the engines use.
var countSignals = []struct {
	key, label string
	floor      int
	pick       func(SignalSummary) int
}{
	{"failed_auth", "Failed authentication", 25, func(d SignalSummary) int { return d.FailedAuthCount }},
	{"failed_crypto", "Refused or failed key operations", 10, func(d SignalSummary) int { return d.FailedCryptoCount }},
	{"refused_requests", "Refused requests (all services)", 20, func(d SignalSummary) int { return d.PolicyDenyCount }},
	{"connector_failures", "Connector failures", 6, func(d SignalSummary) int { return d.ConnectorFailures }},
	{"deletions", "Keys and certificates destroyed", 5, func(d SignalSummary) int { return d.KeyDeleteCount + d.CertDeleteCount }},
	{"denied_approvals", "Denied approvals", 3, func(d SignalSummary) int { return d.DeniedApprovalCount }},
}

var rateSignals = []struct {
	key, label       string
	events, failures func(SignalSummary) int
}{
	{"byok", "BYOK failure rate", func(d SignalSummary) int { return d.BYOKEvents }, func(d SignalSummary) int { return d.BYOKFailures }},
	{"hyok", "HYOK failure rate", func(d SignalSummary) int { return d.HYOKEvents }, func(d SignalSummary) int { return d.HYOKFailures }},
	{"ekm", "EKM failure rate", func(d SignalSummary) int { return d.EKMEvents }, func(d SignalSummary) int { return d.EKMFailures }},
	{"kmip", "KMIP failure rate", func(d SignalSummary) int { return d.KMIPEvents }, func(d SignalSummary) int { return d.KMIPFailures }},
	{"bitlocker", "BitLocker failure rate", func(d SignalSummary) int { return d.BitLockerEvents }, func(d SignalSummary) int { return d.BitLockerFailures }},
	{"sdk", "SDK / wrapper failure rate", func(d SignalSummary) int { return d.SDKEvents }, func(d SignalSummary) int { return d.SDKFailures }},
}

func baselineStatus(b Baseline, current24 SignalSummary) BaselineStatus {
	out := BaselineStatus{
		Ready: b.Ready(), Stable: b.Stable(), Days: len(b.Days),
		RequiredDays: MinBaselineDays, StableDays: StableBaselineDays, SpikeAlpha: SpikeAlpha,
		Signals: make([]BaselineSignal, 0, len(countSignals)+len(rateSignals)),
	}
	if !b.From.IsZero() {
		out.From = &b.From
	}
	if !b.SyncedThrough.IsZero() {
		out.SyncedThrough = &b.SyncedThrough
	}
	status := func(assessed bool) string {
		switch {
		case !b.Ready():
			return "building"
		case !assessed:
			return "needs_events"
		}
		return "ready"
	}
	for _, c := range countSignals {
		t := b.Count(c.pick(current24), c.floor, c.pick)
		mean := 0.0
		if n := len(b.Days); n > 0 {
			mean = float64(b.SumLast(0, n, c.pick)) / float64(n)
		}
		out.Signals = append(out.Signals, BaselineSignal{Key: c.key, Label: c.label, Kind: "count", Status: status(t.Assessed),
			Current24h: t.Current, DailyMean: mean, Floor: c.floor, Unusual: t.Unusual, P: t.P})
	}
	for _, r := range rateSignals {
		t := b.Rate(r.events(current24), r.failures(current24), r.events, r.failures)
		out.Signals = append(out.Signals, BaselineSignal{Key: r.key, Label: r.label, Kind: "rate", Status: status(t.Assessed),
			Current24h: t.Failures, Events24h: t.Events, BaselineEvents: t.BaselineEvents, RequiredEvents: MinRateEvents,
			BaselineRate: t.BaselineRate, Unusual: t.Unusual, P: t.P})
	}
	return out
}
