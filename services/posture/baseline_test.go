package main

import (
	"fmt"
	"math"
	"testing"
)

func baselineOf(days int, auth func(i int) int) Baseline {
	b := Baseline{}
	for i := 0; i < days; i++ {
		b.Days = append(b.Days, SignalDay{Day: fmt.Sprintf("d%02d", i), Summary: SignalSummary{FailedAuthCount: auth(i)}})
	}
	return b
}

func pickAuth(s SignalSummary) int { return s.FailedAuthCount }

func TestTailsMatchKnownValues(t *testing.T) {
	near := func(got, want, tol float64) bool { return math.Abs(got-want) <= tol }
	// Poisson(10): P(X>=20) = 0.003454; P(X>=25) = 4.7e-5.
	if p := upperTail(20, 10, 10); !near(p, 0.003454, 1e-5) {
		t.Fatalf("poisson tail %v", p)
	}
	if p := upperTail(25, 10, 10); !near(p, 4.7e-5, 5e-6) {
		t.Fatalf("poisson tail %v", p)
	}
	// Overdispersion widens the tail: same mean, variance 40.
	if p := upperTail(25, 10, 40); p < 0.01 || p > 0.05 {
		t.Fatalf("negative binomial tail %v", p)
	}
	// Binomial(100, 0.05): P(X>=12) = 0.004274.
	if p := binomialUpperTail(12, 100, 0.05); !near(p, 0.004274, 1e-5) {
		t.Fatalf("binomial tail %v", p)
	}
	// The normal approximation takes over above the exact limit and agrees.
	if p := upperTail(exactTailLimit+1, 20000, 20000); !near(p, normalUpperTail(0.5/math.Sqrt(20000)), 1e-9) {
		t.Fatalf("normal tail %v", p)
	}
}

// No comparison is made before MinBaselineDays: nothing is unusual with
// 5, 10 or 13 days, however large the count.
func TestCountNeedsMinBaselineDays(t *testing.T) {
	for _, days := range []int{0, 1, 5, 10, MinBaselineDays - 1} {
		got := baselineOf(days, func(int) int { return 2 }).Count(10000, 25, pickAuth)
		if got.Assessed || got.Unusual {
			t.Fatalf("%d days: %+v", days, got)
		}
	}
	got := baselineOf(MinBaselineDays, func(int) int { return 2 }).Count(10000, 25, pickAuth)
	if !got.Assessed || !got.Unusual {
		t.Fatalf("%d days: %+v", MinBaselineDays, got)
	}
}

func TestCountJudgesAgainstTheTenantsOwnVariation(t *testing.T) {
	quiet := baselineOf(28, func(int) int { return 30 })
	if got := quiet.Count(35, 25, pickAuth); got.Unusual {
		t.Fatalf("35 against a steady 30 a day is normal: %+v", got)
	}
	if got := quiet.Count(70, 25, pickAuth); !got.Unusual {
		t.Fatalf("70 against a steady 30 a day is unusual: %+v", got)
	}
	// A tenant whose weekdays run at 200 and weekends at 20 is not spiking
	// on a Monday. The old rule (twice yesterday) flagged this every week.
	weekly := baselineOf(28, func(i int) int {
		if i%7 >= 5 {
			return 20
		}
		return 200
	})
	if got := weekly.Count(210, 25, pickAuth); got.Unusual {
		t.Fatalf("a normal weekday after a weekend is not a spike: %+v", got)
	}
	if got := weekly.Count(900, 25, pickAuth); !got.Unusual {
		t.Fatalf("900 is unusual even for this tenant: %+v", got)
	}
	// Statistically rare but below the floor: not an incident.
	if got := baselineOf(28, func(int) int { return 0 }).Count(4, 25, pickAuth); got.Unusual || got.P >= SpikeAlpha {
		t.Fatalf("below the floor must not be flagged (p=%v): %+v", got.P, got)
	}
	// An all-zero history followed by a real burst is flagged.
	if got := baselineOf(28, func(int) int { return 0 }).Count(40, 25, pickAuth); !got.Unusual {
		t.Fatalf("burst after silence: %+v", got)
	}
}

func TestRateNeedsEnoughBaselineEvents(t *testing.T) {
	ev := func(s SignalSummary) int { return s.KMIPEvents }
	fl := func(s SignalSummary) int { return s.KMIPFailures }
	mk := func(days, events, failures int) Baseline {
		b := Baseline{}
		for i := 0; i < days; i++ {
			b.Days = append(b.Days, SignalDay{Summary: SignalSummary{KMIPEvents: events, KMIPFailures: failures}})
		}
		return b
	}
	// 14 days x 20 events = 280 < MinRateEvents: shown, not judged.
	thin := mk(14, 20, 0).Rate(20, 20, ev, fl)
	if thin.Assessed || thin.Unusual || thin.BaselineEvents != 280 {
		t.Fatalf("thin baseline judged: %+v", thin)
	}
	// 14 days x 30 = 420 events at a 10% failure rate.
	b := mk(14, 30, 3)
	if got := b.Rate(30, 4, ev, fl); !got.Assessed || got.Unusual {
		t.Fatalf("4 of 30 against 10%% is normal: %+v", got)
	}
	if got := b.Rate(30, 14, ev, fl); !got.Unusual {
		t.Fatalf("14 of 30 against 10%% is unusual: %+v", got)
	}
	// Too few days, however many events.
	if got := mk(13, 1000, 10).Rate(1000, 900, ev, fl); got.Assessed {
		t.Fatalf("13 days judged: %+v", got)
	}
}
