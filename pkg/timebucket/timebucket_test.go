package timebucket

import (
	"testing"
	"time"
)

func TestWindowsStayWithinMaxBuckets(t *testing.T) {
	to := time.Date(2026, 9, 30, 13, 45, 0, 0, time.UTC)
	for _, c := range []struct {
		span  time.Duration
		width time.Duration
	}{
		{24 * time.Hour, time.Hour},
		{7 * day, 6 * time.Hour},
		{30 * day, day},
		{182 * day, 7 * day},
		{365 * day, 7 * day},
		{5 * 365 * day, 31 * day},
	} {
		starts, w := Buckets(to.Add(-c.span), to)
		if w != c.width {
			t.Fatalf("span %v: width %v, want %v", c.span, w, c.width)
		}
		if len(starts) == 0 || len(starts) > MaxBuckets+2 {
			t.Fatalf("span %v: %d buckets", c.span, len(starts))
		}
		if last := starts[len(starts)-1]; last.After(to) || !last.Add(w).After(to) {
			t.Fatalf("span %v: last bucket %v does not hold %v", c.span, last, to)
		}
	}
}

func TestIndex(t *testing.T) {
	to := time.Date(2026, 9, 30, 13, 45, 0, 0, time.UTC)
	starts, w := Buckets(to.Add(-24*time.Hour), to)
	if got := Index(starts, w, to); got != len(starts)-1 {
		t.Fatalf("now in bucket %d, want last %d", got, len(starts)-1)
	}
	if Index(starts, w, starts[0].Add(-time.Second)) != -1 || Index(starts, w, starts[len(starts)-1].Add(w)) != -1 {
		t.Fatal("times outside the buckets must give -1")
	}
	if got := Index(starts, w, starts[3].Add(59*time.Minute)); got != 3 {
		t.Fatalf("index %d, want 3", got)
	}
}
