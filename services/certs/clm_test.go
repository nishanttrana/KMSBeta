package main

import (
	"testing"
	"time"
)

func TestCABForumSchedule(t *testing.T) {
	cases := []struct {
		date string
		want int64
	}{
		{"2025-12-01", 398},
		{"2026-03-15", 200},
		{"2026-06-11", 200},
		{"2027-03-15", 100},
		{"2028-12-31", 100},
		{"2029-03-15", 47},
		{"2030-01-01", 47},
	}
	for _, c := range cases {
		at, _ := time.Parse("2006-01-02", c.date)
		if got := cabForumMaxValidityDays(at); got != c.want {
			t.Errorf("cabForumMaxValidityDays(%s) = %d, want %d", c.date, got, c.want)
		}
	}
}

func TestEffectiveMaxValidityDays(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-06-11") // CA/B schedule: 200d

	p := defaultCLMPolicy("t1") // warn, 47d, schedule-aware
	if got := effectiveMaxValidityDays(p, now); got != 47 {
		t.Errorf("default policy: got %d, want 47 (policy stricter than schedule)", got)
	}

	p.MaxValidityDays = 365
	if got := effectiveMaxValidityDays(p, now); got != 200 {
		t.Errorf("loose policy: got %d, want 200 (schedule stricter than policy)", got)
	}

	p.ScheduleAware = false
	if got := effectiveMaxValidityDays(p, now); got != 365 {
		t.Errorf("schedule-unaware: got %d, want 365", got)
	}

	p.Mode = CLMModeOff
	if got := effectiveMaxValidityDays(p, now); got != 0 {
		t.Errorf("off mode: got %d, want 0 (no cap)", got)
	}
}

func TestCLMAppliesTo(t *testing.T) {
	for _, certType := range []string{"tls-server", "tls-client", "TLS-Server"} {
		if !clmAppliesTo(certType) {
			t.Errorf("clmAppliesTo(%q) = false, want true", certType)
		}
	}
	for _, certType := range []string{"email", "code-signing", "ca", ""} {
		if clmAppliesTo(certType) {
			t.Errorf("clmAppliesTo(%q) = true, want false", certType)
		}
	}
}
