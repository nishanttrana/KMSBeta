package fips

import (
	"strings"
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name, desired, seed, running string
		reexeced                     bool
		want                         string
		reexec, wantErr              bool
	}{
		{"nothing set follows runtime", "", "", ModeOn, false, ModeOn, false, false},
		{"seed only, matching", "", "on", ModeOn, false, ModeOn, false, false},
		{"admin setting wins over seed", "off", "on", ModeOn, false, ModeOff, true, false},
		{"already in desired mode", "only", "on", ModeOnly, false, ModeOnly, false, false},
		{"invalid value", "true", "", ModeOn, false, "", false, true},
		{"re-exec that did not converge is fatal", "only", "", ModeOn, true, "", false, true},
	}
	for _, tc := range cases {
		got, reexec, err := Decide(tc.desired, tc.seed, tc.running, tc.reexeced)
		if (err != nil) != tc.wantErr || got != tc.want || reexec != tc.reexec {
			t.Errorf("%s: got (%q,%v,%v)", tc.name, got, reexec, err)
		}
	}
}

func TestReexecEnvReplacesOnlyFIPSSettings(t *testing.T) {
	env := ReexecEnv([]string{"PATH=/bin", "GODEBUG=fips140=on,http2debug=1", "VECTA_FIPS_MODE=on"}, ModeOff)
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/bin", "VECTA_FIPS_MODE=off", "GODEBUG=http2debug=1,fips140=off", ReexecMarker + "=1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, env)
		}
	}
	if strings.Contains(joined, "fips140=on") || strings.Count(joined, "VECTA_FIPS_MODE=") != 1 {
		t.Fatalf("old FIPS settings must be replaced: %v", env)
	}
}

func TestRestartDelayOrdersTiers(t *testing.T) {
	if d := RestartDelay("kms-governance"); d != 60*time.Second {
		t.Fatalf("governance restarts last, got %v", d)
	}
	for _, core := range []string{"kms-auth", "kms-keycore", "kms-audit", "kms-policy"} {
		if d := RestartDelay(core); d < 40*time.Second || d >= 60*time.Second {
			t.Fatalf("%s must restart in the core tier, got %v", core, d)
		}
	}
	if d := RestartDelay("kms-dataprotect"); d >= 20*time.Second {
		t.Fatalf("edge services restart first, got %v", d)
	}
}

func TestTransitionImpact(t *testing.T) {
	stops, starts, notes := TransitionImpact(ModeOn, ModeOnly)
	if len(stops) == 0 || len(starts) != 0 {
		t.Fatalf("on->only must list stopped features: %v %v", stops, starts)
	}
	stops, starts, _ = TransitionImpact(ModeOnly, ModeOff)
	if len(starts) == 0 || len(stops) != 0 {
		t.Fatalf("only->off must list resumed features: %v %v", stops, starts)
	}
	_, _, notes = TransitionImpact(ModeOn, ModeOff)
	if !strings.Contains(strings.Join(notes, " "), "downgrade") {
		t.Fatalf("on->off must warn about the downgrade: %v", notes)
	}
}
