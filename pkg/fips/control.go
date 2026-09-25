package fips

import (
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// Platform FIPS mode control (docs/SECURITY/FIPS.md, "Changing the mode").
//
// The mode is a platform setting a root administrator changes in the KMS UI
// (governance stores it). Go fixes GODEBUG=fips140 at process start, so a
// change takes effect by restarting each service: the service shuts down
// gracefully, its supervisor restarts it, and at startup it re-executes itself
// with the desired GODEBUG before any cryptography runs. VECTA_FIPS_MODE from
// the deployment only seeds the mode until an administrator sets one.

// ReexecMarker is set on a re-executed process; a second mismatch is fatal
// instead of looping.
const ReexecMarker = "VECTA_FIPS_REEXEC"

// ValidMode reports whether m is one of on, only, off.
func ValidMode(m string) bool {
	return m == ModeOn || m == ModeOnly || m == ModeOff
}

// Decide returns the mode this process must run in and whether it has to
// re-execute to get there. desired is the administrator's platform setting
// ("" when never set), seed is VECTA_FIPS_MODE from the deployment, running is
// Mode(). With neither set, the process runs as started.
func Decide(desired, seed, running string, reexeced bool) (string, bool, error) {
	target := strings.ToLower(strings.TrimSpace(desired))
	if target == "" {
		target = strings.ToLower(strings.TrimSpace(seed))
	}
	if target == "" {
		return running, false, nil
	}
	if !ValidMode(target) {
		return "", false, fmt.Errorf("FIPS mode %q is invalid; use on, only or off", target)
	}
	if target == running {
		return target, false, nil
	}
	if reexeced {
		return "", false, fmt.Errorf("re-executed with GODEBUG=fips140=%s but the runtime reports %q", target, running)
	}
	return target, true, nil
}

// ReexecEnv returns environ with VECTA_FIPS_MODE and the fips140 GODEBUG
// setting replaced by target (other GODEBUG settings are kept) and the
// re-exec marker set.
func ReexecEnv(environ []string, target string) []string {
	out := make([]string, 0, len(environ)+3)
	godebug := []string{}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		switch name {
		case "VECTA_FIPS_MODE", ReexecMarker:
			continue
		case "GODEBUG":
			for _, part := range strings.Split(value, ",") {
				if p := strings.TrimSpace(part); p != "" && !strings.HasPrefix(p, "fips140=") {
					godebug = append(godebug, p)
				}
			}
			continue
		}
		out = append(out, kv)
	}
	godebug = append(godebug, "fips140="+target)
	return append(out, "VECTA_FIPS_MODE="+target, "GODEBUG="+strings.Join(godebug, ","), ReexecMarker+"=1")
}

// RestartDelay staggers mode-change restarts so the platform never goes down
// at once: edge services first (0-20s), the core crypto and identity services
// next (40-45s), governance, which drives the change and shows its progress,
// last (60s).
func RestartDelay(service string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(service))
	jitter := time.Duration(h.Sum32()%20) * time.Second
	switch service {
	case "kms-governance":
		return 60 * time.Second
	case "kms-auth", "kms-keycore", "kms-audit", "kms-policy":
		return 40*time.Second + jitter%(5*time.Second)
	}
	return jitter
}

// ModeRank orders modes by assurance (off < on < only); a change to a lower
// rank is a security downgrade.
func ModeRank(m string) int {
	switch m {
	case ModeOnly:
		return 2
	case ModeOn:
		return 1
	}
	return 0
}
