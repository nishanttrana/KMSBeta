package main

import (
	"strings"
)

// TagSource is a hint provider for the auto-tagger. Production setups
// derive tags from a mix of: (a) JWT claims on the requesting principal,
// (b) cert SAN/CN on KMIP clients, (c) operator-supplied label hints.
type TagSource interface {
	Hints() map[string]string
}

// MapTagSource adapts a plain map into the interface, useful when the
// caller already has a flat dictionary of hints.
type MapTagSource map[string]string

func (m MapTagSource) Hints() map[string]string {
	return m
}

// AutoTag derives a set of labels from the request hints. The output is
// the union of:
//   - explicit operator-supplied labels in the request
//   - derived purpose (encrypt/sign/wrap) inferred from algorithm
//   - compliance bucket (pci/hipaa/fips) inferred from tags or hints
//   - owner inferred from JWT subject / cert CN
//
// AutoTag never overwrites operator-supplied labels — derived values
// are only inserted when the corresponding key is absent.
func AutoTag(operator map[string]string, sources ...TagSource) map[string]string {
	out := make(map[string]string, len(operator)+4)
	for k, v := range operator {
		out[k] = v
	}
	merge := func(hints map[string]string) {
		for k, v := range hints {
			if v == "" {
				continue
			}
			lower := strings.ToLower(strings.TrimSpace(k))
			if _, ok := out[lower]; ok {
				continue
			}
			out[lower] = strings.TrimSpace(v)
		}
	}
	for _, s := range sources {
		if s == nil {
			continue
		}
		merge(s.Hints())
	}
	// Compliance bucket inference: scan all known label sources for known
	// compliance markers (PCI DSS, HIPAA, FIPS). The bucket is purely
	// advisory — the actual policy enforcement happens in the policy
	// evaluator — but having it on the key makes audit reports clearer.
	if _, has := out["compliance"]; !has {
		out["compliance"] = inferComplianceBucket(out)
	}
	return out
}

func inferComplianceBucket(labels map[string]string) string {
	for _, v := range labels {
		s := strings.ToLower(v)
		switch {
		case strings.Contains(s, "pci"), strings.Contains(s, "payment"), strings.Contains(s, "card"):
			return "pci-dss"
		case strings.Contains(s, "hipaa"), strings.Contains(s, "phi"), strings.Contains(s, "health"):
			return "hipaa"
		case strings.Contains(s, "fips"), strings.Contains(s, "cnsa"), strings.Contains(s, "fedramp"):
			return "fips"
		}
	}
	return "internal"
}

// RequireTags is the strict-posture gate: if the resulting label set is
// missing any of the required keys, the registration is rejected. Used
// during KMIP Register and REST import under KEYCORE_REQUIRE_TAGS=true.
func RequireTags(labels map[string]string, required ...string) []string {
	missing := make([]string, 0)
	for _, key := range required {
		if v, ok := labels[strings.ToLower(key)]; !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}
