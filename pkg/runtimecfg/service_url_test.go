package runtimecfg

import "testing"

// A platform service's address is https with a host; anything else is
// refused at startup (the reconciler's defaults were plain http until
// 13.4.0-beta).
func TestValidateServiceURL(t *testing.T) {
	for _, ok := range []string{"https://keycore:8010", " https://policy:8040 ", "https://keycore.internal"} {
		if err := ValidateServiceURL("KEYCORE_URL", ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://keycore:8010", "keycore:8010", "https://", "nats://keycore:8010"} {
		if err := ValidateServiceURL("KEYCORE_URL", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
