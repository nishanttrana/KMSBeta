package deployed

import "testing"

// Only a known list that leaves the profile out means "not deployed"; an
// unknown list fails closed (deployed).
func TestUnknownProfilesCountAsDeployed(t *testing.T) {
	for _, c := range []struct {
		profiles string
		want     bool
	}{{"", true}, {"  ", true}, {"cloud_byok,hsm_hardware", true}, {"hsm_hardware, cloud_byok", true}, {"ekm_database", false}} {
		if got := in(c.profiles, "cloud_byok"); got != c.want {
			t.Fatalf("in(%q) = %v, want %v", c.profiles, got, c.want)
		}
	}
}
