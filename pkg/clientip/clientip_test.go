package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = remote
	for _, v := range forwarded {
		r.Header.Add(Header, v)
	}
	return r
}

// Whatever a caller writes into the header, the answer is the entry the edge
// appended after it.
func TestFromIsTheEntryTheEdgeAppended(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remote    string
		forwarded []string
		want      string
	}{
		{"through the edge", "172.18.0.9:41000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"a forged first entry", "172.18.0.9:41000", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		{"many forged entries", "172.18.0.9:41000", []string{"10.0.0.1, 127.0.0.1,::1 , 198.51.100.7"}, "198.51.100.7"},
		{"forged entries on their own header line", "172.18.0.9:41000", []string{"203.0.113.9", "10.9.9.9, 198.51.100.7"}, "198.51.100.7"},
		{"an IPv6 client", "172.18.0.9:41000", []string{"203.0.113.9, 2001:db8::7"}, "2001:db8::7"},
		{"an IPv4-mapped address", "172.18.0.9:41000", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"no proxy: another service", "172.18.0.5:41000", nil, "172.18.0.5"},
		{"no proxy, IPv6 peer", "[fd00::5]:41000", nil, "fd00::5"},
		// A last entry that is not an address is not the edge's: fall back to
		// the peer, never to an earlier entry.
		{"a last entry that is not an address", "172.18.0.9:41000", []string{"198.51.100.7, unknown"}, "172.18.0.9"},
		{"a trailing comma", "172.18.0.9:41000", []string{"198.51.100.7,"}, "172.18.0.9"},
		{"an empty header", "172.18.0.9:41000", []string{""}, "172.18.0.9"},
		{"a host name", "172.18.0.9:41000", []string{"localhost"}, "172.18.0.9"},
		{"an address with a port", "172.18.0.9:41000", []string{"198.51.100.7:443"}, "172.18.0.9"},
	} {
		if got := From(req(tc.remote, tc.forwarded...)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if From(nil) != "" {
		t.Error("a nil request has no address")
	}
}

func TestSetReplacesWhatTheHeaderHeld(t *testing.T) {
	r := req("172.18.0.9:41000", "203.0.113.9", "10.9.9.9")
	Set(r, " 198.51.100.7 ")
	if got := r.Header.Values(Header); len(got) != 1 || got[0] != "198.51.100.7" || From(r) != "198.51.100.7" {
		t.Fatalf("after Set: %q, From %q", got, From(r))
	}
	// Something that is not an address is not recorded, and the old value is
	// not left behind either.
	Set(r, "198.51.100.7, 203.0.113.9")
	if got := r.Header.Values(Header); len(got) != 0 || From(r) != "172.18.0.9" {
		t.Fatalf("after Set with a list: %q, From %q", got, From(r))
	}
}
