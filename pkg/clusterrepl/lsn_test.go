package clusterrepl

import "testing"

func TestParseLSN(t *testing.T) {
	for in, want := range map[string]uint64{"": 0, "0/0": 0, "0/16B3748": 0x16B3748, "16/B374D848": 0x16B374D848} {
		got, err := ParseLSN(in)
		if err != nil || got != want {
			t.Fatalf("%q: %x %v", in, got, err)
		}
	}
	a, _ := ParseLSN("1/0")
	b, _ := ParseLSN("0/FFFFFFFF")
	if a <= b {
		t.Fatal("1/0 must follow 0/FFFFFFFF")
	}
	for _, bad := range []string{"16", "x/1", "1/zz"} {
		if _, err := ParseLSN(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
