package crypto

import "testing"

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Fatal("expected equal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Fatal("expected not equal")
	}
}
