package crypto

import (
	"bytes"
	"testing"
)

func refMul(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 == 1 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func TestGFArithmetic(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := gfMul(byte(a), byte(b)), refMul(byte(a), byte(b)); got != want {
				t.Fatalf("gfMul(%d,%d)=%d want %d", a, b, got, want)
			}
		}
		if a != 0 && gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("gfInv(%d) is not an inverse", a)
		}
	}
}

func TestShamirAnyThresholdSubsetRecovers(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := Reader.Read(secret); err != nil {
		t.Fatal(err)
	}
	shares, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				got, err := CombineShares([][]byte{shares[k], shares[i], shares[j]})
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("shares %d,%d,%d did not recover the secret", i, j, k)
				}
			}
		}
	}
	all, _ := CombineShares(shares)
	if !bytes.Equal(all, secret) {
		t.Fatal("all shares did not recover the secret")
	}
}

func TestShamirBelowThresholdDoesNotRecover(t *testing.T) {
	secret := bytes.Repeat([]byte{0xA5}, 32)
	shares, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CombineShares(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("two shares of a 3-of-5 split recovered the secret")
	}
}

func TestShamirRejectsBadInput(t *testing.T) {
	s := []byte("0123456789abcdef")
	for _, p := range [][2]int{{1, 3}, {4, 3}, {2, 256}} {
		if _, err := SplitSecret(s, p[0], p[1]); err == nil {
			t.Fatalf("SplitSecret(k=%d,n=%d) accepted", p[0], p[1])
		}
	}
	if _, err := SplitSecret(nil, 2, 3); err == nil {
		t.Fatal("empty secret accepted")
	}
	shares, _ := SplitSecret(s, 2, 3)
	for name, in := range map[string][][]byte{
		"one share":       shares[:1],
		"duplicate index": {shares[0], shares[0]},
		"zero index":      {append([]byte{0}, shares[0][1:]...), shares[1]},
		"length mismatch": {shares[0], shares[1][:5]},
	} {
		if _, err := CombineShares(in); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
