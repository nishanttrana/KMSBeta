package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

const fpeAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

func toNumerals(t *testing.T, s string) []uint16 {
	t.Helper()
	out := make([]uint16, len(s))
	for i, r := range s {
		out[i] = uint16(strings.IndexRune(fpeAlphabet, r))
	}
	return out
}

func fromNumerals(x []uint16) string {
	var b strings.Builder
	for _, d := range x {
		b.WriteByte(fpeAlphabet[d])
	}
	return b.String()
}

// NIST SP 800-38G FF1 sample vectors (CSRC "FF1samples.pdf").
func TestFF1NISTSamples(t *testing.T) {
	const k128 = "2B7E151628AED2A6ABF7158809CF4F3C"
	const k192 = k128 + "EF4359D8D580AA4F"
	const k256 = k192 + "7F036D6F04FC6A94"
	cases := []struct {
		name, key, tweak string
		radix            int
		pt, ct           string
	}{
		{"sample1", k128, "", 10, "0123456789", "2433477484"},
		{"sample2", k128, "39383736353433323130", 10, "0123456789", "6124200773"},
		{"sample3", k128, "3737373770717273373737", 36, "0123456789abcdefghi", "a9tv40mll9kdu509eum"},
		{"sample4", k192, "", 10, "0123456789", "2830668132"},
		{"sample5", k192, "39383736353433323130", 10, "0123456789", "2496655549"},
		{"sample6", k192, "3737373770717273373737", 36, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"},
		{"sample7", k256, "", 10, "0123456789", "6657667009"},
		{"sample8", k256, "39383736353433323130", 10, "0123456789", "1001623463"},
		{"sample9", k256, "3737373770717273373737", 36, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tc.key)
			tweak, _ := hex.DecodeString(tc.tweak)
			ct, err := FF1Encrypt(key, tweak, tc.radix, toNumerals(t, tc.pt))
			if err != nil {
				t.Fatal(err)
			}
			if got := fromNumerals(ct); got != tc.ct {
				t.Fatalf("encrypt = %s, want %s", got, tc.ct)
			}
			pt, err := FF1Decrypt(key, tweak, tc.radix, ct)
			if err != nil {
				t.Fatal(err)
			}
			if got := fromNumerals(pt); got != tc.pt {
				t.Fatalf("decrypt = %s, want %s", got, tc.pt)
			}
		})
	}
}

// The additive-keystream "FF1" this replaced leaked plaintext differences:
// c1 - c2 = p1 - p2 per digit. Real FF1 must not.
func TestFF1IsNotAnAdditiveKeystream(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	c1, _ := FF1Encrypt(key, nil, 10, toNumerals(t, "4111111111111111"))
	c2, _ := FF1Encrypt(key, nil, 10, toNumerals(t, "4111111111111112"))
	same := 0
	for i := range c1 {
		if c1[i] == c2[i] {
			same++
		}
	}
	if same >= len(c1)-1 {
		t.Fatalf("one-digit plaintext change moved %d of %d ciphertext digits", len(c1)-same, len(c1))
	}
}

func TestFF1RejectsBadInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := FF1Encrypt(key, nil, 10, toNumerals(t, "12345")); err == nil {
		t.Fatal("accepted a domain below 10^6")
	}
	if _, err := FF1Encrypt(make([]byte, 7), nil, 10, toNumerals(t, "0123456789")); err == nil {
		t.Fatal("accepted a non-AES key")
	}
	if _, err := FF1Encrypt(key, nil, 10, []uint16{1, 2, 3, 4, 5, 6, 10}); err == nil {
		t.Fatal("accepted a numeral outside the radix")
	}
	if FF1MinLength(10) != 6 || FF1MinLength(36) != 4 || FF1MinLength(2) != 20 {
		t.Fatal("FF1MinLength does not match SP 800-38G")
	}
}
