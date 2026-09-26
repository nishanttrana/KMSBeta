package crypto

import "errors"

// Shamir secret sharing over GF(2^8) (AES polynomial 0x11b), byte by byte.
// A share is [x, y_1..y_len(secret)] with x in 1..255. Polynomial
// coefficients come from the module DRBG (Reader). Field arithmetic is
// branch-free on data so recovery doesn't leak share bytes through timing.
//
// This is a split-knowledge procedure, not an encryption algorithm: fewer
// than k shares carry no information about the secret (docs/SECURITY/BACKUP_KEYS.md).

// MaxShares is the most shares a secret can be split into.
const MaxShares = 255

var (
	ErrShamirParams = errors.New("shamir: need 2 <= threshold <= shares <= 255 and a non-empty secret")
	ErrShamirShares = errors.New("shamir: shares must be at least two, of equal length, with distinct non-zero indexes")
)

// SplitSecret splits secret into n shares, any k of which recover it.
func SplitSecret(secret []byte, k, n int) ([][]byte, error) {
	if len(secret) == 0 || k < 2 || k > n || n > MaxShares {
		return nil, ErrShamirParams
	}
	coeffs := make([]byte, k-1)
	defer Zeroize(coeffs)
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, len(secret)+1)
		out[i][0] = byte(i + 1)
	}
	for b, s := range secret {
		if _, err := Reader.Read(coeffs); err != nil {
			for _, sh := range out {
				Zeroize(sh)
			}
			return nil, err
		}
		for i := range out {
			x := out[i][0]
			// Horner: s + c1*x + ... + c_{k-1}*x^{k-1}
			var y byte
			for c := len(coeffs) - 1; c >= 0; c-- {
				y = gfMul(y, x) ^ coeffs[c]
			}
			out[i][b+1] = gfMul(y, x) ^ s
		}
	}
	return out, nil
}

// CombineShares recovers the secret from shares by Lagrange interpolation at
// zero. Fewer than the split's threshold yields a wrong value, not an error:
// callers must check the result against a fingerprint.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 || len(shares) > MaxShares {
		return nil, ErrShamirShares
	}
	size := len(shares[0]) - 1
	if size <= 0 {
		return nil, ErrShamirShares
	}
	var seen [256]bool
	for _, sh := range shares {
		if len(sh) != size+1 || sh[0] == 0 || seen[sh[0]] {
			return nil, ErrShamirShares
		}
		seen[sh[0]] = true
	}
	// Lagrange basis at 0: l_i = prod_{j!=i} x_j / (x_i + x_j). Indexes are public.
	basis := make([]byte, len(shares))
	for i, si := range shares {
		num, den := byte(1), byte(1)
		for j, sj := range shares {
			if i != j {
				num = gfMul(num, sj[0])
				den = gfMul(den, si[0]^sj[0])
			}
		}
		basis[i] = gfMul(num, gfInv(den))
	}
	secret := make([]byte, size)
	for b := 0; b < size; b++ {
		var v byte
		for i, sh := range shares {
			v ^= gfMul(sh[b+1], basis[i])
		}
		secret[b] = v
	}
	return secret, nil
}

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= -(b & 1) & a
		a = (a << 1) ^ (0x1b & -(a >> 7))
		b >>= 1
	}
	return p
}

// gfInv returns a^254 = a^-1 (0 maps to 0) with a fixed multiply sequence.
func gfInv(a byte) byte {
	r := byte(1)
	sq := a
	for e := 254; e > 0; e >>= 1 {
		m := -byte(e & 1)
		r = (gfMul(r, sq) & m) | (r &^ m)
		sq = gfMul(sq, sq)
	}
	return r
}
