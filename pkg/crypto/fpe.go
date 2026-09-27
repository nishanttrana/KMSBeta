package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/big"
)

// FF1 format-preserving encryption, NIST SP 800-38G section 5.1, over the
// certified module's AES. The FF1 construction itself is outside the module's
// validation scope (docs/SECURITY/FIPS.md). Numerals are digit values in
// [0, radix); callers map their alphabet to and from them.

const (
	ff1Rounds    = 10
	ff1MaxLen    = 4096 // practical bound; SP 800-38G allows up to 2^32
	ff1MaxTweak  = 256
	ff1MinDomain = 1000000 // SP 800-38G: radix^minlen >= 1,000,000
)

// FF1Encrypt encrypts numeral string x under an AES-128/192/256 key.
func FF1Encrypt(key, tweak []byte, radix int, x []uint16) ([]uint16, error) {
	return ff1(key, tweak, radix, x, true)
}

// FF1Decrypt inverts FF1Encrypt.
func FF1Decrypt(key, tweak []byte, radix int, x []uint16) ([]uint16, error) {
	return ff1(key, tweak, radix, x, false)
}

// FF1MinLength is the shortest input SP 800-38G allows for radix.
func FF1MinLength(radix int) int {
	n, d := 1, radix
	for d < ff1MinDomain {
		d *= radix
		n++
	}
	return n
}

func ff1(key, tweak []byte, radix int, x []uint16, encrypt bool) ([]uint16, error) {
	if radix < 2 || radix > 1<<16 {
		return nil, errors.New("ff1: radix must be 2..65536")
	}
	n := len(x)
	if n < FF1MinLength(radix) {
		return nil, errors.New("ff1: input shorter than the SP 800-38G minimum for this radix")
	}
	if n > ff1MaxLen {
		return nil, errors.New("ff1: input too long")
	}
	if len(tweak) > ff1MaxTweak {
		return nil, errors.New("ff1: tweak too long")
	}
	for _, d := range x {
		if int(d) >= radix {
			return nil, errors.New("ff1: numeral outside radix")
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("ff1: key must be AES-128, AES-192 or AES-256")
	}
	t := len(tweak)
	u := n / 2
	v := n - u
	bigRadix := big.NewInt(int64(radix))
	// b = ceil(ceil(v*log2(radix))/8), computed exactly as the byte length of radix^v - 1.
	b := (new(big.Int).Sub(new(big.Int).Exp(bigRadix, big.NewInt(int64(v)), nil), big.NewInt(1)).BitLen() + 7) / 8
	d := 4*((b+3)/4) + 4

	P := make([]byte, 16)
	P[0], P[1], P[2] = 1, 2, 1
	P[3], P[4], P[5] = byte(radix>>16), byte(radix>>8), byte(radix)
	P[6] = 10
	P[7] = byte(u % 256)
	binary.BigEndian.PutUint32(P[8:12], uint32(n))
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	pad := (16 - (t+b+1)%16) % 16
	Q := make([]byte, t+pad+1+b)
	copy(Q, tweak)

	modU := new(big.Int).Exp(bigRadix, big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(bigRadix, big.NewInt(int64(v)), nil)
	A, B := num(x[:u], radix), num(x[u:], radix)
	S := make([]byte, ((d+15)/16)*16)
	R := make([]byte, 16)
	y, c := new(big.Int), new(big.Int)

	for step := 0; step < ff1Rounds; step++ {
		i := step
		if !encrypt {
			i = ff1Rounds - 1 - step
		}
		src := B
		if !encrypt {
			src = A
		}
		Q[t+pad] = byte(i)
		fillBigEndian(Q[t+pad+1:], src)
		prf(block, R, P, Q)
		copy(S, R)
		for j := 1; j*16 < d; j++ {
			var blk [16]byte
			copy(blk[:], R)
			binary.BigEndian.PutUint32(blk[12:], binary.BigEndian.Uint32(blk[12:])^uint32(j))
			block.Encrypt(S[j*16:], blk[:])
		}
		y.SetBytes(S[:d])
		m := modV
		if i%2 == 0 {
			m = modU
		}
		if encrypt {
			c.Add(A, y).Mod(c, m)
			A, B = B, new(big.Int).Set(c)
		} else {
			c.Sub(B, y).Mod(c, m)
			B, A = A, new(big.Int).Set(c)
		}
	}
	Zeroize(S)
	Zeroize(R)
	out := make([]uint16, n)
	str(out[:u], A, radix)
	str(out[u:], B, radix)
	return out, nil
}

// prf is the CBC-MAC of P||Q with a zero IV (SP 800-38G PRF).
func prf(block cipher.Block, out, P, Q []byte) {
	var y [16]byte
	block.Encrypt(y[:], P)
	for off := 0; off < len(Q); off += 16 {
		for k := 0; k < 16; k++ {
			y[k] ^= Q[off+k]
		}
		block.Encrypt(y[:], y[:])
	}
	copy(out, y[:])
}

func num(x []uint16, radix int) *big.Int {
	r := big.NewInt(int64(radix))
	z := new(big.Int)
	for _, d := range x {
		z.Mul(z, r).Add(z, big.NewInt(int64(d)))
	}
	return z
}

func str(out []uint16, z *big.Int, radix int) {
	r := big.NewInt(int64(radix))
	q, m := new(big.Int).Set(z), new(big.Int)
	for i := len(out) - 1; i >= 0; i-- {
		q.DivMod(q, r, m)
		out[i] = uint16(m.Int64())
	}
}

func fillBigEndian(dst []byte, z *big.Int) {
	for i := range dst {
		dst[i] = 0
	}
	z.FillBytes(dst)
}
