package main

import (
	"errors"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// FPE over the alphabet 0-9a-z (radix 2..36), letter case preserved.
//
// FF1 is NIST SP 800-38G FF1 (pkg/crypto). FF3-1 is not offered: NIST's
// SP 800-38G Rev. 1 draft withdraws it. Before 1.26.0-beta both names ran an
// additive keystream that leaked plaintext differences; that transform
// survives only as decrypt-only LEGACY-FF1 / LEGACY-FF3-1 so existing
// ciphertext can be migrated (docs/DATA_PROTECTION.md).

const fpeAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

func ff1Encrypt(key []byte, tweak string, plaintext string, radix int) (string, error) {
	return ff1Apply(key, tweak, plaintext, radix, true)
}

func ff1Decrypt(key []byte, tweak string, ciphertext string, radix int) (string, error) {
	return ff1Apply(key, tweak, ciphertext, radix, false)
}

func ff1Apply(key []byte, tweak string, in string, radix int, encrypt bool) (string, error) {
	x, runes, err := fpeNumerals(in, radix)
	if err != nil {
		return "", err
	}
	var y []uint16
	if encrypt {
		y, err = pkgcrypto.FF1Encrypt(key, []byte(tweak), radix, x)
	} else {
		y, err = pkgcrypto.FF1Decrypt(key, []byte(tweak), radix, x)
	}
	if err != nil {
		return "", err
	}
	return fpeString(y, runes), nil
}

func fpeNumerals(in string, radix int) ([]uint16, []rune, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil, nil, errors.New("input is required")
	}
	if radix < 2 || radix > len(fpeAlphabet) {
		return nil, nil, errors.New("radix must be 2..36")
	}
	runes := []rune(in)
	x := make([]uint16, len(runes))
	for i, r := range runes {
		v := strings.IndexRune(fpeAlphabet[:radix], toLowerASCII(r))
		if v < 0 {
			return nil, nil, errors.New("input contains chars outside radix alphabet")
		}
		x[i] = uint16(v)
	}
	return x, runes, nil
}

func fpeString(x []uint16, like []rune) string {
	out := make([]rune, len(x))
	for i, v := range x {
		out[i] = rune(fpeAlphabet[v])
		if isUpper(like[i]) {
			out[i] = uppercase(out[i])
		}
	}
	return string(out)
}

// legacyFPEDecrypt inverts the pre-1.26.0 additive transform (ff1: 10 rounds;
// ff3: 8 rounds, tweak prefixed "ff3:"). Decrypt only, for migration.
func legacyFPEDecrypt(key []byte, tweak string, ciphertext string, radix int, ff3 bool) (string, error) {
	x, runes, err := fpeNumerals(ciphertext, radix)
	if err != nil {
		return "", err
	}
	rounds := 10
	if ff3 {
		rounds, tweak = 8, "ff3:"+tweak
	}
	vec := make([]int, len(x))
	for i, v := range x {
		vec[i] = int(v)
	}
	for round := 0; round < rounds; round++ {
		material := hmacSHA256(key, "ff1", tweak, strconvI(round), strconvI(len(vec)), strconvI(radix))
		for i := range vec {
			vec[i] = ((vec[i]-int(material[i%len(material)])%radix)%radix + radix) % radix
		}
		zeroizeAll(material)
	}
	for i, v := range vec {
		x[i] = uint16(v)
	}
	return fpeString(x, runes), nil
}

func toLowerASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

func strtoupper(v string) string {
	return strings.ToUpper(strings.TrimSpace(v))
}

func uppercase(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func isUpper(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

func strconvI(v int) string {
	if v == 0 {
		return "0"
	}
	var out [20]byte
	i := len(out)
	for v > 0 {
		i--
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out[i:])
}
