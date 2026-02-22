package main

import (
	"errors"
	"strings"
)

func ff1Encrypt(key []byte, tweak string, plaintext string, radix int) (string, error) {
	return fpeTransform(key, tweak, plaintext, radix, true, 10)
}

func ff1Decrypt(key []byte, tweak string, ciphertext string, radix int) (string, error) {
	return fpeTransform(key, tweak, ciphertext, radix, false, 10)
}

func fpeTransform(key []byte, tweak string, in string, radix int, encrypt bool, rounds int) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("input is required")
	}
	if radix < 2 || radix > 36 {
		return "", errors.New("radix must be 2..36")
	}
	alphabet := []rune("0123456789abcdefghijklmnopqrstuvwxyz")
	allowed := string(alphabet[:radix])
	index := map[rune]int{}
	for i, r := range []rune(allowed) {
		index[r] = i
		index[uppercase(r)] = i
	}
	runes := []rune(in)
	vec := make([]int, len(runes))
	for i, r := range runes {
		v, ok := index[r]
		if !ok {
			return "", errors.New("input contains chars outside radix alphabet")
		}
		vec[i] = v
	}

	for round := 0; round < rounds; round++ {
		// Use round constants only so decrypt can deterministically invert encrypt.
		roundMaterial := hmacSHA256(key, "ff1", tweak, strconvI(round), strconvI(len(vec)), strconvI(radix))
		for i := range vec {
			delta := int(roundMaterial[i%len(roundMaterial)]) % radix
			if encrypt {
				vec[i] = (vec[i] + delta) % radix
			} else {
				vec[i] = (vec[i] - delta) % radix
				for vec[i] < 0 {
					vec[i] += radix
				}
			}
		}
		zeroizeAll(roundMaterial)
	}

	out := make([]rune, len(vec))
	for i, v := range vec {
		out[i] = alphabet[v]
		if isUpper(runes[i]) {
			out[i] = uppercase(out[i])
		}
	}
	return string(out), nil
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
