package sprawlscanner

import "math"

// ShannonEntropy calculates the Shannon entropy of a string.
// Higher entropy indicates more randomness, which is common in secrets.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int, 256)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy returns true if the string's Shannon entropy exceeds the threshold.
func IsHighEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) > threshold
}
