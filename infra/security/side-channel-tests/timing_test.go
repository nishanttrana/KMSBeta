package sidechanneltests

import (
	"bytes"
	"math"
	"math/big"
	"testing"
	"time"

	cryptopkg "vecta-kms/pkg/crypto"
	mpcpkg "vecta-kms/pkg/mpc"
	paymentpkg "vecta-kms/pkg/payment"
)

func meanVariance(samples []float64) (float64, float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	mean := sum / float64(len(samples))
	if len(samples) == 1 {
		return mean, 0
	}
	var sq float64
	for _, s := range samples {
		d := s - mean
		sq += d * d
	}
	return mean, sq / float64(len(samples)-1)
}

func welchT(a []float64, b []float64) float64 {
	meanA, varA := meanVariance(a)
	meanB, varB := meanVariance(b)
	denom := math.Sqrt((varA / float64(len(a))) + (varB / float64(len(b))))
	if denom == 0 {
		return 0
	}
	return (meanA - meanB) / denom
}

func sampleTiming(samples int, batch int, opA func(), opB func()) ([]float64, []float64) {
	outA := make([]float64, 0, samples)
	outB := make([]float64, 0, samples)

	measure := func(op func()) float64 {
		start := time.Now()
		for i := 0; i < batch; i++ {
			op()
		}
		return float64(time.Since(start).Nanoseconds())
	}

	for i := 0; i < samples; i++ {
		if i%2 == 0 {
			outA = append(outA, measure(opA))
			outB = append(outB, measure(opB))
		} else {
			outB = append(outB, measure(opB))
			outA = append(outA, measure(opA))
		}
	}
	return outA, outB
}

func assertTimingSimilarity(t *testing.T, name string, a []float64, b []float64, threshold float64) {
	t.Helper()
	tscore := math.Abs(welchT(a, b))
	if tscore > threshold {
		t.Fatalf("%s timing deviation too large: t-score=%.2f threshold=%.2f", name, tscore, threshold)
	}
}

func TestConstantTimeEqualTiming(t *testing.T) {
	equalLeft := bytes.Repeat([]byte{0xAB}, 32)
	equalRight := bytes.Repeat([]byte{0xAB}, 32)
	diffRight := bytes.Repeat([]byte{0xAC}, 32)

	a, b := sampleTiming(240, 500, func() {
		_ = cryptopkg.ConstantTimeEqual(equalLeft, equalRight)
	}, func() {
		_ = cryptopkg.ConstantTimeEqual(equalLeft, diffRight)
	})
	assertTimingSimilarity(t, "ConstantTimeEqual", a, b, 10.0)
}

func TestComputeKCVTiming(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x11}, 32)
	keyB := bytes.Repeat([]byte{0x77}, 32)

	a, b := sampleTiming(220, 350, func() {
		_, _ = cryptopkg.ComputeKCV("AES", keyA)
	}, func() {
		_, _ = cryptopkg.ComputeKCV("AES", keyB)
	})
	assertTimingSimilarity(t, "ComputeKCV", a, b, 10.0)
}

func TestRetailMACTiming(t *testing.T) {
	key := []byte("12345678ABCDEFGH")
	msgA := bytes.Repeat([]byte{0x41}, 128)
	msgB := bytes.Repeat([]byte{0x42}, 128)

	a, b := sampleTiming(180, 120, func() {
		_, _ = paymentpkg.RetailMACANSI919(key, msgA)
	}, func() {
		_, _ = paymentpkg.RetailMACANSI919(key, msgB)
	})
	assertTimingSimilarity(t, "RetailMACANSI919", a, b, 10.0)
}

func TestFeldmanVerifyTiming(t *testing.T) {
	secret := big.NewInt(42)
	shares, err := mpcpkg.Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("split failed: %v", err)
	}
	coeffs := []*big.Int{big.NewInt(42), big.NewInt(7), big.NewInt(13)}
	commitments := mpcpkg.FeldmanCommit(coeffs, big.NewInt(5))

	validShare := shares[0]
	invalidShare := mpcpkg.Share{
		X: new(big.Int).Set(validShare.X),
		Y: new(big.Int).Add(validShare.Y, big.NewInt(1)),
	}
	invalidShare.Y.Mod(invalidShare.Y, mpcpkg.Prime)

	a, b := sampleTiming(140, 80, func() {
		_ = mpcpkg.FeldmanVerify(validShare, commitments, big.NewInt(5))
	}, func() {
		_ = mpcpkg.FeldmanVerify(invalidShare, commitments, big.NewInt(5))
	})
	assertTimingSimilarity(t, "FeldmanVerify", a, b, 12.0)
}
