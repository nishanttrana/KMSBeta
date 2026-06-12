package sidechanneltests

import (
	"bytes"
	"math"
	"runtime"
	"sort"
	"testing"
	"time"

	cryptopkg "vecta-kms/pkg/crypto"
	paymentpkg "vecta-kms/pkg/payment"
)

// Statistical timing tests are inherently noisy on shared/loaded machines:
// GC pauses, scheduler migrations, and frequency scaling can push a single
// Welch t-score far past any reasonable threshold even for perfectly
// constant-time code. To stay meaningful as a regression guard without being
// flaky, each assertion runs several independent trials and compares the
// MEDIAN t-score against the threshold: a real timing leak is systematic and
// raises every trial's score, while machine noise must corrupt a majority of
// trials to cause a spurious failure.
const timingTrials = 5

// warmupBatches is the pinned number of batches executed per operation before
// any measurement, so JIT-like effects (cache/branch-predictor warmup, lazy
// allocation) don't skew the first samples.
const warmupBatches = 10

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

	// Pin the measuring goroutine to one OS thread and start from a clean
	// heap so scheduler migrations and GC pauses land in fewer samples.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runtime.GC()

	for i := 0; i < warmupBatches; i++ {
		measure(opA)
		measure(opB)
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

func assertTimingSimilarity(t *testing.T, name string, samples int, batch int, opA func(), opB func(), threshold float64) {
	t.Helper()
	scores := make([]float64, 0, timingTrials)
	for i := 0; i < timingTrials; i++ {
		a, b := sampleTiming(samples, batch, opA, opB)
		scores = append(scores, math.Abs(welchT(a, b)))
	}
	sort.Float64s(scores)
	median := scores[len(scores)/2]
	if median > threshold {
		t.Fatalf("%s timing deviation too large: median t-score=%.2f threshold=%.2f (trials=%v)", name, median, threshold, scores)
	}
}

func TestConstantTimeEqualTiming(t *testing.T) {
	equalLeft := bytes.Repeat([]byte{0xAB}, 32)
	equalRight := bytes.Repeat([]byte{0xAB}, 32)
	diffRight := bytes.Repeat([]byte{0xAC}, 32)

	assertTimingSimilarity(t, "ConstantTimeEqual", 240, 500, func() {
		_ = cryptopkg.ConstantTimeEqual(equalLeft, equalRight)
	}, func() {
		_ = cryptopkg.ConstantTimeEqual(equalLeft, diffRight)
	}, 10.0)
}

func TestComputeKCVTiming(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x11}, 32)
	keyB := bytes.Repeat([]byte{0x77}, 32)

	assertTimingSimilarity(t, "ComputeKCV", 220, 350, func() {
		_, _ = cryptopkg.ComputeKCV("AES", keyA)
	}, func() {
		_, _ = cryptopkg.ComputeKCV("AES", keyB)
	}, 10.0)
}

func TestRetailMACTiming(t *testing.T) {
	key := []byte("12345678ABCDEFGH")
	msgA := bytes.Repeat([]byte{0x41}, 128)
	msgB := bytes.Repeat([]byte{0x42}, 128)

	assertTimingSimilarity(t, "RetailMACANSI919", 180, 120, func() {
		_, _ = paymentpkg.RetailMACANSI919(key, msgA)
	}, func() {
		_, _ = paymentpkg.RetailMACANSI919(key, msgB)
	}, 10.0)
}

