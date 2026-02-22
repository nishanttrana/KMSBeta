package metering

import (
	"testing"
	"time"
)

func TestMeteringLimitAndReset(t *testing.T) {
	m := NewMeter(2, 1*time.Second)
	if !m.IncrementOps() || !m.IncrementOps() {
		t.Fatal("first two ops should pass")
	}
	if m.IncrementOps() {
		t.Fatal("third op should fail limit")
	}
	time.Sleep(1100 * time.Millisecond)
	if !m.IncrementOps() {
		t.Fatal("op should pass after window reset")
	}
}
