package sidechanneltests

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	cryptopkg "vecta-kms/pkg/crypto"
)

func TestZeroizeClearsBuffer(t *testing.T) {
	buf := []byte("sensitive-key-material")
	cryptopkg.Zeroize(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("buffer was not zeroized at offset %d", i)
		}
	}
}

func TestMlockMunlockSmoke(t *testing.T) {
	buf := make([]byte, 4096)
	lockErr := cryptopkg.Mlock(buf)
	if lockErr != nil && !isAcceptableMlockError(lockErr) {
		t.Fatalf("mlock failed with unexpected error: %v", lockErr)
	}

	unlockErr := cryptopkg.Munlock(buf)
	if unlockErr != nil && !isAcceptableMlockError(unlockErr) {
		t.Fatalf("munlock failed with unexpected error: %v", unlockErr)
	}
}

func isAcceptableMlockError(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not permitted") ||
		strings.Contains(msg, "insufficient privilege") ||
		strings.Contains(msg, "cannot allocate memory") ||
		strings.Contains(msg, "access denied")
}
