//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func Mlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func Munlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}
