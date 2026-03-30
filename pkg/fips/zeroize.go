package fips

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// Zeroize overwrites a byte slice with zeros. The //go:noinline directive
// and runtime.KeepAlive call prevent the compiler from optimizing away the loop.
//
//go:noinline
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroizeString overwrites the backing bytes of a string in-place.
// This uses unsafe to mutate an otherwise immutable Go string, which is
// necessary for FIPS 140-3 key material zeroization. After calling this,
// the string is set to empty.
func ZeroizeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	// Access the underlying string header to get the data pointer
	type stringHeader struct {
		Data unsafe.Pointer
		Len  int
	}

	hdr := (*stringHeader)(unsafe.Pointer(s))
	length := hdr.Len
	if length == 0 || hdr.Data == nil {
		return
	}

	// Overwrite each byte through the data pointer
	p := hdr.Data
	for i := 0; i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(p) + uintptr(i))) = 0
	}
	runtime.KeepAlive(s)

	// Set the string to empty so it cannot be read again
	*s = ""
}

// SecureBuffer is a managed byte buffer that guarantees zeroization of its
// contents when closed. It implements io.Writer for convenient data ingestion.
// A runtime finalizer is registered as a safety net in case Close() is not called.
type SecureBuffer struct {
	mu       sync.Mutex
	data     []byte
	released bool
}

// NewSecureBuffer allocates a new SecureBuffer of the given size. A runtime
// finalizer ensures zeroization even if Close() is not explicitly called.
func NewSecureBuffer(size int) *SecureBuffer {
	sb := &SecureBuffer{
		data: make([]byte, size),
	}
	runtime.SetFinalizer(sb, func(buf *SecureBuffer) {
		buf.Close()
	})
	return sb
}

// Bytes returns the underlying byte slice. Returns nil if the buffer
// has been released.
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.released {
		return nil
	}
	return sb.data
}

// Write copies data from p into the buffer, starting from the beginning.
// If p is larger than the buffer, only len(data) bytes are written.
// Returns the number of bytes written.
func (sb *SecureBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.released {
		return 0, errors.New("fips: write to released SecureBuffer")
	}
	n := copy(sb.data, p)
	return n, nil
}

// Close zeroizes the buffer contents and marks it as released.
// Subsequent calls to Close are no-ops. Subsequent calls to Bytes
// return nil, and Write returns an error.
func (sb *SecureBuffer) Close() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.released {
		return
	}
	Zeroize(sb.data)
	sb.released = true
	runtime.SetFinalizer(sb, nil) // Remove the finalizer since we've cleaned up
}
