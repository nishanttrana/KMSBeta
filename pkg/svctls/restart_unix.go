//go:build !windows

package svctls

import (
	"os"
	"syscall"
)

// stopGracefully sends this process SIGTERM so its shutdown handler drains
// connections; the supervisor's restart policy brings it back.
func stopGracefully() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
}
