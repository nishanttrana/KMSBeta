//go:build windows

package svctls

import "os"

// stopGracefully: Windows cannot deliver a signal to its own process, so a
// graceful restart falls back to the forced exit and the service manager's
// recovery action restarts it.
func stopGracefully() {
	os.Exit(75)
}
