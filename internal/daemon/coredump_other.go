//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd

package daemon

import "fmt"

// disableCoreDump is a no-op on platforms where core-dump resource limits are
// not supported. The daemon logs a warning at startup so the operator knows
// the protection is absent; it does not abort startup.
func disableCoreDump() error {
	return fmt.Errorf("daemon: disable core dumps: not supported on this platform (non-Unix)")
}
