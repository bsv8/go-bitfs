//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package bitfs

// Unsupported platforms retain the atomic-rename behavior but do not get a
// cross-process lock. A production port for such a platform must provide an
// equivalent advisory lock or use a transactional database.
func withProcessFileLock(_ string, _ bool, operation func() error) error {
	return operation()
}
