//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package bitfs

import (
	"os"
	"path/filepath"
	"syscall"
)

// withProcessFileLock serializes cooperating FileQuoteStore instances that
// point at the same snapshot. The lock is advisory by design.
func withProcessFileLock(path string, exclusive bool, operation func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lock.Fd()), mode); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}
