//go:build !windows

package requestcapture

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Keep the inode permanently: deleting a lock file would let another process
// lock a different inode while a live owner still writes the same directory.
func lockCaptureDirectory(dir string) (func(), error) {
	fd, err := syscall.Open(filepath.Join(dir, ".owner.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "capture-owner")
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("capture directory has an active owner: %w", err)
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}
