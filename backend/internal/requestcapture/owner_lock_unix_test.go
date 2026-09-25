//go:build !windows

package requestcapture

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCaptureDirectoryLockNotInheritedByChild(t *testing.T) {
	const roleKey = "SUB2API_TEST_CAPTURE_LOCK_ROLE"
	const dirKey = "SUB2API_TEST_CAPTURE_LOCK_DIR"
	switch os.Getenv(roleKey) {
	case "holder":
		// The parent test kills this child after checking lock reacquisition.
		time.Sleep(time.Minute)
		os.Exit(0)
	case "owner":
		_, err := lockCaptureDirectory(os.Getenv(dirKey))
		require.NoError(t, err)
		child := exec.Command(os.Args[0], "-test.run=^TestCaptureDirectoryLockNotInheritedByChild$")
		child.Env = append(os.Environ(), roleKey+"=holder")
		require.NoError(t, child.Start())
		fmt.Println(child.Process.Pid)
		// Simulate abrupt owner shutdown: do not explicitly unlock the file.
		os.Exit(0)
	}

	dir := t.TempDir()
	owner := exec.Command(os.Args[0], "-test.run=^TestCaptureDirectoryLockNotInheritedByChild$")
	owner.Env = append(os.Environ(), roleKey+"=owner", dirKey+"="+dir)
	out, err := owner.Output()
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	require.NoError(t, err)
	child, err := os.FindProcess(pid)
	require.NoError(t, err)
	t.Cleanup(func() { _ = child.Kill(); _ = child.Release() })

	release, err := lockCaptureDirectory(dir)
	require.NoError(t, err, "a surviving child must not hold its exited parent's capture lock")
	release()
}
