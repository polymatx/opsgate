//go:build unix

package audit

import (
	"os"
	"syscall"
)

func lockFile(f *os.File) (func(), error) {
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX)
		if err == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }, nil
		}
		if err != syscall.EINTR {
			return nil, err
		}
	}
}
