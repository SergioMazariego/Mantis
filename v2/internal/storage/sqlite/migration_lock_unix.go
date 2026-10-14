//go:build !windows

package sqlite

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockMigrationFile(file *os.File) (func() error, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil, ErrStoreBusy
	}
	if err != nil {
		return nil, err
	}
	return func() error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }, nil
}
