package sqlite

import (
	"errors"
	"os"
)

// The sidecar is intentionally retained: deleting it could let two processes
// lock different inodes while opening the same database.
func acquireMigrationLock(databasePath string) (func(), error) {
	path := databasePath + ".migration.lock"
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrInvalidStorePath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, ErrInvalidStorePath
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		file.Close()
		return nil, ErrInvalidStorePath
	}
	unlock, err := lockMigrationFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = unlock(); _ = file.Close() }, nil
}
