package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const currentSchemaVersion = 5

var (
	ErrBackupIntegrity      = errors.New("SQLite backup integrity failure")
	ErrInvalidRestoreTarget = errors.New("restore target must be a new absolute path")
)

type BackupInfo struct {
	Path          string
	SHA256        string
	SchemaVersion int
}

func makeMigrationBackup(db *sql.DB, sourcePath string, version int) (BackupInfo, error) {
	dir := filepath.Dir(sourcePath)
	file, err := os.CreateTemp(dir, "."+filepath.Base(sourcePath)+fmt.Sprintf(".pre-v%d-*.sqlite", version))
	if err != nil {
		return BackupInfo{}, err
	}
	backupPath := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(backupPath)
		return BackupInfo{}, err
	}
	success := false
	defer func() {
		if !success {
			os.Remove(backupPath)
			os.Remove(backupPath + ".sha256")
		}
	}()
	// SQLite's VACUUM INTO creates a consistent snapshot even in WAL mode.
	if _, err := db.Exec("VACUUM INTO ?", backupPath); err != nil {
		return BackupInfo{}, err
	}
	if err := verifySQLiteFile(backupPath, version); err != nil {
		return BackupInfo{}, err
	}
	digest, err := hashFile(backupPath)
	if err != nil {
		return BackupInfo{}, err
	}
	if err := writeBackupReceipt(backupPath, version, digest); err != nil {
		return BackupInfo{}, err
	}
	success = true
	return BackupInfo{Path: backupPath, SHA256: digest, SchemaVersion: version}, nil
}

func writeBackupReceipt(path string, version int, digest string) error {
	receipt, err := os.OpenFile(path+".sha256", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			receipt.Close()
			os.Remove(path + ".sha256")
		}
	}()
	if _, err := fmt.Fprintf(receipt, "%d\n%s\n", version, digest); err != nil {
		return err
	}
	if err := receipt.Sync(); err != nil {
		return err
	}
	if err := receipt.Close(); err != nil {
		return err
	}
	success = true
	return nil
}

// LoadBackupInfo reads the persisted receipt and verifies its database file.
// The receipt detects accidental changes; an external signature/anchor is a
// separate requirement against a privileged attacker replacing both files.
func LoadBackupInfo(path string) (BackupInfo, error) {
	if path == "" || !filepath.IsAbs(path) {
		return BackupInfo{}, ErrBackupIntegrity
	}
	receipt, err := os.Open(path + ".sha256")
	if err != nil {
		return BackupInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(receipt, 256))
	closeErr := receipt.Close()
	if err != nil {
		return BackupInfo{}, err
	}
	if closeErr != nil {
		return BackupInfo{}, closeErr
	}
	parts := strings.Split(string(data), "\n")
	if len(parts) != 3 || parts[2] != "" || !validSHA256(parts[1]) {
		return BackupInfo{}, ErrBackupIntegrity
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil || version < 0 || version > currentSchemaVersion {
		return BackupInfo{}, ErrBackupIntegrity
	}
	if err := verifySQLiteFile(path, version); err != nil {
		return BackupInfo{}, err
	}
	digest, err := hashFile(path)
	if err != nil {
		return BackupInfo{}, err
	}
	if digest != parts[1] {
		return BackupInfo{}, ErrBackupIntegrity
	}
	return BackupInfo{Path: path, SHA256: digest, SchemaVersion: version}, nil
}

func verifySQLiteFile(path string, expectedVersion int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		return ErrBackupIntegrity
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != expectedVersion {
		return ErrBackupIntegrity
	}
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return ErrBackupIntegrity
	}
	rows, err := db.Query("PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return ErrBackupIntegrity
	}
	return rows.Err()
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// RestoreBackup copies a verified snapshot to a NEW file. The caller must
// stop writers and switch to that file only after reconciling CAS evidence.
// It never overwrites the active database or its WAL files.
func RestoreBackup(ctx context.Context, backup BackupInfo, target string) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if target == "" || !filepath.IsAbs(target) || strings.HasPrefix(strings.ToLower(target), "file:") ||
		filepath.Clean(target) == filepath.Clean(backup.Path) {
		return ErrInvalidRestoreTarget
	}
	if len(backup.SHA256) != 64 || backup.SchemaVersion < 0 || backup.SchemaVersion > currentSchemaVersion {
		return ErrBackupIntegrity
	}
	loaded, err := LoadBackupInfo(backup.Path)
	if err != nil {
		return err
	}
	if loaded.SHA256 != backup.SHA256 || loaded.SchemaVersion != backup.SchemaVersion {
		return ErrBackupIntegrity
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return ErrInvalidRestoreTarget
	}
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			output.Close()
			os.Remove(target)
		}
	}()
	input, err := os.Open(backup.Path)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, &contextReader{ctx: ctx, reader: input})
	closeErr := input.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := verifySQLiteFile(target, backup.SchemaVersion); err != nil {
		return err
	}
	restoredDigest, err := hashFile(target)
	if err != nil {
		return err
	}
	if restoredDigest != backup.SHA256 {
		return ErrBackupIntegrity
	}
	success = true
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
