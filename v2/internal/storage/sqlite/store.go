// Package sqlite provides the standalone case metadata store. Evidence bytes
// belong in the immutable blob store, not in this database.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	_ "modernc.org/sqlite"
)

var (
	ErrInvalidStorePath = errors.New("invalid SQLite store path")
	ErrStoreBusy        = errors.New("SQLite migration lock busy")
	ErrCaseNotFound     = errors.New("case not found")
)

type Store struct {
	db              *sql.DB
	path            string
	migrationBackup BackupInfo
}

type Case struct {
	TenantID casecore.TenantID
	CaseID   casecore.CaseID
	Title    string
}

// Open creates or opens an on-disk standalone store. The caller chooses a
// trusted absolute location; case/evidence paths must never be accepted here.
func Open(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || strings.HasPrefix(strings.ToLower(path), "file:") {
		return nil, ErrInvalidStorePath
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	release, err := acquireMigrationLock(path)
	if err != nil {
		return nil, err
	}
	defer release()
	existed := false
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, ErrInvalidStorePath
	} else if err == nil {
		existed = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure SQLite: %w", err)
		}
	}
	store := &Store{db: db, path: path}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version < 0 || version > currentSchemaVersion {
		db.Close()
		return nil, fmt.Errorf("unsupported SQLite schema version %d", version)
	}
	if existed && version < currentSchemaVersion {
		backup, err := makeMigrationBackup(db, path, version)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("migration backup: %w", err)
		}
		store.migrationBackup = backup
	}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

// MigrationBackup returns the verified pre-upgrade snapshot created by Open.
// A zero value means no existing database needed an upgrade.
func (s *Store) MigrationBackup() BackupInfo { return s.migrationBackup }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version < 0 || version > currentSchemaVersion {
		return fmt.Errorf("unsupported SQLite schema version %d", version)
	}
	if version == currentSchemaVersion {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{}
	if version == 0 {
		statements = append(statements,
			`CREATE TABLE cases (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, title TEXT NOT NULL,
			PRIMARY KEY (tenant_id, case_id))`,
			`CREATE TABLE case_memberships (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			actor_id TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
			revision INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant_id, case_id, actor_id),
			FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id))`,
			`CREATE TABLE audit_events (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			event_no INTEGER NOT NULL, actor_id TEXT NOT NULL, operation TEXT NOT NULL,
			target_id TEXT NOT NULL, occurred_at TEXT NOT NULL, previous_hash TEXT NOT NULL,
			event_hash TEXT NOT NULL, PRIMARY KEY (tenant_id, case_id, event_no),
			FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id))`,
			`CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
			BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`,
			`CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
			BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`,
		)
	}
	if version < 2 {
		statements = append(statements,
			`CREATE TABLE acquisition_manifests (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			acquisition_id TEXT NOT NULL, manifest_json BLOB NOT NULL, manifest_sha256 TEXT NOT NULL,
			PRIMARY KEY (tenant_id, case_id, acquisition_id),
			FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id))`,
			`CREATE TRIGGER manifest_no_update BEFORE UPDATE ON acquisition_manifests
			BEGIN SELECT RAISE(ABORT, 'acquisition manifests are append-only'); END`,
			`CREATE TRIGGER manifest_no_delete BEFORE DELETE ON acquisition_manifests
			BEGIN SELECT RAISE(ABORT, 'acquisition manifests are append-only'); END`,
		)
	}
	if version < 3 {
		statements = append(statements,
			`CREATE TABLE custody_events (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			event_no INTEGER NOT NULL, evidence_sha256 TEXT NOT NULL, action TEXT NOT NULL,
			actor_id TEXT NOT NULL, occurred_at TEXT NOT NULL, details_json BLOB NOT NULL,
			previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
			PRIMARY KEY (tenant_id, case_id, event_no),
			FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, case_id))`,
			`CREATE TRIGGER custody_no_update BEFORE UPDATE ON custody_events
			BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END`,
			`CREATE TRIGGER custody_no_delete BEFORE DELETE ON custody_events
			BEGIN SELECT RAISE(ABORT, 'custody events are append-only'); END`,
		)
	}
	if version < 4 {
		statements = append(statements,
			`CREATE TABLE artifacts (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			artifact_id TEXT NOT NULL, asset_id TEXT NOT NULL, acquisition_id TEXT NOT NULL,
			evidence_sha256 TEXT NOT NULL, artifact_type TEXT NOT NULL, source_locator TEXT NOT NULL,
			created_at TEXT NOT NULL, PRIMARY KEY (tenant_id,case_id,artifact_id),
			FOREIGN KEY (tenant_id,case_id,acquisition_id)
			REFERENCES acquisition_manifests(tenant_id,case_id,acquisition_id))`,
			`CREATE TABLE parser_runs (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			run_id TEXT NOT NULL, artifact_id TEXT NOT NULL, parser_name TEXT NOT NULL,
			parser_version TEXT NOT NULL, config_sha256 TEXT NOT NULL, status TEXT NOT NULL,
			created_at TEXT NOT NULL, PRIMARY KEY (tenant_id,case_id,run_id),
			FOREIGN KEY (tenant_id,case_id,artifact_id) REFERENCES artifacts(tenant_id,case_id,artifact_id))`,
			`CREATE TABLE record_provenance (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			record_id TEXT NOT NULL, run_id TEXT NOT NULL, record_locator TEXT NOT NULL,
			record_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
			PRIMARY KEY (tenant_id,case_id,record_id),
			FOREIGN KEY (tenant_id,case_id,run_id) REFERENCES parser_runs(tenant_id,case_id,run_id))`,
			`CREATE TRIGGER artifact_no_update BEFORE UPDATE ON artifacts
			BEGIN SELECT RAISE(ABORT, 'artifacts are append-only'); END`,
			`CREATE TRIGGER artifact_no_delete BEFORE DELETE ON artifacts
			BEGIN SELECT RAISE(ABORT, 'artifacts are append-only'); END`,
			`CREATE TRIGGER parser_run_no_update BEFORE UPDATE ON parser_runs
			BEGIN SELECT RAISE(ABORT, 'parser runs are append-only'); END`,
			`CREATE TRIGGER parser_run_no_delete BEFORE DELETE ON parser_runs
			BEGIN SELECT RAISE(ABORT, 'parser runs are append-only'); END`,
			`CREATE TRIGGER provenance_no_update BEFORE UPDATE ON record_provenance
			BEGIN SELECT RAISE(ABORT, 'record provenance is append-only'); END`,
			`CREATE TRIGGER provenance_no_delete BEFORE DELETE ON record_provenance
			BEGIN SELECT RAISE(ABORT, 'record provenance is append-only'); END`,
		)
	}
	statements = append(statements,
		`CREATE TABLE ingest_intent_events (tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
			acquisition_id TEXT NOT NULL, event_no INTEGER NOT NULL, actor_id TEXT NOT NULL,
			state TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
			reason TEXT NOT NULL, occurred_at TEXT NOT NULL, previous_hash TEXT NOT NULL,
			event_hash TEXT NOT NULL, PRIMARY KEY (tenant_id,case_id,acquisition_id,event_no),
			FOREIGN KEY (tenant_id,case_id) REFERENCES cases(tenant_id,case_id))`,
		`CREATE TRIGGER intent_no_update BEFORE UPDATE ON ingest_intent_events
			BEGIN SELECT RAISE(ABORT, 'ingest intent events are append-only'); END`,
		`CREATE TRIGGER intent_no_delete BEFORE DELETE ON ingest_intent_events
			BEGIN SELECT RAISE(ABORT, 'ingest intent events are append-only'); END`,
		`PRAGMA user_version=5`,
	)
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate SQLite: %w", err)
		}
	}
	return tx.Commit()
}

// BootstrapCase is a trusted setup operation. A future API must check tenant
// creation authority before calling it; it is not an end-user authorization path.
func (s *Store) BootstrapCase(ctx context.Context, scope casecore.Scope, title string) error {
	if !scope.Valid() || strings.TrimSpace(title) == "" || len(title) > 256 {
		return auth.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO cases(tenant_id,case_id,title) VALUES(?,?,?)`,
		scope.TenantID().String(), scope.CaseID().String(), title); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO case_memberships(tenant_id,case_id,actor_id,role,active)
		VALUES(?,?,?,?,1)`, scope.TenantID().String(), scope.CaseID().String(), scope.ActorID().String(),
		string(auth.RoleCaseLead)); err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, scope, "case.created", scope.CaseID().String()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LookupMembership(ctx context.Context, tenant casecore.TenantID, caseID casecore.CaseID, actor casecore.ActorID) (auth.Membership, error) {
	if tenant.String() == "" || caseID.String() == "" || actor.String() == "" {
		return auth.Membership{}, auth.ErrMembershipNotFound
	}
	var role string
	var active int
	err := s.db.QueryRowContext(ctx, `SELECT role,active FROM case_memberships
		WHERE tenant_id=? AND case_id=? AND actor_id=?`, tenant.String(), caseID.String(), actor.String()).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Membership{}, auth.ErrMembershipNotFound
	}
	if err != nil {
		return auth.Membership{}, err
	}
	return auth.Membership{TenantID: tenant, CaseID: caseID, ActorID: actor, Role: auth.Role(role), Active: active == 1}, nil
}

// GetCase requires a grant for the exact scope and rechecks active membership
// so revocation takes effect even if a caller retained an older grant.
func (s *Store) GetCase(ctx context.Context, grant auth.Grant, scope casecore.Scope) (Case, error) {
	if !grant.Allows(scope, auth.ActionReadCase) {
		return Case{}, auth.ErrDenied
	}
	var title string
	err := s.db.QueryRowContext(ctx, `SELECT c.title FROM cases AS c
		JOIN case_memberships AS m ON m.tenant_id=c.tenant_id AND m.case_id=c.case_id
		WHERE c.tenant_id=? AND c.case_id=? AND m.actor_id=? AND m.active=1`,
		scope.TenantID().String(), scope.CaseID().String(), scope.ActorID().String()).Scan(&title)
	if errors.Is(err, sql.ErrNoRows) {
		return Case{}, ErrCaseNotFound
	}
	if err != nil {
		return Case{}, err
	}
	return Case{TenantID: scope.TenantID(), CaseID: scope.CaseID(), Title: title}, nil
}

// SetMembership requires current lead/admin authority inside the write
// transaction, in addition to the operation grant. Every change is audited.
func (s *Store) SetMembership(ctx context.Context, grant auth.Grant, scope casecore.Scope,
	member casecore.ActorID, role auth.Role, active bool) error {
	if !grant.Allows(scope, auth.ActionManageMembership) || member.String() == "" || !role.Valid() {
		return auth.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var callerRole string
	var callerActive int
	err = tx.QueryRowContext(ctx, `SELECT role,active FROM case_memberships
		WHERE tenant_id=? AND case_id=? AND actor_id=?`, scope.TenantID().String(),
		scope.CaseID().String(), scope.ActorID().String()).Scan(&callerRole, &callerActive)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrDenied
	}
	if err != nil {
		return err
	}
	if callerActive != 1 ||
		(callerRole != string(auth.RoleAdministrator) && callerRole != string(auth.RoleCaseLead)) {
		return auth.ErrDenied
	}
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO case_memberships(tenant_id,case_id,actor_id,role,active)
		VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,case_id,actor_id) DO UPDATE SET
		role=excluded.role,active=excluded.active,revision=revision+1`, scope.TenantID().String(),
		scope.CaseID().String(), member.String(), string(role), activeInt)
	if err != nil {
		return err
	}
	operation := "membership.revoked"
	if active {
		operation = "membership.set"
	}
	if err := appendAudit(ctx, tx, scope, operation, member.String()); err != nil {
		return err
	}
	return tx.Commit()
}
