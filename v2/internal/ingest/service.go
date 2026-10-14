// Package ingest coordinates the standalone evidence and case metadata stores.
package ingest

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/acquisition"
	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/storage/sqlite"
)

var ErrUnavailable = errors.New("ingest service dependency unavailable")

type Service struct {
	authorizer *auth.Authorizer
	blobs      *evidence.Store
	metadata   *sqlite.Store
}

type Request struct {
	ID            string
	AssetID       string
	PlanDigest    string
	SourceKind    string
	SourceLocator string
	SourceClock   acquisition.SourceClock
	Method        string
	MaxBytes      int64
}

type Result struct {
	Blob           evidence.Blob
	ManifestSHA256 string
	Status         acquisition.Status
	Ready          bool
}

func New(ctx context.Context, authorizer *auth.Authorizer, blobs *evidence.Store, metadata *sqlite.Store) (*Service, error) {
	if ctx == nil || authorizer == nil || blobs == nil || metadata == nil {
		return nil, ErrUnavailable
	}
	s := &Service{authorizer, blobs, metadata}
	if err := s.Reconcile(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Reconcile runs before a service is returned to callers. Incomplete bytes
// remain quarantined; only a verified blob, manifest and custody can complete.
func (s *Service) Reconcile(ctx context.Context) error {
	intents, err := s.metadata.ListPendingIntents(ctx)
	if err != nil {
		return err
	}
	complete, err := s.metadata.ListCompleteIntents(ctx)
	if err != nil {
		return err
	}
	intents = append(intents, complete...)
	for _, intent := range intents {
		intent, err = s.metadata.EnrichIntent(ctx, intent)
		if err != nil {
			return err
		}
		verified := false
		if intent.EvidenceSHA256 != "" {
			tenant, err := casecore.NewTenantID(intent.TenantID)
			if err != nil {
				return err
			}
			caseID, err := casecore.NewCaseID(intent.CaseID)
			if err != nil {
				return err
			}
			actor, err := casecore.NewActorID("system-recovery")
			if err != nil {
				return err
			}
			scope, err := casecore.NewScope(tenant, caseID, actor)
			if err != nil {
				return err
			}
			verified = s.blobs.VerifyForRecovery(ctx, scope, intent.EvidenceSHA256) == nil
		}
		if err := s.metadata.ReconcileIntent(ctx, intent, verified); err != nil {
			return err
		}
	}
	return nil
}

// CollectOne persists an honest outcome for one streamed source. CAS verifies
// the published bytes before a COMPLETE manifest can reference their digest.
func (s *Service) CollectOne(ctx context.Context, scope casecore.Scope, request Request, input io.Reader) (Result, error) {
	if s == nil || input == nil || ctx == nil {
		return Result{}, ErrUnavailable
	}
	grant, err := s.authorizer.Authorize(ctx, scope, auth.ActionIngestEvidence)
	if err != nil {
		return Result{}, err
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	m := acquisition.Manifest{
		Version: 1, Kind: "acquisition-manifest", ID: request.ID,
		CaseID: scope.CaseID().String(), AssetID: request.AssetID,
		PlanDigest: request.PlanDigest, StartedAt: started,
		CompletedAt: started,
		SourceKind:  request.SourceKind, SourceLocator: request.SourceLocator,
		SourceClock: request.SourceClock, Method: request.Method,
		Status: acquisition.StatusFailed, Errors: []string{"preflight"},
	}
	if _, _, err := m.CanonicalBytes(); err != nil {
		return Result{}, err
	}
	if request.MaxBytes <= 0 {
		return Result{}, evidence.ErrTooLarge
	}
	if err := s.metadata.StartIntent(ctx, grant, scope, request.ID); err != nil {
		return Result{}, err
	}
	blob, collectionErr := s.blobs.Put(ctx, grant, scope, input, request.MaxBytes)
	if collectionErr == nil {
		if err := s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentBlobVerified, blob.SHA256, "", ""); err != nil {
			_ = s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, blob.SHA256, "", "blob verified but journal transition failed")
			return Result{Blob: blob}, err
		}
		m.Status = acquisition.StatusCompleted
		m.Errors = nil
		m.Outputs = []acquisition.Output{{EvidenceSHA256: blob.SHA256,
			SizeBytes: blob.SizeBytes, SourceLocator: request.SourceLocator}}
	} else {
		m.Status = acquisition.StatusFailed
		message := collectionErr.Error()
		if len(message) > 4096 {
			message = "collection error message exceeded manifest limit"
		}
		m.Errors = []string{message}
	}
	m.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifestDigest, manifestErr := s.metadata.PutManifest(ctx, grant, scope, m)
	if manifestErr != nil {
		_ = s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, blob.SHA256, "", "manifest write failed")
		return Result{}, errors.Join(collectionErr, manifestErr)
	}
	result := Result{Blob: blob, ManifestSHA256: manifestDigest, Status: m.Status}
	if collectionErr != nil {
		if err := s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, "", manifestDigest, "collection failed"); err != nil {
			return result, errors.Join(collectionErr, err)
		}
		return result, collectionErr
	}
	if err := s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentMetadataCommitted, blob.SHA256, manifestDigest, ""); err != nil {
		_ = s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, blob.SHA256, manifestDigest, "metadata transition failed")
		return result, err
	}
	_, err = s.metadata.AppendCustody(ctx, grant, scope, blob.SHA256,
		sqlite.CustodyIngest, sqlite.CustodyDetails{AcquisitionID: request.ID})
	if err != nil {
		_ = s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, blob.SHA256, manifestDigest, "custody write failed")
		return result, err
	}
	if err := s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentCustodyCommitted, blob.SHA256, manifestDigest, ""); err != nil {
		_ = s.metadata.AdvanceIntent(ctx, grant, scope, request.ID, sqlite.IntentRecoveryRequired, blob.SHA256, manifestDigest, "custody transition failed")
		return result, err
	}
	result.Ready = true
	return result, nil
}

// OpenVerified records an ACCESS event before exposing the verified handle.
// A failed custody write closes the handle and denies access.
func (s *Service) OpenVerified(ctx context.Context, scope casecore.Scope, digest string) (*os.File, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	grant, err := s.authorizer.Authorize(ctx, scope, auth.ActionReadEvidence)
	if err != nil {
		return nil, err
	}
	if err := s.metadata.HasCompleteBlob(ctx, grant, scope, digest); err != nil {
		return nil, err
	}
	file, err := s.blobs.Open(ctx, grant, scope, digest)
	if err != nil {
		return nil, err
	}
	if _, err := s.metadata.AppendCustody(ctx, grant, scope, digest, sqlite.CustodyAccess,
		sqlite.CustodyDetails{Reason: "verified evidence read"}); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
