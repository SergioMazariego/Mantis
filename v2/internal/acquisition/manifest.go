// Package acquisition defines deterministic records of attempted collection.
package acquisition

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalidManifest = errors.New("invalid acquisition manifest")

type Status string

const (
	StatusCompleted Status = "COMPLETE"
	StatusPartial   Status = "PARTIAL"
	StatusFailed    Status = "FAILED"
)

type SourceClock struct {
	Status      string `json:"status"` // MEASURED, REPORTED or UNKNOWN
	Description string `json:"description"`
}

type Output struct {
	EvidenceSHA256 string `json:"evidence_sha256"`
	SizeBytes      int64  `json:"size_bytes"`
	SourceLocator  string `json:"source_locator"`
}

// Manifest follows the acquisition manifest schema. A failed or
// partial capture remains a durable result, with errors kept as data.
type Manifest struct {
	Version       int         `json:"version"`
	Kind          string      `json:"kind"`
	ID            string      `json:"id"`
	CaseID        string      `json:"case_id"`
	AssetID       string      `json:"asset_id"`
	PlanDigest    string      `json:"plan_digest"`
	StartedAt     string      `json:"started_at"`
	CompletedAt   string      `json:"completed_at"`
	Outputs       []Output    `json:"outputs"`
	Status        Status      `json:"status"`
	SourceKind    string      `json:"source_kind"`
	SourceLocator string      `json:"source_locator"`
	SourceClock   SourceClock `json:"source_clock"`
	Method        string      `json:"method"`
	Errors        []string    `json:"errors"`
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := range value {
		ch := value[i]
		if i == 0 {
			if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
				return false
			}
		} else if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-') {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func parseUTC(value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, value)
	return t, err == nil && strings.HasSuffix(value, "Z")
}

// CanonicalBytes validates a v1 manifest and returns stable JSON to hash/store.
func (m Manifest) CanonicalBytes() ([]byte, string, error) {
	start, startOK := parseUTC(m.StartedAt)
	end, endOK := parseUTC(m.CompletedAt)
	if m.Version != 1 || m.Kind != "acquisition-manifest" || !validID(m.ID) ||
		!validID(m.CaseID) || !validID(m.AssetID) || !validDigest(m.PlanDigest) ||
		strings.TrimSpace(m.SourceKind) == "" || strings.TrimSpace(m.SourceLocator) == "" ||
		strings.TrimSpace(m.Method) == "" || strings.TrimSpace(m.SourceClock.Description) == "" ||
		len(m.SourceKind) > 128 || len(m.SourceLocator) > 4096 || len(m.Method) > 128 ||
		len(m.SourceClock.Description) > 1024 || len(m.Outputs) > 256 || len(m.Errors) > 64 ||
		!startOK || !endOK || end.Before(start) {
		return nil, "", ErrInvalidManifest
	}
	if m.SourceClock.Status != "MEASURED" && m.SourceClock.Status != "REPORTED" && m.SourceClock.Status != "UNKNOWN" {
		return nil, "", ErrInvalidManifest
	}
	if m.Status != StatusCompleted && m.Status != StatusPartial && m.Status != StatusFailed {
		return nil, "", ErrInvalidManifest
	}
	if m.Status == StatusCompleted && (len(m.Outputs) == 0 || len(m.Errors) != 0) {
		return nil, "", ErrInvalidManifest
	}
	if m.Status == StatusPartial && (len(m.Outputs) == 0 || len(m.Errors) == 0) {
		return nil, "", ErrInvalidManifest
	}
	if m.Status == StatusFailed && (len(m.Outputs) != 0 || len(m.Errors) == 0) {
		return nil, "", ErrInvalidManifest
	}
	seen := map[string]bool{}
	for _, output := range m.Outputs {
		if !validDigest(output.EvidenceSHA256) || output.SizeBytes < 0 || strings.TrimSpace(output.SourceLocator) == "" || len(output.SourceLocator) > 4096 || seen[output.EvidenceSHA256] {
			return nil, "", ErrInvalidManifest
		}
		seen[output.EvidenceSHA256] = true
	}
	for _, message := range m.Errors {
		if strings.TrimSpace(message) == "" || len(message) > 4096 {
			return nil, "", ErrInvalidManifest
		}
	}
	if m.Outputs == nil {
		m.Outputs = []Output{}
	}
	if m.Errors == nil {
		m.Errors = []string{}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}
