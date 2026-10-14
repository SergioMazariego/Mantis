package acquisition

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func validFixture(status Status) Manifest {
	m := Manifest{
		Version: 1, Kind: "acquisition-manifest", ID: "acq-1", CaseID: "case", AssetID: "host-1", PlanDigest: strings.Repeat("a", 64),
		SourceKind: "windows.evtx", SourceLocator: "Security", SourceClock: SourceClock{Status: "UNKNOWN", Description: "source clock unavailable"},
		Method: "native-copy-v1", Status: status, StartedAt: "2026-01-01T00:00:00Z",
		CompletedAt: "2026-01-01T00:00:01Z", Outputs: []Output{{EvidenceSHA256: strings.Repeat("b", 64), SizeBytes: 6, SourceLocator: "Security"}},
	}
	if status == StatusPartial {
		m.Errors = []string{"source read interrupted"}
	}
	if status == StatusFailed {
		m.Outputs = nil
		m.Errors = []string{"source unavailable"}
	}
	return m
}

func TestStatusDoesNotMisrepresentPartialCapture(t *testing.T) {
	for _, status := range []Status{StatusCompleted, StatusPartial, StatusFailed} {
		m := validFixture(status)
		first, digest, err := m.CanonicalBytes()
		if err != nil {
			t.Fatalf("valid %s: %v", status, err)
		}
		second, secondDigest, err := m.CanonicalBytes()
		if err != nil || string(first) != string(second) || digest != secondDigest {
			t.Fatalf("nondeterministic %s: %v", status, err)
		}
		if bytes.Contains(first, []byte(`"outputs":null`)) || bytes.Contains(first, []byte(`"errors":null`)) {
			t.Fatalf("schema array serialized as null for %s", status)
		}
	}
	m := validFixture(StatusCompleted)
	m.Errors = []string{"ignored failure"}
	if _, _, err := m.CanonicalBytes(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("false completion accepted: %v", err)
	}
	m = validFixture(StatusPartial)
	m.Errors = nil
	if _, _, err := m.CanonicalBytes(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("partial without error accepted: %v", err)
	}
	m = validFixture(StatusFailed)
	m.Outputs = []Output{{EvidenceSHA256: strings.Repeat("b", 64), SizeBytes: 6, SourceLocator: "Security"}}
	if _, _, err := m.CanonicalBytes(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("failed with output accepted: %v", err)
	}
	m = validFixture(StatusCompleted)
	m.SourceLocator = strings.Repeat("x", 4097)
	if _, _, err := m.CanonicalBytes(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unbounded locator accepted: %v", err)
	}
}
