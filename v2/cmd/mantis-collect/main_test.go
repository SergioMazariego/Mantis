package main

import (
	"context"
	"io"
	"testing"

	"github.com/SergioMazariego/Mantis/v2/internal/collector"
)

func TestSelectByIDIsExplicitAndRejectsUnknown(t *testing.T) {
	noop := func(context.Context) (io.ReadCloser, error) { return io.NopCloser(nilReader{}), nil }
	catalog := []collector.Source{
		{ID: "windows.evtx", Kind: "windows.evtx", Locator: "eventlog://System", Method: "test", MaxBytes: 1, Open: noop},
		{ID: "zimbra.audit", Kind: "linux.zimbra_audit_log", Locator: "/opt/zimbra/log/audit.log", Method: "test", MaxBytes: 1, Open: noop},
	}
	selected, err := selectByID(catalog, []string{"windows.evtx"})
	if err != nil || len(selected) != 1 || selected[0].ID != "windows.evtx" {
		t.Fatalf("select: %+v %v", selected, err)
	}
	if _, err := selectByID(catalog, []string{"missing"}); err == nil {
		t.Fatal("unknown optional source accepted")
	}
	if _, err := selectByID(catalog, []string{"windows.evtx", "windows.evtx"}); err == nil {
		t.Fatal("duplicate selection accepted")
	}
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }
