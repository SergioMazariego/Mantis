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

func TestMatchProfileRecognizesExactBuiltInSelections(t *testing.T) {
	mk := func(id string, p collector.ProfileMask, sensitive bool) collector.Source {
		return collector.Source{ID: id, Meta: collector.Meta{Profiles: p, Sensitive: sensitive}}
	}
	all := []collector.Source{
		mk("a", collector.InAll, false), mk("b", collector.InStdFull, false), mk("c", collector.InFullOnly, false), mk("s", collector.InFullOnly, true),
	}
	if name, p := matchProfile(all, []collector.Source{all[0]}); name != "quick" || p != collector.ProfileQuick {
		t.Errorf("quick selection recognized as %q", name)
	}
	if name, _ := matchProfile(all, []collector.Source{all[0], all[1]}); name != "standard" {
		t.Errorf("standard selection recognized as %q", name)
	}
	if name, _ := matchProfile(all, []collector.Source{all[0], all[1], all[2]}); name != "full" {
		t.Errorf("full selection (sensitive excluded) recognized as %q", name)
	}
	if name, _ := matchProfile(all, []collector.Source{all[0], all[2]}); name != "" {
		t.Errorf("a mixed selection must stay custom, got %q", name)
	}
	if name, _ := matchProfile(all, []collector.Source{all[0], all[1], all[2], all[3]}); name != "" {
		t.Errorf("a selection including a sensitive source must stay custom, got %q", name)
	}
}
