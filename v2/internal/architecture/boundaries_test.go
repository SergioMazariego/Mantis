package architecture

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// The case model sits at the center of the monolith and may not depend on
// storage, providers, workflows or command packages. Extend these checks as
// real packages are added; a deliberate boundary change needs ADR review.
func TestFoundationImportBoundary(t *testing.T) {
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = "../.."
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("list packages: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	for {
		var pkg struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(pkg.ImportPath, "/internal/casecore") {
			for _, dependency := range pkg.Imports {
				if strings.Contains(dependency, "/internal/") || strings.Contains(dependency, "/cmd/") {
					t.Errorf("casecore imports outward package %s", dependency)
				}
			}
		}
		if strings.Contains(pkg.ImportPath, "/internal/") {
			for _, dependency := range pkg.Imports {
				if strings.Contains(dependency, "/cmd/") {
					t.Errorf("internal package imports command %s", dependency)
				}
			}
		}
	}
}
