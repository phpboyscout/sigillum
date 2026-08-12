package steps_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPathKeepsArtefactsInsideTheScenarioDirectory is what justifies the
// gosec G703 exclusion for this file in .golangci.yaml.
//
// The taint analysis is right that artefact names reach os.WriteFile from the
// feature files, which are input. What it cannot see is that path anchors every
// name inside the scenario's own temporary directory. This is that claim,
// checked, so the exclusion rests on a test rather than on a comment.
func TestPathKeepsArtefactsInsideTheScenarioDirectory(t *testing.T) {
	t.Parallel()

	w := &world{dir: filepath.Join(t.TempDir(), "scenario")}

	for _, name := range []string{
		"report.txt",
		"../escaped.txt",
		"../../../../etc/passwd",
		"nested/../../escaped.txt",
		"/absolute.txt",
		"",
		".",
		"..",
	} {
		got := w.path(name)

		if !strings.HasPrefix(filepath.Clean(got)+string(filepath.Separator),
			filepath.Clean(w.dir)+string(filepath.Separator)) && filepath.Clean(got) != filepath.Clean(w.dir) {
			t.Errorf("path(%q) = %q, which is outside the scenario directory %q", name, got, w.dir)
		}
	}
}
