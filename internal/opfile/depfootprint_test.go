package opfile_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestOpfileNeedsNothingButTheStandardLibrary is what keeps the default honest.
//
// The package takes an FS so a caller can supply the operating system, an
// in-memory filesystem or their own implementation. That promise is only worth
// anything if importing the package does not drag in a filesystem library
// anyway — otherwise the interface is decoration over a dependency the caller
// never chose, which is exactly what go/config's FS exists to avoid.
//
// The afero coupling belongs in opfileafero, and this is the guard that keeps
// it there.
func TestOpfileNeedsNothingButTheStandardLibrary(t *testing.T) {
	t.Parallel()

	out, err := exec.Command("go", "list", "-deps", "gitlab.com/phpboyscout/sigillum/internal/opfile").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	const self = "gitlab.com/phpboyscout/sigillum/internal/opfile"

	for _, dep := range strings.Fields(string(out)) {
		// A standard-library path has no dot in its first element.
		first, _, _ := strings.Cut(dep, "/")
		if !strings.Contains(first, ".") || dep == self {
			continue
		}

		t.Errorf("opfile reaches %s; the filesystem coupling belongs in opfileafero", dep)
	}
}
