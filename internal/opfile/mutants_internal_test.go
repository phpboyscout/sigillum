package opfile

// Unexported-surface tests that pin behaviour a black-box test cannot reach:
// the directory-sync error path and the path-description collapse. Both are
// points a mutation testing pass showed the suite did not notice a change to.

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// TestSyncDirSurfacesTheOpenError pins that a directory that cannot be opened
// yields THAT open error, rather than the code walking on to sync a handle it
// never obtained. The assertion is on the specific error, not merely that one
// occurred: inverting the guard walks on to sync a nil file, which returns
// os.ErrInvalid — also non-nil, so only checking for the not-exist error tells
// the two apart.
func TestSyncDirSurfacesTheOpenError(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "no-such-directory")

	err := (osFS{}).SyncDir(missing)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("SyncDir on a missing directory = %v, want the open not-exist error surfaced", err)
	}
}

// TestSyncDirFlushesARealDirectory pins the success path: a directory that does
// open flushes without error, or reports the capability as unsupported — never
// some other failure.
func TestSyncDirFlushesARealDirectory(t *testing.T) {
	t.Parallel()

	if err := (osFS{}).SyncDir(t.TempDir()); err != nil && !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("SyncDir on a real directory: %v", err)
	}
}

// TestDescribePathCollapsesOnlyWhenTheWalkStayedPut pins both arms: the same
// path named and reached is rendered once; a walk that moved is rendered as
// both, so the operator sees where a link led.
func TestDescribePathCollapsesOnlyWhenTheWalkStayedPut(t *testing.T) {
	t.Parallel()

	if got := describePath("/reports/today", "/reports/today"); got != "/reports/today" {
		t.Errorf("describePath with named == at = %q, want the bare path", got)
	}

	if got := describePath("/reports/today", "/mnt/share/today"); got != "/reports/today (via /mnt/share/today)" {
		t.Errorf("describePath with named != at = %q, want the via form", got)
	}
}
