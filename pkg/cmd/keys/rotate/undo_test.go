package rotate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// underAFile returns a path whose parent is a regular file, which every write and
// remove refuses with ENOTDIR, root included.
func underAFile(t *testing.T) string {
	t.Helper()

	parent := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(parent, nil, 0o600))

	return filepath.Join(parent, "rotate-keys.json")
}

func TestUndoManifest_SaysWhenRemovingTheNewManifestFails(t *testing.T) {
	t.Parallel()

	path := underAFile(t)

	err := undoManifest(path, nil, false)
	assert.Contains(t, err.Error(), path+" holds an unsigned manifest, and removing it failed")
}

func TestUndoManifest_SaysWhenRestoringTheEarlierManifestFails(t *testing.T) {
	t.Parallel()

	path := underAFile(t)

	err := undoManifest(path, []byte("earlier"), true)
	assert.Contains(t, err.Error(), path+" now holds the new manifest with the earlier signature, and restoring it failed")
}
