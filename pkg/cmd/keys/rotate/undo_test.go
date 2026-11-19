package rotate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readOnlyDirWith(t *testing.T, name, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	require.NoError(t, os.Chmod(dir, 0o500)) //nolint:gosec // the test needs a directory nothing can be created or removed in
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if f, err := os.Create(filepath.Join(dir, "probe")); err == nil {
		_ = f.Close()
		t.Skip("the directory is still writable, as it is for root")
	}

	return path
}

func TestUndoManifest_SaysWhenRemovingTheNewManifestFails(t *testing.T) {
	t.Parallel()

	path := readOnlyDirWith(t, "rotate-keys.json", "new")

	err := undoManifest(path, nil, false)
	assert.Contains(t, err.Error(), "holds an unsigned manifest, and removing it failed")
	assert.FileExists(t, path)
}

func TestUndoManifest_SaysWhenRestoringTheEarlierManifestFails(t *testing.T) {
	t.Parallel()

	path := readOnlyDirWith(t, "rotate-keys.json", "new")

	err := undoManifest(path, []byte("earlier"), true)
	assert.Contains(t, err.Error(), "now holds the new manifest with the earlier signature, and restoring it failed")
}
