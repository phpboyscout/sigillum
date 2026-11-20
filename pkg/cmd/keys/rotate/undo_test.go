package rotate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tooLongToReplace returns a file holding contents whose name fits the 255-byte
// limit but whose keyfile temp name, "."+base+".*", does not. Replacing it fails
// with ENAMETOOLONG for every user, root included, and leaves it readable.
func tooLongToReplace(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), strings.Repeat("m", 250))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	return path
}

// cannotBeRemoved returns a non-empty directory, which os.Remove refuses for
// every user, root included.
func cannotBeRemoved(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "rotate-keys.json")
	require.NoError(t, os.Mkdir(path, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "held"), nil, 0o600))

	return path
}

func TestUndoManifest_SaysWhenRemovingTheNewManifestFails(t *testing.T) {
	t.Parallel()

	path := cannotBeRemoved(t)

	err := undoManifest(path, nil, false)
	assert.Contains(t, err.Error(), path+" holds an unsigned manifest, and removing it failed")
	assert.FileExists(t, filepath.Join(path, "held"), "a failed undo removed more than the manifest")
}

func TestUndoManifest_SaysWhenRestoringTheEarlierManifestFails(t *testing.T) {
	t.Parallel()

	path := tooLongToReplace(t, "new")

	err := undoManifest(path, []byte("earlier"), true)
	assert.Contains(t, err.Error(), path+" now holds the new manifest with the earlier signature, and restoring it failed")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got), "the error says the new manifest is still there")
}
