package signcmd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/phpboyscout/go/errors"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

func TestWriteKeyFile_RefusalKeepsTheForceHintAndTheKnownKind(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.asc")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))

	err := signcmd.WriteKeyFile(path, []byte("replacement"), 0o600, false)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.EqualError(t, err, `"`+path+`" (pass --force to overwrite): output file already exists`)
	assert.Equal(t, "signing-cli.key_file_exists", errors.KindOf(err))

	kept, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "original", string(kept), "a refused write must leave the existing key alone")
}

func TestWriteKeyFile_ForceOverwritesAndTightensTheMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o644))

	require.NoError(t, signcmd.WriteKeyFile(path, []byte("replacement"), 0o600, true))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(got))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
