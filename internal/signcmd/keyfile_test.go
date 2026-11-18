package signcmd_test

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"

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

func TestWriteKeyPair_RefusalNamesTheHalfThatExistsAndWritesNeither(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	private := keyfile.Half{Path: filepath.Join(dir, "image.key"), Data: []byte("private")}
	public := keyfile.Half{Path: filepath.Join(dir, "image.pub"), Data: []byte("public")}
	require.NoError(t, os.WriteFile(public.Path, []byte("original"), 0o600))

	err := signcmd.WriteKeyPair(private, public, false)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.EqualError(t, err, `"`+public.Path+`" (pass --force to overwrite): output file already exists`)
	assert.Equal(t, "signing-cli.key_file_exists", errors.KindOf(err))

	assert.NoFileExists(t, private.Path)

	kept, readErr := os.ReadFile(public.Path)
	require.NoError(t, readErr)
	assert.Equal(t, "original", string(kept))
}

func TestIsSameOutput(t *testing.T) {
	t.Parallel()

	assert.True(t, signcmd.IsSameOutput(errors.Wrap(keyfile.ErrSameOutput, "a.pem")))
	assert.False(t, signcmd.IsSameOutput(stderrors.Join(keyfile.ErrPrivateHalfReplaced, keyfile.ErrSameOutput)),
		"a replaced private half is never reported as a mere refusal")
	assert.False(t, signcmd.IsSameOutput(keyfile.ErrKeyFileExists))
}

func TestWriteKeyPair_OtherRefusalsKeepTheLibrarysError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "image.key")
	half := keyfile.Half{Path: path, Data: []byte("key")}

	require.ErrorIs(t, signcmd.WriteKeyPair(half, half, true), keyfile.ErrSameOutput)
	assert.NoFileExists(t, path)
}
