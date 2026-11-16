package generate_image_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/signing/keyfile"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	generate_image "gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/generate-image"
)

// keyPaths are the two files one generate-image run writes.
type keyPaths struct{ pub, priv string }

func pathsIn(dir string) keyPaths {
	return keyPaths{pub: filepath.Join(dir, "image.pub"), priv: filepath.Join(dir, "image.key")}
}

func run(t *testing.T, paths keyPaths, args ...string) error {
	t.Helper()

	return runWith(t, signtest.Props(), paths, args...)
}

func runWith(t *testing.T, p *props.Props, paths keyPaths, args ...string) error {
	t.Helper()

	all := append([]string{"--output", paths.pub, "--private-output", paths.priv}, args...)

	return signtest.Execute(t, generate_image.NewCmdGenerateImage(p).Command, all...)
}

func readPEM(t *testing.T, path, blockType string) []byte {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	block, rest := pem.Decode(raw)
	require.NotNil(t, block, path)
	assert.Equal(t, blockType, block.Type, path)
	assert.Empty(t, rest, "nothing follows the key in %s", path)

	return block.Bytes
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular(), "%s is a regular file", path)
	assert.Equal(t, want, info.Mode().Perm(), path)
}

func TestGenerateImage_WritesAMatchingP256Pair(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.NoError(t, run(t, paths))

	private, err := x509.ParsePKCS8PrivateKey(readPEM(t, paths.priv, "PRIVATE KEY"))
	require.NoError(t, err)

	public, err := x509.ParsePKIXPublicKey(readPEM(t, paths.pub, "PUBLIC KEY"))
	require.NoError(t, err)

	key, ok := private.(*ecdsa.PrivateKey)
	require.True(t, ok, "the private key is ECDSA")
	assert.Equal(t, elliptic.P256(), key.Curve)
	assert.True(t, key.PublicKey.Equal(public), "the two halves match")

	assertMode(t, paths.priv, keyfile.PrivatePerm)
	assertMode(t, paths.pub, keyfile.PublicPerm)
}

func TestGenerateImage_DefaultsToImagePubAndImageKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, signtest.Execute(t, generate_image.NewCmdGenerateImage(signtest.Props()).Command))

	assert.FileExists(t, filepath.Join(dir, "image.pub"))
	assert.FileExists(t, filepath.Join(dir, "image.key"))
}

func TestGenerateImage_LogsWhereBothHalvesWent(t *testing.T) {
	t.Parallel()

	log := logger.NewBuffer()
	paths := pathsIn(t.TempDir())
	require.NoError(t, runWith(t, &props.Props{Logger: log}, paths))

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "Generated image-signing keypair", entries[0].Message)
	assert.Equal(t, []any{"public", paths.pub, "private", paths.priv}, entries[0].Keyvals)
}

func TestGenerateImage_TakesNoArguments(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.Error(t, run(t, paths, "stray"))
	assert.NoFileExists(t, paths.priv)
}

func TestGenerateImage_RefusesToOverwriteWithoutForce(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.NoError(t, run(t, paths))

	before, err := os.ReadFile(paths.priv)
	require.NoError(t, err)

	err = run(t, paths)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	assert.Contains(t, err.Error(), `"`+paths.priv+`" (pass --force to overwrite)`)

	after, err := os.ReadFile(paths.priv)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused run leaves the private key as it was")

	require.NoError(t, run(t, paths, "--force"))

	after, err = os.ReadFile(paths.priv)
	require.NoError(t, err)
	assert.NotEqual(t, before, after)
}

func TestGenerateImage_AnExistingPublicKeyWritesNothing(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.NoError(t, os.WriteFile(paths.pub, []byte("an older public key"), keyfile.PublicPerm))

	err := run(t, paths)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	assert.Contains(t, err.Error(), `"`+paths.pub+`" (pass --force to overwrite)`)

	assert.NoFileExists(t, paths.priv, "no private key that matches nothing")
}

func TestGenerateImage_ForceReplacesALongerFileAndTightensItsMode(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.NoError(t, os.WriteFile(paths.priv, bytes.Repeat([]byte("x"), 4096), 0o644)) //nolint:gosec // proving the mode is tightened

	require.NoError(t, run(t, paths, "--force"))

	readPEM(t, paths.priv, "PRIVATE KEY")
	assertMode(t, paths.priv, keyfile.PrivatePerm)
}

func TestGenerateImage_ForceReplacesALinkWithoutWritingThroughIt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := pathsIn(dir)
	target := filepath.Join(dir, "elsewhere")
	require.NoError(t, os.WriteFile(target, []byte("not yours to overwrite"), 0o644)) //nolint:gosec // proving it is left alone
	require.NoError(t, os.Symlink(target, paths.priv))

	require.NoError(t, run(t, paths, "--force"))

	untouched, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "not yours to overwrite", string(untouched))

	assertMode(t, paths.priv, keyfile.PrivatePerm)
}

func TestGenerateImage_RefusesOneFileForBothHalves(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "image.key")
	respelt := filepath.Join(dir, "sub", "..", "image.key")

	for _, force := range [][]string{nil, {"--force"}} {
		err := run(t, keyPaths{pub: respelt, priv: path}, force...)
		require.ErrorIs(t, err, generate_image.ErrSameOutput)
		assert.Contains(t, err.Error(), "--output and --private-output name the same file")
		assert.NoFileExists(t, path)
	}
}

func TestGenerateImage_RefusesALinkFromOneHalfToTheOther(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir())
	require.NoError(t, os.WriteFile(paths.priv, []byte("an older private key"), keyfile.PrivatePerm))
	require.NoError(t, os.Symlink(paths.priv, paths.pub))

	err := run(t, paths, "--force")
	require.ErrorIs(t, err, generate_image.ErrSameOutput)

	kept, err := os.ReadFile(paths.priv)
	require.NoError(t, err)
	assert.Equal(t, "an older private key", string(kept))
}

func TestGenerateImage_ADirectoryForEitherHalfWritesNothing(t *testing.T) {
	t.Parallel()

	for _, half := range []string{"public", "private"} {
		for _, force := range [][]string{nil, {"--force"}} {
			paths := pathsIn(t.TempDir())

			occupied, other := paths.pub, paths.priv
			if half == "private" {
				occupied, other = paths.priv, paths.pub
			}

			require.NoError(t, os.Mkdir(occupied, 0o750))

			err := run(t, paths, force...)
			require.ErrorIs(t, err, keyfile.ErrIsDirectory, "%s half, %v", half, force)
			assert.Contains(t, err.Error(), occupied)
			assert.NoFileExists(t, other, "%s half, %v", half, force)
			assert.DirExists(t, occupied)
		}
	}
}
