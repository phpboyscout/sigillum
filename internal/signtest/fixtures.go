package signtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/openpgpkey"
)

const fixturePerm = 0o600

const rsaFixtureBits = 2048

// Execute runs cmd with args as the CLI would, with its output discarded.
func Execute(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()

	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	return cmd.ExecuteContext(context.Background())
}

// RSAKey generates an RSA key of the size the sign-side tests use.
func RSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, rsaFixtureBits)
	require.NoError(t, err)

	return priv
}

// Ed25519Key returns the same Ed25519 key on every call.
func Ed25519Key() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	return ed25519.NewKeyFromSeed(seed)
}

// WritePublicKey writes priv's armored OpenPGP public key to dir/release.asc
// and returns the path.
func WritePublicKey(t *testing.T, dir string, priv *rsa.PrivateKey) string {
	t.Helper()

	armored, err := openpgpkey.ArmoredPublicKey(priv, "Test Signer", "test@example.org", FixtureKeyTime)
	require.NoError(t, err)

	path := filepath.Join(dir, "release.asc")
	require.NoError(t, os.WriteFile(path, armored, fixturePerm))

	return path
}

// WriteFile writes body to dir/name and returns the path.
func WriteFile(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), fixturePerm))

	return path
}
