package signcmd_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

func TestParseCreatedTime_Empty(t *testing.T) {
	t.Parallel()

	got, err := signcmd.ParseCreatedTime("")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), got, time.Minute,
		"empty --created should resolve to now (UTC)")
}

func TestParseCreatedTime_Valid(t *testing.T) {
	t.Parallel()

	got, err := signcmd.ParseCreatedTime("2026-06-08T12:34:56Z")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 6, 8, 12, 34, 56, 0, time.UTC), got)
}

func TestParseCreatedTime_Invalid(t *testing.T) {
	t.Parallel()

	_, err := signcmd.ParseCreatedTime("not-a-timestamp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing --created (RFC3339 expected)")
}

func TestReadFingerprint_NotArmored(t *testing.T) {
	t.Parallel()

	_, err := signcmd.ReadFingerprint([]byte("definitely not a PGP key block"))
	require.Error(t, err)
}

func TestMinisignPublicKey_Ed25519(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	key, err := signcmd.MinisignPublicKey(priv)
	require.NoError(t, err)
	assert.Equal(t, pub, key.Key)
}

func TestMinisignPublicKey_RefusesRSANamingTheOtherFormat(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = signcmd.MinisignPublicKey(priv)
	require.Error(t, err)
	assert.EqualError(t, err, "minisign requires an Ed25519 signing key, but --key-id resolved to *rsa.PublicKey; "+
		"RSA keys sign the OpenPGP manifest path (--format openpgp) instead")
}
