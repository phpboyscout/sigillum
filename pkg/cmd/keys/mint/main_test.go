package mint_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/mint"
)

const (
	fakeBackend = "fake"
	keyID       = "alias/release"
	created     = "2026-06-08T00:00:00Z"
)

var errNoSigner = errors.New("the backend was asked for a signer")

// registerRSA registers a backend serving a fresh RSA key under fakeBackend.
func registerRSA(t *testing.T) *signtest.Backend {
	t.Helper()

	backend := &signtest.Backend{BackendName: fakeBackend, Signer: signtest.RSAKey(t)}
	signtest.Register(t, backend)

	return backend
}

func runMint(t *testing.T, p *props.Props, args ...string) error {
	t.Helper()

	all := append([]string{"--key-id", keyID, "--name", "Test Name", "--email", "test@example.com"}, args...)

	return signtest.Execute(t, mint.NewCmdMint(p).Command, all...)
}

func TestRunMint_WritesAnArmoredKeyAndLogsItsFingerprint(t *testing.T) {
	backend := registerRSA(t)

	out := filepath.Join(t.TempDir(), "out.asc")
	log := logger.NewBuffer()

	require.NoError(t, runMint(t, &props.Props{Logger: log}, "--backend", fakeBackend, "--output", out, "--created", created))

	armored, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(armored, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")), "mint output must be ASCII-armored")

	fingerprint, err := signcmd.ReadFingerprint(armored)
	require.NoError(t, err)
	assert.Len(t, fingerprint, 40, "RSA v4 fingerprint is 40 hex chars")

	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, keyfile.PublicPerm, info.Mode().Perm())
	assert.Equal(t, []string{keyID}, backend.KeyIDs)

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "Minted OpenPGP key", entries[0].Message)
	assert.Equal(t,
		[]any{"backend", fakeBackend, "key_id", keyID, "output", out, "creation_time", created, "fingerprint", fingerprint},
		entries[0].Keyvals)
}

// The selector's settings may hold anything the user typed, so the log names
// the backend by its canonical identity.
func TestRunMint_LogsTheBackendIdentityNotTheSelector(t *testing.T) {
	signtest.RegisterAwsKms(t).Signer = signtest.RSAKey(t)

	out := filepath.Join(t.TempDir(), "out.asc")
	log := logger.NewBuffer()

	require.NoError(t, runMint(t, &props.Props{Logger: log},
		"--backend", "aws-kms:prod?kms-region=eu-west-1", "--output", out, "--created", created))

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, []any{"backend", "aws-kms:prod"}, entries[0].Keyvals[:2])
}

func TestRunMint_APinnedCreationTimeGivesTheSameFingerprint(t *testing.T) {
	backend := registerRSA(t)

	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.asc"), filepath.Join(dir, "second.asc")

	require.NoError(t, runMint(t, signtest.Props(), "--backend", fakeBackend, "--output", first, "--created", created))
	require.NoError(t, runMint(t, signtest.Props(), "--backend", fakeBackend, "--output", second, "--created", created))

	a, err := os.ReadFile(first)
	require.NoError(t, err)

	b, err := os.ReadFile(second)
	require.NoError(t, err)

	fpA, err := signcmd.ReadFingerprint(a)
	require.NoError(t, err)

	fpB, err := signcmd.ReadFingerprint(b)
	require.NoError(t, err)

	assert.Equal(t, fpA, fpB)

	// The fingerprint covers the creation time, so it proves --created was used.
	pinned, err := openpgpkey.ArmoredPublicKey(backend.Signer, "Test Name", "test@example.com",
		time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	want, err := signcmd.ReadFingerprint(pinned)
	require.NoError(t, err)
	assert.Equal(t, want, fpA)
}

func TestRunMint_DefaultsToReleaseAsc(t *testing.T) {
	registerRSA(t)
	t.Chdir(t.TempDir())

	require.NoError(t, runMint(t, signtest.Props(), "--backend", fakeBackend))
	assert.FileExists(t, "release.asc")
}

// Neither refusal needs a key, so neither may reach the backend. For a KMS key
// that is a call, and a failed one would hide the mistake the user made.
func TestRunMint_RefusesBeforeAskingTheBackendForASigner(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"stdout output": {
			args: []string{"--output", "-"},
			want: `--output "-" (stdout) is not supported; pass a file path`,
		},
		"created time": {
			args: []string{"--created", "garbage"},
			want: "parsing --created (RFC3339 expected)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Err: errNoSigner})
			t.Chdir(t.TempDir())

			err := runMint(t, signtest.Props(), append([]string{"--backend", fakeBackend}, tc.args...)...)
			require.ErrorContains(t, err, tc.want)
			require.NotErrorIs(t, err, errNoSigner)
		})
	}
}

func TestRunMint_ASignerFailureNamesTheStep(t *testing.T) {
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Err: errNoSigner})

	out := filepath.Join(t.TempDir(), "out.asc")

	err := runMint(t, signtest.Props(), "--backend", fakeBackend, "--output", out)
	require.ErrorIs(t, err, errNoSigner)
	require.ErrorContains(t, err, "constructing signer")
	assert.NoFileExists(t, out)
}

func TestRunMint_UnknownBackend(t *testing.T) {
	signtest.Register(t)

	err := runMint(t, signtest.Props(), "--backend", "no-such-backend", "--output", filepath.Join(t.TempDir(), "out.asc"))
	require.ErrorIs(t, err, signing.ErrUnknownBackend)
}

func TestRunMint_RefusesAKeyOpenPGPCannotFrame(t *testing.T) {
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.Ed25519Key()})

	out := filepath.Join(t.TempDir(), "out.asc")

	err := runMint(t, signtest.Props(), "--backend", fakeBackend, "--output", out)
	require.ErrorContains(t, err, "minting armored public key")
	assert.NoFileExists(t, out)
}

func TestRunMint_RefusesToClobberOutput(t *testing.T) {
	registerRSA(t)

	out := filepath.Join(t.TempDir(), "release.asc")
	args := []string{"--backend", fakeBackend, "--output", out, "--created", created}

	require.NoError(t, runMint(t, signtest.Props(), args...))

	original, err := os.ReadFile(out)
	require.NoError(t, err)

	err = runMint(t, signtest.Props(), args...)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.ErrorContains(t, err, "pass --force to overwrite")

	after, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, original, after, "a refused mint must not modify the existing file")

	require.NoError(t, runMint(t, signtest.Props(), append(args, "--force")...))
}

func TestRunMint_RequiresBackendKeyNameAndEmail(t *testing.T) {
	registerRSA(t)

	err := signtest.Execute(t, mint.NewCmdMint(signtest.Props()).Command)
	require.ErrorContains(t, err, `required flag(s) "backend", "email", "key-id", "name" not set`)
}

func TestNewCmdMint_OffersEachLinkedBackendSettingAsAFlag(t *testing.T) {
	signtest.RegisterAwsKms(t)

	flag := mint.NewCmdMint(signtest.Props()).Flags().Lookup("kms-region")
	require.NotNil(t, flag)
	assert.Equal(t, "AWS region the KMS key lives in", flag.Usage)
}

func TestRunMint_ABackendFlagConfiguresTheDefaultBackend(t *testing.T) {
	def := signtest.RegisterAwsKms(t)
	def.Signer = signtest.RSAKey(t)

	out := filepath.Join(t.TempDir(), "out.asc")

	require.NoError(t, runMint(t, signtest.Props(), "--backend", "aws-kms", "--kms-region", "eu-west-1", "--output", out))
	assert.Equal(t, "eu-west-1", def.Config.Region)
}

func TestRunMint_RefusesABackendFlagBesideANamedInstance(t *testing.T) {
	signtest.RegisterAwsKms(t)

	out := filepath.Join(t.TempDir(), "out.asc")

	err := runMint(t, signtest.Props(), "--backend", "aws-kms:prod", "--kms-region", "eu-west-1", "--output", out)
	require.ErrorContains(t, err, `--kms-region configures the default "aws-kms" backend, not the named instance "aws-kms:prod"`)
	assert.NoFileExists(t, out)
}
