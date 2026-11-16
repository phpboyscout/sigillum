package minisign_test

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	libminisign "gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/minisign"
)

const fakeBackend = "fake"

// registerEd25519 registers a backend serving the fixture Ed25519 key and
// returns the minisign key the command must emit for it.
func registerEd25519(t *testing.T) libminisign.PublicKey {
	t.Helper()

	priv := signtest.Ed25519Key()
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	key, err := signcmd.MinisignPublicKey(priv)
	require.NoError(t, err)

	return key
}

func runMinisign(t *testing.T, args ...string) error {
	t.Helper()

	all := append([]string{"--backend", fakeBackend, "--key-id", "ignored"}, args...)

	return signtest.Execute(t, minisign.NewCmdMinisign(signtest.Props()).Command, all...)
}

// The real os.Stdout is captured with the command's output left unset, as the
// CLI runs it. A buffer set with SetOut cannot tell stdout from stderr: cobra's
// print helpers use the configured output when there is one and stderr when
// there is not, so `keys minisign > key.b64` once produced an empty file.
func TestRunMinisign_PrintsThePinnableKeyOnRealStdout(t *testing.T) {
	want := registerEd25519(t)

	orig := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	t.Cleanup(func() { os.Stdout = orig })

	cmd := minisign.NewCmdMinisign(signtest.Props()).Command
	cmd.SetArgs([]string{"--backend", fakeBackend, "--key-id", "ignored"})
	runErr := cmd.ExecuteContext(t.Context())

	require.NoError(t, w.Close())

	os.Stdout = orig

	captured, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, runErr)

	assert.Equal(t, want.Encode()+"\n", string(captured), "the key, and only the key, must reach real stdout so it can be piped")
	assert.True(t, strings.HasPrefix(string(captured), "RW"),
		`a minisign public key carries the "Ed" tag, which base64s to a leading "RW"`)
}

func TestRunMinisign_WritesThePublicKeyFile(t *testing.T) {
	want := registerEd25519(t)

	output := filepath.Join(t.TempDir(), "artefact.pub")

	require.NoError(t, runMinisign(t, "--output", output))

	body, err := os.ReadFile(output)
	require.NoError(t, err)

	parsed, err := libminisign.ParsePublicKey(string(body))
	require.NoError(t, err)
	assert.Equal(t, want, parsed)

	comment, _, _ := strings.Cut(string(body), "\n")
	assert.Regexp(t, `^untrusted comment: minisign public key [0-9A-F]{16}$`, comment)

	info, err := os.Stat(output)
	require.NoError(t, err)
	assert.Equal(t, keyfile.PublicPerm, info.Mode().Perm())
}

func TestRunMinisign_CommentReplacesTheDefault(t *testing.T) {
	registerEd25519(t)

	output := filepath.Join(t.TempDir(), "artefact.pub")

	require.NoError(t, runMinisign(t, "--output", output, "--comment", "demo artefact key"))

	body, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(body), "untrusted comment: demo artefact key\n"))
}

func TestRunMinisign_RefusesToClobberWithoutForce(t *testing.T) {
	registerEd25519(t)

	output := filepath.Join(t.TempDir(), "artefact.pub")
	require.NoError(t, os.WriteFile(output, []byte("existing\n"), 0o600))

	err := runMinisign(t, "--output", output)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.ErrorContains(t, err, "writing "+output)

	untouched, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "existing\n", string(untouched))

	require.NoError(t, runMinisign(t, "--output", output, "--force"))

	body, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "existing")
}

func TestRunMinisign_RejectsRSAKey(t *testing.T) {
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.RSAKey(t)})

	output := filepath.Join(t.TempDir(), "artefact.pub")

	err := runMinisign(t, "--output", output)
	require.ErrorContains(t, err, "minisign requires an Ed25519 signing key")
	assert.NoFileExists(t, output)
}

func TestRunMinisign_LogsTheKeyIDNotTheKey(t *testing.T) {
	want := registerEd25519(t)

	log := logger.NewBuffer()
	cmd := minisign.NewCmdMinisign(&props.Props{Logger: log}).Command

	require.NoError(t, signtest.Execute(t, cmd, "--backend", fakeBackend, "--key-id", "alias/artefact"))

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "Resolved minisign public key", entries[0].Message)
	assert.Equal(t,
		[]any{"backend", fakeBackend, "key_id", "alias/artefact", "minisign_key_id", strings.ToUpper(hex.EncodeToString(want.KeyID[:]))},
		entries[0].Keyvals)
}

func TestRunMinisign_RequiresBackendAndKey(t *testing.T) {
	registerEd25519(t)

	err := signtest.Execute(t, minisign.NewCmdMinisign(signtest.Props()).Command)
	require.ErrorContains(t, err, `required flag(s) "backend", "key-id" not set`)
}

func TestRunMinisign_RefusesABackendFlagBesideANamedInstance(t *testing.T) {
	signtest.RegisterAwsKms(t)

	err := signtest.Execute(t, minisign.NewCmdMinisign(signtest.Props()).Command,
		"--backend", "aws-kms:prod", "--kms-region", "eu-west-1", "--key-id", "alias/artefact")
	require.ErrorContains(t, err, `--kms-region configures the default "aws-kms" backend, not the named instance "aws-kms:prod"`)
}
