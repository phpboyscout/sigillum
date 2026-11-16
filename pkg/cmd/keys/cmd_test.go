package keys_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/errorhandling"
	_ "gitlab.com/phpboyscout/go/signing/local" // the backend the round trip mints through

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys"
)

// mounted returns a root with the keys group under it. Cobra refuses a mistyped
// verb itself on a root command, so the group is tested where it runs.
func mounted() *cobra.Command {
	root := &cobra.Command{Use: "sigillum"}
	root.AddCommand(keys.NewCmdKeys(signtest.Props()).Command)

	return root
}

func TestNewCmdKeys_AttachesItsSubcommands(t *testing.T) {
	t.Parallel()

	var got []string
	for _, c := range keys.NewCmdKeys(signtest.Props()).Commands() {
		got = append(got, c.Name())
	}

	assert.ElementsMatch(t, []string{"generate", "minisign", "mint", "publish", "wkd"}, got)
}

func TestKeys_ReportsAVerbItDoesNotHave(t *testing.T) {
	t.Parallel()

	err := signtest.Execute(t, mounted(), "keys", "zzbogus")

	require.ErrorIs(t, err, errorhandling.ErrUnknownSubCommand)
	require.ErrorContains(t, err, `unknown command "zzbogus"`)

	outcome, ok := errorhandling.OutcomeOf(err)
	require.True(t, ok, "the sentinel carries its own disposition")
	assert.Equal(t, errorhandling.ExitCodeUsage, outcome.Code)
}

func TestKeys_BareInvocationPrintsUsageAndSucceeds(t *testing.T) {
	t.Parallel()

	var out strings.Builder

	root := mounted()
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"keys"})

	require.NoError(t, root.ExecuteContext(t.Context()), "a bare group is a request for help, not a failure")
	assert.Contains(t, out.String(), "Available Commands:")
}

// The private half `generate` writes must be the key its public half names. Read
// back through the local backend and minted at the same creation time, it gives
// the same fingerprint, or signatures would fail against the key the operator
// distributed.
func TestKeys_AGeneratedKeyMintsToTheSameFingerprint(t *testing.T) {
	t.Parallel()

	const created = "2026-06-08T00:00:00Z"

	dir := t.TempDir()
	generated := filepath.Join(dir, "gen.asc")
	private := filepath.Join(dir, "gen.pem")
	minted := filepath.Join(dir, "mint.asc")

	identity := []string{"--name", "X", "--email", "x@y", "--created", created}

	require.NoError(t, signtest.Execute(t, mounted(), append([]string{
		"keys", "generate", "--algorithm", "rsa", "--rsa-bits", "2048", "--output", generated, "--private-output", private,
	}, identity...)...))

	require.NoError(t, signtest.Execute(t, mounted(), append([]string{
		"keys", "mint", "--backend", "local", "--key-id", private, "--output", minted,
	}, identity...)...))

	assert.Equal(t, fingerprint(t, generated), fingerprint(t, minted))
}

func fingerprint(t *testing.T, path string) string {
	t.Helper()

	armored, err := os.ReadFile(path)
	require.NoError(t, err)

	fp, err := signcmd.ReadFingerprint(armored)
	require.NoError(t, err)
	require.Len(t, fp, 40)

	return fp
}
