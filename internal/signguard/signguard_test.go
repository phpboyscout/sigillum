package signguard_test

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/local"

	"gitlab.com/phpboyscout/sigillum/internal/signguard"
)

func newCmd(name, format string) *cobra.Command {
	cmd := &cobra.Command{Use: name}
	cmd.Flags().String("format", format, "")

	return cmd
}

func failingWith(err error) func(*cobra.Command, []string) error {
	return func(*cobra.Command, []string) error { return err }
}

func refusal() error {
	return errors.Wrap(errors.Wrap(local.ErrOpenPGPSecretKey, "./ed.priv.asc"), "constructing signer")
}

func TestMiddleware_OpenPGPLaneHintsTheLaneThatTakesTheKey(t *testing.T) {
	t.Parallel()

	err := signguard.Middleware(failingWith(refusal()))(newCmd("sign", "openpgp"), nil)

	if !errors.Is(err, local.ErrOpenPGPSecretKey) {
		t.Fatalf("got %v, want the backend's refusal kept", err)
	}

	if !slices.Contains(errors.Hints(err), signguard.OpenPGPLaneHint) {
		t.Errorf("hints %q do not name the lane that takes the key", errors.Hints(err))
	}
}

func TestMiddleware_LeavesEverythingElseUnchanged(t *testing.T) {
	t.Parallel()

	other := errors.New("some other failure")

	cases := map[string]struct {
		cmd *cobra.Command
		err error
	}{
		"the minisign lane":         {newCmd("sign", "minisign"), refusal()},
		"a command other than sign": {newCmd("mint", "openpgp"), refusal()},
		"a different error":         {newCmd("sign", "openpgp"), other},
		"success":                   {newCmd("sign", "openpgp"), nil},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := signguard.Middleware(failingWith(tc.err))(tc.cmd, nil); got != tc.err { //nolint:errorlint // identity is the point
				t.Errorf("got %v, want %v passed through", got, tc.err)
			}
		})
	}
}
