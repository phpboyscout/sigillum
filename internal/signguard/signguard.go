// Package signguard adds the OpenPGP lane's advice to go/signing's refusal of
// an armored OpenPGP secret key. The backend's own hint names
// --private-format pem, which is enough for minisign but wrong for OpenPGP:
// only sigillum knows the format, and an Ed25519 PEM still cannot sign OpenPGP.
package signguard

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/local"
)

const (
	signCommand    = "sign"
	formatMinisign = "minisign"
)

// OpenPGPLaneHint is added to the sign command's error when the local backend
// refuses an armored OpenPGP secret key and the format is not minisign.
const OpenPGPLaneHint = "OpenPGP signing takes an RSA key (keys generate --algorithm rsa); " +
	"an Ed25519 key signs with --format minisign"

// Middleware hints the lane that takes the key when the sign command's local
// backend refuses an armored OpenPGP secret key, and passes every other error
// and command through unchanged.
func Middleware(next setup.RunE) setup.RunE {
	return func(cmd *cobra.Command, args []string) error {
		err := next(cmd, args)
		if err == nil || cmd.Name() != signCommand || !errors.Is(err, local.ErrOpenPGPSecretKey) {
			return err
		}

		if format, _ := cmd.Flags().GetString("format"); format == formatMinisign {
			return err
		}

		return errors.WithHint(err, OpenPGPLaneHint)
	}
}
