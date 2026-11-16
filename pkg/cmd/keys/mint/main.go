package mint

import (
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// RunMint writes the armored OpenPGP public key for the signer --backend and
// --key-id name. Every refusal that needs no key comes before the backend is
// asked for one, so a mistyped flag costs no KMS call.
func RunMint(cmd *cobra.Command, p *props.Props, opts *MintOptions, _ []string) error {
	backend, backendID, err := signcmd.ResolveBackend(opts.Backend, cmd.Flags())
	if err != nil {
		return err //nolint:wrapcheck // already worded for the user
	}

	created, err := signcmd.ParseCreatedTime(opts.Created)
	if err != nil {
		return err //nolint:wrapcheck // names the flag already
	}

	// Armored bytes on stdout would interleave with log lines.
	if opts.Output == "-" {
		return errors.New(`--output "-" (stdout) is not supported; pass a file path`)
	}

	signer, err := backend.NewSigner(cmd.Context(), opts.KeyID)
	if err != nil {
		return errors.Wrap(err, "constructing signer")
	}

	armored, err := openpgpkey.ArmoredPublicKey(signer, opts.Name, opts.Email, created)
	if err != nil {
		return errors.Wrap(err, "minting armored public key")
	}

	if err := signcmd.WriteKeyFile(opts.Output, armored, keyfile.PublicPerm, opts.Force); err != nil {
		return errors.Wrap(err, "writing output")
	}

	log := p.GetLogger()

	// The file is written, and gpg --show-key recovers the fingerprint, so a
	// failure to read it back is a warning.
	fingerprint, err := signcmd.ReadFingerprint(armored)
	if err != nil {
		log.Warn("Wrote armored key but could not parse it back to read fingerprint", "error", err, "output", opts.Output)

		return nil
	}

	log.Info("Minted OpenPGP key",
		"backend", backendID,
		"key_id", opts.KeyID,
		"output", opts.Output,
		"creation_time", created.Format(time.RFC3339),
		"fingerprint", fingerprint,
	)

	return nil
}
