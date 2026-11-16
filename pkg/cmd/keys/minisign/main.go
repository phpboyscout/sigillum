package minisign

import (
	"fmt"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// RunMinisign prints the bare minisign public key, or with --output writes the
// two-line public-key file.
func RunMinisign(cmd *cobra.Command, p *props.Props, opts *MinisignOptions, _ []string) error {
	signer, backendID, err := signcmd.ResolveSigner(cmd.Context(), cmd.Flags(), opts.Backend, opts.KeyID)
	if err != nil {
		return err
	}

	key, err := signcmd.MinisignPublicKey(signer)
	if err != nil {
		return err
	}

	keyID := fmt.Sprintf("%X", key.KeyID)
	log := p.GetLogger()

	if opts.Output == "" {
		// Not cmd.Println: cobra's print helpers fall back to stderr when no
		// output is set, which breaks `keys minisign > key.b64`. The write is
		// checked because the caller pins what it captures, and a truncated key
		// is worse than an error.
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), key.Encode()); err != nil {
			return errors.Wrap(err, "writing public key to stdout")
		}

		log.Info("Resolved minisign public key",
			"backend", backendID, "key_id", opts.KeyID, "minisign_key_id", keyID)

		return nil
	}

	comment := opts.Comment
	if comment == "" {
		comment = "minisign public key " + keyID
	}

	file, err := key.File(comment)
	if err != nil {
		return err //nolint:wrapcheck // the library names the comment as the fault
	}

	if err := signcmd.WriteKeyFile(opts.Output, file, keyfile.PublicPerm, opts.Force); err != nil {
		return errors.Wrapf(err, "writing %s", opts.Output)
	}

	log.Info("Wrote minisign public key",
		"backend", backendID, "key_id", opts.KeyID, "minisign_key_id", keyID, "output", opts.Output)

	return nil
}
