package minisign

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// MinisignOptions holds the minisign command's flags.
type MinisignOptions struct {
	Backend string
	KeyID   string
	Output  string
	Comment string
	Force   bool
}

// NewCmdMinisign returns the keys minisign command.
func NewCmdMinisign(p *props.Props) *setup.Command {
	opts := &MinisignOptions{}

	cmd := setup.Wrap("minisign", &cobra.Command{
		Use:   "minisign",
		Short: "Emit the minisign public key for an Ed25519 signer",
		Long:  longHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunMinisign(cmd, p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Output, "output", "",
		"Write the two-line minisign public-key file here instead of printing the bare key.")
	fs.StringVar(&opts.Comment, "comment", "",
		"Untrusted comment for the public-key file. Defaults to minisign's own wording. Nothing signs it.")
	fs.BoolVar(&opts.Force, "force", false,
		"Overwrite --output if it already exists.")

	signcmd.AddBackendFlags(cmd.Command, &opts.Backend, &opts.KeyID)

	return cmd
}

const longHelp = `Resolve an Ed25519 signing key through a backend and print its minisign
public key — the single base64 string that release consumers pin.

Nothing secret is involved: this reads only the public half, which for a
KMS-held key means one GetPublicKey call. The key identifier is derived
from the public key itself, so re-running this against the same key always
produces the same output, on any machine.

Where the output goes:

  cargo-binstall   the 'pubkey' field of the crate's
                   [package.metadata.binstall.signing] table.
  rtb-update       'ToolMetadata::update_public_keys' — that field wants the
                   raw 32-byte Ed25519 key, which is the last 32 bytes of the
                   decoded body, not the base64 string itself.

With --output the two-line minisign public-key file is written instead,
for publishing alongside a release.

Examples:

  # Print the pinnable public key for the KMS artefact-signing key
  keys minisign \
      --backend aws-kms \
      --kms-region eu-west-2 \
      --key-id alias/artefact-signing-v1

  # Write the public-key file for publication
  keys minisign --backend local --key-id ./artefact.pem --output artefact.pub`
