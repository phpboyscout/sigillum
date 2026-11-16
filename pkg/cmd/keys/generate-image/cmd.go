package generate_image

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
)

// GenerateImageOptions holds the generate-image command's flags.
type GenerateImageOptions struct {
	Output        string
	PrivateOutput string
	Force         bool
}

// NewCmdGenerateImage returns the keys generate-image command.
func NewCmdGenerateImage(p *props.Props) *setup.Command {
	opts := &GenerateImageOptions{}

	cmd := setup.Wrap("generate-image", &cobra.Command{
		Use:   "generate-image",
		Short: "Generate an ECDSA P-256 keypair for image signing",
		Long:  longHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGenerateImage(cmd.Context(), p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Output, flagOutput, "image.pub", "Where to write the PEM public key.")
	fs.StringVar(&opts.PrivateOutput, flagPrivateOutput, "image.key", "Where to write the PKCS#8 private key, mode 0600.")
	fs.BoolVar(&opts.Force, "force", false, "Overwrite the output files if they exist.")

	return cmd
}

const longHelp = `Generate an ECDSA P-256 keypair in the process and write both halves.

The private key is unencrypted PKCS#8 PEM, which --backend local signs with.
Anyone who can read that file can sign. The public key is PEM, which
cosign verify --key and the other image verifiers read.

This is for tests and local registries. Production image keys live in a key
service, and the private half never leaves it.

Examples:

  keys generate-image --output image.pub --private-output image.key
  sign image --backend local --key-id image.key <repository>@sha256:<hex>`
