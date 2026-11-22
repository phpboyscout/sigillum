package mint

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// MintOptions holds the mint command's flags.
type MintOptions struct {
	Backend string
	KeyID   string
	Name    string
	Email   string
	Output  string
	Created string
	Force   bool
}

// NewCmdMint returns the keys mint command. It is kept off the MCP tool surface:
// its self-signature is a kms:Sign call with the real key (spec 0003 D3).
func NewCmdMint(p *props.Props) *setup.Command {
	opts := &MintOptions{}

	cmd := setup.Wrap("mint", &cobra.Command{
		Use:   "mint",
		Short: "Mint an ASCII-armored OpenPGP public key from an existing signer",
		Long:  longHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunMint(cmd, p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Name, "name", "",
		`OpenPGP user-id real name (required; e.g. "GTB Release").`)
	fs.StringVar(&opts.Email, "email", "",
		"OpenPGP user-id email (required; e.g. release@example.com).")
	fs.StringVar(&opts.Output, "output", "release.asc",
		"Output file path for the armored public key.")
	fs.StringVar(&opts.Created, "created", "",
		"Creation time RFC3339 (default now). Pin only on re-mint of an existing key — different creation times produce different fingerprints.")
	fs.BoolVar(&opts.Force, "force", false,
		"Overwrite an existing output file. Without this, mint refuses to clobber an existing file.")

	for _, required := range []string{"name", "email"} {
		_ = cmd.MarkFlagRequired(required)
	}

	signcmd.AddBackendFlags(cmd.Command, &opts.Backend, &opts.KeyID)

	return setup.ExcludeFromMCP(cmd)
}

const longHelp = `Wrap an existing signer (HSM-held key or on-disk PEM private key) in
OpenPGP framing and write the armored public half to a file. The
private half never touches this tool — every signing operation flows
through the chosen backend.

Backends are activated at build time by blank-imports in the
binary's main package. The standard binary ships with:

  --backend aws-kms   AWS KMS RSA SIGN_VERIFY keys. --key-id is the
                      KMS key ID, ARN, or alias. Uses the AWS SDK
                      default credential chain.
  --backend local     On-disk PEM-encoded RSA private key.
                      --key-id is the file path.

Other backends (GCP KMS, Vault, etc.) can be added by anyone consuming
go/signing. See https://signing.go.phpboyscout.uk/how-to/implement-a-custom-backend/.`
