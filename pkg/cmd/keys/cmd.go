package keys

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/generate"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/minisign"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/mint"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/publish"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/wkd"
)

// NewCmdKeys returns the keys command group with its subcommands attached.
func NewCmdKeys(p *props.Props) *setup.Command {
	cmd := setup.Wrap("keys", &cobra.Command{
		Use:   "keys",
		Short: "Manage OpenPGP keys for release-binary signing",
		Long:  longHelp,
		RunE:  setup.GroupRunE,
	})

	cmd.Register(
		mint.NewCmdMint(p),
		generate.NewCmdGenerate(p),
		wkd.NewCmdWkd(p),
		minisign.NewCmdMinisign(p),
		publish.NewCmdPublish(p),
	)

	return cmd
}

const longHelp = `Commands for the cryptographic operations a tool author runs during
release-binary signing setup.

Available subcommands:
  mint      Wrap an existing signer (KMS or local PEM) in OpenPGP framing and emit the armored public half.
  generate  Generate a fresh keypair locally (Ed25519 or RSA) and emit both halves.
  wkd       Generate a Web Key Directory tree from one or more public keys (for static hosting).
  minisign  Emit the minisign public key for an Ed25519 signer (what release consumers pin).
  publish   Stage a minisign public key into a keys site with a manifest.

See https://gitlab.com/phpboyscout/go-tool-base/-/wikis/specs/0067-keys-mint-command for the full design.`
