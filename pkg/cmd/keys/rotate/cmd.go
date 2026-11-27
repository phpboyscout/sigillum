package rotate

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// RotateOptions holds the rotate command's flags.
type RotateOptions struct {
	Backend           string
	KeyID             string
	Reason            string
	NotAfter          string
	Epoch             uint64
	AllowEpochGap     bool
	Add               []string
	Revoke            []string
	Previous          string
	PreviousAuthority string
	Anchor            []string
	AnchorOnly        []string
	OutputDir         string
	Force             bool
}

// NewCmdRotate returns the keys rotate command. It is kept off the MCP tool
// surface: its key can rewrite every installed binary's trust (spec 0008 D4).
func NewCmdRotate(p *props.Props) *setup.Command {
	opts := &RotateOptions{}

	cmd := setup.Wrap("rotate", &cobra.Command{
		Use:   "rotate",
		Short: "Issue a signed rotation manifest for a project's release keys",
		Long:  longHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunRotate(cmd, p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Reason, flagReason, "",
		"Why the keys change: scheduled or compromise. Only a compromise may revoke a key afresh.")
	fs.StringVar(&opts.NotAfter, flagNotAfter, "",
		"RFC 3339 time after which an updater no longer applies this manifest for the first time.")
	fs.Uint64Var(&opts.Epoch, flagEpoch, 0,
		"Epoch of this manifest. Defaults to 1, or the previous manifest's epoch plus one.")
	fs.BoolVar(&opts.AllowEpochGap, flagAllowEpochGap, false,
		"Accept an --epoch that skips past the previous manifest's next epoch.")
	fs.StringArrayVar(&opts.Add, flagAdd, nil,
		"Armored OpenPGP public key file of a release key to trust. Repeatable.")
	fs.StringArrayVar(&opts.Revoke, flagRevoke, nil,
		"Fingerprint of a release key to stop trusting, optionally @<RFC 3339> for when. Repeatable.")
	fs.StringVar(&opts.Previous, flagPrevious, "",
		"The latest published rotate-keys.json; its .minisig must sit beside it. Required above epoch 1.")
	fs.StringVar(&opts.PreviousAuthority, flagPreviousAuthority, "",
		"Minisign public key that signed --previous, when the authority has been replaced.")
	fs.StringArrayVar(&opts.Anchor, flagAnchor, nil,
		"Armored release key the binaries embed, to check the result as an updater would. Repeatable.")
	fs.StringArrayVar(&opts.AnchorOnly, flagAnchorOnly, nil,
		"Armored key the binaries embed as anchor-only. Repeatable.")
	fs.StringVar(&opts.OutputDir, "output-dir", ".",
		"Directory to write rotate-keys.json and rotate-keys.json.minisig into.")
	fs.BoolVar(&opts.Force, "force", false,
		"Overwrite existing rotate-keys.json and rotate-keys.json.minisig.")

	signcmd.AddBackendFlags(cmd.Command, &opts.Backend, &opts.KeyID)

	_ = cmd.MarkFlagRequired(flagReason)
	_ = cmd.MarkFlagRequired(flagNotAfter)

	return setup.ExcludeFromMCP(cmd)
}

const (
	flagReason            = "reason"
	flagNotAfter          = "not-after"
	flagEpoch             = "epoch"
	flagAllowEpochGap     = "allow-epoch-gap"
	flagAdd               = "add"
	flagRevoke            = "revoke"
	flagPrevious          = "previous"
	flagPreviousAuthority = "previous-authority"
	flagAnchor            = "anchor"
	flagAnchorOnly        = "anchor-only"
)

const longHelp = `Write rotate-keys.json and its minisign signature, rotate-keys.json.minisig,
signed by the project's rotation authority. A rotation-capable binary that
fetches them from a release trusts the keys the manifest adds and stops
trusting the keys it revokes.

The authority key must be Ed25519, held by any signing backend. Its minisign
public key is printed on success; check it against the key your binaries
embed.

A release ships only its latest manifest, so it must carry every earlier add
and revoke for an install that skipped the releases between. Pass the latest
published manifest as --previous and they are carried forward; above epoch 1
that is required. A carried revoke stays under either --reason.

Without --anchor, a manifest that revokes and adds nothing is refused, because
nothing proves a release key would remain. With --anchor and --anchor-only it
is checked exactly as an updater checks it.

Examples:

  # The fire drill: an empty manifest at epoch 1
  keys rotate --reason scheduled --not-after 2027-11-18T00:00:00Z \
      --backend local --key-id ./authority.pem

  # A compromise: trust v3, stop trusting v2, carrying the previous manifest
  keys rotate --reason compromise --not-after 2027-11-18T00:00:00Z \
      --previous ./rotate-keys.json \
      --add ./release-v3.asc \
      --revoke 0123456789ABCDEF0123456789ABCDEF01234567 \
      --anchor ./release-v1.asc --anchor ./release-v2.asc \
      --backend aws-kms --key-id alias/rotation-authority --output-dir ./out`
