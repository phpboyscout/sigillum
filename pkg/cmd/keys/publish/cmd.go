package publish

import (
	"fmt"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/signing/keysite"
)

// PublishOptions holds the publish command's flags.
type PublishOptions struct {
	Output     string
	Project    string
	Generation int
	Status     string
	Purpose    string
	ValidFrom  string
}

// NewCmdPublish returns the keys publish command.
func NewCmdPublish(p *props.Props) *setup.Command {
	opts := &PublishOptions{}

	cmd := setup.Wrap("publish", &cobra.Command{
		Use:   "publish <public-key.pub>",
		Short: "Stage a minisign public key into a keys site with a manifest",
		Long:  longHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunPublish(cmd.Context(), p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Output, "output", "./keys-staging",
		"Site root. Receives minisign/<project>/v<N>.pub and keys.json.")
	fs.StringVar(&opts.Project, "project", "",
		"Project whose artefacts this key signs (required). Used as a path segment, so it must be a safe name.")
	fs.IntVar(&opts.Generation, "generation", 1,
		"Key generation, incrementing on rotation.")
	fs.StringVar(&opts.Status, "status", keysite.StatusActive,
		fmt.Sprintf("Lifecycle state: %q, %q or %q.", keysite.StatusActive, keysite.StatusRetired, keysite.StatusRevoked))
	fs.StringVar(&opts.Purpose, "purpose", "artefact",
		"What this key signs. Recorded in the manifest to tell it apart from other keys the estate publishes.")
	fs.StringVar(&opts.ValidFrom, "valid-from", "",
		"Date this key started signing (YYYY-MM-DD). Defaults to the date already recorded for this key, or today for a new entry.")

	_ = cmd.MarkFlagRequired("project")

	return cmd
}

const longHelp = `Stage a minisign public key into a static keys site: write it to a
stable path and record it in a machine-readable keys.json manifest.

This is the minisign counterpart to 'keys wkd', and it composes the
same way — both write into one staging directory that you then deploy
by hand:

  keys wkd     --output ./keys-staging --domain … release.asc
  keys publish --output ./keys-staging --project mytool mytool.pub
  wrangler pages deploy ./keys-staging

Reading a file rather than a backend is deliberate. Minting a key
touches your KMS; publishing it touches the trust anchor. Keeping those
apart means the publish step needs no cloud credentials, so a
compromised runner cannot rewrite what the world believes your keys
are. Produce the input with 'keys minisign --output'.

Publishing is ADD-ONLY. A key already published at the same path with
different bytes is refused: consumers pin these keys, so changing one
under them is precisely what must never happen. Re-running with
identical content is a no-op, which makes the command safe to re-run
and lets you verify a staging directory still matches production.

Retired and revoked keys stay published — a signature made under a key
must remain checkable long after its private half is destroyed. Rotate
by publishing a new generation and marking the old one retired; never
by removing it.

The manifest is an audit and discovery record, never a trust input.
Consumers verify against a key compiled into them or pinned in crate
metadata; keys.json exists so a pinned value can be checked against
what was actually published.

Examples:

  # Publish a project's first artefact-signing key
  keys publish --output ./keys-staging \
      --project rtb-cli-bin \
      mytool.pub

  # Publish generation 2 and retire generation 1
  keys publish --output ./keys-staging --project rtb-cli-bin \
      --generation 2 rtb-cli-bin-v2.pub
  keys publish --output ./keys-staging --project rtb-cli-bin \
      --generation 1 --status retired rtb-cli-bin-v1.pub`
