package wkd

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"
)

// WkdOptions holds the wkd command's flags.
type WkdOptions struct {
	Domain            string
	Emails            []string
	Output            string
	Method            string
	SubmissionAddress string
}

// NewCmdWkd returns the keys wkd command.
func NewCmdWkd(p *props.Props) *setup.Command {
	opts := &WkdOptions{}

	cmd := setup.Wrap("wkd", &cobra.Command{
		Use:   "wkd <public-key.asc> [<public-key.asc>...]",
		Short: "Generate a Web Key Directory tree from one or more public keys",
		Long:  longHelp,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunWkd(cmd.Context(), p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Domain, "domain", "",
		"DNS domain serving the WKD endpoint (required; e.g. phpboyscout.uk). "+
			"For the advanced method this domain appears in the URL path; for direct it doesn't.")
	fs.StringSliceVar(&opts.Emails, "email", nil,
		"Email address(es) to publish under. Repeatable. Keys whose UIDs match are grouped into that email's hu/<hash> bucket. "+
			"If omitted, every distinct email found across input keys is published.")
	fs.StringVar(&opts.Output, "output", "./wkd-staging",
		"Output directory; receives a .well-known/openpgpkey/... tree.")
	fs.StringVar(&opts.Method, "method", string(openpgpkey.MethodAdvanced),
		`URL layout: "advanced" (default; served from openpgpkey.<domain>) or "direct" (served from <domain> itself).`)
	fs.StringVar(&opts.SubmissionAddress, "submission-address", "",
		"Email address to write to the WKD submission-address file. Empty (default) means do not emit the file. "+
			`Pass "auto" to use the first --email; pass an explicit address to override.`)

	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

const longHelp = `Read one or more ASCII-armored OpenPGP public keys, group them by
email (configured via --email), and write the WKD layout expected by
draft-koch-openpgp-webkey-service §3.1 under --output. The resulting
tree is ready to upload to a static host (e.g. Cloudflare Pages).

Each --email may be passed multiple times. For each email, keys whose
UIDs contain that email are grouped into a single hu/<z-base-32-hash>
file, concatenated in lexicographic fingerprint order for reproducible
output. A key with multiple matching UIDs ends up under every matching
email's bucket (standard WKD behaviour).

Examples:

  # Two keys, one email — typical phpboyscout setup
  keys wkd \
      --domain phpboyscout.uk \
      --email release@phpboyscout.uk \
      --output ./wkd-staging \
      rotation-authority.asc signing-key-v1.asc

  # Two emails, separate hu/ buckets
  keys wkd \
      --domain phpboyscout.uk \
      --email release@phpboyscout.uk \
      --email security@phpboyscout.uk \
      --output ./wkd-staging \
      keys/*.asc

  # Direct method (same-domain layout, no openpgpkey.<domain> subdomain)
  keys wkd --method direct ...`
