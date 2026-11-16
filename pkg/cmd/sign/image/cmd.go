package image

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// ImageOptions holds the sign image command's own flags. Backend settings such
// as --kms-region bind to the backends themselves.
type ImageOptions struct {
	Backend               string
	KeyID                 string
	RegistryUsername      string
	RegistryPasswordStdin bool
}

// NewCmdImage returns the sign image command.
func NewCmdImage(p *props.Props) *setup.Command {
	opts := &ImageOptions{}

	cmd := setup.Wrap("image", &cobra.Command{
		Use:   "image <registry>/<repository>@sha256:<hex>",
		Short: "Sign a container image by digest, in both cosign signature forms",
		Long:  longHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunImage(cmd, p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.RegistryUsername, flagRegistryUsername, "",
		"Registry username. Needs --"+flagRegistryPasswordStdin+".")
	fs.BoolVar(&opts.RegistryPasswordStdin, flagRegistryPasswordStdin, false,
		"Read the registry password from the first line of stdin.")

	signcmd.AddBackendFlags(cmd.Command, &opts.Backend, &opts.KeyID)

	return cmd
}

const longHelp = `Sign a container image by digest and push the signature to its registry in
both cosign forms: the legacy signature at <repository>:sha256-<hex>.sig, and a
Sigstore bundle stored as an OCI referrer. Nothing is uploaded to a
transparency log.

A tag is refused. Signing what a tag points at now races whoever moves the tag
next, so resolve the tag to a digest first and sign that.

The key decides the algorithm. ECDSA P-256 is the one every surveyed verifier
accepts; Ed25519 and RSA keys sign too.

Registry credentials come from --registry-username with the password on
stdin, or otherwise from the Docker config (docker login, crane auth login).

Verify with the public key and the log check off:

  cosign verify --key image.pub --insecure-ignore-tlog <repository>@sha256:<hex>

Examples:

  # In GitLab CI, with the job's registry credentials
  echo "$CI_REGISTRY_PASSWORD" | sign image \
      --backend aws-kms --key-id alias/dispatch-image \
      --registry-username "$CI_REGISTRY_USER" --registry-password-stdin \
      registry.gitlab.com/phpboyscout/go/dispatch/publish@sha256:<hex>`
