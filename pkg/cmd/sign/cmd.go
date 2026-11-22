package sign

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/sign/image"
)

// SignOptions holds the sign command's own flags. Backend settings such as
// --kms-region bind to the backends themselves.
type SignOptions struct {
	Format    string
	Backend   string
	KeyID     string
	Output    string
	Created   string
	PublicKey string
	Append    bool
	Project   string
}

// NewCmdSign returns the sign command. It is kept off the MCP tool surface:
// it signs with the real release key (spec 0003 D3).
func NewCmdSign(p *props.Props) *setup.Command {
	opts := &SignOptions{}

	cmd := setup.Wrap("sign", &cobra.Command{
		Use:   "sign <input-file>",
		Short: "Produce a detached signature over a file using a configured backend",
		Long:  longHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunSign(cmd, p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Format, flagFormat, signcmd.FormatOpenPGP,
		`Signature format: "openpgp" (armored OpenPGP, for checksum manifests), "minisign" (prehashed minisign, for release artefacts consumed by cargo-binstall / rtb-update).`)
	fs.StringVar(&opts.Output, "output", "",
		"Output file path for the detached signature. Defaults to <input>.sig for --format openpgp and <input>.minisig for --format minisign.")
	fs.StringVar(&opts.Created, "created", "",
		"Signature creation time RFC3339 (default now, truncated to whole seconds). Pin to produce byte-identical signatures across re-runs. For --format minisign this sets the trusted comment's timestamp, and "+minisign.SourceDateEpochEnv+" is honoured when the flag is unset.")
	fs.StringVar(&opts.PublicKey, flagPublicKey, "",
		"Path to the armored OpenPGP public-key file (.asc) that identifies the signing key. Required for --format openpgp.")
	fs.BoolVar(&opts.Append, flagAppend, false,
		"Merge the new signature into an existing armored signature at --output instead of overwriting, producing one armored block with multiple signature packets (dual-sign key-rotation overlap). No-op when --output does not exist yet.")
	fs.StringVar(&opts.Project, flagProject, "",
		"Project this artefact belongs to, recorded in the minisign signature's signed trusted comment. Omit to emit minisign's exact default comment.")

	signcmd.AddBackendFlags(cmd.Command, &opts.Backend, &opts.KeyID)

	cmd.Register(image.NewCmdImage(p))

	return setup.ExcludeFromMCP(cmd)
}

const longHelp = `Sign <input-file> with a signing backend (AWS KMS, local PEM, or any other
backend compiled into this binary) and write the resulting
ASCII-armored OpenPGP detached signature to --output (or <input>.sig
by default).

The private key never leaves the backend — the signing operation is
one round-trip to the HSM/KMS via the crypto.Signer interface.

--public-key points at the armored OpenPGP public-key file (a .asc
previously produced by 'keys mint' and published via WKD /
embedded in your tool's trustkeys). It is the source of truth for the
signing identity: the signature's fingerprint will match this file's
fingerprint. The backend-resolved RSA key must match the public half
in this file or sign refuses to proceed.

Backends are activated at build time by blank-imports in the
binary's main package:

  --backend aws-kms   AWS KMS RSA SIGN_VERIFY keys. --key-id is the
                      KMS key ID, ARN, or alias. Uses the AWS SDK
                      default credential chain — under CI/OIDC it picks
                      up an assumed role from AWS_ROLE_ARN plus
                      AWS_WEB_IDENTITY_TOKEN_FILE with no before_script;
                      static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
                      AWS_SESSION_TOKEN also work.
  --backend local     On-disk PEM-encoded RSA private key.
                      --key-id is the file path.

A backend may be selected as a named instance —
--backend aws-kms:prod — and configured inline with url-encoded
settings: --backend 'aws-kms:prod?kms-region=eu-west-1'. Quote the
whole value; ? and & are shell metacharacters.
A named instance takes its settings from the selector only: setting a
backend flag such as --kms-region alongside it is an error.

'sign image' signs a container image instead. To sign a file named
image, write it as ./image.

Examples:

  # Sign checksums.txt with the production KMS key
  sign \
      --backend aws-kms \
      --kms-region eu-west-2 \
      --key-id alias/gtb-release-signing-v1 \
      --public-key release.asc \
      checksums.txt

  # Reproducible signature: pin --created to a fixed RFC3339 instant
  sign \
      --backend local \
      --key-id ./release.pem \
      --public-key ./release.asc \
      --created 2026-01-01T00:00:00Z \
      --output build.txt.sig \
      build.txt

  # Dual-sign (key-rotation overlap window): sign with the old key,
  # then --append the new key's signature into the SAME armored file.
  # Verifiers skip signature packets from issuers they don't know, so
  # one file serves binaries trusting either key.
  sign --backend aws-kms --key-id alias/release-signing-v1 \
      --public-key v1.asc --output checksums.txt.sig checksums.txt
  sign --backend aws-kms --key-id alias/release-signing-v2 \
      --public-key v2.asc --output checksums.txt.sig --append checksums.txt`
