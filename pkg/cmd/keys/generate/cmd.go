package generate

import (
	"fmt"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"
)

const defaultRSABits = 4096

// GenerateOptions holds the generate command's flags.
type GenerateOptions struct {
	Algorithm     string
	PrivateFormat string
	RSABits       int
	Name          string
	Email         string
	Output        string
	PrivateOutput string
	Created       string
	Force         bool
}

// NewCmdGenerate returns the keys generate command.
func NewCmdGenerate(p *props.Props) *setup.Command {
	opts := &GenerateOptions{}

	cmd := setup.Wrap("generate", &cobra.Command{
		Use:   "generate",
		Short: "Generate a fresh keypair locally (Ed25519 or RSA) and emit both halves",
		Long:  longHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGenerate(cmd.Context(), p, opts, args)
		},
	})

	fs := cmd.Flags()
	fs.StringVar(&opts.Algorithm, "algorithm", "",
		fmt.Sprintf("Key algorithm (required): %q or %q", openpgpkey.AlgorithmEd25519, openpgpkey.AlgorithmRSA))
	fs.StringVar(&opts.PrivateFormat, "private-format", "",
		fmt.Sprintf("Private-half encoding: %q (armored OpenPGP secret key, the Ed25519 default) or %q. "+
			"For --algorithm ed25519, %q writes an unencrypted PKCS#8 PEM — the form the local signing backend reads, "+
			"which is what allows minisign artefact signing without an HSM. RSA always writes PKCS#1 PEM.",
			openpgpkey.PrivateFormatOpenPGP, openpgpkey.PrivateFormatPEM, openpgpkey.PrivateFormatPEM))
	fs.IntVar(&opts.RSABits, "rsa-bits", defaultRSABits,
		"RSA modulus size in bits. Ignored for --algorithm ed25519. 2048/3072/4096 accepted; 4096 is the default.")
	fs.StringVar(&opts.Name, "name", "",
		`OpenPGP user-id real name (required).`)
	fs.StringVar(&opts.Email, "email", "",
		"OpenPGP user-id email (required).")
	fs.StringVar(&opts.Output, "output", "",
		"Output file path for the armored public key. Default: <algorithm>.asc.")
	fs.StringVar(&opts.PrivateOutput, "private-output", "",
		"Output file path for the private half. Default: derived from --output by replacing the extension (.asc → .priv.asc for Ed25519, .asc → .pem for RSA).")
	fs.StringVar(&opts.Created, "created", "",
		"Creation time RFC3339 (default now). Pin only when re-deriving an existing key — different creation times produce different fingerprints.")
	fs.BoolVar(&opts.Force, "force", false,
		"Overwrite existing output files. Without this, generate refuses to clobber an existing key to avoid destroying a private key in place.")

	for _, required := range []string{"algorithm", "name", "email"} {
		_ = cmd.MarkFlagRequired(required)
	}

	return cmd
}

const longHelp = `Generate a fresh keypair entirely inside the process. The private
half is written to disk in a format chosen per algorithm:

  --algorithm ed25519   Public half: armored OpenPGP. Private half:
                        armored OpenPGP secret-key block (the same
                        wire format gpg --export-secret-keys uses).
                        Used for rotation-authority keys. Move the
                        private half to offline storage immediately.

  --algorithm rsa       Public half: armored OpenPGP. Private half:
                        PKCS#1 PEM. Pairs with
                        ` + "`keys mint --backend local`" + ` for the tutorial
                        path. For production signing, use AWS KMS via
                        ` + "`keys mint --backend aws-kms`" + ` instead.

Encrypted on-disk private halves are not produced in v0.1 — the
standard library doesn't expose PKCS#8 encryption and a clean
OpenPGP s2k path is additive. Use filesystem-level encryption (LUKS,
FileVault, age) until v0.2 adds in-tool encryption.`
