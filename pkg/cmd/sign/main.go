package sign

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

const (
	flagFormat    = "format"
	flagPublicKey = "public-key"
	flagAppend    = "append"
	flagProject   = "project"

	validFormats = `"` + signcmd.FormatOpenPGP + `" and "` + signcmd.FormatMinisign + `"`

	// Signatures are public and distributed beside what they sign.
	signatureFilePerm = 0o644
)

// formatOfFlag names the one format each format-specific flag belongs to.
var formatOfFlag = map[string]string{
	flagPublicKey: signcmd.FormatOpenPGP,
	flagAppend:    signcmd.FormatOpenPGP,
	flagProject:   signcmd.FormatMinisign,
}

type signFunc func(cmd *cobra.Command, log logger.Logger, opts *SignOptions, input string) error

// RunSign signs args[0] in the format --format names. The flag defaults to
// OpenPGP; an explicitly empty --format is refused, as go/signing-cli refused it.
func RunSign(cmd *cobra.Command, p *props.Props, opts *SignOptions, args []string) error {
	format := opts.Format
	if format == "" {
		return errors.Newf("--format is required; valid values are %s", validFormats)
	}

	formats := map[string]signFunc{
		signcmd.FormatOpenPGP:  signOpenPGP,
		signcmd.FormatMinisign: signMinisign,
	}

	sign, known := formats[format]
	if !known {
		return errors.Newf("unknown --format %q; valid values are %s", format, validFormats)
	}

	if err := refuseOtherFormatsFlags(cmd.Flags(), format); err != nil {
		return err
	}

	return sign(cmd, p.GetLogger(), opts, args[0])
}

// refuseOtherFormatsFlags refuses a flag set for a format other than the one
// chosen, rather than accepting and silently ignoring it.
func refuseOtherFormatsFlags(fs *pflag.FlagSet, chosen string) error {
	var err error

	fs.Visit(func(f *pflag.Flag) {
		if err != nil {
			return
		}

		if format, owned := formatOfFlag[f.Name]; owned && format != chosen {
			err = errors.Newf("--%s is not accepted for --format %s; it is a --format %s flag", f.Name, chosen, format)
		}
	})

	return err
}

// sameSignPath also catches a symlink or hard link to the input, which a
// comparison of the cleaned paths misses.
func sameSignPath(output, input string) bool {
	if filepath.Clean(output) == filepath.Clean(input) {
		return true
	}

	outInfo, outErr := os.Stat(output)

	inInfo, inErr := os.Stat(input)
	if outErr != nil || inErr != nil {
		return false
	}

	return os.SameFile(outInfo, inInfo)
}

func refuseSigningOverInput(output, input string) error {
	if sameSignPath(output, input) {
		return errors.Newf("refusing to write signature to %q which equals the input path %q", output, input)
	}

	return nil
}

func writeSignature(output string, sig []byte) error {
	if err := os.WriteFile(filepath.Clean(output), sig, signatureFilePerm); err != nil {
		return errors.Wrapf(err, "writing %s", output)
	}

	return nil
}
