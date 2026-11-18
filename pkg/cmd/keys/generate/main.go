package generate

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// RunGenerate makes a keypair and writes both halves, or neither.
func RunGenerate(_ context.Context, p *props.Props, opts *GenerateOptions, _ []string) error {
	if err := validatePrivateFormat(opts.Algorithm, opts.PrivateFormat); err != nil {
		return err
	}

	created, err := signcmd.ParseCreatedTime(opts.Created)
	if err != nil {
		return err //nolint:wrapcheck // names the flag already
	}

	pubPath, privPath, err := resolveOutputs(opts.Algorithm, opts.PrivateFormat, opts.Output, opts.PrivateOutput)
	if err != nil {
		return err
	}

	if err := validateRSABits(opts.Algorithm, opts.RSABits); err != nil {
		return err
	}

	key, err := openpgpkey.Generate(openpgpkey.GenerateOptions{
		Algorithm:     opts.Algorithm,
		RSABits:       opts.RSABits,
		Name:          opts.Name,
		Email:         opts.Email,
		CreationTime:  created,
		PrivateFormat: opts.PrivateFormat,
	})
	if err != nil {
		return err //nolint:wrapcheck // the library names the step that failed
	}

	err = signcmd.WriteKeyPair(
		keyfile.Half{Path: privPath, Data: key.PrivateKey},
		keyfile.Half{Path: pubPath, Data: key.PublicKey},
		opts.Force,
	)
	if signcmd.IsSameOutput(err) {
		return sameOutputError(pubPath, privPath)
	}

	if err != nil {
		return err //nolint:wrapcheck // names the path and the fault
	}

	log := p.GetLogger()
	log.Info("Generated OpenPGP keypair",
		"algorithm", opts.Algorithm,
		"public_output", pubPath,
		"private_output", privPath,
		"creation_time", created.Format(time.RFC3339),
		"fingerprint", key.Fingerprint,
	)
	log.Warn("Move the private-half file to offline storage now.",
		"private_output", privPath,
	)

	return nil
}

// The three checks below repeat openpgpkey's, which word them without the flag
// names. A user fixing a command line needs the flag (go/signing#18).

func validatePrivateFormat(algorithm, format string) error {
	switch format {
	case "", openpgpkey.PrivateFormatOpenPGP, openpgpkey.PrivateFormatPEM:
	default:
		return errors.Newf("unknown --private-format %q (expected %q or %q)",
			format, openpgpkey.PrivateFormatOpenPGP, openpgpkey.PrivateFormatPEM)
	}

	if algorithm == openpgpkey.AlgorithmRSA && format == openpgpkey.PrivateFormatOpenPGP {
		return errors.Newf("--private-format %s is not supported for --algorithm %s; RSA private halves are written as PKCS#1 PEM",
			openpgpkey.PrivateFormatOpenPGP, openpgpkey.AlgorithmRSA)
	}

	return nil
}

func validateRSABits(algorithm string, bits int) error {
	if algorithm != openpgpkey.AlgorithmRSA {
		return nil
	}

	switch bits {
	case 2048, 3072, 4096: //nolint:mnd // the RSA sizes openpgpkey.Generate accepts
		return nil
	default:
		return errors.Newf("--rsa-bits must be 2048, 3072, or 4096 (got %d)", bits)
	}
}

// resolveOutputs fills in the paths the flags left empty: <algorithm>.asc for the
// public half, and for the private half the public path with its extension
// replaced by one that says what the file holds.
func resolveOutputs(algorithm, format, output, privateOutput string) (pubPath, privPath string, err error) {
	if output == "" {
		output = algorithm + ".asc"
	}

	if privateOutput == "" {
		base := strings.TrimSuffix(output, filepath.Ext(output))

		switch {
		case algorithm == openpgpkey.AlgorithmEd25519 && format != openpgpkey.PrivateFormatPEM:
			privateOutput = base + ".priv.asc"
		case algorithm == openpgpkey.AlgorithmEd25519, algorithm == openpgpkey.AlgorithmRSA:
			privateOutput = base + ".pem"
		default:
			return "", "", errors.Newf("unknown algorithm %q (expected %q or %q)",
				algorithm, openpgpkey.AlgorithmEd25519, openpgpkey.AlgorithmRSA)
		}
	}

	if output == privateOutput {
		return "", "", sameOutputError(output, privateOutput)
	}

	return output, privateOutput, nil
}

// sameOutputError covers both checks: the spelling compared before a key is
// made, and keyfile's check of the file each path resolves to.
func sameOutputError(output, privateOutput string) error {
	return errors.Newf("--output (%s) must differ from --private-output (%s)", output, privateOutput)
}
