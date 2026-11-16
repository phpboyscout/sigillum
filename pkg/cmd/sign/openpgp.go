package sign

import (
	"crypto"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/local"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// OpenPGPSecretKeyHint is added when the local backend refuses an armored
// OpenPGP secret key in the OpenPGP format. The backend's own hint names
// --private-format pem, which is wrong here: an Ed25519 PEM still cannot sign
// OpenPGP.
const OpenPGPSecretKeyHint = "OpenPGP signing takes an RSA key (keys generate --algorithm rsa); " +
	"an Ed25519 key signs with --format minisign"

func signOpenPGP(cmd *cobra.Command, log logger.Logger, opts *SignOptions, input string) error {
	if opts.PublicKey == "" {
		return errors.Newf("--public-key is required for --format %s", signcmd.FormatOpenPGP)
	}

	created, err := signatureTime(opts.Created)
	if err != nil {
		return err
	}

	output := opts.Output
	if output == "" {
		output = input + ".sig"
	}

	if err := refuseSigningOverInput(output, input); err != nil {
		return err
	}

	publicKey, signer, backendID, err := loadOpenPGPInputs(cmd, opts)
	if err != nil {
		return err
	}

	sig, err := detachSign(signer, publicKey, input, created)
	if err != nil {
		return err
	}

	if opts.Append {
		sig, err = appendSignature(output, sig)
		if err != nil {
			return err
		}
	}

	if err := writeSignature(output, sig); err != nil {
		return err
	}

	logArgs := []any{
		"backend", backendID,
		"key_id", opts.KeyID,
		"public_key", opts.PublicKey,
		"input", input,
		"output", output,
		"sig_creation_time", created.Format(time.RFC3339),
	}

	log.Info("Signed file", withFingerprint(logArgs, publicKey)...)

	return nil
}

func withFingerprint(logArgs []any, publicKey []byte) []any {
	fp, err := openpgpkey.Fingerprint(publicKey)
	if err != nil {
		return logArgs
	}

	return append(logArgs, "fingerprint", fp)
}

// loadOpenPGPInputs resolves the backend before reading the public key, and
// reaches the key service last.
func loadOpenPGPInputs(cmd *cobra.Command, opts *SignOptions) ([]byte, crypto.Signer, string, error) {
	b, backendID, err := signcmd.ResolveBackend(opts.Backend, cmd.Flags())
	if err != nil {
		return nil, nil, "", err
	}

	publicKey, err := os.ReadFile(filepath.Clean(opts.PublicKey))
	if err != nil {
		return nil, nil, "", errors.Wrapf(err, "reading public key %s", opts.PublicKey)
	}

	signer, err := b.NewSigner(cmd.Context(), opts.KeyID)
	if err != nil {
		err = errors.Wrap(err, "constructing signer")
		if errors.Is(err, local.ErrOpenPGPSecretKey) {
			err = errors.WithHint(err, OpenPGPSecretKeyHint)
		}

		return nil, nil, "", err
	}

	return publicKey, signer, backendID, nil
}

func detachSign(signer crypto.Signer, publicKey []byte, input string, created time.Time) ([]byte, error) {
	in, err := os.Open(filepath.Clean(input))
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", input)
	}

	defer func() { _ = in.Close() }()

	sig, err := openpgpkey.DetachSign(signer, publicKey, in, created)
	if err != nil {
		return nil, errors.Wrap(err, "computing signature")
	}

	return sig, nil
}

// appendSignature merges fresh into the armored signature already at output, so
// one file verifies under either key across a rotation. With no file there yet,
// fresh stands alone.
func appendSignature(output string, fresh []byte) ([]byte, error) {
	existing, err := os.ReadFile(filepath.Clean(output))
	if err != nil {
		if os.IsNotExist(err) {
			return fresh, nil
		}

		return nil, errors.Wrapf(err, "reading existing signature %s", output)
	}

	merged, err := openpgpkey.MergeArmoredSignatures(existing, fresh)
	if err != nil {
		return nil, errors.Wrapf(err, "merging signature into %s", output)
	}

	return merged, nil
}

// signatureTime is --created, or now when it is unset.
func signatureTime(raw string) (time.Time, error) {
	created, err := parseCreated(raw)
	if err != nil || !created.IsZero() {
		return created, err
	}

	return time.Now().UTC().Truncate(time.Second), nil
}

// parseCreated reads --created, in whole seconds. Unset is the zero time.
func parseCreated(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}

	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "parsing --created %q as RFC3339", raw)
	}

	return t.UTC().Truncate(time.Second), nil
}
