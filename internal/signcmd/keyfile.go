package signcmd

import (
	"os"
	"strings"

	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"
)

// ErrKeyFileExists is returned when a key file would be overwritten without
// --force. Its kind is go/signing-cli's, which reaches log records users already
// match on (go/signing#18).
var ErrKeyFileExists = errors.NewSentinel("signing-cli.key_file_exists", "output file already exists")

// WriteKeyFile writes a key file through keyfile.Write, adding the --force hint
// to a refusal to overwrite.
func WriteKeyFile(path string, data []byte, perm os.FileMode, force bool) error {
	err := keyfile.Write(path, data, perm, force)
	if errors.Is(err, keyfile.ErrKeyFileExists) {
		return errors.Wrapf(ErrKeyFileExists, "%q (pass --force to overwrite)", path)
	}

	return err //nolint:wrapcheck // keyfile's error names the path and the step
}

// WriteKeyPair writes both halves of a keypair through keyfile.WritePair,
// adding the --force hint to a refusal to overwrite either.
func WriteKeyPair(private, public keyfile.Half, force bool) error {
	err := keyfile.WritePair(private, public, force)
	if errors.Is(err, keyfile.ErrKeyFileExists) {
		quotedPath := strings.TrimSuffix(err.Error(), ": "+keyfile.ErrKeyFileExists.Error())

		return errors.Wrapf(ErrKeyFileExists, "%s (pass --force to overwrite)", quotedPath)
	}

	return err //nolint:wrapcheck // keyfile's error names the path and the step
}
