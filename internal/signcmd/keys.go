package signcmd

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/minisign"
)

// FormatOpenPGP and FormatMinisign are the values --format takes.
const (
	FormatOpenPGP  = "openpgp"
	FormatMinisign = "minisign"
)

// MinisignPublicKey returns the minisign form of signer's public key, refusing
// any key that is not Ed25519.
func MinisignPublicKey(signer crypto.Signer) (minisign.PublicKey, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return minisign.PublicKey{}, errors.Newf(
			"minisign requires an Ed25519 signing key, but --key-id resolved to %T; "+
				"RSA keys sign the OpenPGP manifest path (--format %s) instead",
			signer.Public(), FormatOpenPGP)
	}

	return minisign.NewPublicKey(pub) //nolint:wrapcheck // go/signing-cli's text, unchanged
}

// ParseCreatedTime reads a --created value as RFC3339 in UTC. Empty means now.
func ParseCreatedTime(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "parsing --created (RFC3339 expected)")
	}

	return t.UTC(), nil
}

// ReadFingerprint returns the primary-key fingerprint, in upper-case hex, of an
// armored public key holding exactly one entity.
func ReadFingerprint(armored []byte) (string, error) {
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(armored)))
	if err != nil {
		return "", err //nolint:wrapcheck // go/signing-cli's text, unchanged
	}

	if len(ring) != 1 {
		return "", errors.Newf("expected 1 entity, got %d", len(ring))
	}

	return fmt.Sprintf("%X", ring[0].PrimaryKey.Fingerprint), nil
}
