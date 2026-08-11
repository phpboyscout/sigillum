package openpgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"gitlab.com/phpboyscout/go/encryption"
	"gitlab.com/phpboyscout/go/encryption/certificate"
)

// Errors reported by this package.
var (
	// ErrNotAddressed means the message is not addressed to the certificate
	// supplied — a different recipient, or a different subkey of the same
	// identity after a rotation.
	ErrNotAddressed = errors.New("message is not addressed to this certificate")

	// ErrMalformedMessage means the message could not be read as OpenPGP.
	ErrMalformedMessage = errors.New("malformed message")
)

// SecretDeriver is the key service the decrypt command needs.
//
// One method plus the curve's coordinate length, which is what the core's KDF
// parameters require. gitlab.com/phpboyscout/go/encryption-aws-kms's Deriver
// satisfies it, and so would an HSM or a software key held elsewhere — the
// command has no opinion about which.
type SecretDeriver interface {
	DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error)
	CoordinateBytes() int
}

// Recipient is re-exported so callers need only this package. It is the core's
// type: parsing a certificate is packet work, and the core does it with the
// binding signature verified.
type Recipient = certificate.Recipient

// ReadRecipient extracts the encryption subkey's parameters from a certificate.
//
// The certificate is the source of truth rather than a set of flags: the key
// derivation binds the subkey's fingerprint, so parameters that did not come
// from the certificate the sender used cannot recover anything, and inviting a
// caller to supply them by hand invites exactly that mistake.
//
// Armoured and binary certificates are both accepted — a certificate published
// on a page is armoured, one fetched from WKD is not, and a caller should not
// have to know which they have.
func ReadRecipient(r io.Reader) (Recipient, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Recipient{}, fmt.Errorf("reading the certificate: %w", err)
	}

	if block, decodeErr := armor.Decode(bytes.NewReader(raw)); decodeErr == nil {
		if raw, err = io.ReadAll(block.Body); err != nil {
			return Recipient{}, fmt.Errorf("dearmouring the certificate: %w", err)
		}
	}

	recipient, err := certificate.Parse(raw)
	if err != nil {
		return Recipient{}, err
	}

	return recipient, nil
}

// Decrypt recovers the plaintext of a message addressed to recipient.
//
// The only secret operation is the deriver's: everything else — the KDF, the
// key unwrap, the body decryption — happens locally with public data and the
// recovered session key.
func Decrypt(
	ctx context.Context,
	deriver SecretDeriver,
	recipient Recipient,
	message io.Reader,
	out io.Writer,
) error {
	if deriver == nil {
		return fmt.Errorf("%w: no key service supplied", encryption.ErrMalformed)
	}

	body, rest, err := firstPacket(message)
	if err != nil {
		return err
	}

	pkesk, err := encryption.ParsePKESK(body)
	if err != nil {
		return err
	}

	// Refuse before spending a key-service call. A message for another
	// recipient is the common case when several certificates are in play, and
	// it is not an error worth an API round trip.
	if pkesk.KeyID != recipient.KeyID {
		return fmt.Errorf("%w: addressed to key %x, this certificate is %x",
			ErrNotAddressed, pkesk.KeyID, recipient.KeyID)
	}

	secret, err := deriver.DeriveSharedSecret(ctx, pkesk.EphemeralPoint)
	if err != nil {
		return fmt.Errorf("deriving the shared secret: %w", err)
	}

	params := recipient.KDF
	params.CoordinateBytes = deriver.CoordinateBytes()

	cipherID, sessionKey, err := encryption.SessionKey(encryption.Message{
		Version:      pkesk.Version,
		SharedSecret: secret,
		WrappedKey:   pkesk.WrappedKey,
	}, params)
	if err != nil {
		return err
	}

	return decryptBody(rest, packet.CipherFunction(cipherID), sessionKey, out)
}
