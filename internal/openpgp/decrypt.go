package openpgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

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

	// ErrIntegrity means the message did not survive the journey intact: its
	// modification detection code does not match what was decrypted.
	//
	// Treat it as tampering rather than corruption. The plaintext is
	// deliberately not written out, because a report an attacker has edited is
	// worse than no report at all.
	ErrIntegrity = errors.New("message integrity check failed; it may have been altered")

	// ErrTooLarge means the message, or what it decompresses to, is beyond
	// what this will hold in memory. A compressed packet expands without
	// limit, and the certificate is public.
	ErrTooLarge = errors.New("message is larger than this will decrypt")

	// ErrUnprotected means the message uses the legacy encrypted-data packet,
	// which carries no integrity protection and is refused for that reason.
	ErrUnprotected = errors.New("message has no integrity protection and will not be decrypted")
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
	raw, err := readBounded(r, "certificate")
	if err != nil {
		return Recipient{}, err
	}

	if block, decodeErr := armor.Decode(bytes.NewReader(raw)); decodeErr == nil {
		if raw, err = readBounded(block.Body, "dearmoured certificate"); err != nil {
			return Recipient{}, err
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

	pkesk, rest, err := addressedToUs(message, recipient)
	if err != nil {
		return err
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

// wildcardKeyID is the all-zero key id RFC 9580 §5.1 reserves for a recipient
// the sender chose not to name.
var wildcardKeyID [8]byte

// addressedToUs finds the session-key packet meant for this certificate and
// returns it with the encrypted data that follows.
//
// A message carries one PKESK per recipient, so ours is first only when we are
// the only one. A reporter who copies in a colleague, a coordinating body or
// their own address produces a message where somebody else's packet comes
// first — and refusing it would be a failure they cannot diagnose and we would
// blame on them.
//
// The whole sequence is read before any key-service call, so a message that is
// genuinely not ours still costs nothing.
func addressedToUs(message io.Reader, recipient Recipient) (encryption.PKESK, []byte, error) {
	raw, err := readMessage(message)
	if err != nil {
		return encryption.PKESK{}, nil, err
	}

	var (
		named   [][8]byte
		hidden  []encryption.PKESK
		body    []byte
		matched bool
		ours    encryption.PKESK
	)

	body = raw

	for len(body) > 0 {
		pkt, err := encryption.ParsePacket(body)

		// The session-key packets come first and always carry a definite
		// length; the encrypted data that follows may use a partial length,
		// which this package deliberately does not parse and go-crypto
		// handles. So anything that is not a readable PKESK ends the scan and
		// becomes the body, rather than being an error here.
		if err != nil || pkt.Tag != encryption.TagPKESK {
			break
		}

		pkesk, err := encryption.ParsePKESK(pkt.Body)
		if err != nil {
			return encryption.PKESK{}, nil, err
		}

		switch {
		case pkesk.KeyID == recipient.KeyID && !matched:
			ours, matched = pkesk, true
		case pkesk.KeyID == wildcardKeyID:
			// A hidden recipient names nobody, so the only way to know whether
			// it is ours is to try it. Held back until every named packet has
			// been read, since one of those may match and cost nothing.
			hidden = append(hidden, pkesk)
		default:
			named = append(named, pkesk.KeyID)
		}

		body = pkt.Rest
	}

	return chooseRecipient(ours, matched, hidden, named, body, recipient)
}

// chooseRecipient decides which session-key packet to use, once the sequence
// has been read.
//
// Order matters: a packet naming us is preferred over a hidden one, because a
// named match is certain and a hidden one is a guess that costs a key-service
// call to disprove.
func chooseRecipient(
	ours encryption.PKESK,
	matched bool,
	hidden []encryption.PKESK,
	named [][8]byte,
	body []byte,
	recipient Recipient,
) (encryption.PKESK, []byte, error) {
	switch {
	case matched:
		return ours, body, nil
	case len(hidden) > 0:
		return hidden[0], body, nil
	case len(named) == 0:
		return encryption.PKESK{}, nil, fmt.Errorf(
			"%w: no session-key packet at the start of the message", ErrMalformedMessage)
	default:
		return encryption.PKESK{}, nil, fmt.Errorf("%w: addressed to %s, this certificate is %x",
			ErrNotAddressed, keyIDs(named), recipient.KeyID)
	}
}

// keyIDs renders the recipients a message names, so the error says which
// certificate should have been used rather than only that this one was wrong.
func keyIDs(ids [][8]byte) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%x", id))
	}

	return strings.Join(out, ", ")
}
