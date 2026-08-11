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

	candidates, rest, err := addressedToUs(message, recipient)
	if err != nil {
		return err
	}

	for i, pkesk := range candidates {
		// Each attempt is one key-service call, and for a hidden recipient it
		// is a guess. A message may carry any number of wildcard packets, so
		// without a ceiling anyone who can write to the published address can
		// bill us for as many derivations as they care to append.
		if i >= maxDerivations {
			return fmt.Errorf("%w: gave up after trying %d of %d candidate session-key packets",
				ErrNotAddressed, maxDerivations, len(candidates))
		}

		cipherID, sessionKey, err := unwrap(ctx, deriver, recipient, pkesk)

		switch {
		case err == nil:
			return decryptBody(rest, packet.CipherFunction(cipherID), sessionKey, out)

		// The unwrap failing means this packet was not ours: a hidden
		// recipient names nobody, so trying it is the only way to find out.
		// Any other failure is about the message or the key service and would
		// recur identically on the next candidate.
		case errors.Is(err, encryption.ErrIntegrity), errors.Is(err, encryption.ErrChecksum):
			continue

		default:
			return err
		}
	}

	return fmt.Errorf("%w: none of the %d candidate session-key packets unwrapped",
		ErrNotAddressed, len(candidates))
}

// maxDerivations bounds how many session-key packets Decrypt will try.
//
// Generous against real messages -- a report copied to a coordinating body and
// a colleague carries a handful -- and small enough that a crafted message
// cannot turn one inbound report into an unbounded run of billed key-service
// calls.
const maxDerivations = 8

// unwrap recovers the session key from one candidate packet.
func unwrap(
	ctx context.Context,
	deriver SecretDeriver,
	recipient Recipient,
	pkesk encryption.PKESK,
) (cipherID byte, sessionKey []byte, err error) {
	secret, err := deriver.DeriveSharedSecret(ctx, pkesk.EphemeralPoint)
	if err != nil {
		return 0, nil, fmt.Errorf("deriving the shared secret: %w", err)
	}

	params := recipient.KDF
	params.CoordinateBytes = deriver.CoordinateBytes()

	return encryption.SessionKey(encryption.Message{
		Version:      pkesk.Version,
		SharedSecret: secret,
		WrappedKey:   pkesk.WrappedKey,
	}, params)
}

// wildcardKeyID is the all-zero key id RFC 9580 §5.1 reserves for a recipient
// the sender chose not to name.
var wildcardKeyID [8]byte

// addressedToUs returns the session-key packets worth trying, in the order to
// try them, with the encrypted data that follows.
//
// A message carries one PKESK per recipient, so ours is first only when we are
// the only one. A reporter who copies in a colleague, a coordinating body or
// their own address produces a message where somebody else's packet comes
// first — and refusing it would be a failure they cannot diagnose and we would
// blame on them.
//
// The whole sequence is read before any key-service call, so a message that is
// genuinely not ours still costs nothing.
func addressedToUs(message io.Reader, recipient Recipient) ([]encryption.PKESK, []byte, error) {
	raw, err := readMessage(message)
	if err != nil {
		return nil, nil, err
	}

	var (
		named      [][8]byte
		hidden     []encryption.PKESK
		matched    bool
		unreadable int
		ours       encryption.PKESK
	)

	body := raw

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
			// A co-recipient's packet we cannot read is not a reason to refuse
			// the message. RSA is still the most common key type and parses as
			// unsupported here, as does a version 6 packet from a modern
			// sender — so propagating this would fail a report over somebody
			// else's key while ours sat in the very next packet.
			unreadable++
			body = pkt.Rest

			continue
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

	return chooseRecipients(candidateSet{
		ours:       ours,
		matched:    matched,
		hidden:     hidden,
		named:      named,
		unreadable: unreadable,
	}, body, recipient)
}

// candidateSet is what one pass over the session-key packets found.
type candidateSet struct {
	ours    encryption.PKESK
	matched bool
	hidden  []encryption.PKESK
	named   [][8]byte

	// unreadable counts packets that are session-key packets but not ones this
	// package can parse — a co-recipient on RSA, or a v6 sender. They cannot
	// be ours, but they say the message was addressed to somebody.
	unreadable int
}

// chooseRecipients orders the packets worth trying, once the sequence has been
// read.
//
// A packet naming us comes first, because a named match is certain where a
// hidden one is a guess that costs a key-service call to disprove. Every hidden
// packet follows, in the order the sender wrote them: taking only the first
// means two hidden recipients with ours second fail with a checksum error on a
// message that is genuinely ours.
func chooseRecipients(c candidateSet, body []byte, recipient Recipient) ([]encryption.PKESK, []byte, error) {
	candidates := make([]encryption.PKESK, 0, len(c.hidden)+1)

	if c.matched {
		candidates = append(candidates, c.ours)
	}

	candidates = append(candidates, c.hidden...)

	switch {
	case len(candidates) > 0:
		return candidates, body, nil

	case len(c.named) == 0 && c.unreadable == 0:
		return nil, nil, fmt.Errorf(
			"%w: no session-key packet at the start of the message", ErrMalformedMessage)

	case len(c.named) == 0:
		return nil, nil, fmt.Errorf(
			"%w: its %d session-key packets are all of a kind this cannot read, so none names this certificate (%x)",
			ErrNotAddressed, c.unreadable, recipient.KeyID)

	default:
		return nil, nil, fmt.Errorf("%w: addressed to %s, this certificate is %x",
			ErrNotAddressed, keyIDs(c.named), recipient.KeyID)
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
