package openpgp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

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

	// The same ordering as a message, and the same reason: a binary certificate
	// is consumed as packets, so an armour header embedded in one cannot decide
	// where it begins, and a certificate pasted under a covering line is still
	// found. Shared rather than repeated -- the two carried the same block
	// twice, differing only in a label.
	raw, err = packetsOrArmour(raw, "certificate")
	if err != nil {
		return Recipient{}, err
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

	cipherID, sessionKey, err := recoverSessionKey(ctx, deriver, recipient, candidates)
	if err != nil {
		return err
	}

	return decryptBody(rest, packet.CipherFunction(cipherID), sessionKey, out)
}

// recoverSessionKey attempts the candidates in order and returns the first that
// opens.
//
// Every failure advances to the next, because a candidate can fail for reasons
// that say nothing about ours: a co-recipient on another curve makes the key
// service reject *their* ephemeral point, and a packet naming our key id can be
// planted by anyone who can touch the message, since the key id is public.
// Stopping at the first failure loses a report the very next packet would have
// opened.
//
// What must not be lost is why. Two kinds of failure are worth reporting even
// after a later candidate is tried and also fails, so they are kept as the run
// goes on and reported in preference to a blanket verdict.
func recoverSessionKey(
	ctx context.Context,
	deriver SecretDeriver,
	recipient Recipient,
	candidates []candidate,
) (cipherID byte, sessionKey []byte, err error) {
	var namedFailure, otherFailure error

	for i, c := range candidates {
		// Each attempt is one key-service call, and for a hidden recipient it
		// is a guess. A message may carry any number of wildcard packets, so
		// without a ceiling anyone who can write to the published address can
		// bill us for as many derivations as they care to append.
		if i >= maxDerivations {
			return 0, nil, exhausted(namedFailure, otherFailure, len(candidates))
		}

		cipherID, sessionKey, err := unwrap(ctx, deriver, recipient, c.pkesk)
		if err == nil {
			return cipherID, sessionKey, nil
		}

		switch {
		// The message named this certificate and the unwrap still failed. That
		// is a corrupt message or the wrong --key, not a message for somebody
		// else, and reporting it as the latter sends the operator to find a
		// different certificate when theirs is right.
		case c.named && namedFailure == nil:
			namedFailure = err

		// Not an unwrap verdict at all — a key service that is unreachable or
		// refusing, a point it will not accept. "Not addressed here" would
		// claim we established something we never did.
		case !isUnwrapVerdict(err) && otherFailure == nil:
			otherFailure = err
		}
	}

	switch {
	case namedFailure != nil:
		return 0, nil, namedFailure
	case otherFailure != nil:
		return 0, nil, otherFailure
	}

	// Every candidate was a wildcard and every unwrap said no, which is exactly
	// what a message for somebody else looks like.
	return 0, nil, fmt.Errorf("%w: none of the %d candidate session-key packets unwrapped",
		ErrNotAddressed, len(candidates))
}

// exhausted reports running out of attempts without discarding what was learned
// on the way.
//
// Returning a bare ErrNotAddressed here threw away the failures the loop had
// gone to trouble to accumulate: a key service that was unreachable for every
// candidate was reported as "this message is not for you", and the operator
// went looking for a different certificate while their credentials were the
// fault. The cap is a statement about cost, not about who the message is for.
func exhausted(namedFailure, otherFailure error, candidates int) error {
	switch {
	case namedFailure != nil:
		return fmt.Errorf("gave up after %d of %d candidate session-key packets; the last failure was: %w",
			maxDerivations, candidates, namedFailure)
	case otherFailure != nil:
		return fmt.Errorf("gave up after %d of %d candidate session-key packets; the last failure was: %w",
			maxDerivations, candidates, otherFailure)
	}

	return fmt.Errorf("%w: gave up after trying %d of %d candidate session-key packets",
		ErrNotAddressed, maxDerivations, candidates)
}

// isUnwrapVerdict reports whether an error means "this packet was not ours"
// rather than "we could not tell".
func isUnwrapVerdict(err error) bool {
	return errors.Is(err, encryption.ErrIntegrity) || errors.Is(err, encryption.ErrChecksum)
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

// Packets the format requires a reader to step over rather than act on.
const (
	// tagMarker is the obsolete Marker packet, RFC 9580 §5.8: "MUST be ignored
	// when received". Emitted by some older tooling ahead of a message.
	tagMarker = 10

	// tagPadding is the version 6 Padding packet, RFC 9580 §5.14, which exists
	// to be meaningless.
	tagPadding = 21
)

// isIgnorablePacket reports whether a packet must be stepped over rather than
// treated as the start of the encrypted data.
func isIgnorablePacket(tag byte) bool {
	return tag == tagMarker || tag == tagPadding
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
func addressedToUs(message io.Reader, recipient Recipient) ([]candidate, []byte, error) {
	raw, err := readMessage(message)
	if err != nil {
		return nil, nil, err
	}

	var (
		others     [][8]byte
		ours       []encryption.PKESK
		hidden     []encryption.PKESK
		unreadable int
	)

	body := raw

	for len(body) > 0 {
		pkt, err := encryption.ParsePacket(body)

		// The session-key packets come first and always carry a definite
		// length; the encrypted data that follows may use a partial length,
		// which this package deliberately does not parse and go-crypto
		// handles. So anything that is not a readable PKESK ends the scan and
		// becomes the body, rather than being an error here.
		if err != nil {
			break
		}

		// Except the packets the format says to ignore. Ending the scan at one
		// of those meant a marker placed before the session-key packets hid
		// every one of them: the walk stopped, the body started at the marker,
		// and a report addressed to this certificate was reported as somebody
		// else's. RFC 9580 §5.8 is explicit that a marker MUST be ignored, and
		// ten prepended octets were enough to exploit reading it as a
		// terminator instead.
		if isIgnorablePacket(pkt.Tag) {
			body = pkt.Rest

			continue
		}

		if pkt.Tag != encryption.TagPKESK {
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

		switch pkesk.KeyID {
		// Every packet naming us, not just the first. The key id is public —
		// it is the tail of the certificate's own fingerprint — so anyone able
		// to touch the message can prepend a packet carrying it and a wrapped
		// key that will not open. Keeping only the first filed the genuine one
		// under somebody else's recipients, where nothing could ever reach it.
		case recipient.KeyID:
			ours = append(ours, pkesk)
		case wildcardKeyID:
			// A hidden recipient names nobody, so the only way to know whether
			// it is ours is to try it. Held back until every named packet has
			// been read, since one of those may match and cost nothing.
			hidden = append(hidden, pkesk)
		default:
			others = append(others, pkesk.KeyID)
		}

		body = pkt.Rest
	}

	return chooseRecipients(candidateSet{
		ours:       ours,
		hidden:     hidden,
		others:     others,
		unreadable: unreadable,
	}, body, recipient)
}

// candidate is a session-key packet worth attempting, and whether the message
// named this certificate to reach it.
//
// The distinction decides what a failure means. A packet that named us and did
// not open is a corrupt message or the wrong key; a wildcard that did not open
// is simply not ours.
type candidate struct {
	pkesk encryption.PKESK
	named bool
}

// candidateSet is what one pass over the session-key packets found.
type candidateSet struct {
	ours   []encryption.PKESK
	hidden []encryption.PKESK
	others [][8]byte

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
func chooseRecipients(c candidateSet, body []byte, recipient Recipient) ([]candidate, []byte, error) {
	candidates := make([]candidate, 0, len(c.ours)+len(c.hidden))

	// Deduplicated as they are ordered, because the cap is a cost ceiling and
	// duplicates buy nothing with it. Copying one packet is the cheapest way to
	// push a genuine one past the cap: the wrapped key is public, so anyone who
	// can touch the message can repeat it until the real candidate is never
	// reached, and the operator is told the report was for somebody else.
	seen := make(map[string]bool, len(c.ours)+len(c.hidden))

	add := func(pkesk encryption.PKESK, named bool) {
		key := string(pkesk.WrappedKey) + "\x00" + string(pkesk.EphemeralPoint)
		if seen[key] {
			return
		}

		seen[key] = true

		candidates = append(candidates, candidate{pkesk: pkesk, named: named})
	}

	for _, pkesk := range c.ours {
		add(pkesk, true)
	}

	for _, pkesk := range c.hidden {
		add(pkesk, false)
	}

	switch {
	case len(candidates) > 0:
		return candidates, body, nil

	case len(c.others) == 0 && c.unreadable == 0:
		return nil, nil, fmt.Errorf(
			"%w: no session-key packet at the start of the message", ErrMalformedMessage)

	case len(c.others) == 0:
		return nil, nil, fmt.Errorf(
			"%w: its %d session-key packets are all of a kind this cannot read, so none names this certificate (%x)",
			ErrNotAddressed, c.unreadable, recipient.KeyID)

	default:
		return nil, nil, fmt.Errorf("%w: addressed to %s, this certificate is %x",
			ErrNotAddressed, keyIDs(c.others), recipient.KeyID)
	}
}

// keyIDs renders the recipients a message names, so the error says which
// certificate should have been used rather than only that this one was wrong.
func keyIDs(ids [][8]byte) string {
	// Bounded, because the message chooses how many there are. An
	// attacker-sized list inside maxMessage renders megabytes of hex into an
	// error string that then reaches a log and a terminal.
	const maxRendered = 8

	rendered := min(len(ids), maxRendered)

	out := make([]string, 0, rendered+1)
	for _, id := range ids[:rendered] {
		out = append(out, fmt.Sprintf("%x", id))
	}

	if len(ids) > rendered {
		out = append(out, fmt.Sprintf("and %d more", len(ids)-rendered))
	}

	return strings.Join(out, ", ")
}
