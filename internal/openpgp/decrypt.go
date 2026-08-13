package openpgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
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

	// ErrCostCeiling means the run stopped because it reached the limit on
	// billed key-service derivations, with candidates left untried.
	//
	// Deliberately NOT ErrNotAddressed, which this used to be. Hitting the
	// ceiling establishes nothing about who the message is for — the candidates
	// never tried might have been ours — so reporting it as "addressed
	// elsewhere" sends the operator to find a certificate that may not exist,
	// which is the misdiagnosis this package has produced three separate ways.
	ErrCostCeiling = errors.New("stopped before trying every recipient: too many key-service derivations")

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

	candidates, rest, truncated, err := addressedToUs(message, recipient)
	if err != nil {
		return err
	}

	cipherID, sessionKey, err := recoverSessionKey(ctx, deriver, recipient, candidates, truncated)
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
	truncated int,
) (cipherID byte, sessionKey []byte, err error) {
	var namedFailure, otherFailure error

	// Scoped to this message, so nothing is remembered between calls and a key
	// rotation between two messages is never served from a cache.
	billed := newBilledOnce(deriver)

	// How many candidates the ceiling refused to pay for, which is what turns
	// "none of them opened" into "we stopped before trying them all".
	skipped := 0

	for _, c := range candidates {
		// One ceiling, on distinct billed derivations, applied to every
		// candidate however it is addressed.
		//
		// The earlier rule bounded wildcard packets only, on the grounds that
		// forging a packet naming this certificate requires modifying a message
		// in transit and that such an attacker can delete the message anyway.
		// That reasoning holds for suppressing a report and fails for cost: the
		// key id is the tail of the PUBLISHED fingerprint, so any stranger can
		// compose packets carrying it and send them to the address we publish.
		//
		// Since the derivation depends on the ephemeral point alone, cost is
		// per distinct point and not per packet — so bounding distinct points
		// is the whole of the cost story, and a candidate whose point has
		// already been derived is free and never counted.
		//
		// What this gives up is bounded and already available to the same
		// attacker: someone able to modify a message in transit can now bury a
		// genuine report behind sixteen distinct forged points. They could
		// delete the message outright instead, so the cap costs nothing against
		// them, while its absence handed every stranger an amplifier of about a
		// million billed calls per message.
		//
		// SKIPPED, not returned. This used to end the whole loop, which threw
		// away every later candidate including the ones the ceiling does not
		// govern at all: a packet whose point has already been derived is free,
		// and a genuine report sitting behind sixteen distinct forged points was
		// discarded without being tried. A bound that stops work it was never
		// meant to bound is the exact shape this package keeps getting wrong.
		if billed.wouldExceed(c.pkesk.EphemeralPoint) {
			skipped++

			continue
		}

		cipherID, sessionKey, err := unwrap(ctx, billed, recipient, c.pkesk)
		if err == nil {
			return cipherID, sessionKey, nil
		}

		namedFailure, otherFailure = recordFailure(c, err, namedFailure, otherFailure)
	}

	// Anything skipped means the run was cut short by cost, so it cannot be
	// reported as a settled verdict about who the message is for.
	if skipped > 0 || truncated > 0 {
		return 0, nil, exhausted(namedFailure, otherFailure, len(candidates), skipped+truncated)
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
func exhausted(namedFailure, otherFailure error, candidates, skipped int) error {
	// First-wins, and named before other, so the message names the failure
	// most likely to be actionable rather than the most recent one.
	switch {
	case namedFailure != nil:
		return fmt.Errorf("%w: %d derivations across %d candidates, %d untried; the first failure was: %w",
			ErrCostCeiling, maxDerivations, candidates, skipped, namedFailure)
	case otherFailure != nil:
		return fmt.Errorf("%w: %d derivations across %d candidates, %d untried; the first failure was: %w",
			ErrCostCeiling, maxDerivations, candidates, skipped, otherFailure)
	}

	return fmt.Errorf("%w: %d derivations across %d candidates, %d untried",
		ErrCostCeiling, maxDerivations, candidates, skipped)
}

// recordFailure keeps the two kinds of failure worth reporting after a later
// candidate has also failed, first-wins.
func recordFailure(c candidate, err, namedFailure, otherFailure error) (named, other error) {
	switch {
	// The message named this certificate and the unwrap still failed. That is a
	// corrupt message or the wrong --key, not a message for somebody else, and
	// reporting it as the latter sends the operator to find a different
	// certificate when theirs is right.
	case c.named && namedFailure == nil:
		return err, otherFailure

	// Not an unwrap verdict at all — a key service that is unreachable or
	// refusing, a point it will not accept. "Not addressed here" would claim we
	// established something we never did.
	case !isUnwrapVerdict(err) && otherFailure == nil:
		return namedFailure, err
	}

	return namedFailure, otherFailure
}

// isUnwrapVerdict reports whether an error means "this packet was not ours"
// rather than "we could not tell".
func isUnwrapVerdict(err error) bool {
	return errors.Is(err, encryption.ErrIntegrity) || errors.Is(err, encryption.ErrChecksum)
}

// maxCandidates bounds how many session-key packets of each kind one message
// may have retained from it.
//
// Not a cost bound — [maxDerivations] is that — but a memory one. Every
// retained candidate is a struct and a dedup-map entry, and the message chooses
// how many there are: a 24 MiB message of minimal session-key packets grew the
// heap by 165 MiB, about sevenfold, and the message bound is 128 MiB. That is
// an out-of-memory kill reachable by anyone who can send to the published
// address, not a slow decrypt.
//
// Set far above any real message — a report copied to a coordinating body and a
// colleague carries a handful of recipients — and far above what the derivation
// ceiling could ever pay for, so nothing that could have been tried is dropped
// unless its point was already going to be free. A message that exceeds it is
// reported as cut short rather than as a settled verdict, because the walk did
// not see all of it.
const maxCandidates = 1024

// maxDerivations bounds how many DISTINCT ephemeral points one message may
// cost, which after memoisation is the same as how many billed key-service
// calls it may cost.
//
// Generous against real messages: a report copied to a coordinating body and a
// colleague carries a handful of recipients at most, and every repeat of a
// point already seen is free regardless of this number.
const maxDerivations = 16

// billedOnce memoises derivations by ephemeral point for one message.
//
// The billed operation is the derivation, and it depends on the ephemeral point
// alone — so two candidate packets carrying the same point are the same
// key-service call twice, and the second one buys nothing.
//
// That is not a micro-optimisation. The key id naming this certificate is the
// tail of its published fingerprint, so composing packets that name it needs no
// key material and no interception: a stranger can send one message carrying a
// great many of them to the published address. Measured before this existed, a
// message of 5,000 such packets — all sharing one ephemeral point, differing
// only in the wrapped key, which costs an attacker one XOR each — produced
// 5,001 billed derivations and still delivered the report. The message bound is
// 128 MiB and one of these packets is about a hundred octets, so the ceiling on
// that was of the order of a million calls per message.
//
// Memoising collapses the whole of that to one call while changing no verdict:
// the same point yields the same secret, and the unwrap that follows is local
// arithmetic.
//
// The map is bounded by [maxDerivations], which the walk applies to every
// candidate: a point not seen before is a billed call and counts, a point
// already asked about is free and does not — whether the answer was a secret
// or a refusal.
type billedOnce struct {
	deriver SecretDeriver

	// outcomes records what each point cost and what it produced, so a point
	// asked about twice is billed once whichever way it went.
	outcomes map[string]outcome

	// calls counts derivations actually made, successful or not, which is what
	// [maxDerivations] bounds.
	calls int
}

// outcome is what one ephemeral point yielded.
type outcome struct {
	secret []byte
	err    error
}

func newBilledOnce(deriver SecretDeriver) *billedOnce {
	return &billedOnce{deriver: deriver, outcomes: map[string]outcome{}}
}

func (b *billedOnce) CoordinateBytes() int { return b.deriver.CoordinateBytes() }

// wouldExceed reports whether deriving this point would take the message past
// [maxDerivations] billed calls.
//
// A point already derived is free, so it never counts and never refuses — which
// is what lets the ceiling be small without a repeated packet consuming it.
func (b *billedOnce) wouldExceed(peerPoint []byte) bool {
	if _, ok := b.outcomes[string(peerPoint)]; ok {
		return false
	}

	return b.calls >= maxDerivations
}

func (b *billedOnce) DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error) {
	if got, ok := b.outcomes[string(peerPoint)]; ok {
		return got.secret, got.err
	}

	// Counted before the call, and counted whichever way it goes: a refused
	// call is billed and rate-limited like any other.
	b.calls++

	secret, err := b.deriver.DeriveSharedSecret(ctx, peerPoint)

	// Failures are recorded too, and only for the life of this message.
	//
	// They were once deliberately excluded, on the grounds that a refusal might
	// be particular to one call and recording it would turn a transient outage
	// into a verdict. That reasoning is right across messages and wrong within
	// one: re-asking the same key service for the same point, in the same
	// second, is not a retry strategy — it is paying twice for the same answer.
	// Excluding them made the ceiling per packet rather than per point at
	// exactly the moment cost matters most, which is when a key service is
	// already throttling.
	b.outcomes[string(peerPoint)] = outcome{secret: secret, err: err}

	return secret, err
}

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

// countUnparsed files a session-key packet this cannot read under whichever of
// the two counts it belongs to.
func countUnparsed(body []byte, err error, unreadable, malformed int) (int, int) {
	if isRealRecipientPacket(body, err) {
		return unreadable + 1, malformed
	}

	return unreadable, malformed + 1
}

// isRealRecipientPacket reports whether a session-key packet this cannot parse
// is nonetheless one a sender really wrote.
//
// The distinction decides whether a message is "addressed to somebody else" or
// simply damaged, and the version octet is what settles it. An unsupported
// algorithm or an unsupported-but-defined version is a co-recipient this
// package does not implement — RSA is still the commonest key type, and a
// version 6 sender is a modern one. A version octet naming no version at all is
// not a recipient; it is noise, and whoever wrote it chose it.
//
// Reading the error alone was not enough: ParsePKESK reports an undefined
// version as unsupported, so twelve octets of padding followed by an empty
// encrypted-data packet passed as a co-recipient and the message came back
// "addressed to somebody else" — naming a certificate that was never involved.
func isRealRecipientPacket(body []byte, err error) bool {
	// RFC 9580 §5.1 defines version 3 and version 6; version 5 shipped from a
	// draft in the wild.
	const (
		oldestVersion = 3
		newestVersion = 6
	)

	if !errors.Is(err, encryption.ErrUnsupported) || len(body) == 0 {
		return false
	}

	return body[0] >= oldestVersion && body[0] <= newestVersion
}

// The packets that begin the encrypted data, and therefore end the search for
// session keys.
const (
	// tagSED is the legacy Symmetrically Encrypted Data packet, RFC 9580 §5.7.
	// decryptBody refuses it for having no integrity protection, but it still
	// marks where the session-key packets stop.
	tagSED = 9

	// tagSEIPD is the Symmetrically Encrypted and Integrity Protected Data
	// packet, RFC 9580 §5.13 — what every well-formed message carries.
	tagSEIPD = 18
)

// startsEncryptedData reports whether a packet begins the body.
//
// The scan ends here rather than at "the first packet that is not a session
// key", which is what it used to do and what made it exploitable. Any packet an
// attacker cared to insert — a marker, a padding packet, a tag nothing defines
// — terminated the walk, so every genuine session-key packet after it was never
// seen and a report addressed to this certificate came back as somebody else's.
// Four prepended octets were enough, and a fuzz target found two separate
// shapes of it.
//
// Ending at the encrypted data instead is both narrower and what the search was
// always for. An encrypted-data packet may use a partial length, which this
// package deliberately does not parse and go-crypto handles — so the scan stops
// at it rather than reading it, which is why the tag is all that is needed.
func startsEncryptedData(tag byte) bool {
	return tag == tagSEIPD || tag == tagSED
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
func addressedToUs(message io.Reader, recipient Recipient) ([]candidate, []byte, int, error) {
	raw, err := readMessage(message)
	if err != nil {
		return nil, nil, 0, err
	}

	var found candidateSet

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

		if startsEncryptedData(pkt.Tag) {
			break
		}

		// Anything else is stepped over rather than treated as the body: a
		// marker, a padding packet, or a tag nothing defines. See
		// startsEncryptedData for why ending the scan here was exploitable.
		if pkt.Tag != encryption.TagPKESK {
			body = pkt.Rest

			continue
		}

		pkesk, err := encryption.ParsePKESK(pkt.Body)
		if err != nil {
			// A co-recipient's packet we cannot read is not a reason to refuse
			// the message. RSA is still the most common key type and parses as
			// unsupported here, as does a version 6 packet from a modern
			// sender — so propagating this would fail a report over somebody
			// else's key while ours sat in the very next packet.
			//
			// Which failure it was decides what the message is, so the two are
			// counted apart.
			//
			// ErrUnsupported means a real recipient on an algorithm or version
			// this package does not implement — genuinely somebody else's
			// packet. Anything else means the bytes are not a session-key
			// packet at all, which makes the message malformed rather than
			// addressed elsewhere.
			//
			// Conflating them let an injected prefix — a garbage packet and an
			// empty encrypted-data packet to cut the scan short — be reported
			// as "the message is addressed to somebody else", sending the
			// operator to find a certificate that was never involved.
			found.unreadable, found.malformed = countUnparsed(pkt.Body, err, found.unreadable, found.malformed)
			body = pkt.Rest

			continue
		}

		found.file(pkesk, recipient)

		body = pkt.Rest
	}

	return chooseRecipients(found, body, recipient)
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

// file records one readable session-key packet under whichever heading it
// belongs to.
//
// Separated from the walk because the two are different jobs: the walk decides
// where the session-key packets end, this decides what each one means. Keeping
// them together also put the walk over the complexity limit, which is the same
// observation from the other direction.
func (c *candidateSet) file(pkesk encryption.PKESK, recipient Recipient) {
	switch pkesk.KeyID {
	// Every packet naming us, not just the first. The key id is public — it is
	// the tail of the certificate's own fingerprint — so anyone able to touch
	// the message can prepend a packet carrying it and a wrapped key that will
	// not open. Keeping only the first filed the genuine one under somebody
	// else's recipients, where nothing could ever reach it.
	//
	// Bounded all the same, because "every packet" let the message choose how
	// much memory the walk uses: a 24 MiB message of minimal session-key
	// packets grew the heap by 165 MiB. See maxCandidates.
	case recipient.KeyID:
		if len(c.ours) >= maxCandidates {
			c.truncated++

			return
		}

		c.ours = append(c.ours, pkesk)

	case wildcardKeyID:
		// A hidden recipient names nobody, so the only way to know whether it
		// is ours is to try it. Held back until every named packet has been
		// read, since one of those may match and cost nothing.
		if len(c.hidden) >= maxCandidates {
			c.truncated++

			return
		}

		c.hidden = append(c.hidden, pkesk)

	default:
		// Only as many DISTINCT ids as the error will ever render are kept; the
		// rest are counted. The message chooses how many session-key packets it
		// carries, so an attacker-sized list inside the 128 MiB bound would
		// otherwise grow a slice of megabytes in order to print eight entries.
		//
		// Distinct, because the error tells an operator which certificate they
		// should have used instead. Repeating one id eight times reads as eight
		// certificates when there is one, which is worse than naming it once.
		c.otherCount++

		if len(c.others) < maxRenderedKeyIDs && !slices.Contains(c.others, pkesk.KeyID) {
			c.others = append(c.others, pkesk.KeyID)
		}
	}
}

// candidateSet is what one pass over the session-key packets found.
type candidateSet struct {
	ours   []encryption.PKESK
	hidden []encryption.PKESK

	// others holds at most [maxRenderedKeyIDs] of the key ids the message
	// names, and otherCount how many there were altogether.
	others     [][8]byte
	otherCount int

	// unreadable counts packets that are session-key packets but not ones this
	// package can parse — a co-recipient on RSA, or a v6 sender. They cannot
	// be ours, but they say the message was addressed to somebody.
	unreadable int

	// truncated counts candidates dropped for exceeding [maxCandidates], which
	// means the walk did not see the whole message and cannot report a settled
	// verdict about who it is for.
	truncated int

	// malformed counts packets in the session-key position that are not
	// session-key packets at all. They say nothing about who the message is
	// for, only that it is damaged.
	malformed int
}

// chooseRecipients orders the packets worth trying, once the sequence has been
// read.
//
// A packet naming us comes first, because a named match is certain where a
// hidden one is a guess that costs a key-service call to disprove. Every hidden
// packet follows, in the order the sender wrote them: taking only the first
// means two hidden recipients with ours second fail with a checksum error on a
// message that is genuinely ours.
func chooseRecipients(c candidateSet, body []byte, recipient Recipient) ([]candidate, []byte, int, error) {
	candidates := make([]candidate, 0, len(c.ours)+len(c.hidden))

	// Deduplicated as they are ordered, because trying the same bytes twice can
	// only fail twice.
	//
	// Deliberately not a defence AGAINST evasion. Every octet the key is built
	// from is one the attacker chose, so varying a single byte defeats it —
	// which is exactly what happened when this was relied on to stop a genuine
	// candidate being crowded out. It survives as an efficiency, and the
	// crowding problem is answered by bounding distinct billed derivations. See
	// maxDerivations.
	//
	// It must still be injective, which is the opposite direction and was not
	// true. The two parts were joined by a single 0x00 octet, and since both are
	// attacker-chosen the split could be moved: given a genuine packet whose
	// wrapped key is A‖0x00‖B and whose point is P, a forged packet with wrapped
	// key A and point B‖0x00‖P produced the identical string. Ordered first, the
	// forgery made the genuine packet look like a duplicate and it was dropped —
	// the report unreadable, with no error naming the cause, because from the
	// walk's point of view it was never there.
	seen := make(map[string]bool, len(c.ours)+len(c.hidden))

	add := func(pkesk encryption.PKESK, named bool) {
		key := dedupKey(pkesk)
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
		return candidates, body, c.truncated, nil

	case c.malformed > 0:
		return nil, nil, 0, fmt.Errorf(
			"%w: %d packets before the encrypted data are not session-key packets",
			ErrMalformedMessage, c.malformed)

	case c.otherCount == 0 && c.unreadable == 0:
		return nil, nil, 0, fmt.Errorf(
			"%w: no session-key packet at the start of the message", ErrMalformedMessage)

	case c.otherCount == 0:
		return nil, nil, 0, fmt.Errorf(
			"%w: its %d session-key packets are all of a kind this cannot read, so none names this certificate (%x)",
			ErrNotAddressed, c.unreadable, recipient.KeyID)

	default:
		return nil, nil, 0, fmt.Errorf("%w: addressed to %s, this certificate is %x",
			ErrNotAddressed, keyIDs(c.others, c.otherCount), recipient.KeyID)
	}
}

// dedupKey identifies a session-key packet by the bytes an attempt depends on.
//
// Length-prefixed rather than delimited, so the encoding is injective: a
// delimiter can be forged into either part, a length cannot.
func dedupKey(pkesk encryption.PKESK) string {
	var key strings.Builder

	// Enough for the two parts and their prefixes, so the builder does not
	// grow while an attacker-sized packet is being encoded.
	key.Grow(len(pkesk.WrappedKey) + len(pkesk.EphemeralPoint) + 2*binary.MaxVarintLen64)

	var prefix [binary.MaxVarintLen64]byte

	for _, part := range [][]byte{pkesk.WrappedKey, pkesk.EphemeralPoint} {
		key.Write(prefix[:binary.PutUvarint(prefix[:], uint64(len(part)))])
		key.Write(part)
	}

	return key.String()
}

// keyIDs renders the recipients a message names, so the error says which
// certificate should have been used rather than only that this one was wrong.
func keyIDs(ids [][8]byte, total int) string {
	// Capped here as well as at the point of retention, so neither bound is
	// load-bearing alone. They guard different things — this one an error
	// string that reaches a log and a terminal, the other a slice that reaches
	// memory — and a change to one should not silently undo the other.
	if len(ids) > maxRenderedKeyIDs {
		ids = ids[:maxRenderedKeyIDs]
	}

	out := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%x", id))
	}

	if total > len(ids) {
		out = append(out, fmt.Sprintf("and %d more", total-len(ids)))
	}

	return strings.Join(out, ", ")
}

// maxRenderedKeyIDs bounds both what an error prints and what is retained to
// print it.
//
// The rendering was bounded already; the retention was not, so a message could
// still grow a slice proportional to its own size to show eight entries from
// it. Both ends matter: the error reaches a log and a terminal, and the slice
// reaches memory.
const maxRenderedKeyIDs = 8
