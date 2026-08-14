package openpgp

import (
	"context"
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

// Findings is re-exported alongside Recipient: the certificate parser reports
// things it noticed but had no standing to decide — a revocation it could not
// evaluate, a certificate read only part-way — and a caller surfaces them.
type Findings = certificate.Findings

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
// Findings come back on every path, including the error paths, so a caller can
// surface what the parser noticed even when no usable subkey was found — which
// is exactly the case where an unevaluable revocation matters most.
func ReadRecipient(r io.Reader) (Recipient, Findings, error) {
	raw, err := readBounded(r, "certificate")
	if err != nil {
		return Recipient{}, nil, err
	}

	// The same ordering as a message, and the same reason: a binary certificate
	// is consumed as packets, so an armour header embedded in one cannot decide
	// where it begins, and a certificate pasted under a covering line is still
	// found. Shared rather than repeated -- the two carried the same block
	// twice, differing only in a label.
	raw, err = packetsOrArmour(raw, "certificate")
	if err != nil {
		return Recipient{}, nil, err
	}

	recipient, findings, err := certificate.Parse(raw)
	if err != nil {
		return Recipient{}, findings, err
	}

	return recipient, findings, nil
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

	raw, err := readMessage(message)
	if err != nil {
		return err
	}

	cipherID, sessionKey, rest, err := recoverSessionKey(ctx, deriver, recipient, raw)
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
type attemptRun struct {
	// scanStopped is why the packet walk ended early, when it ended on damage
	// rather than on the encrypted data. nil for an ordinary message.
	//
	// Held because "the walk stopped" and "the walk finished and found nothing
	// for us" are different answers, and reporting the second for the first sent
	// operators hunting for a certificate when what they had was a tampered
	// message.
	scanStopped error

	ctx       context.Context
	recipient Recipient
	billed    *billedOnce

	found                      candidateSet
	namedFailure, otherFailure error
	skipped, tried             int

	cipherID   byte
	sessionKey []byte
}

// attempt tries one candidate, unless the ceiling refuses to pay for it.
//
// SKIPPED, not returned, when the ceiling fires. A bound that stops work it was
// never meant to govern is the shape this package keeps getting wrong: a packet
// whose point is already derived costs nothing, and a genuine report sitting
// behind sixteen distinct forged points must still be tried.
func (r *attemptRun) attempt(pkesk encryption.PKESK, named bool) {
	if r.billed.wouldExceed(pkesk.EphemeralPoint) {
		r.skipped++

		return
	}

	r.tried++

	cipher, key, err := unwrap(r.ctx, r.billed, r.recipient, pkesk)
	if err == nil {
		r.cipherID, r.sessionKey = cipher, key

		return
	}

	r.namedFailure, r.otherFailure = recordFailure(named, err, r.namedFailure, r.otherFailure)
}

// named tries every packet addressing this certificate, and records what the
// rest of the message was addressed to.
func (r *attemptRun) named(raw []byte) []byte {
	body, stopped := eachSessionKey(raw, func(pkesk encryption.PKESK, pktBody []byte, parseErr error) {
		switch {
		case parseErr != nil:
			r.found.fileUnreadable(pktBody, parseErr)

		case r.sessionKey != nil:
			return

		case pkesk.KeyID == r.recipient.KeyID:
			r.attempt(pkesk, true)

		case pkesk.KeyID == wildcardKeyID:
			r.found.hidden++

		default:
			r.found.recordOther(pkesk.KeyID)
		}
	})

	r.scanStopped = stopped

	return body
}

// wildcards tries the packets naming nobody, held back until every named packet
// has been read since one of those may match and cost nothing.
func (r *attemptRun) wildcards(raw []byte) {
	_, _ = eachSessionKey(raw, func(pkesk encryption.PKESK, _ []byte, parseErr error) {
		if parseErr != nil || pkesk.KeyID != wildcardKeyID || r.sessionKey != nil {
			return
		}

		r.attempt(pkesk, false)
	})
}

// outcome turns what the run learned into the error it should report.
func (r *attemptRun) outcome() error {
	// First, because everything below it is a verdict about WHO the message is
	// for, and a walk cut short by damage never got far enough to have one — the
	// packets that would say may be sitting behind the damage. Reporting
	// "addressed to somebody else" here named a recipient read from the packets
	// before the break and sent the operator looking for a certificate, when
	// what they had was a message somebody had edited.
	if r.scanStopped != nil {
		return fmt.Errorf("%w: the packet stream is damaged after %d readable session-key packets, "+
			"so who this message is addressed to cannot be established: %w",
			ErrMalformedMessage, r.tried, r.scanStopped)
	}

	if err := r.found.refuse(r.tried, r.recipient); err != nil {
		return err
	}

	// Anything skipped means the run was cut short by cost, so it cannot be
	// reported as a settled verdict about who the message is for.
	if r.skipped > 0 {
		return exhausted(r.namedFailure, r.otherFailure, r.tried, r.skipped)
	}

	switch {
	case r.namedFailure != nil:
		return r.namedFailure
	case r.otherFailure != nil:
		return r.otherFailure
	}

	// Every candidate was a wildcard and every unwrap said no, which is exactly
	// what a message for somebody else looks like.
	return fmt.Errorf("%w: none of the %d candidate session-key packets unwrapped",
		ErrNotAddressed, r.tried)
}

func recoverSessionKey(
	ctx context.Context,
	deriver SecretDeriver,
	recipient Recipient,
	raw []byte,
) (cipherID byte, sessionKey []byte, body []byte, err error) {
	// The memo is scoped to this message, so nothing is remembered between
	// calls and a key rotation between two messages is never served from cache.
	run := &attemptRun{ctx: ctx, recipient: recipient, billed: newBilledOnce(deriver)}

	// Two passes over the message rather than one pass into a slice, and that
	// is the whole of the memory story.
	//
	// Collecting candidates meant the message chose how much memory the walk
	// held live, so a bound was put on the collection — and that bound then
	// dropped genuine packets that cost nothing to try, which is the crowding
	// defect this package has now produced at three separate bounds. Nothing is
	// retained here, so there is nothing to bound and nothing to crowd out.
	//
	// The message is already in memory: readMessage read it whole, under its
	// own bound. A second walk over bytes already held is cheap, and it is what
	// preserves the ordering that keeps a message naming only other keys free.
	body = run.named(raw)

	if run.sessionKey == nil && run.found.hidden > 0 {
		run.wildcards(raw)
	}

	if run.sessionKey != nil {
		return run.cipherID, run.sessionKey, body, nil
	}

	return 0, nil, nil, run.outcome()
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
func recordFailure(wasNamed bool, err, namedFailure, otherFailure error) (named, other error) {
	switch {
	// The message named this certificate and the unwrap still failed. That is a
	// corrupt message or the wrong --key, not a message for somebody else, and
	// reporting it as the latter sends the operator to find a different
	// certificate when theirs is right.
	case wasNamed && namedFailure == nil:
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

// fileUnreadable files a session-key packet this cannot read under whichever of
// the two counts it belongs to.
//
// A method for the same reason file() is one, and it was a free function taking
// and returning both counters positionally — four untyped ints of the same type
// across a call, where transposing a pair would compile, pass every test, and
// change only which error an operator is shown.
func (c *candidateSet) fileUnreadable(body []byte, err error) {
	if isRealRecipientPacket(body, err) {
		c.unreadable++

		return
	}

	c.malformed++
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
func eachSessionKey(
	raw []byte,
	visit func(pkesk encryption.PKESK, body []byte, err error),
) (body []byte, stopped error) {
	body = raw

	for len(body) > 0 {
		pkt, err := encryption.ParsePacket(body)

		// The session-key packets come first and always carry a definite
		// length; the encrypted data that follows may use a partial length,
		// which this package deliberately does not parse and go-crypto
		// handles. So anything that is not a readable PKESK ends the scan and
		// becomes the body, rather than being an error here.
		//
		// The REASON is carried out, though, and that is the whole change. The
		// scan ending here is ordinary when it is the encrypted data; it is
		// damage when the framing is broken. Ending both ways silently meant one
		// malformed packet planted ahead of the genuine session-key packets got
		// reported as "not addressed to this certificate" — a verdict about who
		// the message is for, from code that never reached the packets that
		// would say. The operator went looking for a certificate instead of at
		// a message somebody had edited.
		if err != nil {
			stopped = err

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

		// A co-recipient's packet we cannot read is not a reason to refuse the
		// message. RSA is still the most common key type and parses as
		// unsupported here, as does a version 6 packet from a modern sender —
		// so propagating this would fail a report over somebody else's key
		// while ours sat in the very next packet. The caller decides what the
		// failure means.
		visit(pkesk, pkt.Body, err)

		body = pkt.Rest
	}

	return body, stopped
}

// candidateSet is what one pass over the session-key packets found.
type candidateSet struct {
	// hidden counts wildcard packets seen, so the second pass is skipped
	// entirely when there are none.
	hidden int

	// others holds at most [maxRenderedKeyIDs] DISTINCT key ids the message
	// names, and otherCount how many named packets there were altogether.
	others     [][8]byte
	otherCount int

	// unreadable counts packets that are session-key packets but not ones this
	// package can parse — a co-recipient on RSA, or a v6 sender. They cannot
	// be ours, but they say the message was addressed to somebody.
	unreadable int

	// malformed counts packets in the session-key position that are not
	// session-key packets at all. They say nothing about who the message is
	// for, only that it is damaged.
	malformed int
}

// recordOther notes a packet addressed to somebody else, for the error that
// tells an operator which certificate they should have used.
func (c *candidateSet) recordOther(id [8]byte) {
	c.otherCount++

	if len(c.others) < maxRenderedKeyIDs && !slices.Contains(c.others, id) {
		c.others = append(c.others, id)
	}
}

// refuse reports why nothing could be tried, or nil when something was.
//
// Separated from the walk because it is a different question: the walk finds
// what is there, this decides what the absence of a usable candidate means. The
// order matters and is the reverse of how the cases were first written — a
// malformed message is a fact about the bytes, while "addressed elsewhere" is a
// claim about who the sender chose, and claiming the second when the first is
// true sends an operator to find a certificate that was never involved.
func (c *candidateSet) refuse(tried int, recipient Recipient) error {
	switch {
	case tried > 0:
		return nil

	case c.malformed > 0:
		return fmt.Errorf("%w: %d packets before the encrypted data are not session-key packets",
			ErrMalformedMessage, c.malformed)

	case c.otherCount == 0 && c.unreadable == 0:
		return fmt.Errorf("%w: no session-key packet at the start of the message", ErrMalformedMessage)

	case c.otherCount == 0:
		return fmt.Errorf(
			"%w: its %d session-key packets are all of a kind this cannot read, so none names this certificate (%x)",
			ErrNotAddressed, c.unreadable, recipient.KeyID)

	default:
		return fmt.Errorf("%w: addressed to %s, this certificate is %x",
			ErrNotAddressed, keyIDs(c.others, c.otherCount), recipient.KeyID)
	}
}

// keyIDs renders the recipients a message names, so the error says which
// certificate should have been used rather than only that this one was wrong.
func keyIDs(ids [][8]byte, total int) string {
	// Deliberately NOT capped again here. candidateSet.file already refuses to
	// retain more than maxRenderedKeyIDs, so a second cap could never execute —
	// and worse, if that retention bound ever regressed this would silently
	// absorb the regression rather than let it show. A guard nothing can reach
	// is a guard nothing can test, and this estate has been bitten by those.
	//
	// TestDecryptDoesNotRetainEveryKeyIDItSaw holds the retention bound
	// instead. A failing test is louder than a reslice nobody sees.
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
