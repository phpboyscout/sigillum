package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"gitlab.com/phpboyscout/go/encryption"
	"gitlab.com/phpboyscout/go/encryption/packetwalk"
)

// Message framing lives here rather than in the core module.
//
// The core takes a PKESK body and gives back a session key; it deliberately
// does not own how a message is wrapped, because that varies with how the
// message arrived — armoured out of an email, binary out of a ticket
// attachment, old-format or new-format headers depending on the sender.

// readMessage returns the message's packet bytes, dearmoured if it was
// armoured.
//
// Dearmours transparently: a report pasted into a ticket is armoured, one
// fetched from an API usually is not, and a caller should not have to know
// which they have.
//
// The caller walks the packets itself, because a message carries one
// session-key packet per recipient and ours is not necessarily the first.
func readMessage(message io.Reader) ([]byte, error) {
	raw, err := readBounded(message, "message")
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: message is empty", ErrMalformedMessage)
	}

	return packetsOrArmour(raw, "message")
}

// packetsOrArmour returns the packet bytes of a message that may be armoured.
//
// Binary is tried first, and that ordering is the whole design.
//
// go-crypto's armor.Decode skips leading garbage: it reads line by line through
// the entire input hunting for a header, and will find one anywhere. An
// attacker composing a binary message chooses where to put one, so decoding
// before checking made their marker decide where the message began — the real
// packets were discarded and the operator got a base64 error instead of a
// report.
//
// Anchoring the search at byte zero closed that and broke something ordinary: a
// report pasted into a ticket under a covering line, a quoted mail header, or a
// From: block from a saved .eml. Those are the arrival shapes the how-to
// describes.
//
// Asking "is this already a message?" first settles both without a bound to
// choose. A valid binary message is consumed as binary, so an embedded header
// inside its ciphertext is never reached; anything that is not one can be
// searched for armour as freely as go-crypto likes, because there are no real
// packets left to discard. No arbitrary preamble limit, which a long forwarded
// header block would eventually have exceeded.
func packetsOrArmour(raw []byte, what string) ([]byte, error) {
	if isPacketStream(raw) {
		return raw, nil
	}

	block, decodeErr := armor.Decode(bytes.NewReader(raw))
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: %s is neither OpenPGP packets nor an armoured block: %w",
			ErrMalformedMessage, what, decodeErr)
	}

	return dearmoured(block.Body, what)
}

// isPacketStream reports whether the input is OpenPGP packets rather than
// armoured text.
//
// Every packet header has its high bit set (RFC 9580 4.2), and armour is
// printable text beginning with a hyphen — 0x2D, high bit clear — so armour can
// never parse as a packet. That asymmetry is what makes the question answerable
// at all, but it is not sufficient on its own, and both ways of getting this
// wrong have been live defects.
//
// An allowlist of opening tags was the first. Restricting the first packet to a
// session-key or public-key packet contradicted the walk that follows, which
// deliberately steps over a marker or padding packet before the session keys —
// so a message legitimately opening with a marker was refused as "neither
// packets nor armour", losing a report addressed to this certificate.
//
// Reading only the first header was the second, and is why this walks. Two
// octets — 0xC1 0x00, a new-format session-key tag with an empty body — parse
// as a packet, so an armoured report with those bytes in front of it was
// declared binary, the armour path was never reached, and the operator was told
// their report was malformed rather than that two bytes had been injected. The
// same holds for 0xC6 0x00, which matters beyond tampering: 0xC6 is a valid
// UTF-8 lead octet, so an armoured report pasted under a covering line starting
// with one of those characters took the binary path by accident. That paste is
// the ordinary arrival shape this ordering exists to keep working.
//
// So: walk, stepping over exactly what the candidate walk steps over, and
// answer yes only on reaching a packet that carries something.
//
// That "exactly" is an invariant between two functions, and it is held by a
// test rather than by care: TestDecryptStepsOverInertPackets runs markers,
// trust, padding and unknown packets through the whole path at every position
// they can occupy, so the two walks drifting apart fails there.
//
// Keeping them as two walks is deliberate. They answer different questions —
// "is this binary at all?" and "which packets are candidates?" — and fusing
// them to save a parse would recouple decisions that were separated because
// holding both in one place is what produced three rounds of findings. The
// duplicate is one ParsePacket over one header on the ordinary path. A header with
// nothing behind it establishes nothing, which is the property the comment
// above claims and this is what makes it true.
func isPacketStream(raw []byte) bool {
	return packetwalk.Walk(parsePackets(raw), packetwalk.Limits{},
		func(pkt encryption.Packet, at packetwalk.Tally) packetwalk.Step[encryption.Packet] {
			// at.Steps == 1 is the first packet, which is where the encrypted-data
			// tag is not yet allowed to settle the question — carriesContent's own
			// distinction.
			if carriesContent(pkt, at.Steps == 1) {
				return packetwalk.Settle[encryption.Packet]()
			}

			return packetwalk.Skip[encryption.Packet]()
		},
		packetwalk.Outcomes[bool]{
			// A packet that carries content: this is a binary stream.
			Settled: func() bool { return true },

			// Walked to the end without one: not a stream this recognises — a
			// header with nothing behind it establishes nothing.
			Exhausted: func() bool { return false },

			// A parse error: armour never parses as a packet, so anything that
			// fails to parse is not a binary stream. The old bare `return false`
			// on the parse error, now the framework's Damaged arm.
			Damaged: func(error) bool { return false },

			// Unbounded on purpose: this asks only "is this binary at all?", and
			// a bound would make a long armour preamble it should reject look like
			// something it could not judge.
			Bounded: packetwalk.Unreachable[bool](),
		})
}

// parsePackets is a [packetwalk.Source] over raw bytes using this module's
// packet parser, shared by the walks in this file.
func parsePackets(raw []byte) *packetwalk.ByteSource[encryption.Packet] {
	return packetwalk.NewByteSource(raw, func(b []byte) (encryption.Packet, []byte, error) {
		pkt, err := encryption.ParsePacket(b)
		if err != nil {
			return encryption.Packet{}, nil, err
		}

		return pkt, pkt.Rest, nil
	})
}

// carriesContent reports whether a packet is one that settles the question,
// rather than one the walk would step over.
//
// The structural checks matter as much as the tags, and a length floor alone is
// not enough. A covering line beginning "Ƈopy of the report below" starts with
// U+0187, which is the two octets 0xC6 0x87 — a public-key tag declaring a
// 135-octet body, and any armour longer than that satisfies a length test. So
// the version octet is checked too: real packets carry a version this format
// defines, and the first character of a word does not.
//
// That covering-line paste is the ordinary arrival shape the binary-first
// ordering exists to protect, not an attack, which is why the check has to be
// strong enough to see the difference.
func carriesContent(pkt encryption.Packet, first bool) bool {
	if len(pkt.Body) == 0 {
		return false
	}

	// The legacy encrypted-data packet has no version octet — its body is raw
	// ciphertext, so there is nothing structural to check and any non-empty
	// body is as plausible as another. It settles the question anyway, because
	// such a message really is binary and refusing it as unprotected is a far
	// better answer than "neither packets nor armour".
	//
	// But NOT in the first position, and that qualifier was missing. A
	// well-formed message never opens with its encrypted data — the session-key
	// packets come first — so nothing is lost by declining to recognise it
	// there, and something real is gained: 0xC9 is both this tag and the UTF-8
	// lead for U+0240-U+027F, so a report pasted under a covering line
	// beginning with one of those characters took the binary path and was
	// refused. That was recorded as an accepted residual until a property that
	// enumerates every two-octet lead showed it is simply avoidable.
	if pkt.Tag == tagSED && !first {
		return true
	}

	want, known := contentShape(pkt.Tag)
	if !known {
		return false
	}

	version := pkt.Body[0]

	return len(pkt.Body) >= want.minBody && version >= want.minVersion && version <= want.maxVersion
}

// shape is what a real packet of a given tag must at least look like.
type shape struct {
	minBody                int
	minVersion, maxVersion byte
}

// contentShape describes the packets that settle the question, and reports
// false for the ones the walk steps over.
func contentShape(tag byte) (shape, bool) {
	const (
		// A public-key packet is at least a version octet, four of creation
		// time and an algorithm octet. RFC 9580 5.5.2.
		publicKeyFixedOctets = 6

		// An encrypted-data packet needs only its version octet to be judged.
		seipdFixedOctets = 1

		// The version ranges each packet format defines. Named because the
		// point of checking them is that a real packet carries a version this
		// format knows and the first letter of a word does not.
		oldestPKESK     = 2
		newestPKESK     = 6
		oldestPublicKey = 3
		newestPublicKey = 6
		oldestSEIPD     = 1
		newestSEIPD     = 2
	)

	switch tag {
	case encryption.TagPKESK:
		// Versions 2 through 6. This package reads only 3, but a version 6
		// packet from a modern sender is still a binary message, and saying so
		// gets a better error than sending it to the armour decoder.
		return shape{minBody: pkeskFixedOctets, minVersion: oldestPKESK, maxVersion: newestPKESK}, true

	case encryption.TagPublicKey:
		return shape{minBody: publicKeyFixedOctets, minVersion: oldestPublicKey, maxVersion: newestPublicKey}, true

	case tagSEIPD:
		// A message whose session-key packets were all of a kind this cannot
		// read is still a binary message.
		return shape{minBody: seipdFixedOctets, minVersion: oldestSEIPD, maxVersion: newestSEIPD}, true

	default:
		return shape{}, false
	}
}

// pkeskFixedOctets is the shortest a version 3 session-key packet body can be:
// a version octet, eight of key id, an algorithm octet and the ephemeral
// point's two-octet MPI header. It mirrors the core's own constant, which is
// unexported there.
const pkeskFixedOctets = 12

// dearmoured reads the decoded body of an armoured block, classifying a failure
// as a malformed message.
//
// The classification is the point. A truncated or mangled armoured paste is the
// commonest real input problem, and the CLI reference documents it as
// "malformed message" — but the base64 error surfaces from reading the block,
// where nothing had attached the sentinel, so errors.Is said otherwise. A size
// failure keeps its own sentinel: too large is not malformed.
func dearmoured(body io.Reader, what string) ([]byte, error) {
	raw, err := readBounded(body, "dearmoured "+what)
	if err == nil {
		return raw, nil
	}

	if errors.Is(err, ErrTooLarge) {
		return nil, err
	}

	return nil, fmt.Errorf("%w: %w", ErrMalformedMessage, err)
}

// maxMessage bounds the ciphertext this will hold.
//
// The input comes from stdin or a path an operator names, and the certificate
// that invites it is published — so the size is chosen by whoever is writing to
// us. Reading it unbounded is an out-of-memory kill for the cost of one large
// paste, and armoured input costs it twice: once for the armour and again for
// what it decodes to.
//
// Generous relative to maxPlaintext, because ciphertext carries armour
// expansion and packet overhead on top of the report itself.
const maxMessage = 128 << 20

// readBounded reads at most maxMessage octets, naming what it was reading so
// the error says which limit was hit.
func readBounded(r io.Reader, what string) ([]byte, error) {
	// One octet beyond the limit, so reaching it exactly is distinguishable
	// from exceeding it.
	raw, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", what, err)
	}

	if len(raw) > maxMessage {
		return nil, fmt.Errorf("%w: %s exceeds %d octets", ErrTooLarge, what, maxMessage)
	}

	return raw, nil
}

// decryptBody opens the encrypted-data packet with the recovered session key
// and writes the literal data out.
//
// This is the part the core module deliberately does not do: it is a full
// OpenPGP concern — symmetric modes, integrity protection, compression — and a
// mature implementation already handles it. The core's job ends at the key.
func decryptBody(rest []byte, cipher packet.CipherFunction, sessionKey []byte, out io.Writer) error {
	reader := packet.NewReader(bytes.NewReader(rest))

	// Bounded like the structurally identical walk in copyLiteral, and for the
	// same reason: the message chooses how many packets sit between the session
	// keys and the encrypted data, and this one had no bound at all while its
	// twin did. Reaching the limit is not a verdict about the message's
	// contents, only about how far this will look.
	// Set when an unprotected packet was seen and stepped over, so that a
	// message carrying ONLY unprotected packets still reports the specific
	// refusal rather than the generic "no encrypted-data packet".
	var unprotected bool

	for range maxPacketsInspected {
		p, err := reader.Next()
		if err != nil {
			if unprotected {
				return ErrUnprotected
			}

			return fmt.Errorf("%w: no encrypted-data packet after the session key: %w",
				ErrMalformedMessage, err)
		}

		se, ok := p.(*packet.SymmetricallyEncrypted)
		if !ok {
			// Drained before moving on, for the same reason the unprotected arm
			// below drains: go-crypto leaves a streaming packet's body on the
			// reader, and skipping one undrained leaves the reader mid-body so
			// the next read desyncs. The SED fix that added draining below fixed
			// one arm and left this one (design-review N3). Reachable only after
			// a drained unprotected packet — the first packet here is always the
			// encrypted data — but there the desync reported ErrUnprotected for
			// a message that did carry a protected packet, one step further on.
			//
			// drainPacket handles the non-streaming case as a no-op, so this is
			// unconditional rather than type-switched.
			if err := drainPacket(p); err != nil {
				return fmt.Errorf("%w: unreadable packet before the encrypted data: %w",
					ErrMalformedMessage, err)
			}

			continue
		}

		// Refuse the legacy Symmetrically Encrypted Data packet outright.
		//
		// It carries no modification detection at all, so an attacker who can
		// touch the ciphertext can flip plaintext bits at will — the EFAIL
		// shape. go-crypto's high-level reader refuses it for the same reason;
		// reading packets directly means re-establishing that guard here.
		// The certificate this package publishes advertises SEIPD support, so
		// a well-behaved sender never produces the unprotected form.
		//
		// Noted and stepped over rather than returned on. The guard governs
		// THIS packet — which is never decrypted, then or now — and says
		// nothing about the packets after it. Returning here meant anyone who
		// could prepend one junk SED packet made a genuine protected report
		// undecryptable, and the operator was told the message had no integrity
		// protection, which was false of the message they were sent.
		//
		// If the walk ends having seen nothing else, the refusal is still the
		// answer and still absolute: see the return below.
		if !se.IntegrityProtected {
			unprotected = true

			// Drained through the same helper as the skip arm above, so the two
			// cannot drift: both step over a streaming packet, and both must
			// consume its body or the reader desyncs.
			if err := drainPacket(p); err != nil {
				return fmt.Errorf("%w: unreadable unprotected packet: %w", ErrMalformedMessage, err)
			}

			continue
		}

		body, err := se.Decrypt(cipher, sessionKey)
		if err != nil {
			return fmt.Errorf("decrypting the message body: %w", err)
		}

		return copyAuthenticated(body, out)
	}

	if unprotected {
		return ErrUnprotected
	}

	return fmt.Errorf("%w: no encrypted-data packet in the first %d packets after the session key",
		ErrMalformedMessage, maxPacketsInspected)
}

// drainPacket consumes a packet's body so the reader can advance past it.
//
// go-crypto leaves the bodies of streaming packets — Compressed, LiteralData,
// SymmetricallyEncrypted — as readers over the underlying stream, and its
// Reader.Next cannot move past one whose body was never read. A non-streaming
// packet has already been consumed by parsing, so its typed value carries no
// reader and this is a no-op. Every skip in decryptBody routes through here so
// the drain rule is stated once rather than per arm.
func drainPacket(p packet.Packet) error {
	var body io.Reader

	switch typed := p.(type) {
	case *packet.Compressed:
		body = typed.Body
	case *packet.LiteralData:
		body = typed.Body
	case *packet.SymmetricallyEncrypted:
		body = typed.Contents
	default:
		return nil
	}

	_, err := io.Copy(io.Discard, body)

	return err
}

// copyAuthenticated writes the plaintext out only once its integrity is proven.
//
// The modification detection code is verified by Close, not by Read — so the
// error it returns arrives *after* every byte has been read. Streaming
// straight to the caller would therefore hand a security contact
// attacker-modified text and only then report a failure they have already
// acted on.
//
// So the plaintext is buffered until Close succeeds, up to maxPlaintext.
func copyAuthenticated(body io.ReadCloser, out io.Writer) error {
	var buf bytes.Buffer

	if copyErr := copyLiteral(body, &buf); copyErr != nil {
		// Deliberately not closed. go-crypto's Close verifies the modification
		// detection code by draining to EOF (seMDCReader.Close, "we need to
		// read to the end"), so on a message already refused it decrypts and
		// decompresses everything we declined to hold — for an oversized one,
		// precisely the work maxPlaintext exists to avoid. The command appears
		// to hang for minutes on input it rejected immediately.
		//
		// Skipping it also keeps the refusal honest. A drain that meets a
		// truncated stream returns ErrMDCHashMismatch, and Close's error took
		// precedence here — so an oversized message was reported as one that
		// may have been altered.
		//
		// No integrity guarantee is lost, because nothing is handed over on
		// this path: the check exists to gate output, and there is none. And
		// nothing here holds an operating-system resource — the readers are
		// over a byte slice — so there is nothing to release.
		return copyErr
	}

	// Close is what makes the plaintext safe to hand over: the modification
	// detection code is verified here, not during Read, so its error arrives
	// only after every byte has been buffered.
	if err := body.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrity, err)
	}

	if _, err := io.Copy(out, &buf); err != nil {
		return fmt.Errorf("writing plaintext: %w", err)
	}

	return nil
}

// maxPlaintext bounds the decompressed report this will accept.
//
// The certificate is published, so anyone may compose a message to it — and a
// compressed packet expands without limit. A megabyte of zeros inflates to
// gigabytes, which with the buffering above is an out-of-memory kill rather
// than a full disk.
//
// 64 MiB is far larger than any vulnerability report and far smaller than a
// denial of service. A reporter with genuinely more than that to send should
// be sending a link, not an attachment.
const maxPlaintext = 64 << 20

// maxCompressionDepth bounds how many nested compressed packets are followed.
//
// maxPlaintext bounds the literal data, but nothing bounded the descent to
// reach it. Each level holds a live flate or zlib reader with its own 32 KiB
// window, and every one of them stays alive because the next is read through
// it — so a few megabytes of ciphertext, well inside maxMessage, nests to
// hundreds of thousands of levels and exhausts memory before a single literal
// octet is read. That is precisely the out-of-memory kill the plaintext bound
// claims to prevent, reached without ever producing plaintext.
//
// Two is past generous: one level is what a sender produces, and go-crypto's
// own high-level reader refuses beyond one or two.
const maxCompressionDepth = 2

// maxPacketsInspected bounds how many packets are walked looking for literal
// data.
//
// maxPlaintext bounds the literal data and maxCompressionDepth bounds the
// descent, so neither covers breadth. copyLiteral skips anything that is
// neither compressed nor literal, and a single compressed packet expanding to
// millions of marker or padding packets is walked one at a time — the same
// denial of service as the nesting bound, reached sideways rather than
// downwards, and just as asymmetric: under 1.5 KiB of ciphertext expands to a
// megabyte of walk.
//
// A real message carries a literal packet, possibly behind one compressed
// packet, possibly after a marker. Sixty-four is far past anything a sender
// produces and far below anything that costs noticeable work.
const maxPacketsInspected = 64

// copyLiteral walks the packets inside the encrypted data — compressed or not —
// and writes the literal contents to out, refusing anything over maxPlaintext.
//
// Descent through packetwalk maintains the source stack that a hand-rolled loop
// once got wrong: descending into a compressed packet used to overwrite the
// reader and never return, abandoning everything after it, so an empty
// compressed packet in front of the real literal data made the report
// unreadable. Exhausting a nested source now pops to its parent by construction.
func copyLiteral(body io.Reader, out io.Writer) error {
	// Total descents, not the live stack depth: a message with several sibling
	// compressed packets is as expensive to walk as one nested that deep, so the
	// bound counts every descent. Held here rather than taken from the walk's
	// Tally.Depth, which is the live depth, so the semantics the test pins are
	// preserved.
	descents := 0

	return packetwalk.Walk(newGCSource(body), packetwalk.Limits{Steps: maxPacketsInspected},
		func(pkt packet.Packet, _ packetwalk.Tally) packetwalk.Step[packet.Packet] {
			switch typed := pkt.(type) {
			case *packet.Compressed:
				descents++
				if descents > maxCompressionDepth {
					return packetwalk.Stop[packet.Packet](fmt.Errorf(
						"%w: message nests compressed packets more than %d deep",
						ErrMalformedMessage, maxCompressionDepth))
				}

				return packetwalk.Descend[packet.Packet](newGCSource(typed.Body))
			case *packet.LiteralData:
				if err := copyBounded(out, typed.Body); err != nil {
					return packetwalk.Stop[packet.Packet](err)
				}

				return packetwalk.Settle[packet.Packet]()
			default:
				// A marker, or anything else that is neither: stepped over. The
				// gcSource drains its body before the next read, so a streaming
				// packet skipped here does not desync the reader.
				return packetwalk.Skip[packet.Packet]()
			}
		},
		packetwalk.Outcomes[error]{
			// The literal was found and written.
			Settled: func() error { return nil },

			// The stream ended with no literal in it.
			Exhausted: func() error {
				return fmt.Errorf("%w: no literal data inside the encrypted packet", ErrMalformedMessage)
			},

			// A source error, a too-deep nesting, or a write/size failure — each
			// carries its own reason from the Stop or the source.
			Damaged: func(err error) error { return err },

			// More packets than the breadth bound allows without a literal: a
			// compressed packet expanding to millions of markers, walked sideways.
			Bounded: func() error {
				return fmt.Errorf("%w: no literal data in the first %d packets inside the encrypted data",
					ErrMalformedMessage, maxPacketsInspected)
			},
		})
}

// copyBounded writes a literal packet's body to out, refusing more than
// maxPlaintext.
func copyBounded(out io.Writer, body io.Reader) error {
	// One octet beyond the limit is read deliberately, so hitting it exactly is
	// distinguishable from exceeding it.
	written, err := io.Copy(out, io.LimitReader(body, maxPlaintext+1))
	if err != nil {
		return fmt.Errorf("writing plaintext: %w", err)
	}

	if written > maxPlaintext {
		return fmt.Errorf("%w: report expands beyond %d octets", ErrTooLarge, maxPlaintext)
	}

	return nil
}

// gcSource is a [packetwalk.Source] over a go-crypto packet reader.
//
// It drains the previous packet's body before reading the next, because
// go-crypto leaves a streaming packet's body on the underlying reader and its
// Reader.Next cannot advance past one left unread. Draining on the NEXT read is
// exactly right: a packet the walk settled on is never followed by another read,
// so its body is left for the caller; a packet the walk skipped is drained when
// the walk reads on; and a packet the walk descended into is consumed by the
// child source, so draining it here afterwards is a harmless no-op.
type gcSource struct {
	reader *packet.Reader
	prev   packet.Packet
}

func newGCSource(r io.Reader) *gcSource {
	return &gcSource{reader: packet.NewReader(r)}
}

// Next drains the previous packet, then returns the next — io.EOF at a clean end,
// any other error as damage.
func (s *gcSource) Next() (packet.Packet, error) {
	if s.prev != nil {
		// Errors draining a packet the walk already stepped past are not the
		// walk's concern: it decided that packet was not the answer.
		_ = drainPacket(s.prev)
		s.prev = nil
	}

	p, err := s.reader.Next()
	if err != nil {
		return nil, err
	}

	s.prev = p

	return p, nil
}
