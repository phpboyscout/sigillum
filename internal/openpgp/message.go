package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"gitlab.com/phpboyscout/go/encryption"
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

// isPacketStream reports whether the input already begins an OpenPGP packet.
//
// A definite answer rather than a heuristic: the first octet of a packet header
// has its high bit set, and the tag must be one this exchange uses. Armour is
// printable text, so it cannot satisfy either.
func isPacketStream(raw []byte) bool {
	pkt, err := encryption.ParsePacket(raw)
	if err != nil {
		return false
	}

	switch pkt.Tag {
	case encryption.TagPKESK, encryption.TagPublicKey:
		return true
	default:
		return false
	}
}

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

	for {
		p, err := reader.Next()
		if err != nil {
			return fmt.Errorf("%w: no encrypted-data packet after the session key: %w",
				ErrMalformedMessage, err)
		}

		se, ok := p.(*packet.SymmetricallyEncrypted)
		if !ok {
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
		if !se.IntegrityProtected {
			return ErrUnprotected
		}

		body, err := se.Decrypt(cipher, sessionKey)
		if err != nil {
			return fmt.Errorf("decrypting the message body: %w", err)
		}

		return copyAuthenticated(body, out)
	}
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
func copyLiteral(body io.Reader, out io.Writer) error {
	reader := packet.NewReader(body)

	depth := 0

	for inspected := 0; ; inspected++ {
		if inspected >= maxPacketsInspected {
			return fmt.Errorf("%w: no literal data in the first %d packets inside the encrypted data",
				ErrMalformedMessage, maxPacketsInspected)
		}

		p, err := reader.Next()
		if err != nil {
			return fmt.Errorf("%w: no literal data inside the encrypted packet: %w",
				ErrMalformedMessage, err)
		}

		switch typed := p.(type) {
		case *packet.Compressed:
			depth++
			if depth > maxCompressionDepth {
				return fmt.Errorf("%w: message nests compressed packets more than %d deep",
					ErrMalformedMessage, maxCompressionDepth)
			}

			reader = packet.NewReader(typed.Body)
		case *packet.LiteralData:
			// One octet beyond the limit is read deliberately, so hitting it
			// exactly is distinguishable from exceeding it.
			written, err := io.Copy(out, io.LimitReader(typed.Body, maxPlaintext+1))
			if err != nil {
				return fmt.Errorf("writing plaintext: %w", err)
			}

			if written > maxPlaintext {
				return fmt.Errorf("%w: report expands beyond %d octets", ErrTooLarge, maxPlaintext)
			}

			return nil
		}
	}
}
