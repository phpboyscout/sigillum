package openpgp

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

	if block, decodeErr := armor.Decode(bytes.NewReader(raw)); decodeErr == nil {
		if raw, err = readBounded(block.Body, "dearmoured message"); err != nil {
			return nil, err
		}
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: message is empty", ErrMalformedMessage)
	}

	return raw, nil
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

	copyErr := copyLiteral(body, &buf)

	// Close first, and always: it reports the integrity failure, and it must
	// be consulted even when the read failed, because a truncated read is one
	// of the things tampering looks like.
	if err := body.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrity, err)
	}

	if copyErr != nil {
		return copyErr
	}

	_, err := io.Copy(out, &buf)
	if err != nil {
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

// copyLiteral walks the packets inside the encrypted data — compressed or not —
// and writes the literal contents to out, refusing anything over maxPlaintext.
func copyLiteral(body io.Reader, out io.Writer) error {
	reader := packet.NewReader(body)

	for {
		p, err := reader.Next()
		if err != nil {
			return fmt.Errorf("%w: no literal data inside the encrypted packet: %w",
				ErrMalformedMessage, err)
		}

		switch typed := p.(type) {
		case *packet.Compressed:
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
