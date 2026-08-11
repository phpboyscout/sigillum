package openpgp

import (
	"bytes"
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

// firstPacket returns the first packet's body and everything after it.
//
// Dearmours transparently: a report pasted into a ticket is armoured, one
// fetched from an API usually is not, and a caller should not have to know
// which they have.
//
// The header parsing itself is the core's — this package used to carry its own
// copy, as did two other places, which is three chances to misread a length in
// a way that surfaces as an unrelated error much later.
func firstPacket(message io.Reader) (body, rest []byte, err error) {
	raw, err := io.ReadAll(message)
	if err != nil {
		return nil, nil, fmt.Errorf("reading message: %w", err)
	}

	if block, decodeErr := armor.Decode(bytes.NewReader(raw)); decodeErr == nil {
		if raw, err = io.ReadAll(block.Body); err != nil {
			return nil, nil, fmt.Errorf("%w: dearmouring: %w", ErrMalformedMessage, err)
		}
	}

	pkt, err := encryption.ParsePacket(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformedMessage, err)
	}

	return pkt.Body, pkt.Rest, nil
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

		body, err := se.Decrypt(cipher, sessionKey)
		if err != nil {
			return fmt.Errorf("decrypting the message body: %w", err)
		}

		defer body.Close() //nolint:errcheck // the read below is what matters.

		return copyLiteral(body, out)
	}
}

// copyLiteral walks the packets inside the encrypted data — compressed or not —
// and writes the literal contents to out.
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
			if _, err := io.Copy(out, typed.Body); err != nil {
				return fmt.Errorf("writing plaintext: %w", err)
			}

			return nil
		}
	}
}
