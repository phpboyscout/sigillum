package openpgp_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"gitlab.com/phpboyscout/go/encryption"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// Integrity, which is the property a vulnerability report most needs and the
// one easiest to lose by accident.
//
// A message that decrypts is not the same as a message that arrived intact.
// OpenPGP's modification detection lives in the *close* of the encrypted-data
// packet, long after the plaintext has been read — so a reader that streams
// output and ignores the close reports success on ciphertext an attacker has
// altered.

// TestTamperedCiphertextIsRefused is the regression test for exactly that.
//
// Flipping a bit in the encrypted body changes the plaintext an attacker
// cannot predict but can influence, and the MDC is what catches it. If this
// test fails, `sigillum decrypt` is writing attacker-modified reports to the
// security rota and exiting zero.
func TestTamperedCiphertextIsRefused(t *testing.T) {
	t.Parallel()

	const plaintext = "a vulnerability report nobody else should read"

	der, deriver := testCertificate(t)
	message := encryptTo(t, der, plaintext, false)

	// Flip one bit inside the encrypted-data packet, well past its header.
	tampered := append([]byte(nil), message...)
	tampered[len(tampered)-30] ^= 0x01

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var out bytes.Buffer

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(tampered), &out)
	if err == nil {
		t.Fatalf("tampered ciphertext decrypted without error, yielding %q", out.String())
	}

	if !errors.Is(err, openpgp.ErrIntegrity) {
		t.Errorf("error = %v, want ErrIntegrity", err)
	}
}

// TestUnauthenticatedPacketIsRefused covers the other half: a message that
// carries no integrity protection at all.
//
// The legacy Symmetrically Encrypted Data packet (tag 9) has no MDC. An
// attacker who intercepts a report can re-frame a protected packet as this one
// and then flip ciphertext bits freely — the EFAIL shape. go-crypto's
// high-level reader refuses it; this package reads packets directly and must
// re-establish that guard itself.
func TestUnauthenticatedPacketIsRefused(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)
	message := encryptTo(t, der, "unprotected", false)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	downgraded := downgradeToSED(t, message)

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(downgraded), io.Discard)
	if err == nil {
		t.Fatal("a message with no integrity protection was accepted")
	}

	if !errors.Is(err, openpgp.ErrUnprotected) {
		t.Errorf("error = %v, want ErrUnprotected", err)
	}
}

// downgradeToSED rewrites the encrypted-data packet as a legacy SED packet.
//
// Done on the wire bytes rather than through a library, because no maintained
// implementation will write the unprotected form any more — which is the point:
// an attacker is not constrained to use one. A SEIPD body is a version octet
// followed by the ciphertext; a SED body is the ciphertext alone.
func downgradeToSED(t *testing.T, message []byte) []byte {
	t.Helper()

	const (
		tagSEIPD = 18
		tagSED   = 9
	)

	var out []byte

	for rest := message; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}

		consumed := len(rest) - len(pkt.Rest)

		if pkt.Tag == tagSEIPD {
			out = append(out, framePacket(t, tagSED, pkt.Body[1:])...)
		} else {
			out = append(out, rest[:consumed]...)
		}

		rest = pkt.Rest
	}

	return out
}

// framePacket wraps a body in a new-format packet header, RFC 9580 4.2.1.
//
// Takes t and fails rather than returning an error, because there is one
// encoder here for the whole test package and every caller is building a
// fixture.
//
// It was two encoders until this round, and both were wrong in the same way:
// each implemented only the two length forms its own caller happened to need,
// and each silently truncated a body that did not fit the form it chose. A
// fixture that quietly frames a packet other than the one the test names is
// exactly the class of defect this round keeps finding, so the boundaries are
// checked here and the failure is loud.
func framePacket(t *testing.T, tag byte, body []byte) []byte {
	t.Helper()

	const (
		newFormat   = 0xC0
		maxTag      = 63
		oneOctetMax = 192     // the one-octet form covers 0..191
		twoOctetMax = 8384    // the two-octet form covers 192..8383
		fiveOctet   = 0xFF    // the marker introducing a four-octet length
		maxLength   = 1 << 32 // the five-octet form's ceiling, exclusive
	)

	if tag > maxTag {
		t.Fatalf("packet tag %d does not fit a new-format header", tag)
	}

	out := []byte{newFormat | tag}

	switch n := len(body); {
	case n < oneOctetMax:
		out = append(out, byte(n))

	case n < twoOctetMax:
		// Encoded as an offset from 192 split across two octets, so the first
		// octet lands in 192..223 and marks the form.
		offset := n - oneOctetMax
		out = append(out, byte(offset>>8)+oneOctetMax, byte(offset&0xFF))

	case n < maxLength:
		out = append(out, fiveOctet)
		out = binary.BigEndian.AppendUint32(out, uint32(n))

	default:
		t.Fatalf("a %d-octet body exceeds every packet length form", n)
	}

	return append(out, body...)
}

// TestCompressionBombIsRefused covers the resource side of accepting messages
// from strangers.
//
// The certificate is published, so anyone can compose one. A compressed packet
// expands without limit, and the plaintext is held in memory until its
// integrity is proven — so an unbounded inflate is an out-of-memory kill, not
// merely a large file.
func TestCompressionBombIsRefused(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)

	entities, err := pgp.ReadKeyRing(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("read key ring: %v", err)
	}

	var buf bytes.Buffer

	w, err := pgp.Encrypt(&buf, entities, nil, nil, &packet.Config{
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{Level: 9},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Highly compressible, and comfortably over the limit once inflated.
	chunk := make([]byte, 1<<20)
	for range 80 {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	err = openpgp.Decrypt(t.Context(), deriver, recipient, &buf, io.Discard)
	if !errors.Is(err, openpgp.ErrTooLarge) {
		t.Errorf("error = %v, want ErrTooLarge", err)
	}
}

// TestAnOversizedMessageIsRefused covers the input side of the same concern as
// the compression bomb.
//
// The certificate is published, so the size of what arrives is chosen by
// whoever writes to us — and the CLI reads from stdin or a path an operator
// names. Reading it unbounded is an out-of-memory kill for the cost of one
// large paste.
func TestAnOversizedMessageIsRefused(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// A reader that never ends, which is what a hostile pipe looks like.
	endless := endlessReader{}

	err = openpgp.Decrypt(t.Context(), deriver, recipient, endless, io.Discard)
	if !errors.Is(err, openpgp.ErrTooLarge) {
		t.Errorf("error = %v, want ErrTooLarge", err)
	}
}

// endlessReader yields OpenPGP-looking octets forever.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xC1
	}

	return len(p), nil
}
