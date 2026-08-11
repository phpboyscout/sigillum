package openpgp_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"encoding/binary"

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
			out = append(out, framePacket(tagSED, pkt.Body[1:])...)
		} else {
			out = append(out, rest[:consumed]...)
		}

		rest = pkt.Rest
	}

	return out
}

// framePacket writes a new-format header for a body of any length.
func framePacket(tag byte, body []byte) []byte {
	const (
		newFormat   = 0xC0
		oneOctetMax = 192
		fiveOctet   = 0xFF
	)

	out := []byte{newFormat | tag}

	if len(body) < oneOctetMax {
		out = append(out, byte(len(body)))
	} else {
		out = append(out, fiveOctet)
		out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
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
