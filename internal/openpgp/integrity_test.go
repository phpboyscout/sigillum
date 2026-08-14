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
		oneOctetMax = 192  // the one-octet form covers 0..191
		twoOctetMax = 8384 // the two-octet form covers 192..8383
		fiveOctet   = 0xFF // the marker introducing a four-octet length

		// The five-octet form's ceiling, exclusive, as an int64.
		//
		// Written for comparison against a WIDENED n rather than as an untyped
		// constant compared to an int. `1 << 32` is not representable as an int
		// on a 32-bit target, so the comparison below was a compile error for
		// GOARCH=386 and arm — which broke the cross-arch CI job this branch
		// itself added, in the one file that job existed to protect.
		//
		// go/encryption/internal/num documents this exact trap and exists to
		// stop it. The lesson did not travel because this is a test helper in
		// another module, which is precisely how a defect class comes back.
		maxLength int64 = 1 << 32
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

	case int64(n) < maxLength:
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

// TestDecryptReadsAMessageOpeningWithAMarker covers the shape that made two
// functions disagree about which packets may open the input.
//
// The candidate walk deliberately steps over a marker or padding packet before
// the session keys. The gate deciding "packets or armour?" once answered the
// same question with a two-tag allowlist, so a binary message opening with a
// marker never reached that walk: it was refused as "neither OpenPGP packets
// nor an armoured block", which points the operator at the wrong problem
// entirely and loses a report addressed to this certificate.
//
// Marker packets (tag 10) are what PGP 2.x-era senders and some mail gateways
// emit, so this is a sender-produced shape rather than a hostile one. A fuzz
// target found it in five octets once the property was strengthened to require
// the report be RECOVERED rather than merely not-misdiagnosed; this is the
// named regression test for it, because a seed corpus entry does not say what
// it is for.
func TestDecryptReadsAMessageOpeningWithAMarker(t *testing.T) {
	t.Parallel()

	const plaintext = "a report from a sender whose client still emits markers"

	der, deriver := testCertificate(t)

	// A marker packet carries the three octets "PGP" and nothing else.
	const tagMarker = 10

	message := framePacket(t, tagMarker, []byte("PGP"))
	message = append(message, encryptTo(t, der, plaintext, false)...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a binary message opening with a marker packet was refused: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestUnprotectedPacketDoesNotHideAProtectedOne covers round-8 finding 12.
//
// decryptBody returned ErrUnprotected on the FIRST SymmetricallyEncrypted packet
// it met that carried no integrity protection, abandoning the rest of the walk.
// The guard governs that packet — it must never be decrypted — and says nothing
// whatever about the packets after it.
//
// So a genuine, integrity-protected report became undecryptable to anyone who
// could prepend one junk SED packet to it, and the operator was told the message
// had no integrity protection, which was false of the message they were actually
// sent. That is the shape this codebase has now produced seven times: a guard
// fires and the code stops instead of continuing down the path the guard does
// not govern.
//
// The refusal itself is unchanged and still absolute — see the sibling test.
func TestUnprotectedPacketDoesNotHideAProtectedOne(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)
	message := encryptTo(t, der, "a genuine report behind a junk packet", false)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// A junk SED packet spliced in immediately before the real encrypted-data
	// packet, leaving the genuine one untouched behind it.
	const tagSED = 9

	junk := framePacket(t, tagSED, []byte{0x00, 0x01, 0x02, 0x03})

	spliced := spliceBeforeEncryptedData(t, message, junk)

	var out bytes.Buffer

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(spliced), &out)
	if err != nil {
		t.Fatalf("a genuine protected report behind one junk unprotected packet was refused: %v.\n"+
			"Prepending a packet must not be able to make a report undecryptable", err)
	}

	if got := out.String(); got != "a genuine report behind a junk packet" {
		t.Errorf("plaintext = %q, want the report", got)
	}
}

// spliceBeforeEncryptedData inserts body immediately before the message's
// encrypted-data packet.
func spliceBeforeEncryptedData(t *testing.T, message, body []byte) []byte {
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

		if pkt.Tag == tagSEIPD || pkt.Tag == tagSED {
			out = append(out, body...)
		}

		out = append(out, rest[:consumed]...)
		rest = pkt.Rest
	}

	return out
}

// TestScanStoppedByDamageIsNotReportedAsNotAddressed covers round-8 finding 22.
//
// eachSessionKey ended its walk on any ParsePacket failure with `break`, keeping
// no record that it had happened. Its comment justified this — anything that is
// not a readable PKESK becomes the body — and that reasoning holds for the
// encrypted data, which legitimately uses a partial length this package does not
// parse. It does not hold for damage.
//
// So one malformed packet planted ahead of the genuine session-key packets ended
// the scan before reaching them, and the operator was told the message was not
// addressed to this certificate: a verdict about WHO the message is for, issued
// by code that never got far enough to look. They go hunting for a certificate
// that may not exist, when what they have is a message somebody tampered with.
func TestScanStoppedByDamageIsNotReportedAsNotAddressed(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)
	message := encryptTo(t, der, "a report behind a damaged packet", false)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// A PKESK header declaring a body far longer than the input holds, so
	// ParsePacket refuses it — the shape a truncated or edited message has.
	damaged := []byte{0xC1, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x01, 0x02}

	// A readable co-recipient packet goes IN FRONT of the damage, and it has to.
	//
	// With the damaged packet first, isPacketStream cannot get past it either,
	// so the message is refused as "neither packets nor armour" long before the
	// candidate walk runs — a pass that proves nothing about the walk. Putting a
	// well-formed foreign packet first makes the message recognisably binary and
	// puts the damage where this test means it: between the walk's start and our
	// own session-key packet.
	spliced := foreignPKESK(t, message)
	spliced = append(spliced, damaged...)
	spliced = append(spliced, message...)

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(spliced), io.Discard)
	if err == nil {
		t.Fatal("a message with a damaged packet decrypted")
	}

	if errors.Is(err, openpgp.ErrNotAddressed) {
		t.Fatalf("a scan stopped by damage was reported as a verdict about the recipient: %v.\n"+
			"The walk never reached the session-key packets, so it cannot say who the message is for", err)
	}

	if !errors.Is(err, openpgp.ErrMalformedMessage) {
		t.Errorf("error = %v, want ErrMalformedMessage naming the damage", err)
	}

}

// foreignPKESK returns the message's first session-key packet with its key id
// changed, so it parses cleanly and belongs to somebody else.
func foreignPKESK(t *testing.T, message []byte) []byte {
	t.Helper()

	const (
		tagPKESK    = 1
		keyIDOffset = 1
		keyIDOctets = 8
	)

	for rest := message; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}

		if pkt.Tag == tagPKESK {
			body := bytes.Clone(pkt.Body)
			for i := range keyIDOctets {
				body[keyIDOffset+i] ^= 0xFF
			}

			return framePacket(t, tagPKESK, body)
		}

		rest = pkt.Rest
	}

	t.Fatal("the fixture has no PKESK packet")

	return nil
}

// TestStreamingPacketAfterAnUnprotectedOneDoesNotWedgeTheReader covers
// design-review finding N3, at its ACTUAL reach.
//
// The panel and the first verification both overstated it. The candidate walk
// stops at the first encrypted-data tag, so decryptBody's body always begins
// with a SymmetricallyEncrypted packet and the `!ok` continue never fires on
// the first packet. The arm is reachable only AFTER a legacy unprotected SED
// packet has been drained and stepped over: at that point a streaming packet
// before the real SEIPD is skipped undrained, and go-crypto's reader desyncs on
// the next read — returning "malformed" for a message whose genuine report sits
// one packet further on.
//
// Narrow, but real and adversarial: [SED][Compressed][SEIPD] is something an
// attacker prepends, not a shape a sender emits, and the effect is the
// guard-that-stops denial this class keeps producing. The empty compressed
// packet is drained now, so the walk reaches the SEIPD behind it.
func TestStreamingPacketAfterAnUnprotectedOneDoesNotWedgeTheReader(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)
	message := encryptTo(t, der, "the report behind an SED and a streaming packet", false)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// An empty compressed packet: streaming, well-formed, carrying nothing.
	var compressed bytes.Buffer

	w, err := packet.SerializeCompressed(nopWC{&compressed}, packet.CompressionZIP, nil)
	if err != nil {
		t.Fatalf("SerializeCompressed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	// A legacy unprotected SED packet (tag 9) with a token body. decryptBody
	// drains and steps over it as unprotected; the drain is not the bug under
	// test. What follows it is.
	const tagSED = 9

	sed := framePacket(t, tagSED, []byte{0x00, 0x01, 0x02, 0x03})

	// [PKESK...] [SED] [Compressed] [SEIPD] — the SED is where the session-key
	// walk stops, so everything after it reaches decryptBody.
	prefix := sed
	prefix = append(prefix, compressed.Bytes()...)

	spliced := spliceBeforeEncryptedData(t, message, prefix)

	var out bytes.Buffer

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(spliced), &out)
	if err != nil {
		t.Fatalf("a report behind an unprotected packet and a streaming packet was refused: %v.\n"+
			"decryptBody skipped the streaming packet without draining and the reader desynced", err)
	}

	if got := out.String(); got != "the report behind an SED and a streaming packet" {
		t.Errorf("plaintext = %q, want the report", got)
	}
}

// nopWC adapts a buffer for go-crypto serializers, which want a WriteCloser.
type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }
