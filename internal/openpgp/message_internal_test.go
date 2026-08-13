package openpgp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"gitlab.com/phpboyscout/go/encryption"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// TestCopyLiteralRefusesDeeplyNestedCompression covers the descent that
// maxPlaintext does not bound.
//
// maxPlaintext limits the literal data, but nothing limited getting to it. Each
// compression level holds a live flate reader with a 32 KiB window, kept alive
// because the next level is read through it — so the memory is spent before a
// single literal octet exists, which is the out-of-memory kill the plaintext
// bound claims to prevent, reached by a route it never covered.
//
// The nesting here costs a few kilobytes to construct. That asymmetry is the
// attack: cheap to send, expensive to receive.
func TestCopyLiteralRefusesDeeplyNestedCompression(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		depth   int
		wantErr bool
	}{
		{"uncompressed", 0, false},
		{"one level, what a sender produces", 1, false},
		{"at the bound", maxCompressionDepth, false},
		{"one past the bound", maxCompressionDepth + 1, true},
		{"absurd", 500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const plaintext = "a report, wrapped a number of times"

			var out bytes.Buffer

			err := copyLiteral(bytes.NewReader(nestedCompressed(t, tc.depth, plaintext)), &out)

			if tc.wantErr {
				if !errors.Is(err, ErrMalformedMessage) {
					t.Fatalf("error = %v, want ErrMalformedMessage", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("copyLiteral: %v", err)
			}

			if out.String() != plaintext {
				t.Errorf("recovered %q, want %q", out.String(), plaintext)
			}
		})
	}
}

// nestedCompressed builds a literal data packet wrapped in depth compressed
// packets.
func nestedCompressed(t *testing.T, depth int, plaintext string) []byte {
	t.Helper()

	var inner bytes.Buffer

	lit, err := packet.SerializeLiteral(nopWriteCloser{&inner}, true, "report.txt", 0)
	if err != nil {
		t.Fatalf("SerializeLiteral: %v", err)
	}

	if _, err := io.WriteString(lit, plaintext); err != nil {
		t.Fatalf("writing the literal: %v", err)
	}

	if err := lit.Close(); err != nil {
		t.Fatalf("closing the literal: %v", err)
	}

	out := inner.Bytes()

	for range depth {
		var buf bytes.Buffer

		w, err := packet.SerializeCompressed(nopWriteCloser{&buf}, packet.CompressionZIP, nil)
		if err != nil {
			t.Fatalf("SerializeCompressed: %v", err)
		}

		if _, err := w.Write(out); err != nil {
			t.Fatalf("writing a compressed layer: %v", err)
		}

		if err := w.Close(); err != nil {
			t.Fatalf("closing a compressed layer: %v", err)
		}

		out = buf.Bytes()
	}

	return out
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// TestIsPacketStreamDecidesWithoutGuessing replaces the anchored armour probe
// with the ordering decision D2 settled.
//
// The probe existed because armor.Decode finds a header anywhere, so an
// attacker composing a binary message chose where the message began. Anchoring
// the probe closed that and broke armour under a covering line. Asking "is this
// already packets?" first settles both: a valid binary message is consumed as
// binary so an embedded header is never reached, and anything that is not one
// can be searched for armour freely, because there are no real packets to lose.
func TestIsPacketStreamDecidesWithoutGuessing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"an armoured block", []byte("-----BEGIN PGP MESSAGE-----\n\nabc\n"), false},
		{"armour under a covering line", []byte("Here is the report:\n\n-----BEGIN PGP MESSAGE-----\n"), false},
		{"empty", nil, false},
		{"prose", []byte("this is not a message at all"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isPacketStream(tc.in); got != tc.want {
				t.Errorf("isPacketStream(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCopyLiteralBoundsPacketBreadth covers finding 09.
//
// copyLiteral silently discards any packet that is neither Compressed nor
// LiteralData and keeps reading, with no bound on how many it will consume.
//
// maxPlaintext bounds literal data and maxCompressionDepth bounds nesting, so
// neither covers breadth. One compressed packet expanding to millions of marker
// packets is walked one at a time — the same denial of service as the nesting
// bound, reached sideways rather than downwards. The expansion is what makes it
// asymmetric: the ciphertext here is a few kilobytes and the walk is megabytes.
func TestCopyLiteralBoundsPacketBreadth(t *testing.T) {
	t.Parallel()

	const filler = 200_000

	// User ID packets: small, and a type the packet reader hands back rather
	// than consuming itself, so they reach the walk and are skipped there.
	//
	// Marker packets do not work for this — go-crypto absorbs those internally,
	// so two hundred thousand of them never reach copyLiteral at all and cost
	// almost nothing. Worth recording, because the finding described the
	// mechanism in terms of "any packet that is neither compressed nor
	// literal", and that is not the whole story.
	var inner bytes.Buffer
	for range filler {
		inner.Write([]byte{0xCD, 0x01, 'x'})
	}

	var buf bytes.Buffer

	w, err := packet.SerializeCompressed(nopWriteCloser{&buf}, packet.CompressionZIP, nil)
	if err != nil {
		t.Fatalf("SerializeCompressed: %v", err)
	}

	if _, err := w.Write(inner.Bytes()); err != nil {
		t.Fatalf("writing markers: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	t.Logf("%d filler packets, %d octets uncompressed, compress to %d octets",
		filler, inner.Len(), buf.Len())

	err = copyLiteral(bytes.NewReader(buf.Bytes()), io.Discard)
	if err == nil {
		t.Fatal("a message carrying no literal data was accepted")
	}

	// Asserted on the error rather than on octets consumed: the compressed
	// input is buffered into the flate reader whole, so bytes read cannot
	// distinguish stopping early from walking everything. The two outcomes are
	// distinguishable by which failure is reported — the bound, or running out
	// of packets after inspecting all two hundred thousand.
	if !strings.Contains(err.Error(), "first 64 packets") {
		t.Errorf("error = %v; want the breadth bound to have stopped the walk", err)
	}

	if !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("error = %v, want ErrMalformedMessage", err)
	}
}

// TestIsPacketStreamNeedsMoreThanAHeader covers the two-octet inputs that used
// to be enough to declare an armoured message binary.
//
// The probe read one packet header and concluded the whole input was a packet
// stream. A header with nothing behind it establishes nothing: 0xC1 0x00 is a
// session-key tag with an empty body, and 0xC6 0x87 is a public-key tag whose
// declared 135 octets any armour longer than that satisfies. Both took the
// binary path, so the armour decoder was never reached and the operator was
// told their report was malformed.
func TestIsPacketStreamNeedsMoreThanAHeader(t *testing.T) {
	t.Parallel()

	armour := []byte("-----BEGIN PGP MESSAGE-----\n\nhQEMA0000000\n-----END PGP MESSAGE-----\n")

	for _, tc := range []struct {
		name   string
		raw    []byte
		expect bool
	}{
		{"a session-key header with an empty body", []byte{0xC1, 0x00}, false},
		{"a public-key header with an empty body", []byte{0xC6, 0x00}, false},
		{"an old-format header with an empty body", []byte{0x84, 0x00}, false},

		// The shapes that used to suppress the armour path entirely.
		{"an empty session-key header ahead of armour", append([]byte{0xC1, 0x00}, armour...), false},
		{"a public-key header ahead of armour", append([]byte{0xC6, 0x87}, armour...), false},

		// A covering line beginning with U+0187, which encodes as those same
		// two octets. Not an attack — the arrival shape the ordering protects.
		{"armour under a covering line", append([]byte("Ƈopy of the report below:\n\n"), armour...), false},
		{"armour under an ordinary covering line", append([]byte("Here it is:\n\n"), armour...), false},

		// Armour itself, which can never parse as a packet.
		{"armour alone", armour, false},
		{"nothing at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isPacketStream(tc.raw); got != tc.expect {
				t.Errorf("isPacketStream = %t, want %t", got, tc.expect)
			}
		})
	}
}

// TestPKESKFixedOctetsMatchesTheCore covers a constant copied by hand.
//
// pkeskFixedOctets is the same value as the core's unexported constant of the
// same name, maintained separately because nothing exports it. Copies of wire
// constants drift, and this one decides whether a packet is treated as a real
// session key or as bytes that merely resemble one.
//
// The core's minimum is MEASURED rather than written here a second time: probe
// upward until it stops complaining about length, and compare. Asserting one
// side of the boundary would only catch drift in one direction — checking that
// a too-short body is refused misses a constant that has grown, which is the
// direction that makes this package ignore packets the core can read.
func TestPKESKFixedOctetsMatchesTheCore(t *testing.T) {
	t.Parallel()

	const probeLimit = 64

	coreMinimum := -1

	for n := range probeLimit {
		body := make([]byte, n)
		if n > 0 {
			body[0] = 3
		}

		if n > 9 {
			body[9] = 18
		}

		_, err := encryption.ParsePKESK(body)
		if err == nil || !strings.Contains(err.Error(), "want at least") {
			coreMinimum = n

			break
		}
	}

	if coreMinimum < 0 {
		t.Fatalf("the core refused every body up to %d octets on length grounds", probeLimit)
	}

	if coreMinimum != pkeskFixedOctets {
		t.Errorf("pkeskFixedOctets is %d but the core's minimum is %d — a session-key packet the "+
			"core can read is treated here as bytes that merely resemble one, or the reverse",
			pkeskFixedOctets, coreMinimum)
	}
}

// TestCopyLiteralKeepsWalkingPastAnEmptyCompressedPacket covers round-8
// finding 23.
//
// copyLiteral replaced its reader on the first Compressed packet:
//
//	reader = packet.NewReader(typed.Body)
//
// and never came back. Every packet that followed the compressed one in the
// OUTER stream was abandoned, so descending into a compressed packet holding
// nothing useful discarded the literal data sitting right behind it.
//
// The same shape as decryptBody's SED refusal and the revocation-filing defect
// before it: the branch handles one packet correctly and takes the rest of the
// walk down with it. An attacker who can prepend one empty compressed packet to
// the plaintext stream makes the report unreadable, and the operator is told
// there is no literal data in a message that plainly contains some.
func TestCopyLiteralKeepsWalkingPastAnEmptyCompressedPacket(t *testing.T) {
	t.Parallel()

	const plaintext = "the report that follows an empty compressed packet"

	// An empty compressed packet: valid, well-formed, and holding no literal.
	var empty bytes.Buffer

	w, err := packet.SerializeCompressed(nopWriteCloser{&empty}, packet.CompressionZIP, nil)
	if err != nil {
		t.Fatalf("SerializeCompressed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("closing the compressed packet: %v", err)
	}

	body := append(empty.Bytes(), nestedCompressed(t, 0, plaintext)...)

	var out bytes.Buffer
	if err := copyLiteral(bytes.NewReader(body), &out); err != nil {
		t.Fatalf("literal data behind an empty compressed packet was abandoned: %v.\n"+
			"Descending into one packet must not discard the packets after it", err)
	}

	if out.String() != plaintext {
		t.Errorf("plaintext = %q, want %q", out.String(), plaintext)
	}
}
