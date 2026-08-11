package openpgp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

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
