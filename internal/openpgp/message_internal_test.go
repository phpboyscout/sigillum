package openpgp

import (
	"bytes"
	"errors"
	"io"
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

// TestLooksArmouredAnchorsAtTheStart covers the probe that decides whether to
// reach for a decoder.
//
// go-crypto's armor.Decode skips leading garbage, so it will find a header
// anywhere in the input. An attacker composing a binary message can put one
// inside the encrypted-data packet, and Decode then succeeds on their choice of
// where the message begins — the real packets are discarded and the operator
// gets a base64 error instead of their report.
func TestLooksArmouredAnchorsAtTheStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"an armoured block", "-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n", true},
		{"leading whitespace", "\n\t  -----BEGIN PGP MESSAGE-----\n", true},
		{"binary", "\xc1\x0e\x03\x01\x02\x03", false},
		{"the header buried in binary", "\xc1\x0e\x03\n-----BEGIN PGP MESSAGE-----\n", false},
		{"empty", "", false},
		{"a near miss", "-----BEGI", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := looksArmoured([]byte(tc.in)); got != tc.want {
				t.Errorf("looksArmoured(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
