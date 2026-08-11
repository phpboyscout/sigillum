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

// TestCopyAuthenticatedDoesNotDrainAfterRefusing covers what Close costs on a
// message that has already been rejected.
//
// go-crypto's Close verifies the modification detection code by reading to the
// end, so calling it after a refusal decrypts and decompresses everything the
// bound declined to hold — the command appears to hang for minutes on input it
// rejected immediately. It also misreports: a drain meeting a truncated stream
// returns an MDC mismatch, and Close's error used to take precedence, so an
// oversized message was reported as one that may have been altered.
//
// Nothing is handed over on the refusal path, so no integrity guarantee is
// lost by not checking it.
func TestCopyAuthenticatedDoesNotDrainAfterRefusing(t *testing.T) {
	t.Parallel()

	t.Run("refused input is not closed", func(t *testing.T) {
		t.Parallel()

		// Not a packet stream, so copyLiteral fails immediately.
		body := &recordingCloser{Reader: bytes.NewReader([]byte("not openpgp packets at all"))}

		err := copyAuthenticated(body, io.Discard)
		if err == nil {
			t.Fatal("unreadable input was accepted")
		}

		if errors.Is(err, ErrIntegrity) {
			t.Errorf("error = %v, want the read failure rather than an integrity verdict", err)
		}

		if body.closed {
			t.Error("Close was called on a message already refused, which is the drain")
		}
	})

	t.Run("accepted input is closed", func(t *testing.T) {
		t.Parallel()

		const plaintext = "a report that should be verified before it is handed over"

		body := &recordingCloser{Reader: bytes.NewReader(nestedCompressed(t, 1, plaintext))}

		var out bytes.Buffer
		if err := copyAuthenticated(body, &out); err != nil {
			t.Fatalf("copyAuthenticated: %v", err)
		}

		if !body.closed {
			t.Error("plaintext was handed over without verifying the modification detection code")
		}

		if out.String() != plaintext {
			t.Errorf("recovered %q, want %q", out.String(), plaintext)
		}
	})
}

// recordingCloser reports whether Close was reached, standing in for the drain
// go-crypto performs there.
type recordingCloser struct {
	io.Reader

	closed bool
}

func (r *recordingCloser) Close() error {
	r.closed = true

	return nil
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

	const markers = 200_000

	// A marker packet is tag 10 with the body "PGP" — the smallest packet that
	// is neither compressed data nor literal data, so copyLiteral skips it.
	var inner bytes.Buffer
	for range markers {
		inner.Write([]byte{0xCA, 0x03, 'P', 'G', 'P'})
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

	t.Logf("%d marker packets, %d octets uncompressed, compress to %d octets",
		markers, inner.Len(), buf.Len())

	counted := &countingReader{Reader: bytes.NewReader(buf.Bytes())}

	err = copyLiteral(counted, io.Discard)
	if err == nil {
		t.Fatal("a message carrying no literal data was accepted")
	}

	// The bound that matters is work done, not the error returned: the walk
	// must stop long before the whole expansion has been read.
	if counted.n >= buf.Len() {
		t.Errorf("read %d of %d ciphertext octets — the whole expansion was walked, so nothing bounds breadth",
			counted.n, buf.Len())
	}
}

// countingReader records how much of the ciphertext was actually consumed.
type countingReader struct {
	io.Reader

	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n

	return n, err
}
