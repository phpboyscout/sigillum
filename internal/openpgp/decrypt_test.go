package openpgp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"gitlab.com/phpboyscout/go/encryption"
	"gitlab.com/phpboyscout/go/encryption/certificate"
	_ "gitlab.com/phpboyscout/go/encryption/local"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// The end-to-end test for this module: a certificate assembled by the core,
// a message composed by an independent implementation, and the plaintext
// recovered through the one operation a key service performs.
//
// The keys are local because what is under test is the framing and the wiring,
// not the key service. TestCertificateRoundTripAgainstRealKMS in
// gitlab.com/phpboyscout/go/encryption-aws-kms is the same shape driven by KMS.

func TestDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	const plaintext = "a vulnerability report nobody else should read"

	for _, armoured := range []bool{false, true} {
		name := "binary"
		if armoured {
			name = "armoured"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			der, deriver := testCertificate(t)
			message := encryptTo(t, der, plaintext, armoured)

			recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
			if err != nil {
				t.Fatalf("ReadRecipient: %v", err)
			}

			var out bytes.Buffer
			if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &out); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if out.String() != plaintext {
				t.Errorf("recovered %q, want %q", out.String(), plaintext)
			}
		})
	}
}

// TestDecryptRefusesAMessageForAnotherKey covers the check that happens before
// any key-service call.
//
// Several certificates in play is the normal case, and a message addressed
// elsewhere is not worth a billable round trip — nor an error that reads as a
// cryptographic failure when it is really just the wrong recipient.
func TestDecryptRefusesAMessageForAnotherKey(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	theirs, _ := testCertificate(t)

	message := encryptTo(t, theirs, "not for us", false)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
	if !errors.Is(err, openpgp.ErrNotAddressed) {
		t.Fatalf("error = %v, want ErrNotAddressed", err)
	}

	if counting.calls != 0 {
		t.Errorf("the key service was called %d times before the recipient check", counting.calls)
	}
}

func TestDecryptRejectsBadInput(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	for _, tc := range []struct {
		name    string
		message string
		want    error
	}{
		{"empty", "", openpgp.ErrMalformedMessage},
		{"not a packet", "just some text\n", openpgp.ErrMalformedMessage},
		{"truncated packet", "\xc1\x40short", openpgp.ErrMalformedMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := openpgp.Decrypt(t.Context(), deriver, recipient,
				strings.NewReader(tc.message), io.Discard)
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecryptRequiresAKeyService(t *testing.T) {
	t.Parallel()

	der, _ := testCertificate(t)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	err = openpgp.Decrypt(t.Context(), nil, recipient, strings.NewReader("x"), io.Discard)
	if !errors.Is(err, encryption.ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// TestReadRecipientRejectsACertificateWithNoEncryptionSubkey covers a
// signing-only certificate, which parses perfectly and can receive nothing.
func TestReadRecipientRejectsACertificateWithNoEncryptionSubkey(t *testing.T) {
	t.Parallel()

	entity, err := pgp.NewEntity("signing only", "", "sign@example.invalid", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	var buf bytes.Buffer
	if err := entity.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Serialize writes the primary and its identity but no subkey binding,
	// leaving a certificate with nothing to encrypt to.
	// The core refuses it: a certificate with no ECDH subkey cannot receive
	// anything, and that is a malformed input for this purpose.
	if _, _, err := openpgp.ReadRecipient(&buf); !errors.Is(err, encryption.ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// countingDeriver records whether the key service was reached at all.
type countingDeriver struct {
	openpgp.SecretDeriver

	calls int
}

func (d *countingDeriver) DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error) {
	d.calls++

	return d.SecretDeriver.DeriveSharedSecret(ctx, peerPoint)
}

// localSigner is an ordinary crypto.Signer, standing in for a key service.
type localSigner struct{ key *rsa.PrivateKey }

func (s localSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s localSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.key, opts.HashFunc(), digest)
}

// testCertificate assembles a certificate through the core and returns it with
// a deriver for its encryption subkey.
func testCertificate(t *testing.T) ([]byte, openpgp.SecretDeriver) {
	t.Helper()

	created := time.Unix(1_700_000_000, 0).UTC()

	// 2048 rather than the 4096 a real certification key would use: this runs
	// on every commit and the size proves nothing here.
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}

	agreement, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an agreement key: %v", err)
	}

	der, err := certificate.Certificate{
		UserID:  "Security Contact <security@example.invalid>",
		Created: created,
		Subkey: certificate.ECDHPublicKey{
			Created:  created,
			CurveOID: []byte{0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
			Point:    agreement.PublicKey().Bytes(),
			HashID:   8, // SHA-256
			KEKAlgID: 7, // AES-128
		},
	}.Assemble(localSigner{key: signing})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	return der, registeredDeriver(t, agreement)
}

// registeredDeriver returns the agreement half through the real key-service
// registry rather than as a hand-rolled double.
//
// The double it replaces satisfied openpgp.SecretDeriver directly, so nothing
// checked that the interface a real provider implements is the one these tests
// exercise — a drift that would surface only in production. Going through the
// registry means the tests reach the deriver exactly as the command does, and
// the local backend is what makes that affordable: an attempt costs nothing, so
// candidate-selection behaviour can be tested apart from the cost ceiling that
// exists only because a KMS call is billed.
func registeredDeriver(t *testing.T, key *ecdh.PrivateKey) openpgp.SecretDeriver {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the agreement key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "agreement.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing the agreement key: %v", err)
	}

	service, err := encryption.LookupKeyService("local")
	if err != nil {
		t.Fatalf("the local backend is not registered: %v", err)
	}

	deriver, err := service.Deriver(t.Context(), path)
	if err != nil {
		t.Fatalf("Deriver: %v", err)
	}

	return deriver
}

// encryptTo composes a message addressed to the certificate, using an
// independent implementation so the test is not checking our encoder against
// our own decoder.
func encryptTo(t *testing.T, der []byte, plaintext string, armoured bool) []byte {
	t.Helper()

	entities, err := pgp.ReadKeyRing(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("reference implementation rejected the certificate: %v", err)
	}

	var buf bytes.Buffer

	var sink io.WriteCloser = nopCloser{&buf}

	if armoured {
		if sink, err = armor.Encode(&buf, "PGP MESSAGE", nil); err != nil {
			t.Fatalf("armor: %v", err)
		}
	}

	w, err := pgp.Encrypt(sink, entities, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	return buf.Bytes()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// TestReadRecipientAcceptsAnArmouredCertificate covers the other way a
// certificate arrives.
//
// A certificate published on a website or pasted into a ticket is armoured; one
// fetched from WKD is binary. A reader that handles only one silently fails on
// half of what it is given, so both routes are exercised.
func TestReadRecipientAcceptsAnArmouredCertificate(t *testing.T) {
	t.Parallel()

	der, _ := testCertificate(t)

	var armoured bytes.Buffer

	w, err := armor.Encode(&armoured, pgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}

	if _, err := w.Write(der); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fromArmour, _, err := openpgp.ReadRecipient(&armoured)
	if err != nil {
		t.Fatalf("ReadRecipient (armoured): %v", err)
	}

	fromBinary, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient (binary): %v", err)
	}

	if fromArmour.KeyID != fromBinary.KeyID {
		t.Error("the two encodings of one certificate produced different recipients")
	}
}

// TestReadRecipientRejectsRubbish covers input that is not a certificate at
// all — a truncated paste, or an error page saved as a key file.
func TestReadRecipientRejectsRubbish(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"plain text", "-- no key here --\n"},
		{"truncated armour", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := openpgp.ReadRecipient(strings.NewReader(tc.in)); err == nil {
				t.Error("accepted something that is not a certificate")
			}
		})
	}
}

// TestDecryptOpensACompressedMessage covers the path a real report takes.
//
// gpg compresses by default, so the literal data sits inside a compressed
// packet rather than directly inside the encrypted one. A reader that expects
// the literal immediately would work on every hand-made test message and fail
// on everything a person actually sends.
func TestDecryptOpensACompressedMessage(t *testing.T) {
	t.Parallel()

	const plaintext = "a long report, repeated so it compresses. "

	der, deriver := testCertificate(t)

	entities, err := pgp.ReadKeyRing(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("read key ring: %v", err)
	}

	var buf bytes.Buffer

	w, err := pgp.Encrypt(&buf, entities, nil, nil, &packet.Config{
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig:      &packet.CompressionConfig{Level: 6},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := io.WriteString(w, strings.Repeat(plaintext, 40)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, &buf, &got); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if got.String() != strings.Repeat(plaintext, 40) {
		t.Error("the decompressed plaintext does not match")
	}
}

// TestDecryptReportsAKeyServiceFailure covers the outage case: the message is
// well-formed and addressed to us, and the key service will not answer.
func TestDecryptReportsAKeyServiceFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("kms: throttled")

	der, _ := testCertificate(t)
	message := encryptTo(t, der, "unreadable today", false)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	err = openpgp.Decrypt(t.Context(), &failingDeriverWith{err: sentinel}, recipient,
		bytes.NewReader(message), io.Discard)
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want it to wrap the key service failure", err)
	}
}

// TestDecryptRejectsAMessageWithNoEncryptedData covers a PKESK addressed to us
// with nothing after it — a truncated paste that stops at the header.
func TestDecryptRejectsAMessageWithNoEncryptedData(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)
	full := encryptTo(t, der, "truncated", false)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// Keep only the first packet. firstPacket parses the length rather than
	// re-deriving the two-octet form by hand, which is the fourth copy of that
	// arithmetic this package has carried and the one most likely to be wrong,
	// since nothing here would notice if it truncated in the wrong place.
	err = openpgp.Decrypt(t.Context(), deriver, recipient,
		bytes.NewReader(firstPacket(t, full)), io.Discard)
	if !errors.Is(err, openpgp.ErrMalformedMessage) {
		t.Errorf("error = %v, want ErrMalformedMessage", err)
	}
}
