package openpgp_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"gitlab.com/phpboyscout/go/encryption"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// Property fuzzing over message reading and the candidate walk.
//
// The same reasoning as the parser's targets in go/encryption: every
// high-severity finding in the last two rounds was a guard that fired and fell
// back to a permissive path, and every test written from a finding covered the
// case in the finding rather than the space around it.
//
// The properties here describe what an attacker gets by touching a message in a
// ticket system or in transit — prepending packets, repeating them, wrapping the
// whole thing differently — which is the position all of those findings
// occupied.
//
// Run longer than the default with, e.g.:
//
//	go test ./internal/openpgp -run '^$' -fuzz FuzzDecryptPrependedPackets -fuzztime 5m

// message is a valid encrypted report and everything needed to open it.
//
// Built once: generating a certificate per iteration would make the targets too
// slow to explore anything.
var message = sync.OnceValue(func() (m struct {
	der        []byte
	deriver    openpgp.SecretDeriver
	recipient  openpgp.Recipient
	ciphertext []byte
	plaintext  string
}) {
	t := &testing.T{}

	m.plaintext = "a vulnerability report that must survive tampering"
	m.der, m.deriver = testCertificate(t)
	m.ciphertext = encryptTo(t, m.der, m.plaintext, false)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(m.der))
	if err != nil {
		panic("fuzz fixture: " + err.Error())
	}

	m.recipient = recipient

	return m
})

// FuzzReadRecipientNeverPanics is the floor for the certificate path, which
// takes bytes fetched from a published page or an API.
func FuzzReadRecipientNeverPanics(f *testing.F) {
	f.Add(message().der)
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot base64\n"))
	f.Add([]byte{0x99, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}

		_, _ = openpgp.ReadRecipient(bytes.NewReader(raw))
	})
}

// FuzzDecryptNeverPanics is the floor for the message path. The certificate is
// published, so anyone may compose the input.
func FuzzDecryptNeverPanics(f *testing.F) {
	f.Add(message().ciphertext)
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PGP MESSAGE-----\n\n!!!!\n-----END PGP MESSAGE-----\n"))
	f.Add([]byte{0xC1, 0x00})

	f.Fuzz(func(_ *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}

		m := message()

		_ = openpgp.Decrypt(context.Background(), m.deriver, m.recipient, bytes.NewReader(raw), io.Discard)
	})
}

// FuzzDecryptPrependedPackets is the property that matters, and the one the
// last two rounds of findings kept violating.
//
// Anyone able to touch a message can put packets in front of it — the key id is
// public, being the tail of the certificate's own fingerprint, so forging a
// packet that *names* us needs no key material at all. Findings have lived here
// twice: keeping only the first packet naming us hid the genuine one behind a
// forgery, and counting forgeries against the attempt cap pushed it out of
// reach.
//
// So: prepending SELF-CONTAINED packets may make the decrypt fail, but it must
// never
//
//   - produce plaintext that is not the report, and
//   - report the message as addressed elsewhere, since it names us and always
//     did — that verdict sends the operator to find a certificate that does not
//     exist.
//
// Two restrictions, both taught by the fuzzer rather than reasoned out in
// advance — which is worth recording, because a property that is too strong is
// the failure mode of this technique and it looks exactly like a defect.
//
// Self-contained: an unrefined version failed in under a second on the prefix
// c1 30, a packet header declaring forty-eight octets, which swallows the
// genuine session-key packet behind it. The message really is destroyed there
// and "not addressed here" is defensible, so the property was wrong rather than
// the code.
//
// No encrypted data in the prefix: once a prefix carries its own
// encrypted-data packet it is a complete message in its own right, and the
// input is two messages concatenated. A reader that stops at the first is
// behaving correctly, however unhelpful that is. The fuzzer found this as
// [a version 5 session-key packet][an empty encrypted-data packet], which is a
// syntactically plausible message for somebody else.
//
// Neither restriction weakens what the property is for. Everything an attacker
// can prepend that leaves a readable message readable is still covered, which
// is where all four rounds of findings lived.
func FuzzDecryptPrependedPackets(f *testing.F) {
	// The seed corpus doubles as the hostile-input regression suite: `go test`
	// replays these without -fuzz, so a shape once found stays found.
	f.Add([]byte{})
	f.Add([]byte{0xC1, 0x00})
	f.Add([]byte{0xCA, 0x03, 'P', 'G', 'P'})
	f.Add(bytes.Repeat([]byte{0xCA, 0x03, 'P', 'G', 'P'}, 40))

	// Found by this target in three seconds against the round-three candidate
	// walk, unseeded: an old-format signature packet followed by a marker,
	// which was enough to hide a report addressed to us.
	f.Add([]byte{0x84, 0x03, 0x30, 0x30, 0x30, 0xCA, 0x03, 0x30, 0x30, 0x30})

	f.Fuzz(func(t *testing.T, prefix []byte) {
		if len(prefix) > 1<<16 || !selfContained(prefix) || carriesEncryptedData(prefix) {
			return
		}

		m := message()

		var got bytes.Buffer

		err := openpgp.Decrypt(context.Background(), m.deriver, m.recipient,
			bytes.NewReader(append(append([]byte(nil), prefix...), m.ciphertext...)), &got)

		// The report must be RECOVERED, not merely not-misdiagnosed.
		//
		// An earlier version of this property allowed any error except
		// ErrNotAddressed, which made losing the report a passing outcome. It
		// inherited that weakness from a unit test whose assertion had been
		// softened until the code satisfied it, so the two agreed with each
		// other and neither could catch the defect they were both written for.
		// A property that permits the failure it exists to detect is worse than
		// no property, because it reads as coverage.
		if err != nil {
			t.Fatalf("%d prepended octets lost a report addressed to us (%v): %x", len(prefix), err, prefix)
		}

		if got.String() != m.plaintext {
			t.Fatalf("%d prepended octets changed the plaintext to %q: %x", len(prefix), got.String(), prefix)
		}
	})
}

// selfContained reports whether a prefix is a whole number of packets, so that
// appending a message after it leaves that message's own packets intact.
//
// A prefix whose last packet declares more octets than it carries eats into
// whatever follows, which is a corrupted message rather than a prefixed one.
func selfContained(prefix []byte) bool {
	for rest := prefix; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			return false
		}

		// A body reaching exactly the end is fine; one that would have run past
		// it is what ParsePacket cannot see, so compare what it consumed.
		if len(pkt.Rest) >= len(rest) {
			return false
		}

		rest = pkt.Rest
	}

	return true
}

// carriesEncryptedData reports whether a prefix is already a message.
//
// A prefix containing an encrypted-data packet makes the input two messages
// concatenated rather than one message with a preamble, and stopping at the
// first is correct.
func carriesEncryptedData(prefix []byte) bool {
	const (
		tagSED   = 9
		tagSEIPD = 18
	)

	for rest := prefix; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			return false
		}

		if pkt.Tag == tagSED || pkt.Tag == tagSEIPD {
			return true
		}

		rest = pkt.Rest
	}

	return false
}

// FuzzDecryptNeverEmitsUnauthenticatedPlaintext is the guarantee the whole
// package exists for.
//
// The modification detection code is verified on Close, after every byte has
// been read, so streaming would hand a security contact attacker-modified text
// and only then report the failure. Whatever is done to the ciphertext, a
// successful return must mean the plaintext is the one that was sent.
func FuzzDecryptNeverEmitsUnauthenticatedPlaintext(f *testing.F) {
	f.Add(0, byte(0))
	f.Add(1, byte(0xFF))

	f.Fuzz(func(t *testing.T, offset int, flip byte) {
		m := message()

		if offset < 0 || flip == 0 || len(m.ciphertext) == 0 {
			return
		}

		tampered := append([]byte(nil), m.ciphertext...)
		tampered[offset%len(tampered)] ^= flip

		var got bytes.Buffer

		if err := openpgp.Decrypt(context.Background(), m.deriver, m.recipient,
			bytes.NewReader(tampered), &got); err != nil {
			return
		}

		// A successful decrypt of altered ciphertext is only acceptable if it
		// produced exactly the original report — which happens when the flipped
		// octet was not load-bearing.
		if got.String() != m.plaintext {
			t.Fatalf("altered ciphertext at %d by %#02x decrypted to %q without an integrity failure",
				offset%len(tampered), flip, got.String())
		}
	})
}
