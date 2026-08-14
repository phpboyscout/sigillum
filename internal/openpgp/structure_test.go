package openpgp_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gitlab.com/phpboyscout/go/encryption"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// Message-structure robustness: what must still work when a message is not
// shaped the way a hand-built fixture is.
//
// # Why this file exists
//
// Six review rounds produced the same defect six times, in six different
// functions, and every unit test written from every finding covered the case in
// the finding rather than the space around it. The shape is always this:
//
//	a guard fires, and the code stops instead of continuing down the path
//	the guard does not govern.
//
//   - the session-key scan ended at the first packet it did not recognise, so
//     a marker packet hid the whole message
//   - only the first packet naming us was kept, so a forgery hid the genuine one
//   - the attempt ceiling counted packets an attacker could forge freely
//   - the ceiling returned instead of skipping, so candidates that cost nothing
//     were discarded with the ones that did
//   - the candidate dedup key was ambiguous, so a forgery displaced a packet it
//     collided with
//   - "packets or armour?" read one header, so two octets suppressed the
//     armour path
//
// Written as six separate findings they look like six unrelated bugs. Written
// as a property they are one, and it is a property this file states once.
//
// # The property
//
// Recoverability is MONOTONE under adding packets that cost nothing:
//
//	if a message decrypts, then that message with any number of additional
//	packets that carry no encrypted data and require no new key-service
//	derivation still decrypts, to the same plaintext.
//
// The qualifier is the whole of the subtlety, and stating it precisely is what
// six rounds of findings were really about. Packets that DO require new
// derivations are bounded on purpose — see maxDerivations — so inserting more
// than that ceiling allows may legitimately stop the run. Everything else must
// not.
//
// # Where the shapes come from
//
// The named cases below follow the "Message structure" section of Sequoia's
// OpenPGP interoperability test suite, which is the closest thing the ecosystem
// has to a reference corpus for this: marker packets, trust packets, unknown
// packets, and unusual arrangements. Our marker-packet defect is literally one
// of its entries, and we found it by fuzzing rather than by looking. The
// suite's own framing is whether an implementation "gracefully handles
// unexpected or unrecognized packets while maintaining decryption
// functionality" — which is this property, stated for an ecosystem rather than
// for one codebase.
//
// See https://tests.sequoia-pgp.org/ and
// https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite.
//
// # What this catches, measured
//
// Each historical defect was reintroduced and the properties below re-run. The
// numbers are how many of them failed:
//
//	the session-key scan ends at the first unrecognised packet   18
//	"packets or armour?" reads one header                        31
//	the ceiling returns instead of skipping a free candidate      1
//	derivations are not memoised by ephemeral point               1
//	the candidate dedup key is ambiguous                          0
//
// # What it does not catch, and why
//
// The dedup collision is the one that stays invisible here, and the reason is
// worth writing down because it bounds what this technique is for. Every other
// defect is provoked by adding SOMETHING — any marker, any spare session-key
// packet, any covering line — so generating structures finds them. A collision
// has to be built from the genuine packet's own bytes, re-split at a 0x00 that
// happens to be inside them. No generator that does not already know the answer
// will produce that, so it needs a targeted test, and it has one:
// TestDecryptIsNotDisplacedByAColligingDedupKey in candidates_test.go.
//
// The rule that follows: a property covers the space around a defect, and a
// targeted test covers a defect whose input is a function of the secret. Both,
// not either.

// inertPackets are packets a reader must step over: they carry no session key,
// no encrypted data, and no cost.
//
// Each is a shape a real sender or gateway emits, not an invention.
func inertPackets(t *testing.T) map[string][]byte {
	t.Helper()

	const (
		tagMarker  = 10 // RFC 9580 5.8 — emitted by PGP 5.x and some gateways
		tagTrust   = 12 // RFC 9580 5.10 — local keyring state that leaks into exports
		tagPadding = 21 // RFC 9580 5.14 — added by modern senders to hide length
		tagUnknown = 60 // the private/experimental range, meaningless to us
	)

	return map[string][]byte{
		"a marker packet":  framePacket(t, tagMarker, []byte("PGP")),
		"a trust packet":   framePacket(t, tagTrust, []byte{0x00, 0x00}),
		"a padding packet": framePacket(t, tagPadding, bytes.Repeat([]byte{0x00}, 32)),
		"an unknown packet": framePacket(t, tagUnknown,
			[]byte("a packet from a future version of something")),
		"an empty packet": framePacket(t, tagMarker, nil),
	}
}

// TestDecryptStepsOverInertPackets is the property for one inert packet in
// every position it can occupy.
//
// Position matters and is exactly what the unit tests missed: every one of them
// put its extra packet at the front, because that is what a finding described.
// A reader that special-cases the leading packet passes all of those and still
// loses a message whose marker sits between two session keys.
func TestDecryptStepsOverInertPackets(t *testing.T) {
	t.Parallel()

	const plaintext = "a report that must survive an unusual message structure"

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	// Two recipients, so there is a position BETWEEN two session-key packets.
	base := encryptToMany(t, plaintext, other, ours)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	positions := packetBoundaries(t, base)

	for name, inert := range inertPackets(t) {
		for _, at := range positions {
			t.Run(name+" at offset "+itoa(at), func(t *testing.T) {
				t.Parallel()

				message := make([]byte, 0, len(base)+len(inert))
				message = append(message, base[:at]...)
				message = append(message, inert...)
				message = append(message, base[at:]...)

				var got bytes.Buffer
				if err := openpgp.Decrypt(t.Context(), deriver, recipient,
					bytes.NewReader(message), &got); err != nil {
					t.Fatalf("%s at offset %d lost a report addressed to us: %v", name, at, err)
				}

				if got.String() != plaintext {
					t.Errorf("recovered %q, want %q", got.String(), plaintext)
				}
			})
		}
	}
}

// TestDecryptSurvivesManyInertPackets is the same property at volume, which is
// where a bound that should not apply starts applying.
//
// One inert packet is stepped over by any reader that does not special-case the
// first position. A thousand of them reach whatever counter the walk keeps, and
// a counter that does not distinguish "packet I stepped over" from "derivation
// I paid for" stops the run.
func TestDecryptSurvivesManyInertPackets(t *testing.T) {
	t.Parallel()

	const (
		plaintext = "a report behind a great many inert packets"
		count     = 1000
	)

	der, deriver := testCertificate(t)

	base := encryptTo(t, der, plaintext, false)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	for name, inert := range inertPackets(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var message []byte

			for range count {
				message = append(message, inert...)
			}

			message = append(message, base...)

			counting := &countingDeriver{SecretDeriver: deriver}

			var got bytes.Buffer
			if err := openpgp.Decrypt(t.Context(), counting, recipient,
				bytes.NewReader(message), &got); err != nil {
				t.Fatalf("%d copies of %s lost a report addressed to us: %v", count, name, err)
			}

			if got.String() != plaintext {
				t.Errorf("recovered %q, want %q", got.String(), plaintext)
			}

			// They cost nothing, so they must not have been billed for.
			if counting.calls != 1 {
				t.Errorf("%d inert packets cost %d key-service derivations, want 1",
					count, counting.calls)
			}
		})
	}
}

// TestDecryptSurvivesFreeSessionKeyPackets is the property for the packets that
// are NOT inert but still cost nothing.
//
// A session-key packet whose ephemeral point has already been derived is free:
// the secret is memoised and the unwrap that follows is local arithmetic. The
// derivation ceiling exists to bound cost, so it must not stop the run for
// candidates that carry none — and it did, which lost a genuine report sitting
// behind sixteen forged points.
//
// This is the case that separates a cost bound from a correctness verdict, and
// it is the one the codebase has got wrong three times.
func TestDecryptSurvivesFreeSessionKeyPackets(t *testing.T) {
	t.Parallel()

	const (
		plaintext = "a report behind packets that cost nothing to rule out"
		copies    = 20
	)

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)
	leading := firstPacket(t, genuine)

	// Every copy reuses the genuine ephemeral point, so after the first
	// derivation each one is free.
	var message []byte

	for i := range copies {
		forged := append([]byte(nil), leading...)
		forged[len(forged)-1] ^= byte(i%255 + 1)
		message = append(message, forged...)
	}

	// Then MORE DISTINCT POINTS THAN THE CEILING ALLOWS, before the genuine
	// packet. This is the part the first version of this property missed, and
	// missing it made the property useless for the defect it was written for.
	//
	// With free packets alone the budget is never approached, so a ceiling that
	// abandons the run instead of skipping one candidate is never exercised —
	// the property passed against the defective code. Exhausting the budget
	// first is what puts a free candidate on the far side of the guard.
	message = append(message, pkesksOnly(t, repeatFirstPKESK(t, genuine, 20))...)
	message = append(message, genuine...)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("%d free session-key packets lost a report addressed to us: %v", copies, err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}

	// The genuine packet's point was derived by the very first candidate, so
	// recovering it cost nothing beyond the budget the forgeries spent.
	if counting.calls > 16 {
		t.Errorf("recovering a free candidate cost %d derivations, past the ceiling of 16",
			counting.calls)
	}
}

// TestDecryptReportsHonestlyWhenTheCeilingStopsIt is the other side of the
// property, and states what the ceiling is allowed to do.
//
// Packets carrying DISTINCT ephemeral points do cost, so more of them than the
// ceiling allows may legitimately stop the run. What is not allowed is
// reporting that as a settled verdict about who the message is for: the
// candidates never tried might have been ours, and sending the operator to find
// a certificate that may not exist is the misdiagnosis this package has
// produced four separate ways.
func TestDecryptReportsHonestlyWhenTheCeilingStopsIt(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, "a report nobody will reach", false)
	message := repeatFirstPKESK(t, genuine, 200)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
	if err == nil {
		t.Fatal("a message of nothing but distinct forged points decrypted")
	}

	if !errors.Is(err, openpgp.ErrCostCeiling) {
		t.Errorf("error = %v, want ErrCostCeiling", err)
	}

	if errors.Is(err, openpgp.ErrNotAddressed) {
		t.Error("stopping on cost was reported as a settled verdict about who the message is for")
	}

	if counting.calls > 16 {
		t.Errorf("the ceiling let %d derivations through", counting.calls)
	}
}

// packetBoundaries returns every offset at which a packet begins, up to and
// including the start of the encrypted data.
//
// These are the positions an extra packet can legally occupy. Generating them
// from the message rather than hard-coding "the front" is the point: the front
// is the only one the unit tests ever used.
func packetBoundaries(t *testing.T, message []byte) []int {
	t.Helper()

	var (
		out    []int
		offset int
	)

	for rest := message; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			break
		}

		out = append(out, offset)

		// Past the encrypted data an inserted packet is no longer part of the
		// session-key region, and the reader has stopped looking by then.
		if pkt.Tag == 9 || pkt.Tag == 18 {
			break
		}

		consumed := len(rest) - len(pkt.Rest)
		offset += consumed
		rest = pkt.Rest
	}

	if len(out) < 2 {
		t.Fatalf("the fixture has %d packet boundaries; the property needs at least two", len(out))
	}

	return out
}

// itoa keeps subtest names readable without pulling strconv into the header.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var digits []byte

	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	return string(digits)
}

// TestDecryptReadsArmourUnderAnyCoveringLine is the same monotonicity property
// for the other arrival shape.
//
// An armoured report reaches a security address pasted into a ticket or a mail
// body, under a line of explanation. Text before the armour costs nothing and
// must not change the outcome — the armour decoder skips leading text by
// design, so the only thing that can go wrong is the decision made before it is
// reached.
//
// Systematic rather than exemplary, and that distinction is the point. The
// defect here was that "packets or armour?" read the first two octets, so a
// covering line whose first character encoded to a plausible packet header took
// the binary path and the report was refused as malformed. It was found with
// three hand-picked covering lines, which is three samples of a space with a
// known shape: every two-octet UTF-8 lead is 0xC2-0xDF, and every one of those
// is also a new-format packet header for tags 2 to 31. So the whole class is
// enumerable, and enumerating it is cheaper than guessing which member of it
// somebody will paste.
func TestDecryptReadsArmourUnderAnyCoveringLine(t *testing.T) {
	t.Parallel()

	const plaintext = "a report pasted under a covering line"

	der, deriver := testCertificate(t)
	armoured := encryptTo(t, der, plaintext, true)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// Every two-octet UTF-8 lead, each of which is also a packet header.
	const (
		firstLead = 0xC2
		lastLead  = 0xDF
	)

	for lead := byte(firstLead); lead <= lastLead; lead++ {
		t.Run("a covering line beginning "+itoa(int(lead)), func(t *testing.T) {
			t.Parallel()

			// A two-octet character, then ordinary prose and a blank line.
			line := []byte{lead, 0x87}
			line = append(line, "opy of the report is below:\n\n"...)

			message := make([]byte, 0, len(line)+len(armoured))
			message = append(message, line...)
			message = append(message, armoured...)

			var got bytes.Buffer
			if err := openpgp.Decrypt(t.Context(), deriver, recipient,
				bytes.NewReader(message), &got); err != nil {
				t.Fatalf("a covering line beginning %#02x lost a report addressed to us: %v", lead, err)
			}

			if got.String() != plaintext {
				t.Errorf("recovered %q, want %q", got.String(), plaintext)
			}
		})
	}
}
