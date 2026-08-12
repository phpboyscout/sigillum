package openpgp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"gitlab.com/phpboyscout/go/encryption"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// Verification for the candidate-selection defects the third review found.
//
// All four live in addressedToUs and Decrypt, so all four tests exist before
// either is reshaped. Fixing them one at a time is how the previous two rounds
// generated their own regressions: a change to the loop that satisfies one case
// silently re-breaks its neighbour, and a test written afterwards records the
// new behaviour rather than the intended one.

// TestDecryptIsNotFooledByAPacketClaimingOurKeyID covers finding 02.
//
// addressedToUs keeps only the FIRST packet naming our key. A second one naming
// us is filed under `named` — somebody else's recipients — and can never be
// tried, even though Decrypt is now a loop.
//
// Anyone able to touch the message in the ticket system or in transit can
// prepend a packet carrying our key id and a corrupt wrapped key. No key
// material is needed: the key id is public, and it is the certificate's own
// fingerprint tail. The real packet is then unreachable, and the operator is
// told the report was encrypted to somebody else.
func TestDecryptIsNotFooledByAPacketClaimingOurKeyID(t *testing.T) {
	t.Parallel()

	const plaintext = "a genuine report, behind a packet that impersonates our key id"

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)

	// A copy of our own packet with the wrapped key corrupted. The ephemeral
	// point is untouched, so the derivation still succeeds and the failure is
	// an AES-KW integrity check — exactly what a forged packet looks like.
	forged := corruptWrappedKey(t, firstPacket(t, genuine))

	message := append(append([]byte(nil), forged...), genuine...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a report was lost behind a packet impersonating our key id: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptReportsAnUnwrapFailureAsSuchCoversFinding05 covers finding 05.
//
// The loop swallows ErrChecksum and ErrIntegrity and the terminal return
// re-labels the failure ErrNotAddressed, so a corrupt message or a wrong --key
// is reported as being for somebody else. The operator is sent to find a
// different certificate when the certificate is right.
func TestDecryptReportsAnUnwrapFailureAsSuchCoversFinding05(t *testing.T) {
	t.Parallel()

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, "a report that did not survive the journey", false)
	corrupt := append(corruptWrappedKey(t, firstPacket(t, genuine)), afterFirstPacket(t, genuine)...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(corrupt), io.Discard)
	if err == nil {
		t.Fatal("a corrupt wrapped key was accepted")
	}

	// The message named our key and the derivation was made and billed, so
	// "not addressed here" is the one thing this is not.
	if errors.Is(err, openpgp.ErrNotAddressed) {
		t.Errorf("error = %v, want an unwrap failure rather than ErrNotAddressed", err)
	}

	if !errors.Is(err, encryption.ErrIntegrity) && !errors.Is(err, encryption.ErrChecksum) {
		t.Errorf("error = %v, want it to wrap ErrIntegrity or ErrChecksum", err)
	}
}

// TestDecryptTriesTheNextCandidateAfterADerivationFailure covers finding 04.
//
// The loop advances only on ErrIntegrity/ErrChecksum, so a DeriveSharedSecret
// failure caused by one candidate's own ephemeral point ends the whole scan.
//
// A reporter sends gpg --hidden-recipient to a coordinating body on a different
// curve and to us, theirs written first. The key service rejects the other
// party's point as not on our curve; that matches neither sentinel, so the
// error is returned and our own packet — the very next candidate — is never
// tried. This is the previous round's finding 8 through a different door, and
// the comment above the switch asserts the opposite.
func TestDecryptTriesTheNextCandidateAfterADerivationFailure(t *testing.T) {
	t.Parallel()

	const plaintext = "a report behind a co-recipient on another curve"

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	// Somebody else's packet first, ours second, both anonymised — the shape
	// two --hidden-recipient arguments produce.
	message := hideRecipients(t, encryptToMany(t, plaintext, other, ours))

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	// Refuses the first candidate's point the way a key service refuses a point
	// that is not on the curve it holds, and succeeds for ours.
	picky := &pickyDeriver{
		SecretDeriver: deriver,
		reject:        ephemeralPointOf(t, firstPacket(t, message)),
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), picky, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a derivation failure on somebody else's packet ended the scan: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}

	if picky.rejected == 0 {
		t.Error("the fixture never exercised the rejecting path")
	}
}

// TestDecryptKeyServiceCostIsWhatWeDocument covers finding 03.
//
// The property "a message that is genuinely not ours still costs nothing" was
// true when a named key id could be compared before any call. A wildcard packet
// names nobody, so it can only be ruled out by attempting it — and decision D1
// narrows the property rather than defending it.
//
// Both halves are pinned here, because the narrowing is only safe if the half
// that still holds keeps holding: a message naming other keys must remain free.
func TestDecryptKeyServiceCostIsWhatWeDocument(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	t.Run("named recipients only, still free", func(t *testing.T) {
		t.Parallel()

		message := encryptToMany(t, "not for us", other)

		recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
		if err != nil {
			t.Fatalf("ReadRecipient: %v", err)
		}

		counting := &countingDeriver{SecretDeriver: deriver}

		err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
		if !errors.Is(err, openpgp.ErrNotAddressed) {
			t.Fatalf("error = %v, want ErrNotAddressed", err)
		}

		if counting.calls != 0 {
			t.Errorf("a message naming only other keys cost %d key-service calls, want 0", counting.calls)
		}
	})

	t.Run("a hidden recipient costs one call", func(t *testing.T) {
		t.Parallel()

		message := hideRecipients2(t, encryptToMany(t, "not for us", other))

		recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
		if err != nil {
			t.Fatalf("ReadRecipient: %v", err)
		}

		counting := &countingDeriver{SecretDeriver: deriver}

		err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
		if !errors.Is(err, openpgp.ErrNotAddressed) {
			t.Fatalf("error = %v, want ErrNotAddressed", err)
		}

		// The point of the narrowing: this is not free, and the documentation
		// must not claim it is.
		//
		// One hidden packet, so exactly one call. This subtest used to be named
		// "hidden recipients cost, and are bounded" and carried a `calls > 8`
		// check alongside — on a message with a single hidden packet, where the
		// count could never approach eight. The bound is a separate property
		// needing a separate fixture, and it is the subtest below.
		if counting.calls != 1 {
			t.Errorf("one hidden recipient cost %d key-service calls, want exactly 1", counting.calls)
		}
	})

	t.Run("hidden recipients are bounded", func(t *testing.T) {
		t.Parallel()

		// Twenty distinct hidden candidates, comfortably past the ceiling, so
		// the ceiling is what stops the run rather than running out of packets.
		message := repeatFirstPKESK(t, hideRecipients2(t, encryptToMany(t, "not for us", other)), 20)

		recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
		if err != nil {
			t.Fatalf("ReadRecipient: %v", err)
		}

		counting := &countingDeriver{SecretDeriver: deriver}

		err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
		if !errors.Is(err, openpgp.ErrNotAddressed) {
			t.Fatalf("error = %v, want ErrNotAddressed", err)
		}

		if counting.calls != 8 {
			t.Errorf("20 hidden candidates cost %d key-service calls, want exactly the cap, 8",
				counting.calls)
		}
	})
}

// pickyDeriver refuses one specific ephemeral point, the way a key service
// refuses a point that is not on the curve it holds.
type pickyDeriver struct {
	openpgp.SecretDeriver

	reject   []byte
	rejected int
}

func (d *pickyDeriver) DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error) {
	if bytes.Equal(peerPoint, d.reject) {
		d.rejected++

		return nil, errors.New("kms: ValidationException: the point is not on the curve this key uses")
	}

	return d.SecretDeriver.DeriveSharedSecret(ctx, peerPoint)
}

// firstPacket returns the framed leading packet of a message.
func firstPacket(t *testing.T, message []byte) []byte {
	t.Helper()

	pkt, err := encryption.ParsePacket(message)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	return append([]byte(nil), message[:len(message)-len(pkt.Rest)]...)
}

// afterFirstPacket returns everything following the leading packet.
func afterFirstPacket(t *testing.T, message []byte) []byte {
	t.Helper()

	pkt, err := encryption.ParsePacket(message)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	return append([]byte(nil), pkt.Rest...)
}

// corruptWrappedKey flips the last octet of a session-key packet, which is
// inside the wrapped key — so the ephemeral point still derives and the failure
// is the AES-KW integrity check rather than a curve error.
func corruptWrappedKey(t *testing.T, framed []byte) []byte {
	t.Helper()

	out := append([]byte(nil), framed...)
	out[len(out)-1] ^= 0xFF

	return out
}

// ephemeralPointOf returns the ephemeral point a session-key packet carries.
func ephemeralPointOf(t *testing.T, framed []byte) []byte {
	t.Helper()

	pkt, err := encryption.ParsePacket(framed)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	pkesk, err := encryption.ParsePKESK(pkt.Body)
	if err != nil {
		t.Fatalf("ParsePKESK: %v", err)
	}

	return pkesk.EphemeralPoint
}

// TestDecryptAcceptsArmourWithACoveringLine covers finding 08.
//
// looksArmoured anchors the `-----BEGIN ` probe at byte zero after whitespace,
// so armour preceded by any text is fed to the packet parser as binary.
//
// A report pasted into a confidential ticket — the arrival shape the how-to
// describes — routinely carries a covering line, a quoted header, or a From:
// block from a saved .eml. armor.Decode skipped leading garbage and handled all
// of them. The operator now gets "no session-key packet at the start of the
// message" for a perfectly good report, with nothing naming the leading line.
//
// Decision D2 resolves this by attempting a binary parse first and only then
// looking for armour, which removes the hijack by construction rather than by
// choosing a preamble bound. Both halves are pinned here.
func TestDecryptAcceptsArmourWithACoveringLine(t *testing.T) {
	t.Parallel()

	const plaintext = "a report pasted into a ticket under a covering line"

	der, deriver := testCertificate(t)

	armoured := encryptTo(t, der, plaintext, true)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	for _, tc := range []struct {
		name     string
		preamble string
	}{
		{"no preamble", ""},
		{"a covering line", "Here is the report:\n\n"},
		{"a quoted mail header", "From: researcher@example.invalid\nSubject: security issue\n\n"},
		{"an indented paste", "    \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			message := append([]byte(tc.preamble), armoured...)

			var got bytes.Buffer
			if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
				t.Fatalf("armoured report refused: %v", err)
			}

			if got.String() != plaintext {
				t.Errorf("recovered %q, want %q", got.String(), plaintext)
			}
		})
	}
}

// TestDecryptStillRefusesAnEmbeddedArmourHijack is the property the anchoring
// was introduced for, and which the fix for the covering line must not lose.
//
// armor.Decode skips leading garbage, so it finds a header anywhere. An
// attacker composing a binary message chooses where to put one; decoding from
// their marker discards the real packets and hands the operator a base64 error
// where their report should be.
func TestDecryptStillRefusesAnEmbeddedArmourHijack(t *testing.T) {
	t.Parallel()

	const plaintext = "a binary report carrying an armour header in its ciphertext"

	der, deriver := testCertificate(t)

	message := encryptTo(t, der, plaintext, false)
	message = append(message, "\n-----BEGIN PGP MESSAGE-----\n\nZm9v\n-----END PGP MESSAGE-----\n"...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a binary message containing an armour header was hijacked: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// Round four's findings on this file were the same mistake as round three's,
// one layer out: a bound that fired discarded what it had learned, and the cap
// counted packets an attacker supplies. These test around each boundary.

// TestDecryptIsNotCrowdedOutByRepeatedPackets covers the cap being used as the
// attack rather than the defence.
//
// maxDerivations counts every candidate, including ones naming our key id — and
// the key id is public. Copying the message's own session-key packet eight
// times, with the wrapped key corrupted, pushes the genuine packet past the cap
// so it is never tried, and the operator is told the report was for somebody
// else. That is finding 02 again at a threshold of eight instead of one.
func TestDecryptIsNotCrowdedOutByRepeatedPackets(t *testing.T) {
	t.Parallel()

	const plaintext = "a report behind a pile of forged packets"

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)
	leading := firstPacket(t, genuine)

	// Twelve distinct forgeries, past the cap of eight, each naming our key id
	// with a wrapped key that will not open.
	var message []byte

	for i := range 12 {
		forged := append([]byte(nil), leading...)
		forged[len(forged)-1] ^= byte(i + 1)
		message = append(message, forged...)
	}

	message = append(message, genuine...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer

	// The report must be RECOVERED. An earlier version of this test accepted
	// "either the genuine packet is reached, or the run stops at the cap",
	// which made the defect one of its passing outcomes — the assertion was
	// weakened until the code satisfied it, and the property fuzz target
	// inherited the same weakness, so neither could ever have caught this.
	//
	// Forging a packet that names us requires modifying the message in
	// transit, and an attacker with that capability can delete it outright.
	// Losing the report to a cost ceiling is therefore never an acceptable
	// outcome: the ceiling exists for unauthenticated senders, who cannot
	// produce these at all.
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a report behind %d forged packets was not recovered: %v", 12, err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptSurvivesManyForgedNamedPackets is the same attack at a scale no
// tuning of a ceiling could absorb.
//
// Two hundred forged packets, each naming this certificate with a distinct
// wrapped key so nothing collapses them. The point is that bounding named
// candidates cannot be made safe by choosing a larger number — the attacker
// picks the count — so the answer is not to bound them at all.
//
// Affordable to assert because the local backend makes an attempt free; against
// a billed key service this test would be the very cost the ceiling exists to
// prevent, which is precisely why the two properties had to be separated before
// either could be tested honestly.
func TestDecryptSurvivesManyForgedNamedPackets(t *testing.T) {
	t.Parallel()

	const (
		plaintext = "a report behind two hundred forgeries"
		forgeries = 200
	)

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)
	leading := firstPacket(t, genuine)

	var message []byte

	for i := range forgeries {
		forged := append([]byte(nil), leading...)
		forged[len(forged)-1] ^= byte(i%255 + 1)
		message = append(message, forged...)
	}

	message = append(message, genuine...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a report behind %d forged packets was not recovered: %v", forgeries, err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptStillBoundsHiddenRecipientGuesses is the other half, now testable
// on its own.
//
// A wildcard names nobody, so ruling one out costs a billed call — and anyone
// can send a message full of them without modifying anything. That is the case
// the ceiling exists for, and it is unaffected by no longer bounding named
// packets.
func TestDecryptStillBoundsHiddenRecipientGuesses(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	message := repeatFirstPKESK(t, hideRecipients2(t, encryptToMany(t, "not for us", other)), 60)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	if err := openpgp.Decrypt(t.Context(), counting, recipient,
		bytes.NewReader(message), io.Discard); err == nil {
		t.Fatal("a message for somebody else was accepted")
	}

	// Exactly the ceiling. With sixty distinct candidates the count is
	// determined, so "at most eight, and not zero" — which is what this
	// asserted before — admits the run stopping for some other reason without
	// the ceiling ever being reached. It did exactly that: the fixture emitted
	// sixty identical packets, which deduplicate to one candidate and one call.
	if counting.calls != 8 {
		t.Errorf("the key service was called %d times for 60 hidden candidates; want exactly the ceiling, 8",
			counting.calls)
	}
}

// TestDecryptIgnoresDuplicateCandidates is the cheaper half of the same attack:
// the identical packet repeated costs nothing with the cap, because trying it
// twice can only fail twice.
func TestDecryptIgnoresDuplicateCandidates(t *testing.T) {
	t.Parallel()

	const plaintext = "a report behind copies of one forged packet"

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)
	forged := corruptWrappedKey(t, firstPacket(t, genuine))

	var message []byte
	for range 30 {
		message = append(message, forged...)
	}

	message = append(message, genuine...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("thirty copies of one packet hid the report: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}

	// The duplicates collapse to one attempt, so the genuine packet is the
	// second call rather than the thirty-first.
	if counting.calls > 2 {
		t.Errorf("the key service was called %d times for one duplicated packet", counting.calls)
	}
}

// TestDecryptKeepsTheReasonWhenTheCapIsReached covers the failures the cap
// discarded.
//
// Hitting the cap returned a bare ErrNotAddressed, throwing away the key-service
// failure the loop had accumulated — so an unreachable key service was reported
// as "this message is not for you" and the operator went hunting for a
// different certificate while their credentials were the fault.
func TestDecryptKeepsTheReasonWhenTheCapIsReached(t *testing.T) {
	t.Parallel()

	der, _ := testCertificate(t)
	other, _ := testCertificate(t)

	// More hidden candidates than the cap, none of them ours.
	message := repeatFirstPKESK(t, hideRecipients2(t, encryptToMany(t, "not for us", other)), 30)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	outage := errors.New("kms: ExpiredTokenException: the security token has expired")

	failing := &failingDeriverWith{err: outage}

	err = openpgp.Decrypt(t.Context(), failing, recipient, bytes.NewReader(message), io.Discard)
	if err == nil {
		t.Fatal("an unreachable key service was reported as success")
	}

	// The cap must be what ended the run, or the test's name is a claim about a
	// path it never took. It was: the fixture's thirty packets were identical
	// and deduplicated to one candidate, so this reached the cap on no run at
	// all and still passed.
	if failing.calls != 8 {
		t.Fatalf("the run made %d derivations of 30 candidates; the cap is 8, so it did not end at the cap",
			failing.calls)
	}

	if !errors.Is(err, outage) {
		t.Errorf("error = %v, want it to carry the key-service failure", err)
	}

	if errors.Is(err, openpgp.ErrNotAddressed) {
		t.Error("a key-service outage was reported as the message being addressed elsewhere")
	}
}

// failingDeriverWith fails every derivation with one error, standing in for
// expired credentials or an unreachable endpoint.
type failingDeriverWith struct {
	err   error
	calls int
}

func (d *failingDeriverWith) DeriveSharedSecret(context.Context, []byte) ([]byte, error) {
	d.calls++

	return nil, d.err
}

func (d *failingDeriverWith) CoordinateBytes() int { return 32 }

// TestDecryptBillsOneDerivationPerEphemeralPoint is the cost half of accepting
// packets that name us.
//
// The key id naming this certificate is the tail of its published fingerprint,
// so composing packets that carry it needs no key material and no interception.
// A stranger can simply send one message full of them to the published address.
//
// Those packets are deliberately not capped — see maxGuesses for why capping
// them loses genuine reports — so what bounds the cost instead is that the
// billed operation depends on the ephemeral point alone. Copies sharing a point
// are one key-service call between them, however many there are.
//
// Measured before that memo existed: 5,000 such packets produced 5,001 billed
// derivations, and the report still decrypted, so nothing failed loudly enough
// to notice. The message bound is 128 MiB and one of these packets is about a
// hundred octets, which put the ceiling at roughly a million calls per message.
func TestDecryptBillsOneDerivationPerEphemeralPoint(t *testing.T) {
	t.Parallel()

	const (
		plaintext = "a report behind a great many forged packets"
		forgeries = 500
	)

	der, deriver := testCertificate(t)

	genuine := encryptTo(t, der, plaintext, false)
	leading := firstPacket(t, genuine)

	// Each forgery names our key id and reuses the genuine ephemeral point,
	// varying only the wrapped key — one XOR per packet, and the cheapest
	// version of this attack.
	var message []byte

	for i := range forgeries {
		forged := append([]byte(nil), leading...)
		forged[len(forged)-1] ^= byte(i%255 + 1)
		forged[len(forged)-2] ^= byte(i / 255)
		message = append(message, forged...)
	}

	message = append(message, genuine...)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("a report behind %d forged packets was not recovered: %v", forgeries, err)
	}

	// Recovery first: the memo must not have changed any verdict.
	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}

	// One point, so one billed call, regardless of how many packets carried it.
	if counting.calls != 1 {
		t.Errorf("%d packets sharing one ephemeral point cost %d billed derivations, want 1",
			forgeries+1, counting.calls)
	}
}
