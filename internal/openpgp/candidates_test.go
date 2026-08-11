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

	t.Run("hidden recipients cost, and are bounded", func(t *testing.T) {
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
		if counting.calls == 0 {
			t.Error("a hidden recipient was ruled out without a key-service call, which is not possible")
		}

		if counting.calls > 8 {
			t.Errorf("the key service was called %d times; the cap is 8", counting.calls)
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
