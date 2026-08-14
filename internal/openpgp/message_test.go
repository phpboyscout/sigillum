package openpgp_test

import (
	"bytes"
	"testing"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// How a message arrives, as opposed to what is inside it.
//
// A report reaches a security address pasted into a ticket, quoted in a mail
// body, or attached as binary — so deciding "is this armour or packets?" is
// the first thing the command does and the place a wrong answer costs a report.

// TestDecryptReadsArmourUnderACoveringLine is the user-facing half of the
// probe's structural checks.
//
// A report pasted into a ticket under a line of explanation is the arrival
// shape the how-to describes, and deciding "packets or armour?" from the first
// two octets broke it for any covering line whose first character encodes to a
// plausible packet header. U+0187 is 0xC6 0x87 — a public-key tag declaring 135
// octets, which any armour longer than that satisfies — so that paste took the
// binary path and was refused as malformed.
func TestDecryptReadsArmourUnderACoveringLine(t *testing.T) {
	t.Parallel()

	const plaintext = "a report pasted under a covering line"

	der, deriver := testCertificate(t)
	armoured := encryptTo(t, der, plaintext, true)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	for _, line := range []string{
		"Here is the report you asked for:\n\n",

		// Both begin with a character encoding to a packet-header-shaped pair.
		"Ƈopy of the report below:\n\n",
		"Ƅeport attached:\n\n",
	} {
		t.Run(line[:8], func(t *testing.T) {
			t.Parallel()

			message := append([]byte(line), armoured...)

			var got bytes.Buffer
			if err := openpgp.Decrypt(t.Context(), deriver, recipient,
				bytes.NewReader(message), &got); err != nil {
				t.Fatalf("a report under a covering line was refused: %v", err)
			}

			if got.String() != plaintext {
				t.Errorf("recovered %q, want %q", got.String(), plaintext)
			}
		})
	}
}

// TestDecryptIsNotHijackedByAnEmbeddedArmourHeader is the property the
// binary-first ordering was introduced for, and the one the covering-line
// tolerance must not cost.
//
// armor.Decode skips leading garbage, so it finds a header anywhere. An
// attacker composing a binary message chooses where to put one; decoding from
// their marker would discard the real packets and hand the operator a base64
// error where their report should be.
//
// Asking "is this already a packet stream?" first settles it without a
// preamble bound to choose: a valid binary message is consumed as binary, so a
// header inside its ciphertext is never reached.
//
// There were two copies of this test, in candidates_test.go and
// recipients_test.go, identical but for their wording. Neither file is about
// how a message arrives, which is why they drifted apart in name while staying
// the same in substance.
func TestDecryptIsNotHijackedByAnEmbeddedArmourHeader(t *testing.T) {
	t.Parallel()

	const plaintext = "a binary report carrying an armour header in its ciphertext"

	der, deriver := testCertificate(t)

	message := encryptTo(t, der, plaintext, false)
	message = append(message, "\n-----BEGIN PGP MESSAGE-----\n\nZm9v\n-----END PGP MESSAGE-----\n"...)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
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
