package openpgp_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"gitlab.com/phpboyscout/go/encryption"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// How a message addresses us, which is not always simply and not always first.
//
// A report arrives from a stranger using whatever client they have, configured
// however they configured it. Two shapes are ordinary and neither is what a
// hand-built test fixture produces: a message sent to more than one recipient,
// and one sent with the recipient deliberately hidden.

// TestDecryptFindsOurPKESKAmongSeveral covers a reporter who copies in a second
// contact — their own address, a colleague, a coordinating body.
//
// One PKESK is emitted per recipient, in recipient order, so ours is first only
// by luck. Refusing the message because somebody else's key came first would be
// a failure the reporter cannot diagnose and we would blame on them.
func TestDecryptFindsOurPKESKAmongSeveral(t *testing.T) {
	t.Parallel()

	const plaintext = "a report sent to two contacts"

	ours, deriver := testCertificate(t)
	theirs, _ := testCertificate(t)

	// Theirs first, so ours is not the packet firstPacket would return.
	message := encryptToMany(t, plaintext, theirs, ours)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
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
}

// TestDecryptAcceptsAHiddenRecipient covers `gpg --hidden-recipient`, which
// common disclosure advice recommends so an intercepted message does not reveal
// who it was for.
//
// It produces an all-zero key id — the wildcard encryption.PKESK documents as
// "an anonymous recipient". Refusing it means a reporter who followed good
// advice writes a report we can never open.
func TestDecryptAcceptsAHiddenRecipient(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not on PATH; skipping hidden-recipient interoperability")
	}

	const plaintext = "a report from someone who hid the recipient"

	der, deriver := testCertificate(t)

	home, gpg := gpgHome(t)

	importedCertificate(t, home, gpg, der)

	in := writtenReport(t, home, plaintext)

	out := filepath.Join(home, "report.pgp")
	gpg("--trust-model", "always", "--encrypt",
		"--hidden-recipient", "security@example.invalid", "--output", out, in)

	message, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("decrypting a hidden-recipient message: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptStillRefusesAMessageForSomebodyElse guards the property the
// multi-recipient walk must not lose: a message with no PKESK for us is still
// refused, and still without contacting the key service.
func TestDecryptStillRefusesAMessageForSomebodyElse(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	a, _ := testCertificate(t)
	b, _ := testCertificate(t)

	message := encryptToMany(t, "not for us", a, b)

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
		t.Errorf("the key service was called %d times for a message that is not ours", counting.calls)
	}
}

// encryptToMany composes one message addressed to several certificates, in the
// order given.
func encryptToMany(t *testing.T, plaintext string, certs ...[]byte) []byte {
	t.Helper()

	var entities []*pgp.Entity

	for _, der := range certs {
		read, err := pgp.ReadKeyRing(bytes.NewReader(der))
		if err != nil {
			t.Fatalf("reading a certificate: %v", err)
		}

		entities = append(entities, read...)
	}

	var buf bytes.Buffer

	w, err := pgp.Encrypt(&buf, entities, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	return buf.Bytes()
}

// TestDecryptTriesEveryHiddenRecipient covers two hidden recipients with ours
// second, which is what a reporter produces by copying in a coordinating body
// and hiding both.
//
// Taking only the first wildcard packet means the unwrap fails its integrity
// check and the operator is told the session key did not check out — which the
// CLI reference documents as "usually the wrong certificate" — for a message
// that is genuinely theirs and that the very next packet would have opened.
func TestDecryptTriesEveryHiddenRecipient(t *testing.T) {
	t.Parallel()

	const plaintext = "a report copied to a coordinating body, both hidden"

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	// Somebody else's packet first, then ours, then both anonymised — the shape
	// gpg --hidden-recipient produces, built deterministically so the test does
	// not depend on the order gpg happens to emit.
	message := hideRecipients(t, encryptToMany(t, plaintext, other, ours), 2)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("decrypting a message whose hidden packet is second: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptSkipsACoRecipientItCannotRead covers the commonest real
// co-recipient: somebody on an RSA key.
//
// encryption.ParsePKESK reports RSA as unsupported, and propagating that fails
// the whole message over a stranger's key while ours sits in the very next
// packet. The same applies to a version 6 packet from a modern sender.
func TestDecryptSkipsACoRecipientItCannotRead(t *testing.T) {
	t.Parallel()

	const plaintext = "a report copied to someone still on RSA"

	ours, deriver := testCertificate(t)

	message := append(rsaSessionKeyPacket(t), encryptToMany(t, plaintext, ours)...)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(message), &got); err != nil {
		t.Fatalf("decrypting past an RSA co-recipient: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// TestDecryptRefusesWhenEveryPacketIsUnreadable is the other half: skipping a
// packet must not turn "addressed to somebody else" into "malformed", which
// would send the operator looking at the report rather than at who it was for.
func TestDecryptRefusesWhenEveryPacketIsUnreadable(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	message := append(rsaSessionKeyPacket(t), encryptToMany(t, "not for us", other)...)

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
		t.Errorf("the key service was called %d times for a message that is not ours", counting.calls)
	}
}

// hideRecipients rewrites every session-key packet's key id to the all-zero
// wildcard, which is what `gpg --hidden-recipient` produces.
//
// want is how many packets the caller expects to anonymise, and it is checked
// rather than assumed. There were two of these: one insisting on at least two
// packets and one insisting on exactly the first, so a fixture that quietly
// stopped exercising the multi-packet path would fail one and pass the other,
// and the difference between them was a hand-computed offset expression rather
// than anything meaningful. One helper, with the expectation as an argument.
func hideRecipients(t *testing.T, message []byte, want int) []byte {
	t.Helper()

	out := append([]byte(nil), message...)

	// A version 3 PKESK body opens with a version octet, then eight of key id.
	const (
		keyIDOffset = 1
		keyIDOctets = 8
	)

	hidden := 0

	for rest := out; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil || pkt.Tag != encryption.TagPKESK {
			break
		}

		// The body's offset within out, so the key id can be zeroed in place.
		//
		// The len(rest) terms of the obvious form — where this sits in out, plus
		// where the body sits in rest — cancel, leaving the body's distance from
		// the end of the message. Written the short way with the reason stated,
		// rather than the long way that invited checking the arithmetic twice.
		bodyStart := len(out) - len(pkt.Body) - len(pkt.Rest)

		for i := range keyIDOctets {
			out[bodyStart+keyIDOffset+i] = 0
		}

		hidden++

		rest = pkt.Rest
	}

	if hidden != want {
		t.Fatalf("anonymised %d session-key packets, want %d — the fixture is not the shape the test names",
			hidden, want)
	}

	return out
}

// rsaSessionKeyPacket builds a version 3 session-key packet for an RSA
// recipient, which this package parses as unsupported.
func rsaSessionKeyPacket(t *testing.T) []byte {
	t.Helper()

	const (
		pkeskVersion3    = 3
		publicKeyAlgoRSA = 1
		tagPKESK         = 1
	)

	body := []byte{pkeskVersion3}
	body = append(body, bytes.Repeat([]byte{0xAB}, 8)...) // somebody else's key id
	body = append(body, publicKeyAlgoRSA)

	// A 2048-bit RSA encrypted session key, as an MPI: bit count then octets.
	body = binary.BigEndian.AppendUint16(body, 2048)
	body = append(body, bytes.Repeat([]byte{0xCD}, 256)...)

	return framePacket(t, tagPKESK, body)
}

// TestDecryptCapsTheNumberOfDerivations is the cost half of trying every
// hidden recipient.
//
// A hidden packet can only be ruled out by attempting it, and each attempt is
// one billed key-service call. A message is bounded at 128 MiB and a session-key
// packet is a few hundred octets, so without a ceiling anyone who can write to
// the published security address can turn one inbound report into hundreds of
// thousands of KMS requests — a billing and rate-limit amplifier reachable
// without authenticating.
func TestDecryptCapsTheNumberOfDerivations(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)
	other, _ := testCertificate(t)

	// Far more anonymous packets than the cap, none of them ours.
	message := repeatFirstPKESK(t, hideRecipients(t, encryptToMany(t, "not for us", other), 1), 40)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
	// The ceiling, not "addressed elsewhere". Twenty-four candidates were never
	// tried, so nothing here establishes who the message is for.
	if !errors.Is(err, openpgp.ErrCostCeiling) {
		t.Fatalf("error = %v, want ErrCostCeiling", err)
	}

	if errors.Is(err, openpgp.ErrNotAddressed) {
		t.Errorf("stopping at the ceiling was reported as the message being addressed elsewhere: %v", err)
	}

	// EXACTLY the cap, not "at most".
	//
	// "At most" is what this asserted before, alongside a separate check that
	// the count was not zero. Both held at one call — the fixture's forty
	// identical packets deduplicated to a single candidate — so the pair
	// admitted the one outcome that proves nothing: the run stopped for a
	// reason other than the ceiling, and the ceiling was never reached.
	//
	// With forty candidates on distinct ephemeral points the count is
	// determined: the ceiling stops it at sixteen. Any other number is a
	// defect, in either direction.
	if counting.calls != 16 {
		t.Errorf("the key service was called %d times for 40 hidden candidates; want exactly the cap, 16",
			counting.calls)
	}
}

// repeatFirstPKESK copies a message's leading session-key packet count times,
// each copy DISTINCT, standing in for a sender — or an attacker — who addressed
// it to a great many hidden recipients.
//
// The copies must differ, and that is the whole reason this helper is not three
// lines of bytes.Repeat.
//
// chooseRecipients deduplicates candidates on the wrapped key and the ephemeral
// point, and says in its own comment that this is "deliberately not a defence"
// because every octet of that key is one the attacker chose. It is right. But
// this helper used to emit identical copies, so the dedup collapsed all of them
// to a single candidate: the tests for the guess ceiling built forty, sixty and
// thirty packets and every one of them made exactly ONE key-service call. The
// ceiling they exist to prove was never reached, and all three passed.
//
// Varying one octet of the wrapped key is what an attacker does for free, and
// it is enough to defeat the dedup while leaving the ephemeral point valid — so
// the derivation succeeds and the unwrap fails, which is the expensive path.
func repeatFirstPKESK(t *testing.T, message []byte, count int) []byte {
	t.Helper()

	pkt, err := encryption.ParsePacket(message)
	if err != nil || pkt.Tag != encryption.TagPKESK {
		t.Fatalf("first packet is not a session-key packet: %v", err)
	}

	// Parsed as a PKESK too, because the point's length is what a fresh one
	// must match and only the PKESK layout knows it.
	pkesk, err := encryption.ParsePKESK(pkt.Body)
	if err != nil {
		t.Fatalf("the leading packet does not parse as a PKESK: %v", err)
	}

	out := make([]byte, 0, (len(pkt.Body)+5)*count+len(pkt.Rest))

	for i := range count {
		body := append([]byte(nil), pkt.Body...)

		// A fresh ephemeral point per copy, which is what makes each one a
		// separate billed derivation.
		//
		// Varying the wrapped key alone is not enough and used to be all this
		// did. The derivation depends on the point, so Decrypt memoises on it
		// and copies sharing a point cost one call between them however many
		// there are — the right behaviour, and the reason that variant of the
		// attack is now cheap to absorb. Reaching the ceiling takes points the
		// memo cannot collapse, which costs the attacker one EC keypair each.
		replaceEphemeralPoint(t, body, freshPoint(t, len(pkesk.EphemeralPoint)))

		// The wrapped key varies too. Not for the dedup — the fresh point above
		// already makes every dedup key distinct — but so that each copy is a
		// different packet rather than the genuine one repeated, which is what
		// a caller passing this fixture expects it to be.
		body[len(body)-1] ^= byte(i)
		if len(body) > 1 {
			body[len(body)-2] ^= byte(i >> 8)
		}

		out = append(out, framePacket(t, encryption.TagPKESK, body)...)
	}

	assertDistinctPKESKs(t, out, count)

	return append(out, pkt.Rest...)
}

// assertDistinctPKESKs checks the fixture built what it claims, because the
// defect this helper was written to fix was invisible from the tests using it.
func assertDistinctPKESKs(t *testing.T, packets []byte, want int) {
	t.Helper()

	seen := make(map[string]bool, want)

	for rest := packets; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil {
			t.Fatalf("re-parsing the fixture: %v", err)
		}

		seen[string(pkt.Body)] = true
		rest = pkt.Rest
	}

	if len(seen) != want {
		t.Fatalf("the fixture holds %d distinct session-key packets, want %d — "+
			"identical copies are deduplicated and never reach the guess ceiling", len(seen), want)
	}
}

// TestDecryptClassifiesACorruptArmouredMessage covers the commonest real input
// problem: a truncated or mangled armoured paste.
//
// The CLI reference documents this row as "malformed message", and a caller
// distinguishing it from a size or addressing failure needs errors.Is to agree.
// The base64 failure surfaces from reading the decoded block, where nothing had
// attached the sentinel.
func TestDecryptClassifiesACorruptArmouredMessage(t *testing.T) {
	t.Parallel()

	ours, deriver := testCertificate(t)

	armoured := encryptTo(t, ours, "a report that did not survive the paste", true)

	// Corrupt the base64 payload, leaving the armour frame intact — which is
	// what a truncated copy out of a ticket looks like.
	corrupt := bytes.Replace(armoured, []byte("\n\n"), []byte("\n\n!!!!\n"), 1)

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	err = openpgp.Decrypt(t.Context(), deriver, recipient, bytes.NewReader(corrupt), io.Discard)
	if !errors.Is(err, openpgp.ErrMalformedMessage) {
		t.Fatalf("error = %v, want ErrMalformedMessage", err)
	}
}

// pkeskPointOffset is where a version 3 PKESK body's ephemeral point begins:
// one version octet, eight of key id, one algorithm octet and the MPI's
// two-octet bit count. RFC 9580 5.1 and RFC 6637 8.
const pkeskPointOffset = 12

// freshPoint returns a valid, previously unused uncompressed point of the given
// length, on whichever NIST curve has points that size.
//
// Valid rather than random bytes, because the key service refuses a point that
// is not on its curve — a fixture of random points would exercise the rejection
// path instead of the cost path, and the two are counted differently.
func freshPoint(t *testing.T, length int) []byte {
	t.Helper()

	var curve ecdh.Curve

	switch length {
	case 65:
		curve = ecdh.P256()
	case 97:
		curve = ecdh.P384()
	case 133:
		curve = ecdh.P521()
	default:
		t.Fatalf("no NIST curve has a %d-octet uncompressed point", length)
	}

	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an ephemeral point: %v", err)
	}

	return key.PublicKey().Bytes()
}

// replaceEphemeralPoint overwrites a PKESK body's point in place.
//
// Same length and the same 0x04 uncompressed prefix, so the MPI's bit count
// stays correct without recomputing it — a point of a different size would need
// the length rewritten and would no longer be the packet under test.
func replaceEphemeralPoint(t *testing.T, body, point []byte) {
	t.Helper()

	if len(body) < pkeskPointOffset+len(point) {
		t.Fatalf("PKESK body is %d octets, too short to hold a %d-octet point at %d",
			len(body), len(point), pkeskPointOffset)
	}

	if got := body[pkeskPointOffset]; got != 0x04 {
		t.Fatalf("the point at offset %d begins %#02x, want 0x04 — the layout is not what this assumes",
			pkeskPointOffset, got)
	}

	copy(body[pkeskPointOffset:], point)
}
