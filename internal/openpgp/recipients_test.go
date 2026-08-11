package openpgp_test

import (
	"bytes"
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

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
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

	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() {
		if err := exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run(); err != nil {
			t.Logf("stopping the gpg agent: %v", err)
		}
	})

	certPath := filepath.Join(home, "cert.pgp")
	if err := os.WriteFile(certPath, der, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	gpg := func(args ...string) {
		t.Helper()

		full := append([]string{"--homedir", home, "--batch", "--no-tty", "--yes"}, args...)

		var stderr bytes.Buffer

		cmd := exec.Command("gpg", full...)
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, stderr.String())
		}
	}

	gpg("--import", certPath)

	in := filepath.Join(home, "report.txt")
	if err := os.WriteFile(in, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	out := filepath.Join(home, "report.pgp")
	gpg("--trust-model", "always", "--encrypt",
		"--hidden-recipient", "security@example.invalid", "--output", out, in)

	message, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
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
	message := hideRecipients(t, encryptToMany(t, plaintext, other, ours))

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
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

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
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
		t.Errorf("the key service was called %d times for a message that is not ours", counting.calls)
	}
}

// hideRecipients rewrites every session-key packet's key id to the all-zero
// wildcard, which is what gpg --hidden-recipient emits.
func hideRecipients(t *testing.T, message []byte) []byte {
	t.Helper()

	out := append([]byte(nil), message...)

	hidden := 0

	for rest := out; len(rest) > 0; {
		pkt, err := encryption.ParsePacket(rest)
		if err != nil || pkt.Tag != encryption.TagPKESK {
			break
		}

		// The body's offset within out, so the key id can be zeroed in place.
		bodyStart := len(out) - len(rest) + (len(rest) - len(pkt.Body) - len(pkt.Rest))

		// Version, then eight octets of key id.
		for i := range 8 {
			out[bodyStart+1+i] = 0
		}

		hidden++

		rest = pkt.Rest
	}

	if hidden < 2 {
		t.Fatalf("anonymised %d session-key packets, want at least 2", hidden)
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
		newFormatPKESK   = 0xC0 | 1
	)

	body := []byte{pkeskVersion3}
	body = append(body, bytes.Repeat([]byte{0xAB}, 8)...) // somebody else's key id
	body = append(body, publicKeyAlgoRSA)

	// A 2048-bit RSA encrypted session key, as an MPI: bit count then octets.
	body = binary.BigEndian.AppendUint16(body, 2048)
	body = append(body, bytes.Repeat([]byte{0xCD}, 256)...)

	if len(body) >= 192 {
		// Two-octet new-format length, RFC 9580 4.2.1.
		n := len(body) - 192

		return append([]byte{newFormatPKESK, byte(n>>8) + 192, byte(n & 0xFF)}, body...)
	}

	return append([]byte{newFormatPKESK, byte(len(body))}, body...)
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
	message := repeatFirstPKESK(t, hideRecipients2(t, encryptToMany(t, "not for us", other)), 40)

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(ours))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	counting := &countingDeriver{SecretDeriver: deriver}

	err = openpgp.Decrypt(t.Context(), counting, recipient, bytes.NewReader(message), io.Discard)
	if !errors.Is(err, openpgp.ErrNotAddressed) {
		t.Fatalf("error = %v, want ErrNotAddressed", err)
	}

	if counting.calls > 8 {
		t.Errorf("the key service was called %d times; the cap is 8", counting.calls)
	}

	if counting.calls == 0 {
		t.Error("no candidate was tried at all, so the cap is not what stopped it")
	}
}

// hideRecipients2 anonymises a single-recipient message, which hideRecipients
// deliberately refuses to do — it guards against a fixture that silently stopped
// exercising the multi-packet path.
func hideRecipients2(t *testing.T, message []byte) []byte {
	t.Helper()

	out := append([]byte(nil), message...)

	pkt, err := encryption.ParsePacket(out)
	if err != nil || pkt.Tag != encryption.TagPKESK {
		t.Fatalf("first packet is not a session-key packet: %v", err)
	}

	bodyStart := len(out) - len(pkt.Body) - len(pkt.Rest)
	for i := range 8 {
		out[bodyStart+1+i] = 0
	}

	return out
}

// repeatFirstPKESK duplicates a message's leading session-key packet, standing
// in for a sender who addressed it to a great many hidden recipients.
func repeatFirstPKESK(t *testing.T, message []byte, count int) []byte {
	t.Helper()

	pkt, err := encryption.ParsePacket(message)
	if err != nil || pkt.Tag != encryption.TagPKESK {
		t.Fatalf("first packet is not a session-key packet: %v", err)
	}

	framed := message[:len(message)-len(pkt.Rest)]

	out := make([]byte, 0, len(framed)*count+len(pkt.Rest))
	for range count {
		out = append(out, framed...)
	}

	return append(out, pkt.Rest...)
}
