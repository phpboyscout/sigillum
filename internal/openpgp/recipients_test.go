package openpgp_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

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
