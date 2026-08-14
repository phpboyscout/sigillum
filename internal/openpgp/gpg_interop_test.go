package openpgp_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	openpgp "gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// The full end-to-end against the implementation a reporter actually uses.
//
// The core proves it can recover a session key from a message gpg composed.
// This proves the rest: that the encrypted body opens and the plaintext comes
// back out — which is the whole job of this module, and the one thing a person
// on the security rota cares about.
//
// Skips when gpg is absent so a developer without it is not blocked; CI has it.

func TestDecryptsAMessageComposedByGPG(t *testing.T) {
	t.Parallel()

	const plaintext = "SQL injection in /api/v1/search, PoC attached\n"

	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not on PATH; skipping GnuPG interoperability")
	}

	home, gpg := gpgHome(t)

	der, deriver := testCertificate(t)

	importedCertificate(t, home, gpg, der)

	in := writtenReport(t, home, plaintext)

	// Armoured, because that is how a report arrives: pasted into a ticket or
	// an email body rather than attached as binary.
	out := filepath.Join(home, "report.asc")
	gpg("--trust-model", "always", "--armor", "--encrypt",
		"--recipient", "security@example.invalid", "--output", out, in)

	message, err := os.Open(out)
	if err != nil {
		t.Fatalf("open message: %v", err)
	}

	defer func() {
		if err := message.Close(); err != nil {
			t.Errorf("closing the message: %v", err)
		}
	}()

	recipient, _, err := openpgp.ReadRecipient(bytes.NewReader(der))
	if err != nil {
		t.Fatalf("ReadRecipient: %v", err)
	}

	var got bytes.Buffer
	if err := openpgp.Decrypt(t.Context(), deriver, recipient, message, &got); err != nil {
		t.Fatalf("decrypting a message gpg composed: %v", err)
	}

	if got.String() != plaintext {
		t.Errorf("recovered %q, want %q", got.String(), plaintext)
	}
}

// gpgHome prepares an isolated GnuPG home and returns a runner bound to it.
//
// Both interoperability tests had their own verbatim copy of this — the same
// chmod, the same agent cleanup, the same argument prefix and the same stderr
// capture. Two copies of a fixture drift, and a fixture that drifts makes one
// of the two tests quietly stop testing what it says it does.
//
// The runner fails the test on a non-zero exit rather than returning an error:
// every call is setup, and a gpg that did not run means the test never reached
// its subject.
func gpgHome(t *testing.T) (string, func(args ...string)) {
	t.Helper()

	home := t.TempDir()

	// gpg refuses a world-readable home and says so only on stderr.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() {
		// Reported rather than discarded: a surviving agent holds the home
		// directory open, and the next test then inherits state that makes a
		// failure look cryptographic.
		if err := exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run(); err != nil {
			t.Logf("could not stop the gpg agent for %s: %v", home, err)
		}
	})

	return home, func(args ...string) {
		t.Helper()

		full := append([]string{"--homedir", home, "--batch", "--no-tty", "--yes"}, args...)

		var stderr bytes.Buffer

		cmd := exec.Command("gpg", full...)
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
		}
	}
}

// importedCertificate writes der into home and imports it, returning its path.
func importedCertificate(t *testing.T, home string, gpg func(...string), der []byte) string {
	t.Helper()

	path := filepath.Join(home, "cert.pgp")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	gpg("--import", path)

	return path
}

// writtenReport writes the plaintext a test will ask gpg to encrypt.
func writtenReport(t *testing.T, home, plaintext string) string {
	t.Helper()

	path := filepath.Join(home, "report.txt")
	if err := os.WriteFile(path, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	return path
}
