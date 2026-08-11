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

	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run() //nolint:errcheck // best effort.
	})

	der, deriver := testCertificate(t)

	certPath := filepath.Join(home, "cert.pgp")
	if err := os.WriteFile(certPath, der, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	gpg := func(args ...string) {
		t.Helper()

		full := append([]string{"--homedir", home, "--batch", "--no-tty", "--yes"}, args...)

		cmd := exec.Command("gpg", full...)

		var stderr bytes.Buffer

		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
		}
	}

	gpg("--import", certPath)

	in := filepath.Join(home, "report.txt")
	if err := os.WriteFile(in, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	// Armoured, because that is how a report arrives: pasted into a ticket or
	// an email body rather than attached as binary.
	out := filepath.Join(home, "report.asc")
	gpg("--trust-model", "always", "--armor", "--encrypt",
		"--recipient", "security@example.invalid", "--output", out, in)

	message, err := os.Open(out)
	if err != nil {
		t.Fatalf("open message: %v", err)
	}

	defer message.Close() //nolint:errcheck // read-only.

	recipient, err := openpgp.ReadRecipient(bytes.NewReader(der))
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
