package certificate

import (
	"errors"
	"strings"
	"testing"
)

// TestCheckFlagsReportsTheSameMissingFlagEveryTime covers finding 25.
//
// checkFlags USED TO range over a map literal, and Go randomises map iteration
// order — so with more than one flag missing, which one was named varied
// between runs. An operator who omitted two flags was told about a different
// one each time they re-ran, which makes reproducible support guesswork, and
// any test asserting a specific message was flaky by construction rather than
// by accident.
//
// It ranges over a slice now and reports every missing flag, so the message is
// determined. This is what keeps it that way: the defect is invisible in a
// single run, so only repetition can catch its return.
func TestCheckFlagsReportsTheSameMissingFlagEveryTime(t *testing.T) {
	t.Parallel()

	var first string

	for i := range 500 {
		_, err := checkFlags(&CertificateOptions{})
		if err == nil {
			t.Fatal("no flags supplied, but checkFlags was content")
		}

		if i == 0 {
			first = err.Error()

			continue
		}

		if err.Error() != first {
			t.Fatalf("iteration %d reported %q, iteration 0 reported %q — map iteration order leaks into the message",
				i, err.Error(), first)
		}
	}
}

// TestCheckFlagsNamesEveryMissingFlag is the better answer to the same problem:
// with three flags missing, naming one and stopping means three round trips.
func TestCheckFlagsNamesEveryMissingFlag(t *testing.T) {
	t.Parallel()

	_, err := checkFlags(&CertificateOptions{})
	if err == nil {
		t.Fatal("no flags supplied, but checkFlags was content")
	}

	for _, flag := range []string{"--user-id", "--certify-key", "--encrypt-key", "--created"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error %q does not name the missing %s", err, flag)
		}
	}
}

// TestCheckFlagsRefusesAnOutputThatNamesAKey covers round-8 finding 1, which is
// the most destructive defect any review of this workstream has produced.
//
// The local backend's key identifiers ARE filesystem paths — its own package doc
// says so: "The key identifier is a path to an unencrypted PEM file". So
// `--encrypt-key encrypt.pem --output encrypt.pem` is a plausible slip, and it
// used to succeed: both PEMs are read into memory before the destination is even
// opened, the certificate assembles, and the staged file is renamed over the
// private key. The command exited 0 having destroyed it, and every report
// already encrypted to the published certificate became undecryptable at the
// same moment.
//
// decrypt grew ErrOutputOverInput for exactly this shape one round earlier. The
// guard was written for the command that reads two inputs and never given to the
// command that can overwrite a private key.
func TestCheckFlagsRefusesAnOutputThatNamesAKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		opts  CertificateOptions
		named string
	}{
		{
			name: "the encryption key",
			opts: CertificateOptions{
				UserId: "Security <security@example.com>", CertifyKey: "certify.pem",
				EncryptKey: "encrypt.pem", Created: validCreated, Output: "encrypt.pem",
			},
			named: "--encrypt-key",
		},
		{
			name: "the certification key",
			opts: CertificateOptions{
				UserId: "Security <security@example.com>", CertifyKey: "certify.pem",
				EncryptKey: "encrypt.pem", Created: validCreated, Output: "certify.pem",
			},
			named: "--certify-key",
		},
		{
			// Cleaned before comparison, or the same file typed two ways walks
			// straight past the guard.
			name: "the same key by a non-canonical path",
			opts: CertificateOptions{
				UserId: "Security <security@example.com>", CertifyKey: "./keys/encrypt.pem",
				EncryptKey: "keys/encrypt.pem", Created: validCreated, Output: "keys/../keys/encrypt.pem",
			},
			named: "--encrypt-key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := checkFlags(&tc.opts)
			if !errors.Is(err, ErrOutputOverInput) {
				t.Fatalf("--output %q names %s and was accepted: err = %v",
					tc.opts.Output, tc.named, err)
			}

			if !strings.Contains(err.Error(), tc.named) {
				t.Errorf("error %q does not name which input was hit (%s)", err, tc.named)
			}
		})
	}
}

// TestCheckFlagsAllowsAnOutputThatNamesNoInput is the other half, and it asserts
// the positive rather than "not this one error".
//
// A guard that refuses everything satisfies the test above perfectly.
func TestCheckFlagsAllowsAnOutputThatNamesNoInput(t *testing.T) {
	t.Parallel()

	for _, output := range []string{"", "-", "security-contact.asc", "./out/cert.asc"} {
		opts := CertificateOptions{
			UserId: "Security <security@example.com>", CertifyKey: "certify.pem",
			EncryptKey: "encrypt.pem", Created: validCreated, Output: output,
		}

		if _, err := checkFlags(&opts); err != nil {
			t.Errorf("--output %q names no input but was refused: %v", output, err)
		}
	}
}

// validCreated keeps the fixtures above from tripping the --created check and
// reporting a pass for the wrong reason.
const validCreated = "2026-01-01T00:00:00Z"
