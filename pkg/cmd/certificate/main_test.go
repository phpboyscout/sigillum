package certificate

import (
	"strings"
	"testing"
)

// TestCheckFlagsReportsTheSameMissingFlagEveryTime covers finding 25.
//
// checkFlags reports the first missing flag by ranging over a map literal, and
// Go randomises map iteration order — so with more than one flag missing, which
// one is named varies between runs.
//
// An operator who omits two flags is told about a different one each time they
// re-run, which makes reproducible support guesswork; and any test asserting a
// specific message is flaky by construction rather than by accident.
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

	for _, flag := range []string{"--user-id", "--certify-key", "--encrypt-key"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error %q does not name the missing %s", err, flag)
		}
	}
}
