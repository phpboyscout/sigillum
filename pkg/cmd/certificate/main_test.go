package certificate

import (
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

	for _, flag := range []string{"--user-id", "--certify-key", "--encrypt-key"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error %q does not name the missing %s", err, flag)
		}
	}
}
