package oprun_test

import (
	"errors"
	"strings"
	"testing"

	"gitlab.com/phpboyscout/sigillum/internal/oprun"
)

// TestRequireFlagsNamesEveryMissingFlag is the shared guarantee that closed N4:
// the decrypt command named the first missing flag and stopped while the
// certificate command named them all, so three omissions cost three round trips
// on one side and one on the other. One collector, one behaviour.
func TestRequireFlagsNamesEveryMissingFlag(t *testing.T) {
	t.Parallel()

	err := oprun.RequireFlags(
		oprun.Flag{Name: "--certificate", Value: ""},
		oprun.Flag{Name: "--key", Value: ""},
		oprun.Flag{Name: "--backend", Value: "supplied"},
	)
	if !errors.Is(err, oprun.ErrMissingFlag) {
		t.Fatalf("error = %v, want ErrMissingFlag", err)
	}

	for _, want := range []string{"--certificate", "--key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not name %s: %v", want, err)
		}
	}

	if strings.Contains(err.Error(), "--backend") {
		t.Errorf("a supplied flag was named as missing: %v", err)
	}
}

// TestRequireFlagsIsSilentWhenAllPresent is the other half.
func TestRequireFlagsIsSilentWhenAllPresent(t *testing.T) {
	t.Parallel()

	if err := oprun.RequireFlags(
		oprun.Flag{Name: "--a", Value: "x"},
		oprun.Flag{Name: "--b", Value: "y"},
	); err != nil {
		t.Fatalf("all flags supplied, but RequireFlags refused: %v", err)
	}
}

// TestRequireFlagsAppendsWhyForAMissingFlag covers the explanation a flag's
// absence needs beyond its name — the fingerprint sentence --created carries,
// which an e2e scenario pins.
func TestRequireFlagsAppendsWhyForAMissingFlag(t *testing.T) {
	t.Parallel()

	err := oprun.RequireFlags(
		oprun.Flag{Name: "--created", Value: "", Why: "it is hashed into the fingerprint"},
	)
	if err == nil {
		t.Fatal("a missing flag was accepted")
	}

	if !strings.Contains(err.Error(), "hashed into the fingerprint") {
		t.Errorf("the Why explanation was dropped: %v", err)
	}
}

// TestRequireFlagsOmitsWhyWhenTheFlagIsPresent keeps the explanation from
// appearing when the flag it belongs to was supplied.
func TestRequireFlagsOmitsWhyWhenTheFlagIsPresent(t *testing.T) {
	t.Parallel()

	err := oprun.RequireFlags(
		oprun.Flag{Name: "--user-id", Value: ""},
		oprun.Flag{Name: "--created", Value: "2026-01-01T00:00:00Z", Why: "the fingerprint reason"},
	)
	if err == nil {
		t.Fatal("a missing flag was accepted")
	}

	if strings.Contains(err.Error(), "fingerprint reason") {
		t.Errorf("a supplied flag's Why leaked into the message: %v", err)
	}
}
