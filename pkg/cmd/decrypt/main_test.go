package decrypt

import (
	"errors"
	"strings"
	"testing"
)

// TestCheckFlagsRefusesStdinTwice covers the flag combination the reference
// advertised on the same page without saying the two are exclusive.
//
// Reading the certificate drains stdin to EOF, so the message is then empty and
// the run failed with "malformed message: message is empty" — which sends the
// operator to look at the report rather than at the flags. There is no ordering
// of the two that works, so it is refused rather than left to fail.
func TestCheckFlagsRefusesStdinTwice(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opts DecryptOptions
		args []string
		want error
	}{
		{
			name: "certificate from stdin, message omitted",
			opts: DecryptOptions{Certificate: "-", Key: "alias/x"},
			args: nil,
			want: ErrStdinTwice,
		},
		{
			name: "certificate from stdin, message explicitly stdin",
			opts: DecryptOptions{Certificate: "-", Key: "alias/x"},
			args: []string{"-"},
			want: ErrStdinTwice,
		},
		{
			name: "certificate from stdin, message from a file",
			opts: DecryptOptions{Certificate: "-", Key: "alias/x"},
			args: []string{"report.asc"},
			want: nil,
		},
		{
			name: "certificate from a file, message from stdin",
			opts: DecryptOptions{Certificate: "cert.asc", Key: "alias/x"},
			args: nil,
			want: nil,
		},
		{
			name: "no certificate at all",
			opts: DecryptOptions{Key: "alias/x"},
			args: nil,
			want: ErrMissingFlag,
		},
		{
			name: "no key",
			opts: DecryptOptions{Certificate: "cert.asc"},
			args: nil,
			want: ErrMissingFlag,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := checkFlags(&tc.opts, tc.args)

			if tc.want == nil {
				if err != nil {
					t.Fatalf("checkFlags: %v", err)
				}

				return
			}

			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestStdinTwiceErrorSaysWhatToDo is the diagnostic half. The operator hit this
// because the documentation implied both were available, so the error has to
// say which to change.
func TestStdinTwiceErrorSaysWhatToDo(t *testing.T) {
	t.Parallel()

	err := checkFlags(&DecryptOptions{Certificate: "-", Key: "alias/x"}, nil)
	if err == nil {
		t.Fatal("the combination was accepted")
	}

	for _, want := range []string{"--certificate", "stdin", "file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestCheckFlagsReportsTheSameMissingFlagEveryTime guards this command against
// the defect finding 25 found in the certificate command, whose checkFlags
// reports the first missing flag by ranging over a map literal.
//
// This command's checkFlags tests its flags in a fixed order, so the message is
// stable. Pinned here so a future refactor toward a map does not reintroduce it
// on this side.
func TestCheckFlagsReportsTheSameMissingFlagEveryTime(t *testing.T) {
	t.Parallel()

	var first string

	for i := range 200 {
		err := checkFlags(&DecryptOptions{}, nil)
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
