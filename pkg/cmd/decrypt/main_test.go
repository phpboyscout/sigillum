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

// TestCheckFlagsRefusesMoreThanOneMessage covers the arguments that were
// silently discarded.
//
// The command reads args[0] and nothing else, and its generated Use string
// declares no positional arguments at all. So `sigillum decrypt a.pgp b.pgp`
// decrypted a.pgp, reported success, and said nothing whatever about b.pgp —
// an operator running it over a directory of reports would have been told
// every one of them succeeded.
//
// Refusing is the only honest answer available: there is a single --output, so
// decrypting several in one run was never something this command could do.
func TestCheckFlagsRefusesMoreThanOneMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"none, meaning stdin", nil, false},
		{"the stdin sentinel", []string{"-"}, false},
		{"one message", []string{"report.pgp"}, false},
		{"two messages", []string{"report.pgp", "other.pgp"}, true},
		{"a directory's worth", []string{"a.pgp", "b.pgp", "c.pgp"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := &DecryptOptions{Certificate: "certificate.pgp", Key: "alias/encrypt"}

			err := checkFlags(opts, tc.args)

			switch {
			case tc.wantErr && !errors.Is(err, ErrTooManyArguments):
				t.Errorf("error = %v, want ErrTooManyArguments", err)
			case !tc.wantErr && errors.Is(err, ErrTooManyArguments):
				t.Errorf("%v were refused as too many", tc.args)
			}
		})
	}
}

// TestTooManyArgumentsNamesThemAll is what makes the refusal actionable: the
// operator has to be able to see which invocation was wrong.
func TestTooManyArgumentsNamesThemAll(t *testing.T) {
	t.Parallel()

	opts := &DecryptOptions{Certificate: "certificate.pgp", Key: "alias/encrypt"}

	err := checkFlags(opts, []string{"first.pgp", "second.pgp"})
	if err == nil {
		t.Fatal("two messages were accepted")
	}

	for _, name := range []string{"first.pgp", "second.pgp"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s: %v", name, err)
		}
	}
}
