package decrypt

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"

	"gitlab.com/phpboyscout/go/encryption"

	"gitlab.com/phpboyscout/sigillum/internal/openpgp"
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
// used to range over a map literal — Go randomises map iteration order, so
// which missing flag was named varied between runs.
//
// This command's checkFlags has always tested its flags in a fixed order, so
// the message is stable. Pinned here so a future refactor toward a map does not
// introduce on this side what has since been fixed on the other.
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

// TestNotesReachTheOperator covers the last link in the chain the parser
// changes opened.
//
// certificate.Parse now reports findings it has no standing to decide about: a
// revocation it cannot evaluate, or a certificate that stopped parsing before
// its end. Both are deliberately not refusals — refusing an unverifiable
// revocation would let a stranger retire a published key by appending a packet.
//
// That only helps if something reads them. A note nobody logs is the same
// silence the parser was changed to break, so this pins that the command
// actually surfaces them.
func TestNotesReachTheOperator(t *testing.T) {
	t.Parallel()

	logged := &recordingWarner{}

	recipient := openpgp.Recipient{
		Notes: []error{
			fmt.Errorf("%w: version 6", encryption.ErrUnverifiableRevocation),
			fmt.Errorf("%w: stopped at a bad packet", encryption.ErrIncompleteCertificate),
		},
	}

	reportNotes(logged, recipient)

	for _, want := range []string{"version 6", "stopped at a bad packet"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("the operator is never told %q; logged: %s", want, logged.String())
		}
	}
}

// recordingWarner captures what would have been warned.
type recordingWarner struct{ lines []string }

func (w *recordingWarner) Warn(msg string, args ...any) {
	w.lines = append(w.lines, fmt.Sprint(append([]any{msg}, args...)...))
}

func (w *recordingWarner) String() string { return strings.Join(w.lines, "\n") }

// TestStdinSentinelIsHonoured covers the two arrangements the CLI reference
// documents as working, and which nothing exercised.
//
// The reference shows three cases: the certificate on stdin with the message
// in a file, the certificate in a file with the message on stdin, and the pair
// that is refused. Only the refusal was tested — so openInput's `-` branch and
// openMessage's empty-args branch had no test at any level, while the
// consolidation that removed the duplicate sentinel check was made on the
// strength of a doc comment.
//
// A regression here fails the documented workflow with "no such file or
// directory: -" on the input a researcher's report most often arrives through:
// a paste on a pipe.
func TestStdinSentinelIsHonoured(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	fsys := opfileafero.Wrap(mem)

	t.Run("openInput resolves - to standard input", func(t *testing.T) {
		t.Parallel()

		got, closer, err := openInput(fsys, "-")
		if err != nil {
			t.Fatalf("openInput(-): %v", err)
		}

		defer closer()

		if got != os.Stdin {
			t.Errorf("openInput(-) returned %T, want os.Stdin", got)
		}
	})

	t.Run("openMessage resolves no argument to standard input", func(t *testing.T) {
		t.Parallel()

		got, closer, err := openMessage(fsys, nil)
		if err != nil {
			t.Fatalf("openMessage(nil): %v", err)
		}

		defer closer()

		if got != os.Stdin {
			t.Errorf("openMessage(nil) returned %T, want os.Stdin", got)
		}
	})

	t.Run("openMessage resolves - to standard input", func(t *testing.T) {
		t.Parallel()

		got, closer, err := openMessage(fsys, []string{"-"})
		if err != nil {
			t.Fatalf("openMessage(-): %v", err)
		}

		defer closer()

		if got != os.Stdin {
			t.Errorf("openMessage(-) returned %T, want os.Stdin", got)
		}
	})

	t.Run("a real path is still opened as a file", func(t *testing.T) {
		t.Parallel()

		if err := afero.WriteFile(mem, "/report.pgp", []byte("x"), 0o600); err != nil {
			t.Fatalf("seeding: %v", err)
		}

		got, closer, err := openMessage(fsys, []string{"/report.pgp"})
		if err != nil {
			t.Fatalf("openMessage(path): %v", err)
		}

		defer closer()

		if got == os.Stdin {
			t.Error("a named file was read from standard input")
		}
	})
}

// TestCheckFlagsRefusesWritingOverAnInput covers --output naming a file the
// run is reading.
//
// The certificate is read fully before the output is staged, so the run
// succeeds and the commit replaces the certificate with the decrypted report.
// The operator has lost the certificate correspondents encrypt to, and the only
// copy of it, in a command that exits zero.
//
// The message file is the same shape and worse in one respect: the report is
// replaced by its own plaintext, so a second run has nothing to decrypt.
//
// signing-cli refuses the equivalent — "Refuses to let --output equal
// --private-output (would overwrite)" — so this is the estate's own rule
// applied to the command that did not have it.
func TestCheckFlagsRefusesWritingOverAnInput(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		opts DecryptOptions
		args []string
	}{
		"output over the certificate": {
			opts: DecryptOptions{Certificate: "security.asc", Key: "alias/e", Output: "security.asc"},
		},
		"output over the message": {
			opts: DecryptOptions{Certificate: "security.asc", Key: "alias/e", Output: "report.pgp"},
			args: []string{"report.pgp"},
		},
		"output over the certificate, spelled differently": {
			opts: DecryptOptions{Certificate: "./security.asc", Key: "alias/e", Output: "security.asc"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if err := checkFlags(&opts, tc.args); !errors.Is(err, ErrOutputOverInput) {
				t.Errorf("error = %v, want ErrOutputOverInput", err)
			}
		})
	}
}

// TestCheckFlagsAllowsAnOrdinaryOutput is the companion: refusing must not
// refuse the normal case, including stdout, which is not a file at all.
func TestCheckFlagsAllowsAnOrdinaryOutput(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		opts DecryptOptions
		args []string
	}{
		"a different file":  {opts: DecryptOptions{Certificate: "security.asc", Key: "alias/e", Output: "report.txt"}, args: []string{"report.pgp"}},
		"stdout by default": {opts: DecryptOptions{Certificate: "security.asc", Key: "alias/e"}, args: []string{"report.pgp"}},
		"stdout by sentinel": {opts: DecryptOptions{Certificate: "security.asc", Key: "alias/e", Output: "-"},
			args: []string{"-"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if err := checkFlags(&opts, tc.args); errors.Is(err, ErrOutputOverInput) {
				t.Errorf("an ordinary invocation was refused: %v", err)
			}
		})
	}
}

// TestLazyDeriverWiresOnceEvenWhenItFails covers a failure that was retried
// per candidate.
//
// wire caches only success, so a key service that cannot be constructed was
// rebuilt on every distinct ephemeral point the message carried — up to the
// derivation ceiling. For the AWS backend each attempt is a full SDK config
// load plus a billed kms:GetPublicKey, so a message a stranger composed turned
// one misconfiguration into sixteen of them.
//
// It is also the wrong diagnosis: the operator sees the same wiring error
// sixteen times and cannot tell whether it is one problem or several.
func TestLazyDeriverWiresOnceEvenWhenItFails(t *testing.T) {
	t.Parallel()

	failing := &countingKeyService{err: errors.New("no credentials")}
	d := &lazyDeriver{service: failing, keyID: "alias/x", log: discardLogger{}}

	for range 5 {
		if _, err := d.DeriveSharedSecret(t.Context(), []byte{0x04}); err == nil {
			t.Fatal("a key service that cannot be constructed reported success")
		}
	}

	if failing.calls != 1 {
		t.Errorf("the key service was constructed %d times for one run; a failure is as final "+
			"as a success and costs a config load and a billed call each time", failing.calls)
	}
}

// countingKeyService fails to construct a Deriver and counts the attempts.
type countingKeyService struct {
	err   error
	calls int
}

func (s *countingKeyService) Name() string { return "counting" }

func (s *countingKeyService) Deriver(context.Context, string) (encryption.Deriver, error) {
	s.calls++

	return nil, s.err
}

func (s *countingKeyService) Signer(context.Context, string) (crypto.Signer, error) {
	return nil, s.err
}

// discardLogger satisfies the sliver of the logger lazyDeriver uses.
type discardLogger struct{}

func (discardLogger) Debug(string, ...any) {}
