package decrypt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the command does with the operator's filesystem and flags, which the
// library layer cannot see.

// TestOpenOutputAbandonLeavesNothingBehind covers the temporary file a failed
// run would otherwise leave.
//
// opfile writes beside the destination and renames on commit, so a run that
// fails partway leaves a dot-prefixed temporary. The failures here are routine
// — a message addressed to another key, a truncated paste — so without a
// deferred abandon they accumulate in the operator's directory, owner-readable
// and sometimes holding part of a report.
//
// An earlier shape returned the writer's commit and dropped the writer, so no
// caller could reach Abandon at all.
func TestOpenOutputAbandonLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	out, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	if _, err := out.w.Write([]byte("a partial report")); err != nil {
		t.Fatalf("write: %v", err)
	}

	out.abandon()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		t.Errorf("abandon left %q behind", e.Name())
	}
}

// TestOpenOutputAbandonAfterCommitIsSafe is what lets the defer be
// unconditional. If abandon removed the committed file, every successful run
// would delete its own output.
func TestOpenOutputAbandonAfterCommitIsSafe(t *testing.T) {
	t.Parallel()

	const plaintext = "the whole report"

	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	out, err := openOutput(path)
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}

	if _, err := out.w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := out.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	out.abandon()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the committed file did not survive abandon: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("file contains %q, want %q", got, plaintext)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the committed file", len(entries))
	}
}

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
