package opdest_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opdest"
	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

// The staged-write behaviour both commands depend on.
//
// These lived in the decrypt command's tests, beside the copy of this code that
// command used to carry. They moved with the code: a test for a shared
// implementation that sits in one of its two callers is a test the other caller
// does not run.

// TestAbandonLeavesNothingBehind covers the temporary file a failed
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
func TestAbandonLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	dir := "/reports"
	path := filepath.Join(dir, "report.txt")

	out, err := opdest.Open(opfileafero.Wrap(mem), path, 0o600, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := out.Writer.Write([]byte("a partial report")); err != nil {
		t.Fatalf("write: %v", err)
	}

	out.Abandon()

	entries, err := afero.ReadDir(mem, dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		t.Errorf("abandon left %q behind", e.Name())
	}
}

// TestAbandonAfterCommitIsSafe is what lets the defer be
// unconditional. If abandon removed the committed file, every successful run
// would delete its own output.
func TestAbandonAfterCommitIsSafe(t *testing.T) {
	t.Parallel()

	const plaintext = "the whole report"

	mem := afero.NewMemMapFs()
	dir := "/reports"
	path := filepath.Join(dir, "report.txt")

	out, err := opdest.Open(opfileafero.Wrap(mem), path, 0o600, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := out.Writer.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := out.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	out.Abandon()

	got, err := afero.ReadFile(mem, path)
	if err != nil {
		t.Fatalf("the committed file did not survive abandon: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("file contains %q, want %q", got, plaintext)
	}

	entries, err := afero.ReadDir(mem, dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the committed file", len(entries))
	}
}

// TestResolvedNamesWhereTheBytesActuallyLanded covers the mitigation that
// makes --follow-symlinks defensible.
//
// opfile's own doc says following is only acceptable because "the resolved path
// is reported back so it can be logged: the failure mode of following is
// silence, and that part is cheap to remove". opfile did report it; both
// commands dropped the writer into a struct of closures and never read Path(),
// so an operator following a link planted in a shared directory got a
// decrypted vulnerability report written somewhere they were never told about.
//
// Uses a real filesystem, because the behaviour under test is a symbolic link
// and MemMapFs cannot make one.
func TestResolvedNamesWhereTheBytesActuallyLanded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	target := filepath.Join(dir, "elsewhere.txt")
	if err := os.WriteFile(target, []byte("previous"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	link := filepath.Join(dir, "report.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	out, err := opdest.Open(opfile.OS(), link, 0o600, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	defer out.Abandon()

	if !out.Resolved() {
		t.Error("following a link was not reported as resolving elsewhere, so nothing can log it")
	}

	if out.Path() != target {
		t.Errorf("Path() = %q, want the resolved %q", out.Path(), target)
	}

	if out.Requested() != link {
		t.Errorf("Requested() = %q, want the path the operator typed, %q", out.Requested(), link)
	}
}

// TestOrdinaryDestinationsAreNotReportedAsResolved is the other half: a path
// that is exactly where the operator asked must not be announced, or the signal
// is worthless.
func TestOrdinaryDestinationsAreNotReportedAsResolved(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()

	for _, tc := range []struct{ name, path string }{
		{"an ordinary file", "/reports/report.txt"},
		{"standard output by sentinel", "-"},
		{"standard output by default", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := opdest.Open(opfileafero.Wrap(mem), tc.path, 0o600, true)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			defer out.Abandon()

			if out.Resolved() {
				t.Errorf("%s was reported as having resolved elsewhere", tc.name)
			}
		})
	}
}

// TestResolvedIgnoresMerelyNonCanonicalPaths covers the warning crying wolf.
//
// Resolved() drives an Info-level warning telling the operator the report did
// not land where they typed. It compared the path opfile had cleaned against
// the raw string, so `--output ./reports/x.txt` — or any path with a doubled
// slash, a `.` or a `..` — reported as resolved-elsewhere even with symlink
// following switched off and no link in sight.
//
// A warning that fires on ordinary input is worse than no warning: the one
// case worth surfacing is a report written through a planted link, and it
// cannot be seen among false alarms.
func TestResolvedIgnoresMerelyNonCanonicalPaths(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll("/reports", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	for _, path := range []string{
		"/reports/report.txt",
		"/reports/./report.txt",
		"/reports//report.txt",
		"/reports/../reports/report.txt",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			out, err := opdest.Open(opfileafero.Wrap(mem), path, 0o600, false)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			defer out.Abandon()

			if out.Resolved() {
				t.Errorf("%s was reported as having landed elsewhere; it is the same file, "+
					"spelled differently", path)
			}
		})
	}
}

// TestModeNoteReachesTheCaller covers the promise that was kept by nothing.
//
// opfile computes a note whenever the filesystem refuses to set the requested
// mode — the vfat and exfat case, which is what a USB stick is formatted as.
// Both the code and the CLI reference say the difference "is reported". It was
// computed on every write and no caller could read it: the Destination was
// built from the writer's Commit, Abandon and Path alone.
//
// The concrete cost of the silence: an operator writes the published
// certificate to a stick, it lands at 0600 rather than the documented 0644,
// the command exits zero and says nothing, they copy it into the web root, and
// every correspondent who fetches it to encrypt a report gets a 403.
func TestModeNoteReachesTheCaller(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll("/reports", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	out, err := opdest.Open(&refusingChmodFS{FS: opfileafero.Wrap(mem)}, "/reports/report.txt", 0o600, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	defer out.Abandon()

	if out.ModeNote() == "" {
		t.Error("the filesystem refused to set the mode and the Destination reports nothing, " +
			"so no command can tell the operator")
	}
}

// refusingChmodFS satisfies Chmoder and refuses, as a vfat mount does, and
// creates narrower than asked so there is genuinely something to report.
type refusingChmodFS struct{ opfile.FS }

func (refusingChmodFS) Chmod(string, fs.FileMode) error { return fs.ErrPermission }

func (f refusingChmodFS) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	return f.FS.CreateExcl(name, perm&0o400)
}
