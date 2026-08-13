package opfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

// TestCommittedFileHasExactlyTheRequestedMode covers the promise made in two
// places: docs/reference/cli/certificate.md says a published certificate is
// "created mode 0644", and opfile's own comment says the staged file is
// "created at its final mode rather than widened afterwards".
//
// Neither was true. CreateExcl's perm is a request that the process umask
// masks, so an operator with `umask 077` — ordinary on a hardened or shared
// host — published a certificate at 0600 and the web server serving it got
// EACCES. The rewrite that introduced this dropped an explicit chmod, and
// nothing went red because the suite asserted no resulting mode anywhere.
//
// Deliberately not parallel. The umask is process-wide, so this would corrupt
// any test running beside it — and Go's ordering is what makes that safe: every
// non-parallel top-level test in a package completes before the parallel ones
// resume, so the cleanup below has restored the umask before anything else in
// this package runs.
func TestCommittedFileHasExactlyTheRequestedMode(t *testing.T) {
	// The umask that provoked it. Restored before returning.
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		// A published certificate: world-readable on purpose, and the case the
		// umask actually broke.
		{"a published certificate", 0o644},

		// A decrypted report: owner-only, where the umask happened to agree and
		// so nothing looked wrong.
		{"a decrypted report", 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artefact")

			w, err := opfile.Create(opfile.OS(), path, tc.mode)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			if _, err := w.Write([]byte("content")); err != nil {
				t.Fatalf("Write: %v", err)
			}

			if err := w.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}

			if got := info.Mode().Perm(); got != tc.mode {
				t.Errorf("committed file is mode %#o, want %#o — the umask masked "+
					"the requested mode and nothing put it back", got, tc.mode)
			}
		})
	}
}

// TestModeIsSetBeforeAnyContentIsWritten is the safety half of setting the mode
// after creation rather than at creation.
//
// Widening a file that already holds a decrypted report, even for an instant,
// is the thing this ordering exists to prevent — so the chmod must happen while
// the file is still empty. That is the entire argument for doing it this way
// round, which makes it worth checking rather than asserting in a comment.
//
// The previous version of this test checked that the staged file was not
// broader than 0600 and that its size was zero, both read before anything was
// written. Neither could distinguish the outcomes: with umask 077 a 0600 file
// is 0600 whether the chmod ran or not, and a file nothing has written to is
// empty by construction. It passed identically with the chmod before the write,
// after the write, or absent altogether — which is the exact defect class this
// round exists to remove, in the test written to guard against it.
//
// Observing the ORDER of the operations is what actually distinguishes them.
func TestModeIsSetBeforeAnyContentIsWritten(t *testing.T) {
	t.Parallel()

	spy := &orderSpyFS{FS: opfileafero.Wrap(afero.NewMemMapFs())}

	w, err := opfile.Create(spy, "/report.txt", 0o644)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("a decrypted vulnerability report")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	ops := spy.file.ops

	chmodAt := slices.Index(ops, "chmod")
	if chmodAt < 0 {
		t.Fatalf("the mode was never set through the handle; operations were %v", ops)
	}

	if writeAt := slices.Index(ops, "write"); writeAt >= 0 && writeAt < chmodAt {
		t.Errorf("content was written before the mode was set (%v), so the file held a report "+
			"at whatever mode the umask happened to allow", ops)
	}
}

// orderSpyFS records the order of operations on the staged file.
type orderSpyFS struct {
	opfile.FS

	file *orderSpyFile
}

func (f *orderSpyFS) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	inner, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}

	f.file = &orderSpyFile{File: inner}

	return f.file, nil
}

// orderSpyFile satisfies opfile.ModeSetter so the handle path is taken, which
// is the path the real filesystems use.
type orderSpyFile struct {
	opfile.File

	ops []string
}

func (f *orderSpyFile) Chmod(fs.FileMode) error {
	f.ops = append(f.ops, "chmod")

	return nil
}

func (f *orderSpyFile) Write(p []byte) (int, error) {
	f.ops = append(f.ops, "write")

	return f.File.Write(p)
}
