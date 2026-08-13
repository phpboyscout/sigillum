package opfile_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
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

// TestStagedFileIsNeverBroaderThanItsDestination is the safety half.
//
// Setting the mode after creation must not open a window in which a report
// exists at a broader mode than it will end up with. It does not, because the
// staged file is chmod'd while still empty — but that ordering is the whole
// argument, so it is checked rather than asserted in a comment.
func TestStagedFileIsNeverBroaderThanItsDestination(t *testing.T) {
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	dir := t.TempDir()

	w, err := opfile.Create(opfile.OS(), filepath.Join(dir, "report.txt"), 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Before a single byte is written, find the staged file and check it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected exactly one staged file, found %d", len(entries))
	}

	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if got := info.Mode().Perm(); got&^0o600 != 0 {
		t.Errorf("the staged file is mode %#o, broader than the 0600 destination", got)
	}

	if info.Size() != 0 {
		t.Errorf("the staged file already holds %d octets, so the mode was set too late", info.Size())
	}

	w.Abandon()
}
