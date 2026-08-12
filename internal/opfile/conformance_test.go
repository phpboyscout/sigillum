package opfile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

// One property set, run against every filesystem this package supports.
//
// The package documents the standard library as its default — "using this
// package standalone requires nothing beyond the standard library" — and until
// this file nothing exercised it. Every test wrapped afero, so opfile.OS() and
// all seven of its methods sat at zero coverage while the claim that they work
// was the first thing a reader was told.
//
// Written as a conformance suite rather than a copy of the existing tests with
// the constructor swapped, because a copy is what drifts: the guarantees below
// are the package's contract, and an implementation that cannot honour one of
// them is not a valid FS regardless of which one it is. Running the same list
// against each is what keeps the abstraction honest.
//
// Capabilities that are genuinely optional — links — are declared per backend
// rather than assumed, since the estate's rule is that an implementation must
// not claim an optional interface it cannot honour, and MemMapFs cannot make a
// symbolic link.

// backend is a filesystem to run the contract against.
type backend struct {
	name string

	// open returns a fresh, self-contained instance. Everything a subtest needs
	// comes back from one call, so parallel subtests share nothing — an earlier
	// version kept the in-memory filesystem in a variable closed over by the
	// listing function, and each parallel subtest calling open overwrote it.
	// The race detector found it immediately.
	open func(t *testing.T) instance

	// links reports whether the backend can create a symbolic link, which is a
	// property of the underlying store rather than of the wrapper.
	links bool
}

// instance is one filesystem, a directory on it, and how to list that
// directory.
type instance struct {
	fsys opfile.FS
	dir  string

	// list names the directory's entries. Carried here rather than on [FS]
	// because the package needs no directory listing, and adding a method to
	// the interface to satisfy a test would be the tail wagging the dog.
	list func(t *testing.T) []string
}

func backends() []backend {
	return []backend{
		{
			// The documented default, and the reason this file exists.
			name:  "stdlib",
			links: true,
			open: func(t *testing.T) instance {
				t.Helper()

				dir := t.TempDir()

				return instance{
					fsys: opfile.OS(),
					dir:  dir,
					list: func(t *testing.T) []string { return listOnDisk(t, dir) },
				}
			},
		},
		{
			name:  "afero over the operating system",
			links: true,
			open: func(t *testing.T) instance {
				t.Helper()

				dir := t.TempDir()

				return instance{
					fsys: opfileafero.Wrap(afero.NewOsFs()),
					dir:  dir,
					list: func(t *testing.T) []string { return listOnDisk(t, dir) },
				}
			},
		},
		{
			name:  "afero in memory",
			links: false,
			open: func(t *testing.T) instance {
				t.Helper()

				const dir = "/reports"

				mem := afero.NewMemMapFs()
				if err := mem.MkdirAll(dir, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}

				return instance{
					fsys: opfileafero.Wrap(mem),
					dir:  dir,
					list: func(t *testing.T) []string {
						t.Helper()

						found, err := afero.ReadDir(mem, dir)
						if err != nil {
							t.Fatalf("listing %s: %v", dir, err)
						}

						names := make([]string, 0, len(found))
						for _, entry := range found {
							names = append(names, entry.Name())
						}

						return names
					},
				}
			},
		},
	}
}

// TestFSConformance runs the package"s contract against every backend.
func TestFSConformance(t *testing.T) {
	t.Parallel()

	checks := []struct {
		name string
		run  func(t *testing.T, b backend)

		// needsLinks marks a check that only applies where the backend can
		// create a symbolic link.
		needsLinks bool
	}{
		{name: "abandon leaves the destination untouched", run: assertAbandonLeavesTheDestinationUntouched, needsLinks: false},
		{name: "commit replaces the destination", run: assertCommitReplacesTheDestination, needsLinks: false},
		{name: "no staged file is left behind", run: assertNoStagedFileIsLeftBehind, needsLinks: false},
		{name: "a directory is refused as a destination", run: assertADirectoryIsRefusedAsADestination, needsLinks: false},
		{name: "stat reports a file and an absence", run: assertStatReportsAFileAndAnAbsence, needsLinks: false},
		{name: "creating an existing name is refused", run: assertCreatingAnExistingNameIsRefused, needsLinks: false},
		{name: "a symbolic link is refused by default", run: assertASymbolicLinkIsRefusedByDefault, needsLinks: true},
		{name: "a symbolic link is followed on request", run: assertASymbolicLinkIsFollowedOnRequest, needsLinks: true},
	}

	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			for _, check := range checks {
				if check.needsLinks && !b.links {
					continue
				}

				t.Run(check.name, func(t *testing.T) {
					t.Parallel()

					check.run(t, b)
				})
			}
		})
	}
}

// assertAbandonLeavesTheDestinationUntouched checks that abandon leaves the destination untouched.
func assertAbandonLeavesTheDestinationUntouched(t *testing.T, b backend) {
	t.Helper()

	const existing = "the report I decrypted yesterday"

	in := b.open(t)
	path := filepath.Join(in.dir, "report.txt")

	seed(t, in.fsys, path, existing)

	w, err := opfile.Create(in.fsys, path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("half a plaintext")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	w.Abandon()

	if got := readBack(t, in.fsys, path); got != existing {
		t.Errorf("destination holds %q, want the untouched %q", got, existing)
	}
}

// assertCommitReplacesTheDestination checks that commit replaces the destination.
func assertCommitReplacesTheDestination(t *testing.T, b backend) {
	t.Helper()

	const plaintext = "the whole report"

	in := b.open(t)
	path := filepath.Join(in.dir, "report.txt")

	seed(t, in.fsys, path, "yesterday's")

	w, err := opfile.Create(in.fsys, path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Both commands defer this unconditionally, so it must be
	// harmless after a commit on every backend.
	w.Abandon()

	if got := readBack(t, in.fsys, path); got != plaintext {
		t.Errorf("destination holds %q, want %q", got, plaintext)
	}
}

// assertNoStagedFileIsLeftBehind checks that no staged file is left behind.
func assertNoStagedFileIsLeftBehind(t *testing.T, b backend) {
	t.Helper()

	in := b.open(t)
	path := filepath.Join(in.dir, "report.txt")

	w, err := opfile.Create(in.fsys, path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("abandoned")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	w.Abandon()

	// The staged name is generated, so the check is that nothing
	// beyond the destination survives in the directory.
	for _, name := range in.list(t) {
		if name != "report.txt" {
			t.Errorf("staging left %q behind in %s", name, in.dir)
		}
	}
}

// assertADirectoryIsRefusedAsADestination checks that a directory is refused as a destination.
func assertADirectoryIsRefusedAsADestination(t *testing.T, b backend) {
	t.Helper()

	in := b.open(t)

	if _, err := opfile.Create(in.fsys, in.dir, 0o600); !errors.Is(err, opfile.ErrNotRegular) {
		t.Errorf("error = %v, want ErrNotRegular", err)
	}
}

// assertStatReportsAFileAndAnAbsence checks that stat reports a file and an absence.
func assertStatReportsAFileAndAnAbsence(t *testing.T, b backend) {
	t.Helper()

	// Part of the FS contract, so every implementation owes it —
	// even though the package itself only reaches Stat as the
	// fallback for a filesystem with no Lstat, which is why this is
	// exercised here rather than incidentally.
	in := b.open(t)
	path := filepath.Join(in.dir, "report.txt")

	seed(t, in.fsys, path, "a report")

	info, err := in.fsys.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if info.IsDir() || info.Size() != int64(len("a report")) {
		t.Errorf("Stat reported dir=%t size=%d, want a regular file of %d octets",
			info.IsDir(), info.Size(), len("a report"))
	}

	// An absent file must be distinguishable, because that is how
	// Create decides there is nothing to preserve.
	if _, err := in.fsys.Stat(filepath.Join(in.dir, "absent.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat of an absent file: error = %v, want fs.ErrNotExist", err)
	}
}

// assertCreatingAnExistingNameIsRefused checks that creating an existing name is refused.
func assertCreatingAnExistingNameIsRefused(t *testing.T, b backend) {
	t.Helper()

	// The exclusivity CreateExcl is named for. Staging depends on
	// it: two concurrent runs must never be handed the same
	// temporary, and an implementation that silently truncates
	// would break the package's whole guarantee.
	in := b.open(t)
	path := filepath.Join(in.dir, "report.txt")

	seed(t, in.fsys, path, "the previous report")

	if f, err := in.fsys.CreateExcl(path, 0o600); err == nil {
		_ = f.Close()

		t.Error("CreateExcl overwrote an existing file")
	}

	if got := readBack(t, in.fsys, path); got != "the previous report" {
		t.Errorf("the existing file now holds %q", got)
	}
}

// assertASymbolicLinkIsRefusedByDefault checks that a symbolic link is refused by default.
func assertASymbolicLinkIsRefusedByDefault(t *testing.T, b backend) {
	t.Helper()

	fsys, link, _ := linkOn(t, b)

	if _, err := opfile.Create(fsys, link, 0o600); !errors.Is(err, opfile.ErrNotRegular) {
		t.Errorf("error = %v, want ErrNotRegular", err)
	}
}

// assertASymbolicLinkIsFollowedOnRequest checks that a symbolic link is followed on request.
func assertASymbolicLinkIsFollowedOnRequest(t *testing.T, b backend) {
	t.Helper()

	const plaintext = "the new report"

	fsys, link, target := linkOn(t, b)

	w, err := opfile.Create(fsys, link, 0o600, opfile.FollowSymlinks())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := w.Path(); got != target {
		t.Errorf("Path() = %q, want the resolved %q", got, target)
	}

	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symbolic link did not survive being followed")
	}

	if got := readBack(t, fsys, target); got != plaintext {
		t.Errorf("target holds %q, want %q", got, plaintext)
	}
}

// linkOn builds a symbolic link to an existing file on a backend that supports
// one, returning the filesystem, the link and its target.
func linkOn(t *testing.T, b backend) (opfile.FS, string, string) {
	t.Helper()

	in := b.open(t)

	target := filepath.Join(in.dir, "target.txt")
	seed(t, in.fsys, target, "the previous report")

	link := filepath.Join(in.dir, "report.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	return in.fsys, link, target
}

// seed writes a file through the FS under test, so the fixture uses the same
// surface as the code and no backend is seeded by a route it does not own.
func seed(t *testing.T, fsys opfile.FS, path, content string) {
	t.Helper()

	f, err := fsys.CreateExcl(path, 0o600)
	if err != nil {
		t.Fatalf("seeding %s: %v", path, err)
	}

	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("seeding %s: %v", path, err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("seeding %s: %v", path, err)
	}
}

// readBack reads a file through the FS under test.
func readBack(t *testing.T, fsys opfile.FS, path string) string {
	t.Helper()

	f, err := fsys.Open(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("closing %s: %v", path, err)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	buf := make([]byte, info.Size())
	if _, err := f.Read(buf); err != nil && info.Size() > 0 {
		t.Fatalf("reading %s: %v", path, err)
	}

	return string(buf)
}

// listOnDisk names the entries in a directory the operating system can see.
func listOnDisk(t *testing.T, dir string) []string {
	t.Helper()

	found, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}

	names := make([]string, 0, len(found))
	for _, entry := range found {
		names = append(names, entry.Name())
	}

	return names
}
