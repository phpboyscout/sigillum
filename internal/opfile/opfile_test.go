package opfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// The package takes the filesystem it writes through, so these run entirely in
// memory: no temporary directories, no cleanup, and nothing on the developer's
// disk. The abstraction is not decoration — the two properties this package
// exists to provide are only observable because the filesystem can be
// substituted.
//
// The seeding and reading here go through afero directly and only the boundary
// is wrapped, which is what a consumer does. The one case that needs a real
// filesystem says so and uses one.

// TestAbandonLeavesTheDestinationUntouched is the point of the package.
//
// Decryption fails routinely — a message addressed to another key is the
// documented common case — and opening the destination with O_TRUNC would
// empty it before the command had any idea whether it would succeed. A rota
// member who saved a report at that path would lose it and get nothing back.
func TestAbandonLeavesTheDestinationUntouched(t *testing.T) {
	t.Parallel()

	const existing = "the report I decrypted yesterday"

	mem := afero.NewMemMapFs()
	path := "/reports/report.txt"

	if err := afero.WriteFile(mem, path, []byte(existing), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	w, err := opfile.Create(opfileafero.Wrap(mem), path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("half a plaintext")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	w.Abandon()

	got, err := afero.ReadFile(mem, path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	if string(got) != existing {
		t.Errorf("destination now holds %q, want the untouched %q", got, existing)
	}

	assertNoTemporaries(t, mem, filepath.Dir(path), filepath.Base(path))
}

// TestCommitReplacesTheDestination is the other half: once the content is
// complete, it does land.
func TestCommitReplacesTheDestination(t *testing.T) {
	t.Parallel()

	const plaintext = "the whole report"

	mem := afero.NewMemMapFs()
	path := "/reports/report.txt"

	if err := afero.WriteFile(mem, path, []byte("yesterday's"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	w, err := opfile.Create(opfileafero.Wrap(mem), path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Deferred unconditionally by both commands, so it must be harmless here.
	w.Abandon()

	got, err := afero.ReadFile(mem, path)
	if err != nil {
		t.Fatalf("the committed file did not survive Abandon: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("destination holds %q, want %q", got, plaintext)
	}

	assertNoTemporaries(t, mem, filepath.Dir(path), filepath.Base(path))
}

// TestCommitSyncsBeforeRenaming covers finding 10.
//
// Rename is atomic with respect to the directory entry, not to the data behind
// it. Without a sync first, a crash between the write and writeback can leave
// the new name pointing at content that never reached the disk — a zero-length
// or partial file where a complete one used to be.
//
// That matters twice: a decrypted vulnerability report the operator believes
// they have saved, and a published certificate correspondents encrypt to. "The
// old content or the complete new content" is the entire promise of the
// package.
//
// Durability cannot be tested by crashing the machine, so the ordering is
// observed instead — which the filesystem seam is what makes possible.
func TestCommitSyncsBeforeRenaming(t *testing.T) {
	t.Parallel()

	fsys := &syncSpyFS{FS: opfileafero.Wrap(afero.NewMemMapFs())}

	w, err := opfile.Create(fsys, "/reports/report.txt", 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("a complete report")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if !fsys.synced {
		t.Fatal("Commit renamed without syncing, so the rename can outlive the data it points at")
	}

	if !fsys.syncedBeforeRename {
		t.Error("the sync happened after the rename, which is too late to be part of the guarantee")
	}
}

// TestCommitReportsAFailedSync is the other half: a sync that fails means the
// data is not on disk, so the rename must not happen and the destination must
// be left exactly as it was.
func TestCommitReportsAFailedSync(t *testing.T) {
	t.Parallel()

	const existing = "the previous report"

	mem := afero.NewMemMapFs()
	fsys := &syncSpyFS{FS: opfileafero.Wrap(mem), fail: errors.New("disk went away")}
	path := "/reports/report.txt"

	if err := afero.WriteFile(mem, path, []byte(existing), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	w, err := opfile.Create(fsys, path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("a report that never reached the platter")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err == nil {
		t.Fatal("Commit reported success although the sync failed")
	}

	got, err := afero.ReadFile(mem, path)
	if err != nil {
		t.Fatalf("reading the destination: %v", err)
	}

	if string(got) != existing {
		t.Errorf("the destination was replaced despite a failed sync: %q", got)
	}
}

// TestCreateRefusesANonRegularDestination covers finding 18, per decision D3.
//
// Replacing atomically renames over the directory entry rather than writing
// through it, so a symbolic link named as the destination is removed and a
// regular file takes its place. For a decrypted vulnerability report that is a
// confidentiality question: an operator who pointed through a link into a
// mounted volume finds the plaintext on local disk instead.
//
// Uses a real filesystem, because the behaviour under test is what happens to a
// symbolic link and MemMapFs has no way to make one.
func TestCreateRefusesANonRegularDestination(t *testing.T) {
	t.Parallel()

	fsys := opfileafero.Wrap(afero.NewOsFs())
	dir := t.TempDir()

	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	link := filepath.Join(dir, "report.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	_, err := opfile.Create(fsys, link, 0o600)
	if !errors.Is(err, opfile.ErrNotRegular) {
		t.Fatalf("error = %v, want ErrNotRegular", err)
	}

	if got, statErr := os.Lstat(link); statErr != nil || got.Mode()&os.ModeSymlink == 0 {
		t.Error("the symbolic link did not survive being refused")
	}

	// A directory is the other shape an operator reaches by accident.
	if _, err := opfile.Create(fsys, dir, 0o600); !errors.Is(err, opfile.ErrNotRegular) {
		t.Errorf("error = %v, want ErrNotRegular for a directory", err)
	}
}

// TestCreateAcceptsAnAbsentOrRegularDestination is the companion: refusing must
// not refuse the ordinary cases.
func TestCreateAcceptsAnAbsentOrRegularDestination(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	fsys := opfileafero.Wrap(mem)

	if _, err := opfile.Create(fsys, "/reports/new.txt", 0o600); err != nil {
		t.Errorf("an absent destination was refused: %v", err)
	}

	if err := afero.WriteFile(mem, "/reports/existing.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := opfile.Create(fsys, "/reports/existing.txt", 0o600); err != nil {
		t.Errorf("an existing regular file was refused: %v", err)
	}
}

// assertNoTemporaries checks that nothing dot-prefixed was left beside the
// destination, which is what a leaked temporary looks like.
func assertNoTemporaries(t *testing.T, fsys afero.Fs, dir, keep string) {
	t.Helper()

	entries, err := afero.ReadDir(fsys, dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		if e.Name() != keep {
			t.Errorf("%q was left beside the destination", e.Name())
		}
	}
}

// syncSpyFS records whether a staged file was synced, and whether that
// happened before the rename.
//
// Five methods rather than afero's thirteen, because the interface states only
// what the package uses — which is the practical argument for owning it: a test
// double is a handful of lines instead of a struct embedding a library type.
type syncSpyFS struct {
	opfile.FS

	fail               error
	synced             bool
	renamed            bool
	syncedBeforeRename bool
}

func (f *syncSpyFS) CreateExcl(name string, perm os.FileMode) (opfile.File, error) {
	file, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}

	return &syncSpyFile{File: file, fs: f}, nil
}

func (f *syncSpyFS) Rename(oldpath, newpath string) error {
	f.renamed = true

	return f.FS.Rename(oldpath, newpath)
}

type syncSpyFile struct {
	opfile.File

	fs *syncSpyFS
}

func (f *syncSpyFile) Sync() error {
	f.fs.synced = true
	f.fs.syncedBeforeRename = !f.fs.renamed

	if f.fs.fail != nil {
		return f.fs.fail
	}

	return f.File.Sync()
}
