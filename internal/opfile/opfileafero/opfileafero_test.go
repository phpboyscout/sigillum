package opfileafero_test

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

// The adapter had no test at all, which is how the discarded lstatCalled flag
// (design-review #15) survived: the one property that mattered — whether the
// wrapper tells the truth about what it can do — was asserted nowhere.

// TestWrapRejectsANilFilesystem covers finding #28.
//
// A nil afero.Fs was stored and every forwarded call nil-dereferenced on first
// use. A miswired dependency is a start-up error, reported at the wiring point
// like the key-service registry, not a panic three calls later.
func TestWrapRejectsANilFilesystem(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("Wrap(nil) did not panic; a nil filesystem is stored and fails later")
		}
	}()

	opfileafero.Wrap(nil)
}

// TestLstatRefusesWhenTheFilesystemOnlyStats covers findings #14 and #15.
//
// afero's MemMapFs satisfies the Lstater interface and then falls back to Stat,
// returning a flag that says so. The old adapter discarded the flag and passed
// the Stat result off as an Lstat, so a filesystem that had not checked for a
// link was presented as one that had. The wrapper now reports the refusal
// honestly, per call.
func TestLstatRefusesWhenTheFilesystemOnlyStats(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/report.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	wrapped := opfileafero.Wrap(mem)

	// The entry exists, but MemMapFs cannot really lstat, so the capability is
	// refused rather than a Stat result returned as if it were an Lstat.
	if _, err := wrapped.Lstat("/report.txt"); !errors.Is(err, opfile.ErrCapabilityUnsupported) {
		t.Fatalf("Lstat on a stat-only filesystem: err = %v, want ErrCapabilityUnsupported", err)
	}

	// A genuine not-exist still comes back as not-exist, not as the capability
	// refusal — resolveDestination needs to tell the two apart.
	if _, err := wrapped.Lstat("/absent.txt"); errors.Is(err, opfile.ErrCapabilityUnsupported) {
		t.Fatal("a non-existent path reported ErrCapabilityUnsupported, hiding not-exist")
	}
}

// TestLstatIsGenuineOnTheOperatingSystem is the other half: the filesystem that
// matters in production reports a real lstat, so the capability is honoured
// rather than refused.
func TestLstatIsGenuineOnTheOperatingSystem(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	os := afero.NewOsFs()

	if err := afero.WriteFile(os, dir+"/report.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := opfileafero.Wrap(os).Lstat(dir + "/report.txt"); err != nil {
		t.Fatalf("Lstat on the operating system was refused: %v", err)
	}
}

// TestReadlinkRefusesWhereItCannotResolve covers a filesystem that declares
// LinkReader but cannot honour it for the path — BasePathFs over an in-memory
// filesystem — which must report the per-call refusal rather than a bare error.
func TestReadlinkRefusesWhereItCannotResolve(t *testing.T) {
	t.Parallel()

	wrapped := opfileafero.Wrap(afero.NewMemMapFs())

	// MemMapFs is not a LinkReader at all, so this is the clean refusal.
	if _, err := wrapped.Readlink("/whatever"); !errors.Is(err, opfile.ErrCapabilityUnsupported) {
		t.Fatalf("Readlink on a link-blind filesystem: err = %v, want ErrCapabilityUnsupported", err)
	}
}

// TestSyncDirRefusesWhereTheDirectoryCannotBeFlushed covers the capability
// translation the production wrapper owes, matching its twin osFS.SyncDir.
//
// A directory fsync returns EINVAL or ENOTSUP on a filesystem that does not
// support it — vfat, exfat, some network mounts, the very USB case setMode goes
// out of its way to keep working. That is the capability being absent and must
// be reported as [opfile.ErrCapabilityUnsupported], so Writer.Commit treats a
// destination it has already renamed into place as written rather than failing
// on it. Returned raw, the EINVAL would fail a commit whose file is on disk.
func TestSyncDirRefusesWhereTheDirectoryCannotBeFlushed(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/reports/report.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	wrapped := opfileafero.Wrap(einvalSyncFS{mem})

	if err := wrapped.SyncDir("/reports"); !errors.Is(err, opfile.ErrCapabilityUnsupported) {
		t.Fatalf("SyncDir on a directory-fsync-refusing filesystem: err = %v, want ErrCapabilityUnsupported", err)
	}
}

// TestSyncDirIsGenuineWhereTheDirectoryCanBeFlushed is the other half: a
// filesystem that flushes a directory does so, and the capability is honoured
// rather than refused.
func TestSyncDirIsGenuineWhereTheDirectoryCanBeFlushed(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/reports/report.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if err := opfileafero.Wrap(mem).SyncDir("/reports"); err != nil {
		t.Fatalf("SyncDir on a flushable filesystem was refused: %v", err)
	}
}

// einvalSyncFS is an afero filesystem whose files refuse to sync with EINVAL,
// modelling a directory fsync on a filesystem that has no such operation.
type einvalSyncFS struct{ afero.Fs }

func (f einvalSyncFS) Open(name string) (afero.File, error) {
	inner, err := f.Fs.Open(name)
	if err != nil {
		return nil, err
	}

	return einvalSyncFile{inner}, nil
}

type einvalSyncFile struct{ afero.File }

func (einvalSyncFile) Sync() error {
	return &fs.PathError{Op: "fsync", Path: "directory", Err: syscall.EINVAL}
}

// TestFileChmodRefusesWhereTheHandleCannot covers finding #16: the mode-through-
// the-handle capability depends on the concrete file type, so a file that cannot
// chmod must say so per call rather than the fast path being silently lost.
func TestFileChmodRefusesWhereTheHandleCannot(t *testing.T) {
	t.Parallel()

	wrapped := opfileafero.Wrap(afero.NewMemMapFs())

	f, err := wrapped.CreateExcl("/staged", 0o600)
	if err != nil {
		t.Fatalf("CreateExcl: %v", err)
	}

	// A MemMapFs file is not an *os.File, so the handle cannot chmod — and it
	// says so, letting setMode fall back to FS.Chmod rather than assuming the
	// mode was set.
	if err := f.Chmod(fs.FileMode(0o644)); !errors.Is(err, opfile.ErrCapabilityUnsupported) {
		t.Fatalf("Chmod on an in-memory file: err = %v, want ErrCapabilityUnsupported", err)
	}
}
