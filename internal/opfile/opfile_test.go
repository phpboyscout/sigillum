package opfile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// TestCommitSyncsTheDirectoryAfterRenaming covers the second half of
// durability. Flushing the staged file's data makes the CONTENT durable;
// flushing the containing directory makes the RENAME durable. Without the
// second flush a crash after Commit can leave the directory entry pointing at
// the old name — a complete file that is not where it was written — which is the
// same partial-report outcome the data sync prevents, one level up.
//
// The directory flush must come after the rename: it is the rename it makes
// durable.
func TestCommitSyncsTheDirectoryAfterRenaming(t *testing.T) {
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

	if !fsys.dirSynced {
		t.Fatal("Commit renamed without flushing the directory, so the rename can be lost across a crash")
	}

	if !fsys.dirSyncedAfterRename {
		t.Error("the directory was flushed before the rename, which cannot make the rename durable")
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

	fail                 error
	synced               bool
	renamed              bool
	syncedBeforeRename   bool
	dirSynced            bool
	dirSyncedAfterRename bool
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

func (f *syncSpyFS) SyncDir(name string) error {
	f.dirSynced = true
	f.dirSyncedAfterRename = f.renamed

	return f.FS.SyncDir(name)
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

// TestFollowSymlinksIsOptIn covers the destination decision as settled: refuse a
// symbolic link by default, write through it when the caller asks.
//
// Neither answer is right for every caller. Following is what the commands did
// before content was staged and renamed, and it is what a managed symlink
// expects — replacing the link detaches every other path pointing at the
// target. Against that, a link at the destination is not necessarily one the
// operator made: anyone who can write to the destination directory can plant
// one, and following it then chooses where a decrypted report lands.
//
// So the caller decides and the default is the safe half.
func TestFollowSymlinksIsRefusedByDefault(t *testing.T) {
	t.Parallel()

	fsys, link, _ := symlinkedDestination(t)

	if _, err := opfile.Create(fsys, link, 0o600); !errors.Is(err, opfile.ErrNotRegular) {
		t.Fatalf("error = %v, want ErrNotRegular", err)
	}
}

// TestFollowSymlinksWritesThroughOnRequest is the opted-in half: the link is
// preserved and the content lands on its target.
func TestFollowSymlinksWritesThroughOnRequest(t *testing.T) {
	t.Parallel()

	const plaintext = "the new report"

	fsys, link, target := symlinkedDestination(t)

	w, err := opfile.Create(fsys, link, 0o600, opfile.FollowSymlinks())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := w.Path(); got != target {
		t.Errorf("Path() = %q, want the resolved %q — the caller cannot log where it went", got, target)
	}

	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The link survives and points at the fresh content, which is the whole
	// reason for following rather than replacing.
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symbolic link did not survive being followed")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading the target: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("target holds %q, want %q", got, plaintext)
	}
}

// symlinkedDestination builds a destination that is a symbolic link to an
// existing file, on a real filesystem because MemMapFs has no way to make one.
func symlinkedDestination(t *testing.T) (fsys opfile.FS, link, target string) {
	t.Helper()

	dir := t.TempDir()

	target = filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("the previous report"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	link = filepath.Join(dir, "report.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	return opfileafero.Wrap(afero.NewOsFs()), link, target
}

// TestFollowSymlinksRefusesWhatItCannotResolve covers the filesystem that can
// say "this is a link" and not what it points at — afero's in-memory one,
// exactly.
//
// Guessing there would mean writing through a link whose target nobody
// established. Refusing is the honest outcome, and it is why Lstater and
// LinkReader are separate optional interfaces rather than one.
func TestFollowSymlinksRefusesWhatItCannotResolve(t *testing.T) {
	t.Parallel()

	// The fixture is written here rather than borrowed from afero because the
	// case needs a filesystem with one capability and not the other, and no
	// real one is guaranteed to stay in that shape. An earlier version of this
	// test used afero's in-memory filesystem and asserted only that an *absent*
	// destination still worked — so it never reached a refusal at all, and the
	// name promised a guarantee nothing checked.
	for _, tc := range []struct {
		name string
		fsys opfile.FS
	}{
		{
			// Says "this is a link", cannot say what it points at.
			name: "no link resolution at all",
			fsys: linkFS{},
		},
		{
			name: "resolution that fails",
			fsys: resolvingFS{readlink: func(string) (string, error) {
				return "", errors.New("permission denied")
			}},
		},
		{
			// Every hop lands on another link, so resolution never terminates.
			name: "a link that never resolves to a file",
			fsys: resolvingFS{readlink: func(name string) (string, error) {
				return name + ".next", nil
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := opfile.Create(tc.fsys, "/reports/new.txt", 0o600, opfile.FollowSymlinks())
			if !errors.Is(err, opfile.ErrUnresolvableLink) {
				t.Fatalf("error = %v, want ErrUnresolvableLink — following wrote through a link "+
					"whose target nobody established", err)
			}
		})
	}
}

// TestFollowSymlinksLeavesAnAbsentDestinationAlone is the other half, and the
// only thing the test above used to cover.
//
// Enabling the option must not turn "there is nothing here yet" into a
// resolution failure: the ordinary case is a destination that does not exist.
func TestFollowSymlinksLeavesAnAbsentDestinationAlone(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()

	if _, err := opfile.Create(opfileafero.Wrap(mem), "/reports/new.txt", 0o600,
		opfile.FollowSymlinks()); err != nil {
		t.Errorf("an absent destination was refused with following enabled: %v", err)
	}
}

// linkFS reports every path as a symbolic link and cannot resolve one.
//
// It lstat's genuinely — it can tell a link from a target — but REFUSES
// Readlink with [opfile.ErrCapabilityUnsupported], which is the case under test:
// a filesystem honest about lacking a capability says so per call, and following
// is then refused rather than guessed. The refusal is a runtime answer now, not
// a missing method, so one type expresses it; resolvingFS overrides Readlink to
// reach the hops past the capability check.
type linkFS struct{}

func (linkFS) Open(string) (fs.File, error)                        { return nil, fs.ErrNotExist }
func (linkFS) CreateExcl(string, fs.FileMode) (opfile.File, error) { return nil, fs.ErrPermission }
func (linkFS) Stat(string) (fs.FileInfo, error)                    { return nil, fs.ErrNotExist }
func (linkFS) Rename(string, string) error                         { return fs.ErrPermission }
func (linkFS) SyncDir(string) error                                { return opfile.ErrCapabilityUnsupported }
func (linkFS) Remove(string) error                                 { return nil }
func (linkFS) Chmod(string, fs.FileMode) error                     { return opfile.ErrCapabilityUnsupported }

func (linkFS) Lstat(name string) (fs.FileInfo, error) {
	return linkInfo{name: filepath.Base(name)}, nil
}

// Readlink refuses: this filesystem can see a link but not resolve it.
func (linkFS) Readlink(string) (string, error) { return "", opfile.ErrCapabilityUnsupported }

// resolvingFS is a linkFS that can also resolve, so it reaches the hops past
// the capability check.
type resolvingFS struct {
	linkFS

	readlink func(name string) (string, error)
}

func (r resolvingFS) Readlink(name string) (string, error) { return r.readlink(name) }

// linkInfo is the metadata of a symbolic link and nothing else.
type linkInfo struct{ name string }

func (i linkInfo) Name() string     { return i.name }
func (linkInfo) Size() int64        { return 0 }
func (linkInfo) Mode() fs.FileMode  { return os.ModeSymlink | 0o777 }
func (linkInfo) ModTime() time.Time { return time.Time{} }
func (linkInfo) IsDir() bool        { return false }
func (linkInfo) Sys() any           { return nil }

// TestFollowSymlinksResolvesAChainWithinItsBudget covers the off-by-one in the
// hop limit.
//
// Each pass inspects a path and then follows at most one link, so resolving a
// chain of exactly maxHops links needs one more inspection than there are
// links. Looping maxHops times refused a chain of eight that had in fact
// resolved to a regular file well inside its budget — the operator was told
// their destination "leads through more than 8 links" when it led through
// exactly eight and ended somewhere perfectly writable.
func TestFollowSymlinksResolvesAChainWithinItsBudget(t *testing.T) {
	t.Parallel()

	const maxHops = 8

	for _, tc := range []struct {
		name    string
		links   int
		wantErr bool
	}{
		{"one short of the limit", maxHops - 1, false},
		{"exactly the limit", maxHops, false},
		{"one past the limit", maxHops + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			target := filepath.Join(dir, "target.txt")
			if err := os.WriteFile(target, []byte("the previous report"), 0o600); err != nil {
				t.Fatalf("write target: %v", err)
			}

			// A chain of tc.links symbolic links ending at the regular file.
			at := target

			for i := range tc.links {
				link := filepath.Join(dir, "link"+strconv.Itoa(i))
				if err := os.Symlink(at, link); err != nil {
					t.Skipf("symlinks unavailable here: %v", err)
				}

				at = link
			}

			_, err := opfile.Create(opfileafero.Wrap(afero.NewOsFs()), at, 0o600, opfile.FollowSymlinks())

			switch {
			case tc.wantErr && !errors.Is(err, opfile.ErrUnresolvableLink):
				t.Errorf("a chain of %d links: error = %v, want ErrUnresolvableLink", tc.links, err)
			case !tc.wantErr && err != nil:
				t.Errorf("a chain of %d links resolved to a regular file but was refused: %v", tc.links, err)
			}
		})
	}
}

// TestRefusalNamesThePathTheOperatorTyped covers the diagnostic.
//
// Every error from the resolver used to read the walking variable, so from the
// second hop onwards it named an intermediate link the operator had never
// typed and that appeared nowhere in their command.
func TestRefusalNamesThePathTheOperatorTyped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A chain ending at a directory, which cannot be replaced atomically — so
	// the refusal comes from deep in the walk rather than the first pass.
	destination := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	at := destination

	for i := range 3 {
		link := filepath.Join(dir, "link"+strconv.Itoa(i))
		if err := os.Symlink(at, link); err != nil {
			t.Skipf("symlinks unavailable here: %v", err)
		}

		at = link
	}

	_, err := opfile.Create(opfileafero.Wrap(afero.NewOsFs()), at, 0o600, opfile.FollowSymlinks())
	if err == nil {
		t.Fatal("a chain ending at a directory was accepted")
	}

	if !strings.Contains(err.Error(), at) {
		t.Errorf("the refusal does not name %s, the path the operator typed: %v", at, err)
	}
}

// TestCleanupHappensOnceOnEveryFailurePath covers the double-cleanup that the
// committed flag did not guard against.
//
// Both commands defer Abandon unconditionally, which is deliberate: without it
// a failed run leaves its temporary behind, and the common failures here are
// routine. But Commit's three failure branches each cleaned up by hand and left
// the flag false, so the deferred Abandon ran the cleanup a second time —
// closing an already-closed handle and removing an already-removed path.
//
// Nothing was lost with the filesystems in this tree, because both second calls
// return errors that are discarded and the staged name is unique. It is pinned
// anyway: File's contract does not promise Close-once, so an implementation
// that counted on it — a pooled handle, a strict double — would break on a
// failed sync, and that is exactly the kind of thing nobody would connect back
// to this function.
func TestCleanupHappensOnceOnEveryFailurePath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fail func(f *countingFile, fsys *countingFS)
	}{
		{"sync fails", func(f *countingFile, _ *countingFS) { f.syncErr = errors.New("disk went away") }},
		{"close fails", func(f *countingFile, _ *countingFS) { f.closeErr = errors.New("cannot close") }},
		{"rename fails", func(_ *countingFile, fsys *countingFS) { fsys.renameErr = errors.New("cross-device") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fsys := &countingFS{FS: opfileafero.Wrap(afero.NewMemMapFs())}

			w, err := opfile.Create(fsys, "/reports/report.txt", 0o600)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			tc.fail(fsys.file, fsys)

			if _, err := w.Write([]byte("a report")); err != nil {
				t.Fatalf("Write: %v", err)
			}

			if err := w.Commit(); err == nil {
				t.Fatal("Commit reported success although the run failed")
			}

			// What both commands do, unconditionally.
			w.Abandon()

			if fsys.file.closes > 1 {
				t.Errorf("the staged handle was closed %d times", fsys.file.closes)
			}

			if fsys.removes > 1 {
				t.Errorf("the staged file was removed %d times", fsys.removes)
			}

			if fsys.removes == 0 {
				t.Error("the staged file was never removed, so a failed run leaves it behind")
			}
		})
	}
}

// countingFS counts the cleanup operations and can fail a rename.
type countingFS struct {
	opfile.FS

	file      *countingFile
	removes   int
	renameErr error
}

func (f *countingFS) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	inner, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}

	f.file = &countingFile{File: inner}

	return f.file, nil
}

func (f *countingFS) Remove(name string) error {
	f.removes++

	return f.FS.Remove(name)
}

func (f *countingFS) Rename(oldpath, newpath string) error {
	if f.renameErr != nil {
		return f.renameErr
	}

	return f.FS.Rename(oldpath, newpath)
}

// countingFile counts closes and can fail either of the two operations Commit
// performs before the rename.
type countingFile struct {
	opfile.File

	closes   int
	syncErr  error
	closeErr error
}

func (f *countingFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}

	return f.File.Sync()
}

func (f *countingFile) Close() error {
	f.closes++

	if f.closeErr != nil {
		return f.closeErr
	}

	return f.File.Close()
}

// TestAChmodThisFilesystemRefusesIsNotFatal covers the regression the mode fix
// would otherwise have introduced.
//
// chmod returns EPERM on a vfat or exfat mount, which is what a USB stick is
// formatted as. Failing the write there would refuse `sigillum certificate
// --output /media/usb/security.asc` outright — a destination that worked before
// the mode was made exact.
//
// The security half of the promise is what is enforced: CreateExcl's perm is
// masked by the umask, which only ever narrows, so a file whose chmod failed is
// at worst tighter than asked for and never broader. The file is written, and
// the discrepancy is reported rather than swallowed.
func TestAChmodThisFilesystemRefusesIsNotFatal(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll("/reports", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	fsys := &refusingChmodFS{FS: opfileafero.Wrap(mem)}

	w, err := opfile.Create(fsys, "/reports/report.txt", 0o600)
	if err != nil {
		t.Fatalf("a filesystem that cannot chmod refused the write entirely: %v", err)
	}

	defer w.Abandon()

	if w.ModeNote() == "" {
		t.Error("the mode could not be set and nothing says so, so the operator cannot learn of it")
	}
}

// TestAFailedChmodLeavesNothingBehind covers the leak the mode fix introduced.
//
// This package exists to guarantee two things: the destination is untouched
// until the content is complete, and no staged file is ever left behind. When
// the chmod fails AND the file is broader than requested, Create refuses — and
// on that path it returns no Writer, so nobody can reach Abandon. Without an
// explicit removal the staged file is unreachable garbage in the operator's
// directory, holding a mode too broad for what was about to be written into it.
func TestAFailedChmodLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll("/reports", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	fsys := &broadeningFS{FS: opfileafero.Wrap(mem)}

	if _, err := opfile.Create(fsys, "/reports/report.txt", 0o600); err == nil {
		t.Fatal("a staged file broader than requested was accepted")
	}

	found, err := afero.ReadDir(mem, "/reports")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}

	for _, entry := range found {
		t.Errorf("a failed chmod left %q behind, and no Writer exists to abandon it", entry.Name())
	}
}

// refusingChmodFS satisfies Chmoder and refuses, which is what a vfat mount
// does — the capability is present, the operation is not permitted.
//
// It also creates NARROWER than asked, which is the shape that makes the note
// worth having. A filesystem that refuses chmod but happens to create at
// exactly the requested mode has nothing to report, and reporting it anyway
// would be a warning that fires on a correct outcome.
type refusingChmodFS struct{ opfile.FS }

func (refusingChmodFS) Chmod(string, fs.FileMode) error {
	return fs.ErrPermission
}

func (f refusingChmodFS) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	return f.FS.CreateExcl(name, perm&0o400)
}

// broadeningFS creates files world-readable whatever was asked for, and then
// refuses to change them — the one shape that must be refused rather than
// noted, since a decrypted report would land at a mode broader than requested.
type broadeningFS struct{ opfile.FS }

func (*broadeningFS) Chmod(string, fs.FileMode) error { return fs.ErrPermission }

func (f *broadeningFS) CreateExcl(name string, _ fs.FileMode) (opfile.File, error) {
	return f.FS.CreateExcl(name, 0o666)
}

// TestModeIsSetThroughTheHandleNotThePath covers a time-of-check race the mode
// fix opened.
//
// Setting the mode by path means chmod(2) resolves that path again, at a moment
// after the file was created. The staged name is unpredictable, but the
// directory is one the operator chose and may be shared — /tmp, a spool, a
// group-writable reports directory — and anyone who can write there can replace
// the staged name with a symbolic link in the window between the two calls. The
// mode then lands on whatever the link points at.
//
// The fix is fchmod: the descriptor already refers to the file that was
// created, so no path is resolved a second time and there is no window. This
// test forces the window deterministically rather than racing for it.
func TestModeIsSetThroughTheHandleNotThePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Something an attacker would like to widen: another user's private file.
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("someone else's report"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	fsys := &swappingFS{FS: opfile.OS(), swapTo: victim, t: t}

	w, err := opfile.Create(fsys, filepath.Join(dir, "report.txt"), 0o644)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	defer w.Abandon()

	if !fsys.swapped {
		t.Fatal("the fixture never got to plant the link, so nothing was under test")
	}

	info, err := os.Lstat(victim)
	if err != nil {
		t.Fatalf("lstat victim: %v", err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the victim file is now mode %#o, want the untouched 0600 — the mode was applied "+
			"through a path an attacker replaced rather than through the open handle", got)
	}
}

// swappingFS replaces the staged name with a symbolic link the instant after it
// is created, which is the window a path-based chmod leaves open.
//
// It declares Chmod explicitly rather than relying on the embedded opfile.FS.
// That embed is an INTERFACE, and opfile.FS has no Chmod — so without this the
// type does not satisfy Chmoder, setMode returns having done nothing, and the
// test passes without exercising anything at all. It did exactly that when
// first written.
type swappingFS struct {
	opfile.FS

	t       *testing.T
	swapTo  string
	swapped bool
}

// Chmod is path-based, like the real osFS one this test exists to replace.
func (f *swappingFS) Chmod(name string, mode fs.FileMode) error {
	return os.Chmod(name, mode)
}

func (f *swappingFS) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	file, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}

	if err := os.Remove(name); err != nil {
		f.t.Fatalf("fixture: removing the staged name: %v", err)
	}

	if err := os.Symlink(f.swapTo, name); err != nil {
		f.t.Skipf("symlinks unavailable here: %v", err)
	}

	f.swapped = true

	return file, nil
}
