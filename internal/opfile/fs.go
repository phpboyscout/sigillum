package opfile

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FS is the filesystem surface this package needs, and the whole of it.
//
// Deliberately small, for the reason config.FS is: stating exactly the
// operations required is what lets a caller supply the operating system, an
// in-memory filesystem or their own implementation without inheriting a
// dependency chosen on their behalf. This package is reached from a command
// that already holds an afero.Fs, but nothing here should oblige a reader of
// this package to know that.
//
// The standard library has no equivalent. io/fs.FS is read-only by design — no
// create, no rename, no remove — so it cannot express a package whose whole
// purpose is replacing a file safely. os.Root has the operations but is a
// concrete type with no in-memory implementation, so nothing can substitute for
// it in a test.
//
// Every method is mandatory, and the capability that varies between filesystems
// — can this one tell a link from its target, set a POSIX mode — is reported
// PER CALL with [ErrCapabilityUnsupported] rather than by whether the type
// happens to carry a method.
//
// That is the correction to what came before: four optional interfaces a caller
// sniffed for. Whether an afero filesystem can lstat is not a property of its
// type — afero's MemMapFs satisfies the Lstater interface and then falls back to
// Stat, discarding the flag that said so, so it claimed to have checked for a
// link when it had not. A method every implementation must provide, answering
// "I could not" per call, makes the capability a value-and-call fact instead of
// a type-level guess, which is the only granularity that can be honest.
type FS interface {
	// Open reads an existing file.
	Open(name string) (fs.File, error)

	// CreateExcl creates a new file and fails if the name already exists.
	//
	// Exclusive because the caller stages content under a generated name: two
	// concurrent runs writing the same destination must not be handed the same
	// temporary, and silently truncating an existing file is exactly the
	// behaviour this package exists to avoid.
	CreateExcl(name string, perm fs.FileMode) (File, error)

	// Stat reports a file's metadata, following symbolic links.
	Stat(name string) (fs.FileInfo, error)

	// Lstat reports on a path without following a symbolic link, or returns
	// [ErrCapabilityUnsupported] if this filesystem cannot tell a link from its
	// target.
	//
	// The refusal is honest where the old optional interface was not: a
	// filesystem that cannot distinguish a link says so per call, and the caller
	// consults Stat and decides what an unverifiable destination means, rather
	// than being handed a Stat result dressed up as an Lstat one.
	Lstat(name string) (fs.FileInfo, error)

	// Readlink resolves one symbolic-link hop, or returns
	// [ErrCapabilityUnsupported] where the filesystem cannot say what a link
	// points at.
	Readlink(name string) (string, error)

	// Chmod sets a file's mode by path, or returns [ErrCapabilityUnsupported]
	// where the filesystem has no POSIX modes.
	//
	// Needed because CreateExcl's perm is a request, not an instruction — the
	// process umask masks it, so an operator with `umask 077` publishing a
	// certificate at the documented 0644 got 0600 and a web server that could
	// not read it. The staged file is chmod'd immediately after creation, before
	// any content is written, so the mode is exact without ever widening a file
	// that holds a report. Where it is unsupported the requested mode is subject
	// to the umask, which narrows and never widens — the safe direction.
	Chmod(name string, mode fs.FileMode) error

	// Rename moves a file, and is how a write is committed: content is staged
	// beside the destination and renamed over it, so a reader never observes a
	// half-written file.
	Rename(oldpath, newpath string) error

	// Remove deletes a file, used to discard staged content never committed.
	Remove(name string) error
}

// File is a staged file being written.
//
// Sync is part of the minimum rather than an optional extra, because the
// package's guarantee depends on it: rename is atomic with respect to the
// directory entry, not the data behind it, so a filesystem that cannot flush
// cannot honour "the old content or the complete new content". An in-memory
// implementation satisfies it trivially and truthfully — there is no writeback
// to wait for.
type File interface {
	io.Writer

	// Chmod sets this open file's mode through its handle, or returns
	// [ErrCapabilityUnsupported] where the file cannot.
	//
	// Preferred over [FS.Chmod] because it closes a window that setting the mode
	// by path leaves open: chmod(2) resolves the path a second time, after the
	// file was created, and anyone who can write to the directory can replace the
	// staged name with a symbolic link in between — the mode then lands on
	// whatever the link points at. The descriptor already refers to the file that
	// was created, so it resolves nothing and there is no window. *os.File
	// honours it; an in-memory file refuses per call and setMode falls back to
	// [FS.Chmod].
	Chmod(mode fs.FileMode) error

	Sync() error
	Close() error
}

// ErrModeUnverified means the staged file's mode could not be confirmed no
// broader than requested — it could not be set and could not be read back, or
// it read back broader. A refusal, because leaving a decrypted report at a mode
// this cannot bound is the one outcome the mode handling exists to prevent.
var ErrModeUnverified = errors.New("staged file mode could not be confirmed no broader than requested")

// ErrCapabilityUnsupported is returned by a per-call capability — Lstat,
// Readlink, Chmod — that this filesystem or file cannot honour.
//
// The one signal that replaced four optional interfaces. A caller matches it
// with errors.Is and decides what the absence means for its own operation,
// rather than discovering the capability's absence from a missing method and
// having no way to tell "genuinely absent" from "present but faked".
var ErrCapabilityUnsupported = errors.New("filesystem capability not supported")

// ErrNoStagingName means no unused temporary name could be found beside the
// destination, which in practice means the directory is unwritable or something
// is generating collisions deliberately.
var ErrNoStagingName = errors.New("no unused name to stage content under")

// OS returns an [FS] backed by the operating system.
//
// The default, so that using this package standalone requires nothing beyond
// the standard library. A caller who holds a different filesystem passes that
// instead.
func OS() FS { return osFS{} }

type osFS struct{}

func (osFS) Open(name string) (fs.File, error) { return os.Open(name) }

func (osFS) CreateExcl(name string, perm fs.FileMode) (File, error) {
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
}

func (osFS) Stat(name string) (fs.FileInfo, error)     { return os.Stat(name) }
func (osFS) Rename(oldpath, newpath string) error      { return os.Rename(oldpath, newpath) }
func (osFS) Remove(name string) error                  { return os.Remove(name) }
func (osFS) Lstat(name string) (fs.FileInfo, error)    { return os.Lstat(name) }
func (osFS) Chmod(name string, mode fs.FileMode) error { return os.Chmod(name, mode) }
func (osFS) Readlink(name string) (string, error)      { return os.Readlink(name) }

// stage creates a uniquely named file beside the destination.
//
// The name is generated here rather than asking the filesystem for a temporary,
// so [FS] needs no CreateTemp method — one fewer operation every implementation
// has to provide, and the retry on collision is the same either way.
func stage(fsys FS, dir, name string, perm fs.FileMode) (f File, path, note string, err error) {
	const attempts = 10

	for range attempts {
		path := filepath.Join(dir, "."+name+"."+randomSuffix())

		f, err := fsys.CreateExcl(path, perm)

		switch {
		case err == nil:
			// The umask masked perm on the way in, so the mode is set again
			// here — while the file is still empty, so nothing is ever exposed
			// at a mode broader than it will end up with.
			note, err := setMode(fsys, f, path, perm)
			if err != nil {
				// Remove what was just created. Create returns no Writer on
				// this path, so nobody downstream can reach Abandon and the
				// staged file would be unreachable garbage in the operator's
				// directory — in the package whose whole promise is that
				// nothing is left behind.
				_ = f.Close()
				_ = fsys.Remove(path)

				return nil, "", "", err
			}

			return f, path, note, nil
		case errors.Is(err, fs.ErrExist):
			continue
		default:
			return nil, "", "", err
		}
	}

	return nil, "", "", fmt.Errorf("%w: %s, after %d attempts",
		ErrNoStagingName, filepath.Join(dir, name), attempts)
}

func randomSuffix() string {
	var b [10]byte

	// crypto/rand.Read cannot fail on any supported platform; it panics
	// internally rather than returning an error worth handling here.
	_, _ = rand.Read(b[:])

	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// setMode makes a staged file's mode exactly what the caller asked for, where
// the filesystem can, and reports what happened when it cannot.
//
// A chmod failure is NOT fatal, and that is a deliberate choice between two
// promises. Exactness — "created mode 0644" — matters because a published
// certificate a web server cannot read is a certificate nobody can encrypt to.
// But chmod returns EPERM on a vfat or exfat mount, which is what a USB stick
// is formatted as, so failing the write would refuse `--output
// /media/usb/security.asc` outright: a destination that worked before the mode
// was made exact.
//
// The security half of the promise is the one that is enforced. CreateExcl's
// perm is masked by the umask, which only ever NARROWS, so a file whose chmod
// failed is at worst tighter than asked for — never broader, which is the
// direction that would expose a decrypted report. That is checked here rather
// than assumed, because "the umask only narrows" is a claim about the
// filesystem and this package takes the filesystem from its caller.
//
// So: exact where possible, tighter with a note where not, and refused only if
// the file somehow ended up BROADER than requested.
func setMode(fsys FS, f File, path string, perm fs.FileMode) (note string, err error) {
	chmodErr, attempted := chmod(fsys, f, path, perm)
	if chmodErr == nil && attempted {
		return "", nil
	}

	// Checked when no chmod was POSSIBLE too, not only when one failed.
	//
	// That case is precisely the one where nothing corrected CreateExcl's mode,
	// so it is where the never-broader-than-requested property is least
	// established — and this returned early without looking, while its own
	// comment said the property "is checked here rather than assumed, because
	// 'the umask only narrows' is a claim about the filesystem and this package
	// takes the filesystem from its caller".
	//
	// why states, in one place, why the mode is not exact — a chmod that failed,
	// or one the filesystem cannot do at all — so the messages below never wrap a
	// nil error and never fall silent about which it was.
	why := "this filesystem does not support changing it"
	if attempted {
		why = fmt.Sprintf("this filesystem refused to change it: %v", chmodErr)
	}

	info, statErr := fsys.Stat(path)
	if statErr != nil {
		// The mode could neither be set nor read back, so this cannot prove the
		// file is not broader than requested — the one property it must never
		// leave unverified. Refused rather than passed silently, which is what it
		// used to do when no chmod had been attempted (finding #17).
		return "", fmt.Errorf("%w: mode neither settable nor readable (%s), and reading it back: %w",
			ErrModeUnverified, why, statErr)
	}

	if broader := info.Mode().Perm() &^ perm.Perm(); broader != 0 {
		// Refused whether or not a chmod was attempted, and without wrapping a
		// nil error: the old form wrapped chmodErr unconditionally, so when no
		// chmod had been possible the message ended in %!w(<nil>) (finding #18).
		return "", fmt.Errorf("%w: the staged file is mode %#o, broader than the %#o requested, and %s",
			ErrModeUnverified, info.Mode().Perm(), perm.Perm(), why)
	}

	// Tighter than requested, which is safe, so it is a note rather than a
	// refusal — and only worth saying when it actually differs.
	if info.Mode().Perm() == perm.Perm() {
		return "", nil
	}

	return fmt.Sprintf("%s is mode %#o rather than the %#o requested; %s",
		path, info.Mode().Perm(), perm.Perm(), why), nil
}

// chmod sets the mode through the open handle where it can, and by path where
// it cannot, reporting whether either was possible.
//
// The handle first, because chmod-by-descriptor resolves nothing and so cannot
// be redirected through a planted link. Each is asked by CALLING it: the file or
// the filesystem answers ErrCapabilityUnsupported when it has no modes to set,
// and only then does this fall through — so a filesystem that can chmod by path
// but not by handle still gets its mode set, which the old handle-or-nothing
// type assertion missed whenever an afero decorator hid the *os.File.
func chmod(fsys FS, f File, path string, perm fs.FileMode) (err error, attempted bool) {
	if ferr := f.Chmod(perm); !errors.Is(ferr, ErrCapabilityUnsupported) {
		return ferr, true
	}

	if perr := fsys.Chmod(path, perm); !errors.Is(perr, ErrCapabilityUnsupported) {
		return perr, true
	}

	return nil, false
}
