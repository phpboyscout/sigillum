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
// Adding a method here is a breaking change for every implementation, so
// capability beyond this minimum is an optional interface — see [Lstater] —
// that an implementation may simply not have.
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

	Sync() error
	Close() error
}

// LinkReader optionally resolves a symbolic link.
//
// Separate from [Lstater] because they are different capabilities: a filesystem
// may be able to say "this is a link" without being able to say what it points
// at. Only a caller who has opted into following needs the second, so a
// filesystem that cannot resolve simply does not have the method and following
// is refused rather than guessed at.
type LinkReader interface {
	Readlink(name string) (string, error)
}

// Chmoder optionally sets a file's mode after it has been created.
//
// Optional for the same reason [Lstater] is: not every filesystem has POSIX
// modes to set, and one that does not must not claim it can.
//
// Needed because CreateExcl's perm is a request, not an instruction — the
// process umask masks it, so an operator with `umask 077` publishing a
// certificate at the documented 0644 got 0600 and a web server that could not
// read it. The staged file is chmod'd immediately after creation and before any
// content is written, so the mode is exact without ever widening a file that
// holds a report.
//
// Where it is absent the requested mode is subject to the umask, which narrows
// and never widens — the safe direction, and the one that matters for a
// decrypted report.
type Chmoder interface {
	Chmod(name string, mode fs.FileMode) error
}

// ModeSetter optionally sets an open file's mode through its handle.
//
// Preferred over [Chmoder] wherever a [File] provides it, because it closes a
// window that setting the mode by path leaves open: chmod(2) resolves the path
// a second time, at a moment after the file was created, and anyone who can
// write to the directory can replace the staged name with a symbolic link in
// between. The mode then lands on whatever the link points at. The descriptor
// already refers to the file that was created, so it resolves nothing and
// there is no window.
//
// *os.File satisfies this, and so does the file afero's OsFs returns, since it
// is the same type — so the real filesystems both take this path. An in-memory
// implementation that cannot honour it must simply not have the method, and
// falls back to [Chmoder].
type ModeSetter interface {
	Chmod(mode fs.FileMode) error
}

// Lstater optionally reports on a path without following a symbolic link.
//
// Optional because a filesystem with no notion of links cannot honour it, and
// per the estate's rule an implementation must not satisfy an optional
// interface it cannot honour — returning "not a link" from a filesystem that
// has no links makes every path look checked when nothing was.
//
// Where it is absent, [Stat] is used and a link is indistinguishable from its
// target, which is the honest outcome rather than a guess.
type Lstater interface {
	Lstat(name string) (fs.FileInfo, error)
}

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

	info, statErr := fsys.Stat(path)
	if statErr != nil {
		if chmodErr == nil {
			return "", nil
		}

		return "", fmt.Errorf("setting the mode of the staged file: %w", chmodErr)
	}

	if broader := info.Mode().Perm() &^ perm.Perm(); broader != 0 {
		return "", fmt.Errorf("the staged file is mode %#o, broader than the %#o requested, "+
			"and this filesystem will not change it: %w", info.Mode().Perm(), perm.Perm(), chmodErr)
	}

	// Tighter than requested, which is safe, so it is a note rather than a
	// refusal — and only worth saying when it actually differs.
	if info.Mode().Perm() == perm.Perm() {
		return "", nil
	}

	return fmt.Sprintf("%s is mode %#o rather than the %#o requested; this filesystem does not "+
		"support changing it", path, info.Mode().Perm(), perm.Perm()), nil
}

// chmod sets the mode through the open handle where it can, and by path where
// it cannot, reporting whether either was possible.
func chmod(fsys FS, f File, path string, perm fs.FileMode) (err error, attempted bool) {
	if setter, ok := f.(ModeSetter); ok {
		return setter.Chmod(perm), true
	}

	if chmoder, ok := fsys.(Chmoder); ok {
		return chmoder.Chmod(path, perm), true
	}

	return nil, false
}
