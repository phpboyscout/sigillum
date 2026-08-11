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

func (osFS) Stat(name string) (fs.FileInfo, error)  { return os.Stat(name) }
func (osFS) Rename(oldpath, newpath string) error   { return os.Rename(oldpath, newpath) }
func (osFS) Remove(name string) error               { return os.Remove(name) }
func (osFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (osFS) Readlink(name string) (string, error)   { return os.Readlink(name) }

// stage creates a uniquely named file beside the destination.
//
// The name is generated here rather than asking the filesystem for a temporary,
// so [FS] needs no CreateTemp method — one fewer operation every implementation
// has to provide, and the retry on collision is the same either way.
func stage(fsys FS, dir, name string, perm fs.FileMode) (File, string, error) {
	const attempts = 10

	for range attempts {
		path := filepath.Join(dir, "."+name+"."+randomSuffix())

		f, err := fsys.CreateExcl(path, perm)

		switch {
		case err == nil:
			return f, path, nil
		case errors.Is(err, fs.ErrExist):
			continue
		default:
			return nil, "", err
		}
	}

	return nil, "", fmt.Errorf("%w: %s, after %d attempts",
		ErrNoStagingName, filepath.Join(dir, name), attempts)
}

func randomSuffix() string {
	var b [10]byte

	// crypto/rand.Read cannot fail on any supported platform; it panics
	// internally rather than returning an error worth handling here.
	_, _ = rand.Read(b[:])

	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}
