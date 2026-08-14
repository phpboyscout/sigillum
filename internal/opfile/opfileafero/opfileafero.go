// Package opfileafero adapts an afero filesystem to [opfile.FS].
//
// The bridge for consumers who already hold one, which sigillum does: root
// wiring puts afero.NewOsFs() into props.Props.FS and every command reaches it
// through GetFS.
//
// A separate package for the reason config-afero is a separate module: opfile
// states the operations it needs and nothing more, so reading it does not
// oblige anyone to know which filesystem library the tool happens to hold. The
// coupling lives here, where it can be replaced without touching the package
// that does the work.
//
// Wrap is the whole API.
package opfileafero

import (
	"errors"
	"io/fs"
	"os"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// Wrap adapts an afero filesystem to [opfile.FS].
//
// One wrapper, not the four shapes this used to build. opfile.FS asks for Lstat,
// Readlink and Chmod on every implementation and lets each answer
// [opfile.ErrCapabilityUnsupported] per call, so the adapter no longer has to
// encode "can this filesystem lstat?" in its type. It encodes it in the answer,
// which is where afero keeps it too: LstatIfPossible returns a flag saying
// whether a real lstat happened, and the old adapter threw that flag away — so a
// filesystem that only Stat'd was presented as one that had checked for a link.
//
// A nil filesystem panics rather than deferring the failure to the first write,
// matching the registry's stance that a miswired dependency is a start-up error.
func Wrap(fsys afero.Fs) opfile.FS {
	if fsys == nil {
		panic("opfileafero: Wrap called with a nil afero.Fs")
	}

	return wrapper{fsys: fsys}
}

type wrapper struct{ fsys afero.Fs }

func (w wrapper) Open(name string) (fs.File, error) { return w.fsys.Open(name) }

func (w wrapper) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	// afero mirrors the os flags, so exclusivity carries across unchanged.
	f, err := w.fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return nil, err
	}

	return file{f}, nil
}

func (w wrapper) Stat(name string) (fs.FileInfo, error)     { return w.fsys.Stat(name) }
func (w wrapper) Chmod(name string, mode fs.FileMode) error { return w.fsys.Chmod(name, mode) }
func (w wrapper) Rename(oldpath, newpath string) error      { return w.fsys.Rename(oldpath, newpath) }
func (w wrapper) Remove(name string) error                  { return w.fsys.Remove(name) }

// Lstat reports on a path without following a link, or refuses per call.
//
// The refusal is where the old adapter lied. afero's LstatIfPossible returns a
// flag saying whether it performed a real lstat or fell back to Stat; a
// filesystem like MemMapFs satisfies the Lstater interface and always falls
// back, so the flag is the only honest signal. When it is false the wrapper
// reports ErrCapabilityUnsupported rather than passing off the Stat result as an
// Lstat one, and opfile then treats the destination as unverifiable.
func (w wrapper) Lstat(name string) (fs.FileInfo, error) {
	lstater, ok := w.fsys.(afero.Lstater)
	if !ok {
		return nil, opfile.ErrCapabilityUnsupported
	}

	info, lstatCalled, err := lstater.LstatIfPossible(name)

	switch {
	case err != nil:
		// A real error — not-exist above all — passes through unchanged, so the
		// caller can still tell "nothing there" from "cannot check".
		return info, err
	case !lstatCalled:
		return info, opfile.ErrCapabilityUnsupported
	default:
		return info, nil
	}
}

// Readlink resolves one hop, or refuses per call.
func (w wrapper) Readlink(name string) (string, error) {
	reader, ok := w.fsys.(afero.LinkReader)
	if !ok {
		return "", opfile.ErrCapabilityUnsupported
	}

	target, err := reader.ReadlinkIfPossible(name)
	if errors.Is(err, afero.ErrNoReadlink) {
		// The filesystem declares LinkReader but cannot honour it for this path
		// — BasePathFs over an in-memory filesystem is the case — so the refusal
		// is a per-call fact, reported as one.
		return "", opfile.ErrCapabilityUnsupported
	}

	return target, err
}

// file adds Chmod-through-the-handle to an afero file.
//
// afero.File carries no Chmod, so the capability depends on the concrete type
// the filesystem hands back: OsFs returns an *os.File, which has it; an
// in-memory file does not. The old adapter returned the raw afero.File, so
// opfile's handle-first chmod only ever reached the *os.File by luck of the
// concrete type and was lost through any decorator. Wrapping it makes the
// capability a method that answers per call.
type file struct{ afero.File }

func (f file) Chmod(mode fs.FileMode) error {
	chmoder, ok := f.File.(interface {
		Chmod(fs.FileMode) error
	})
	if !ok {
		return opfile.ErrCapabilityUnsupported
	}

	return chmoder.Chmod(mode)
}
