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
	"io/fs"
	"os"

	"github.com/spf13/afero"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// Wrap adapts an afero filesystem to [opfile.FS].
//
// The result always satisfies [opfile.Chmoder], since afero requires Chmod of
// every filesystem, and satisfies [opfile.Lstater] and [opfile.LinkReader] only
// where the wrapped filesystem genuinely provides each. Both are optional in afero too,
// and an adapter that always had the methods would make every filesystem look
// able to tell a link from its target and to resolve it — which is precisely
// the rule that an implementation must not satisfy an optional interface it
// cannot honour.
//
// The two are separate capabilities and afero really does split them: its
// in-memory filesystem can lstat but cannot readlink. So a caller who has asked
// to follow symlinks gets a clear refusal there rather than a guess.
func Wrap(fsys afero.Fs) opfile.FS {
	w := wrapper{fsys: fsys}

	_, canLstat := fsys.(afero.Lstater)
	_, canReadlink := fsys.(afero.LinkReader)

	switch {
	case canLstat && canReadlink:
		return lstatAndLink{w}
	case canLstat:
		return lstatOnly{w}
	case canReadlink:
		return linkOnly{w}
	default:
		return w
	}
}

type wrapper struct{ fsys afero.Fs }

func (w wrapper) Open(name string) (fs.File, error) { return w.fsys.Open(name) }

func (w wrapper) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	// afero mirrors the os flags, so exclusivity carries across unchanged.
	return w.fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
}

func (w wrapper) Stat(name string) (fs.FileInfo, error) { return w.fsys.Stat(name) }

// Chmod satisfies [opfile.Chmoder] on every shape, because afero.Fs requires it
// of every filesystem — unlike lstat and readlink, it is not optional there, so
// no extra shape is needed to express its absence.
func (w wrapper) Chmod(name string, mode fs.FileMode) error { return w.fsys.Chmod(name, mode) }
func (w wrapper) Rename(oldpath, newpath string) error      { return w.fsys.Rename(oldpath, newpath) }
func (w wrapper) Remove(name string) error                  { return w.fsys.Remove(name) }

func (w wrapper) lstat(name string) (fs.FileInfo, error) {
	info, _, err := w.fsys.(afero.Lstater).LstatIfPossible(name)

	return info, err
}

func (w wrapper) readlink(name string) (string, error) {
	return w.fsys.(afero.LinkReader).ReadlinkIfPossible(name)
}

// Four shapes rather than one, because the two capabilities are independent and
// a type either has a method or does not. Anything cleverer — a method that
// reports its own absence — is the thing the optional-interface rule forbids.

type lstatOnly struct{ wrapper }

func (w lstatOnly) Lstat(name string) (fs.FileInfo, error) { return w.lstat(name) }

type linkOnly struct{ wrapper }

func (w linkOnly) Readlink(name string) (string, error) { return w.readlink(name) }

type lstatAndLink struct{ wrapper }

func (w lstatAndLink) Lstat(name string) (fs.FileInfo, error) { return w.lstat(name) }
func (w lstatAndLink) Readlink(name string) (string, error)   { return w.readlink(name) }
