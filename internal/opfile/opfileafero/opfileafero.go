// Package opfileafero adapts an afero filesystem to [opfile.FS].
//
// The bridge for consumers who already hold one, which sigillum does: root
// wiring puts afero.NewOsFs() into props.Props.FS and every command reaches it
// through GetFS.
//
// A separate package for the reason config-afero is a separate module: opfile
// states the six operations it needs and nothing more, so reading it does not
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
// The result additionally satisfies [opfile.Lstater] when — and only when — the
// wrapped filesystem can tell a symbolic link from its target. Both afero's OS
// and in-memory filesystems can, so the distinction survives under test.
func Wrap(fsys afero.Fs) opfile.FS {
	w := wrapper{fsys: fsys}

	if _, ok := fsys.(afero.Lstater); ok {
		return lstatWrapper{wrapper: w}
	}

	return w
}

type wrapper struct{ fsys afero.Fs }

func (w wrapper) Open(name string) (fs.File, error) { return w.fsys.Open(name) }

func (w wrapper) CreateExcl(name string, perm fs.FileMode) (opfile.File, error) {
	// afero mirrors the os flags, so exclusivity carries across unchanged.
	return w.fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
}

func (w wrapper) Stat(name string) (fs.FileInfo, error) { return w.fsys.Stat(name) }
func (w wrapper) Rename(oldpath, newpath string) error  { return w.fsys.Rename(oldpath, newpath) }
func (w wrapper) Remove(name string) error              { return w.fsys.Remove(name) }

// lstatWrapper adds [opfile.Lstater] for the afero filesystems that can honour
// it.
//
// Split from wrapper deliberately. afero.Lstater is optional there too, and an
// adapter that always had the method would make every filesystem look able to
// tell a link from its target — including ones that cannot, which is precisely
// the "must not satisfy an optional interface it cannot honour" rule. Wrap
// returns this variant only when the wrapped filesystem genuinely provides it.
type lstatWrapper struct{ wrapper }

func (w lstatWrapper) Lstat(name string) (fs.FileInfo, error) {
	info, _, err := w.fsys.(afero.Lstater).LstatIfPossible(name)

	return info, err
}
