// Package opdest opens the destination a command writes its result to.
//
// One implementation for both commands. They had a copy each — the same
// destination struct, the same stdout sentinel, the same staged-write wiring,
// differing only in the file mode and in which sentence the comments used. Two
// copies of this drift, and the drift is invisible: an improvement made to one
// command silently does not reach the other, which is exactly what happened to
// the resolved-path reporting below.
//
// The stdout case lives here rather than in opfile because it is a property of
// how a command is invoked, not of a filesystem: `-` and the empty string both
// mean "write to standard output", where there is nothing to stage, nothing to
// replace and nothing to abandon.
package opdest

import (
	"io"
	"io/fs"
	"os"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// Destination is somewhere a command's output will land.
//
// Nothing replaces the operator's file until [Destination.Commit] is called, so
// a run that fails part way leaves whatever was there untouched. That matters
// for both commands and for different reasons: a failed decryption is routine —
// a message addressed to another key, a truncated paste — and a published
// certificate replaced by a half-written one is worse than writing nothing,
// because correspondents encrypt to it.
type Destination struct {
	// Writer takes the output. Never nil.
	Writer io.Writer

	commit  func() error
	abandon func()

	path  string
	typed string
}

// Open prepares the destination named by path, staging the write unless it is
// standard output.
//
// mode is the mode the committed file will carry exactly, umask
// notwithstanding — see [opfile.Chmoder].
func Open(fsys opfile.FS, path string, mode fs.FileMode, followSymlinks bool) (Destination, error) {
	if path == "" || path == "-" {
		return Destination{
			Writer:  os.Stdout,
			commit:  func() error { return nil },
			abandon: func() {},
		}, nil
	}

	var opts []opfile.Option
	if followSymlinks {
		opts = append(opts, opfile.FollowSymlinks())
	}

	w, err := opfile.Create(fsys, path, mode, opts...)
	if err != nil {
		return Destination{}, err
	}

	return Destination{
		Writer:  w,
		commit:  w.Commit,
		abandon: w.Abandon,
		path:    w.Path(),
		typed:   path,
	}, nil
}

// Commit puts the staged content in place. A no-op for standard output.
func (d Destination) Commit() error { return d.commit() }

// Abandon discards staged content that was never committed.
//
// Safe after a commit and safe on standard output, so a caller can defer it
// unconditionally — which they should: without it a failed run leaves its
// temporary behind, and the common failures are routine enough that they
// accumulate, owner-readable, sometimes holding part of a report.
func (d Destination) Abandon() { d.abandon() }

// Path is where the bytes will actually land, which is not always what the
// operator typed. Empty for standard output.
func (d Destination) Path() string { return d.path }

// Resolved reports whether the bytes landed somewhere other than the path the
// operator named, which happens when --follow-symlinks resolves a link.
//
// The whole justification for offering that option is opfile's own: "the
// resolved path is reported back so it can be logged: the failure mode of
// following is silence, and that part is cheap to remove". opfile did report
// it; until this existed neither command read it, so the mitigation lived in a
// comment and nowhere else.
func (d Destination) Resolved() bool { return d.path != "" && d.path != d.typed }

// Requested is the path as the operator gave it.
func (d Destination) Requested() string { return d.typed }
