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
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// Destination is somewhere a command's output will land.
//
// Nothing replaces the operator's file until [Destination.Commit] is called, so
// a run that fails BEFORE the commit leaves whatever was there untouched. That
// matters for both commands and for different reasons: a failed decryption is
// routine — a message addressed to another key, a truncated paste — and a
// published certificate replaced by a half-written one is worse than writing
// nothing, because correspondents encrypt to it.
//
// The one exception is durability. Once Commit's rename lands the destination is
// replaced whatever happens next; a failure to flush the directory afterwards
// leaves the new content in place but its survival across a crash unconfirmed,
// reported as [ErrDurabilityUnconfirmed] rather than as a failed write, because
// the old file is already gone.
type Destination struct {
	// Writer takes the output. Never nil.
	Writer io.Writer

	commit  func() error
	abandon func()

	path  string
	typed string

	// modeNote records that the file could not be given exactly the mode asked
	// for. Empty when it could.
	//
	// Carried through from opfile because it was computed on every write and no
	// caller could read it: the Destination was built from the writer's Commit,
	// Abandon and Path alone, so the "the difference is reported" promise made
	// in both the code and the CLI reference was kept by nothing.
	modeNote string
}

// ModeNote reports that the committed file does not carry exactly the mode
// requested, and why. Empty when it does.
//
// Not an error — the file is written either way and is never broader than
// requested. It matters because a published certificate a web server cannot
// read is a certificate nobody can encrypt to, and the operator has no other
// way to learn that.
func (d Destination) ModeNote() string { return d.modeNote }

// Open prepares the destination named by path, staging the write unless it is
// standard output.
//
// mode is the mode the committed file will carry, exact where the filesystem can
// set it — umask notwithstanding — and never broader than requested where it
// cannot. A filesystem without POSIX modes leaves the file tighter and reports
// that through [Destination.ModeNote], which is why the promise here is
// "no broader", not "exactly": the old wording claimed an exactness the code
// deliberately does not guarantee on every filesystem.
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
		Writer:   w,
		commit:   w.Commit,
		abandon:  w.Abandon,
		path:     w.Path(),
		typed:    path,
		modeNote: w.ModeNote(),
	}, nil
}

// ErrDurabilityUnconfirmed is [opfile.ErrDurabilityUnconfirmed], re-exported so
// a command holding this package matches the one sentinel without importing
// opfile — the destination was replaced but the directory flush that makes the
// rename survive a crash did not complete. A warning over a written file, not a
// failed write.
var ErrDurabilityUnconfirmed = opfile.ErrDurabilityUnconfirmed

// Commit puts the staged content in place. A no-op for standard output.
func (d Destination) Commit() error { return d.commit() }

// CommitOrWarn commits, treating a durability-unconfirmed result as a warning
// over a written file rather than a failure.
//
// The destination was replaced the instant the rename landed; only the flush
// that makes that survive a crash did not complete. Returning the error would
// tell the operator nothing was written when their old file is already gone, so
// this passes it to warn and reports success. warn is the logger's Warn method,
// taken as a function so this needs no logging interface of its own. Any other
// commit error is returned unchanged.
func (d Destination) CommitOrWarn(warn func(msg string, keyvals ...any)) error {
	err := d.Commit()
	if err == nil || !errors.Is(err, ErrDurabilityUnconfirmed) {
		return err
	}

	warn("the output was written but its durability could not be confirmed", "detail", err)

	return nil
}

// Reporter is the sliver of a logger [Destination.Report] needs.
type Reporter interface {
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
}

// Report tells the operator where the content landed and whether its mode is
// what was asked for — once.
//
// The one place both are said. Each command used to log the mode note itself
// and then call a reporter that logged it again, so a single narrowing mode
// produced two identical lines (finding #32). Owning the reporting here, where
// the command has no Destination method left to duplicate it with, is what keeps
// that from recurring.
//
// what names the thing written ("report decrypted", "certificate written"), so
// the message reads for whichever command called it. The resolved-elsewhere case
// is Info because it is the one worth seeing without --verbose: the operator
// asked to follow a link and the content is not where they typed. The ordinary
// case is Debug.
func (d Destination) Report(log Reporter, what string) {
	switch {
	case d.Resolved():
		log.Info(what, "path", d.path, "requested", d.typed)
	case d.path != "":
		log.Debug(what, "path", d.path)
	}

	// Narrower than asked for rather than broader, so not a confidentiality
	// problem — but content the operator expected at one mode and got at a
	// tighter one is worth a line, said exactly once.
	if d.modeNote != "" {
		log.Info("the output file's mode is not what was asked for", "note", d.modeNote)
	}
}

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
func (d Destination) Resolved() bool {
	if d.path == "" {
		return false
	}

	// Compared against the CLEANED form of what the operator typed, because
	// opfile cleans before it resolves. Comparing against the raw string made
	// every non-canonical path — a doubled slash, a "./", a "../" — report as
	// having landed elsewhere, with following switched off and no link in
	// sight. A warning that fires on ordinary input hides the one case worth
	// seeing, which is a report written through a planted link.
	return d.path != filepath.Clean(d.typed)
}

// Requested is the path as the operator gave it.
func (d Destination) Requested() string { return d.typed }
