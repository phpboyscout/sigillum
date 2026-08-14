// Package opfile opens and creates the files an operator names on the command
// line.
//
// It exists to put three decisions in one place rather than at every call site:
// that a path typed by the operator is an instruction rather than untrusted
// input, that a command which fails must not have destroyed the file it was
// asked to write, and that every one of those touches goes through the
// filesystem the tool was given rather than reaching for the operating system
// directly.
//
// # The filesystem is a parameter
//
// Every touch goes through an [FS], which defaults to the operating system via
// [OS] — so standalone use needs nothing beyond the standard library — and can
// be any implementation a caller supplies.
//
// That follows go/config rather than reaching for afero directly: a narrow
// interface of exactly the operations needed, with adapters living outside the
// package, so importing this does not oblige a reader to know which filesystem
// library the tool happens to hold. sigillum wires its afero.Fs in through the
// adapter in opfileafero.
//
// It is not decoration. The two properties this package exists to provide —
// that a failed command leaves the destination alone, and that a rename never
// outlives the data behind it — are only observable because the filesystem can
// be substituted.
package opfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotRegular means the destination exists and is not an ordinary file.
var ErrNotRegular = errors.New("destination is not a regular file")

// ErrUnresolvableLink means following was asked for and the filesystem cannot
// say what a link points at.
var ErrUnresolvableLink = errors.New("symbolic link cannot be resolved")

// Option adjusts how a destination is prepared.
type Option func(*options)

type options struct{ followSymlinks bool }

// FollowSymlinks writes through a symbolic link named as the destination,
// replacing what it points at and leaving the link itself in place.
//
// Off by default, and the default is the safe half of a genuine trade-off
// rather than a considered preference for one workflow over another.
//
// Following is what the commands did before content was staged and renamed,
// and it is what a dotfile-style managed symlink expects: replacing the link
// would detach every other path pointing at the target. go/config takes that
// position for configuration files, and this package's own Open says a path the
// operator typed is an instruction rather than untrusted input.
//
// Against that, a symbolic link at the destination is not necessarily one the
// operator made. Anyone who can write to the destination *directory* can plant
// one, and following it then decides where the content lands — which for a
// decrypted vulnerability report written into a shared directory is the classic
// symlink-planting problem.
//
// Neither answer is right for every caller, so the caller chooses and the
// default refuses. Where following is enabled, the resolved path is reported
// back so it can be logged: the failure mode of following is silence, and that
// part is cheap to remove.
func FollowSymlinks() Option {
	return func(o *options) { o.followSymlinks = true }
}

// Open reads a file the operator named.
//
// The path is cleaned before use. It is not otherwise constrained: an operator
// running a command against a path they typed is the entire interaction, and a
// tool that second-guessed it would be unusable for the job it exists to do.
func Open(fsys FS, path string) (fs.File, error) {
	f, err := fsys.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	return f, nil
}

// Writer is a file being written, which replaces its destination only once
// the caller says the content is complete.
type Writer struct {
	fsys FS
	tmp  File

	// tmpPath is the staged name, held by the Writer rather than asked of the
	// file.
	//
	// A file handle is not a stable answer to "what path is this?": *os.File
	// reports whatever it was opened with and never learns about a rename,
	// while afero's in-memory filesystem updates the name in place, so after
	// Commit it reports the destination. Abandon is deferred unconditionally,
	// so reading the name back there deleted the file that had just been
	// committed. Only one of those two behaviours is obviously wrong, which is
	// why neither is relied on — and why File has no Name method.
	tmpPath string

	final string

	// done means the staged file has been dealt with — committed or discarded —
	// so any further cleanup is a genuine no-op rather than one that happens to
	// remove a path nothing is using.
	//
	// It covers both outcomes deliberately. It used to be a `committed` flag
	// guarding only the success path, while all three of Commit's failure
	// branches left it false and cleaned up by hand — so the unconditional
	// deferred Abandon that both commands make ran the cleanup a second time.
	// Nothing was lost, because a second Close and a second Remove both return
	// errors that are discarded and the staged name is unique, but File's
	// contract does not promise Close-once and an implementation that counted
	// on it would have been broken by a failed sync.
	done bool

	// closed tracks the staged handle separately, so a Close that already
	// happened — or already failed — is not attempted again on the way out.
	closed bool

	// modeNote records that the file could not be given exactly the mode asked
	// for. Empty when it could. See [Writer.ModeNote].
	modeNote string
}

// ModeNote reports that the committed file does not carry exactly the mode
// requested, and why. Empty when it does.
//
// Not an error, because the file is written either way and is never broader
// than requested — see setMode. It is worth surfacing because a published
// certificate a web server cannot read is a certificate nobody can encrypt to,
// and the operator has no other way to learn that.
func (w *Writer) ModeNote() string { return w.modeNote }

// Create prepares to write path, without disturbing whatever is already there.
//
// The content goes to a temporary file alongside the destination and replaces
// it only on Commit. Opening the destination directly with O_TRUNC would empty
// it the moment the command started — so a decryption that then failed, which
// happens routinely when a message is addressed to another key, would leave the
// operator with neither the new report nor the one they had saved before.
//
// The temporary file is created in the destination's own directory so the
// rename is within one filesystem, and therefore atomic.
func Create(fsys FS, path string, mode fs.FileMode, opts ...Option) (*Writer, error) {
	var cfg options
	for _, opt := range opts {
		opt(&cfg)
	}

	final, err := resolveDestination(fsys, filepath.Clean(path), cfg)
	if err != nil {
		return nil, err
	}

	dir, name := filepath.Split(final)
	if dir == "" {
		dir = "."
	}

	// Created at its final mode rather than widened afterwards: a certificate
	// is public and a decrypted report is not, and there must be no window in
	// which a report exists at a broader mode than it will end up with.
	tmp, tmpPath, note, err := stage(fsys, dir, name, mode)
	if err != nil {
		return nil, fmt.Errorf("preparing to write %s: %w", path, err)
	}

	return &Writer{fsys: fsys, tmp: tmp, tmpPath: tmpPath, final: final, modeNote: note}, nil
}

// resolveDestination decides what path will actually be written, refusing a
// destination that cannot be replaced atomically.
//
// Replacing atomically means renaming over the directory entry rather than
// writing through it, so a symbolic link, a FIFO or a device node named as the
// destination would be removed rather than followed. For a decrypted
// vulnerability report that is a confidentiality question, not a tidiness one:
// an operator who pointed through a link into a mounted volume, or at a pipe
// feeding another process, would find the plaintext sitting on local disk
// instead, with nothing having said so.
//
// A symbolic link is the one case the caller can decide: see [FollowSymlinks].
// Everything else — a FIFO, a device, a directory — cannot be replaced by a
// rename at all, so it is refused regardless. Piping is already served by
// stdout, which is the default and what "-" selects.
func resolveDestination(fsys FS, path string, cfg options) (string, error) {
	// Bounded, because a link may point at another and eventually at itself.
	const maxHops = 8

	// The path the caller named, kept apart from the one being walked.
	//
	// Every error here used to read the walking variable, so from the second
	// hop onwards they named an intermediate link the operator had never typed
	// and that appeared nowhere in their command, with nothing connecting the
	// two. Both are reported now: the destination they asked for, and where the
	// walk was when it gave up.
	named := path

	// maxHops+1 passes, not maxHops: each pass inspects a path and then follows
	// at most one link, so resolving a chain of exactly maxHops links needs one
	// more inspection than there are links. Looping maxHops times refused a
	// chain of eight that had in fact resolved to a regular file well inside
	// its budget.
	for range maxHops + 1 {
		info, err := lstat(fsys, path)

		switch {
		case errors.Is(err, os.ErrNotExist):
			// Nothing there: the ordinary case.
			return path, nil
		case err != nil:
			return "", fmt.Errorf("inspecting %s: %w", describePath(named, path), err)
		case info.Mode().IsRegular():
			return path, nil
		case info.Mode()&os.ModeSymlink == 0:
			// A FIFO, device or directory cannot be replaced by a rename
			// whatever the caller asked for, so following does not arise.
			return "", fmt.Errorf("%w: %s is %s; this command replaces its destination atomically "+
				"and cannot write through it — write to stdout and pipe instead",
				ErrNotRegular, describePath(named, path), describe(info.Mode()))
		case !cfg.followSymlinks:
			return "", fmt.Errorf("%w: %s is %s; replacing it atomically would remove the link. "+
				"Pass --follow-symlinks to write through it, or name the file it points at",
				ErrNotRegular, describePath(named, path), describe(info.Mode()))
		}

		target, err := readlink(fsys, path)
		if err != nil {
			return "", err
		}

		// A relative target is relative to the link's own directory.
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}

		path = filepath.Clean(target)
	}

	return "", fmt.Errorf("%w: %s leads through more than %d links", ErrUnresolvableLink,
		describePath(named, path), maxHops)
}

// describePath names a path the way an operator can act on it.
//
// While the walk is still on the path they typed, that alone. Once it has
// followed a link, both — the destination they named is what connects the
// message to their command, and where the walk reached is what explains it.
func describePath(named, at string) string {
	if named == at {
		return named
	}

	return fmt.Sprintf("%s (via %s)", named, at)
}

// readlink resolves one hop, where the filesystem can.
func readlink(fsys FS, path string) (string, error) {
	target, err := fsys.Readlink(path)

	switch {
	case errors.Is(err, ErrCapabilityUnsupported):
		return "", fmt.Errorf("%w: %s, and this filesystem cannot resolve links", ErrUnresolvableLink, path)
	case err != nil:
		return "", fmt.Errorf("%w: %s: %w", ErrUnresolvableLink, path, err)
	}

	return target, nil
}

// lstat reports on the path itself rather than what it points at, falling back
// to Stat where the filesystem cannot.
//
// The fallback is EXPLICIT here rather than hidden in the adapter, which is the
// structural half of the fix for the capability lie: opfileafero now refuses
// Lstat honestly with ErrCapabilityUnsupported instead of passing off a Stat as
// an Lstat, and this — the package that owns the security policy — decides what
// to do with that refusal.
//
// It falls back to Stat and proceeds. A filesystem that cannot lstat cannot hold
// symbolic links, since link support requires lstat to be usable at all, so
// there is no link for the following Stat to have resolved and the result is
// authoritative. On the operating system, the one filesystem that matters, Lstat
// is genuine and never reaches this fallback, so a planted link is always seen.
func lstat(fsys FS, path string) (fs.FileInfo, error) {
	info, err := fsys.Lstat(path)
	if errors.Is(err, ErrCapabilityUnsupported) {
		return fsys.Stat(path)
	}

	return info, err
}

// describe names a file mode the way an operator would.
func describe(mode fs.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeDevice != 0:
		return "a device"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode.IsDir():
		return "a directory"
	default:
		return "not a regular file"
	}
}

// Path is the file that will actually be replaced.
//
// The same path the caller named, unless following a symbolic link resolved it
// elsewhere — which is worth logging, because the failure mode of following is
// that nobody knows where the content went.
func (w *Writer) Path() string { return w.final }

// Write sends bytes to the temporary file.
func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.tmp.Write(p)
	if err != nil {
		return n, fmt.Errorf("writing %s: %w", w.final, err)
	}

	return n, nil
}

// Commit closes the temporary file and moves it into place.
func (w *Writer) Commit() error {
	// Before the rename, and this is the whole guarantee. Rename is atomic with
	// respect to the directory entry, not to the data behind it: without the
	// sync a crash can leave the new name pointing at a file whose contents
	// never reached the disk, which is a zero-length or partial report where a
	// complete one used to be.
	if err := w.tmp.Sync(); err != nil {
		w.discard()

		return fmt.Errorf("flushing %s: %w", w.final, err)
	}

	if err := w.closeTemp(); err != nil {
		w.discard()

		return fmt.Errorf("closing %s: %w", w.final, err)
	}

	if err := w.fsys.Rename(w.tmpPath, w.final); err != nil {
		w.discard()

		return fmt.Errorf("replacing %s: %w", w.final, err)
	}

	w.done = true

	return nil
}

// closeTemp closes the staged handle at most once.
func (w *Writer) closeTemp() error {
	if w.closed {
		return nil
	}

	w.closed = true

	return w.tmp.Close()
}

// Abandon discards the temporary file, leaving the destination untouched.
//
// Safe to call after Commit, so it can be deferred unconditionally.
func (w *Writer) Abandon() { w.discard() }

func (w *Writer) discard() {
	if w.done {
		return
	}

	w.done = true

	_ = w.closeTemp()
	_ = w.fsys.Remove(w.tmpPath)
}

// Ensure Writer satisfies the writer the commands pass around.
var _ io.Writer = (*Writer)(nil)
