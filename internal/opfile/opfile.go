// Package opfile opens and creates the files an operator names on the command
// line.
//
// It exists to put two decisions in one place rather than at every call site:
// that a path typed by the operator is an instruction rather than untrusted
// input, and that a command which fails must not have destroyed the file it was
// asked to write.
package opfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Open reads a file the operator named.
//
// The path is cleaned before use. It is not otherwise constrained: an operator
// running a command against a path they typed is the entire interaction, and a
// tool that second-guessed it would be unusable for the job it exists to do.
func Open(path string) (*os.File, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	return f, nil
}

// Writer is a file being written, which replaces its destination only once
// the caller says the content is complete.
type Writer struct {
	tmp   tempFile
	final string
}

// tempFile is the part of *os.File this package uses.
//
// An interface rather than the concrete type so a test can observe that Commit
// syncs before it renames. That is not a property any test can establish by
// crashing the machine, and it is the one property the package exists to
// provide — so it has to be observable some other way.
type tempFile interface {
	io.Writer

	Name() string
	Sync() error
	Close() error
}

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
func Create(path string, mode os.FileMode) (*Writer, error) {
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}

	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return nil, fmt.Errorf("preparing to write %s: %w", path, err)
	}

	// CreateTemp makes the file 0600. Widen it only if the caller asked for
	// more — a certificate is public, a decrypted report is not.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return nil, fmt.Errorf("setting mode on %s: %w", path, err)
	}

	return &Writer{tmp: tmp, final: filepath.Clean(path)}, nil
}

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
		_ = w.tmp.Close()
		_ = os.Remove(w.tmp.Name())

		return fmt.Errorf("flushing %s: %w", w.final, err)
	}

	if err := w.tmp.Close(); err != nil {
		_ = os.Remove(w.tmp.Name())

		return fmt.Errorf("closing %s: %w", w.final, err)
	}

	if err := os.Rename(w.tmp.Name(), w.final); err != nil {
		_ = os.Remove(w.tmp.Name())

		return fmt.Errorf("replacing %s: %w", w.final, err)
	}

	return nil
}

// Abandon discards the temporary file, leaving the destination untouched.
//
// Safe to call after Commit, so it can be deferred unconditionally.
func (w *Writer) Abandon() {
	_ = w.tmp.Close()
	_ = os.Remove(w.tmp.Name())
}

// Ensure Writer satisfies the writer the commands pass around.
var _ io.Writer = (*Writer)(nil)
