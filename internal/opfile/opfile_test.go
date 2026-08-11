package opfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/phpboyscout/sigillum/internal/opfile"
)

// TestAbandonLeavesTheDestinationUntouched is the point of the package.
//
// Decryption fails routinely — a message addressed to another key is the
// documented common case — and opening the destination with O_TRUNC would
// empty it before the command had any idea whether it would succeed. A rota
// member who saved a report at that path would lose it and get nothing back.
func TestAbandonLeavesTheDestinationUntouched(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	const existing = "the report I decrypted yesterday"

	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	w, err := opfile.Create(path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("half a plaintext")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	w.Abandon()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	if string(got) != existing {
		t.Errorf("destination = %q, want it unchanged as %q", got, existing)
	}

	// Nothing left behind either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("%d files remain, want only the destination", len(entries))
	}
}

func TestCommitReplacesTheDestination(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	w, err := opfile.Create(path, 0o600)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := w.Write([]byte("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	if string(got) != "new" {
		t.Errorf("destination = %q, want %q", got, "new")
	}
}

// TestCreateHonoursTheMode covers the difference that matters: a decrypted
// report is owner-only, a published certificate is not. CreateTemp makes
// everything 0600, so the widening has to be explicit.
func TestCreateHonoursTheMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []os.FileMode{0o600, 0o644} {
		path := filepath.Join(t.TempDir(), "out")

		w, err := opfile.Create(path, mode)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		if err := w.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}

		if info.Mode().Perm() != mode {
			t.Errorf("mode = %v, want %v", info.Mode().Perm(), mode)
		}
	}
}

func TestOpenReportsAMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := opfile.Open(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want os.ErrNotExist", err)
	}
}

// TestCommitSyncsBeforeRenaming covers finding 10.
//
// os.Rename is atomic with respect to the directory entry, not to the data
// behind it. Without a sync first, a crash between the write and writeback can
// leave the new name pointing at content that never reached the disk — a
// zero-length or partial file where a complete one used to be.
//
// That matters twice here: a decrypted vulnerability report the operator
// believes they have saved, and a published certificate correspondents encrypt
// to. Both are cases where "the old content or the complete new content" is the
// entire promise of the package.
//
// Durability cannot be tested by crashing the machine, so the ordering is
// observed instead: sync must happen, and must happen before the rename.
func TestCommitSyncsBeforeRenaming(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	final := filepath.Join(dir, "report.txt")

	real, err := os.CreateTemp(dir, ".report.txt.*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}

	spy := &syncSpy{File: real}

	w := opfile.NewWriterForTest(spy, final)

	if _, err := w.Write([]byte("a complete report")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if !spy.synced {
		t.Fatal("Commit renamed without syncing, so the rename can outlive the data it points at")
	}

	if !spy.syncedBeforeClose {
		t.Error("Sync happened after Close, which is too late to be part of the guarantee")
	}

	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("reading the committed file: %v", err)
	}

	if string(got) != "a complete report" {
		t.Errorf("file contains %q", got)
	}
}

// TestCommitReportsAFailedSync is the other half: a sync that fails means the
// data is not on disk, so the rename must not happen and the destination must
// be left alone.
func TestCommitReportsAFailedSync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	final := filepath.Join(dir, "report.txt")

	if err := os.WriteFile(final, []byte("the previous report"), 0o600); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	real, err := os.CreateTemp(dir, ".report.txt.*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}

	spy := &syncSpy{File: real, fail: errors.New("disk went away")}

	w := opfile.NewWriterForTest(spy, final)

	if _, err := w.Write([]byte("a report that never reached the platter")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := w.Commit(); err == nil {
		t.Fatal("Commit reported success although the sync failed")
	}

	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("reading the destination: %v", err)
	}

	if string(got) != "the previous report" {
		t.Errorf("the destination was replaced despite a failed sync: %q", got)
	}
}

// syncSpy records whether Sync was reached, and whether it preceded Close.
type syncSpy struct {
	*os.File

	fail              error
	synced            bool
	closed            bool
	syncedBeforeClose bool
}

func (s *syncSpy) Sync() error {
	s.synced = true
	s.syncedBeforeClose = !s.closed

	if s.fail != nil {
		return s.fail
	}

	return s.File.Sync()
}

func (s *syncSpy) Close() error {
	s.closed = true

	return s.File.Close()
}
