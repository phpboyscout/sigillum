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
