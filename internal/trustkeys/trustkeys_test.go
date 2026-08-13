package trustkeys_test

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"gitlab.com/phpboyscout/sigillum/internal/trustkeys"
)

// The embedded trust anchor, which nothing checked.
//
// This is the key that decides whether a self-update is genuine. The package
// doc says outright that with no keys present "Keys returns nil, so signature
// verification stays dormant" — so the failure mode of losing the key is not a
// build error or a loud refusal, it is silently accepting an unsigned release
// binary. On the machine that holds the reader role for decrypting
// vulnerability reports.
//
// Rename the file, truncate it, add it to .gitignore, or let a regeneration
// restore the ships-empty state the doc describes, and nothing in the
// repository goes red. These are the tests that make it go red.
//
// trustkeys.go is generated and carries DO NOT EDIT, so the guarantee has to
// live here rather than as a check inside Keys().

// TestAKeyIsEmbedded is the whole point: an empty trust anchor disables
// verification rather than failing.
func TestAKeyIsEmbedded(t *testing.T) {
	t.Parallel()

	keys := trustkeys.Keys()
	if len(keys) == 0 {
		t.Fatal("no trust anchor is embedded, so self-update signature verification is dormant " +
			"and an unsigned release binary would be accepted")
	}
}

// TestEveryEmbeddedKeyParses covers the other way to lose verification without
// losing the file: a key that is present but not readable as one.
//
// A truncated paste, a stray CRLF mangling, or an armour block that lost its
// checksum all leave a file of plausible size in the right place.
func TestEveryEmbeddedKeyParses(t *testing.T) {
	t.Parallel()

	for i, key := range trustkeys.Keys() {
		entities, err := pgp.ReadArmoredKeyRing(strings.NewReader(string(key)))
		if err != nil {
			t.Errorf("embedded key %d does not parse as an OpenPGP public key: %v", i, err)

			continue
		}

		if len(entities) == 0 {
			t.Errorf("embedded key %d parses but carries no entity", i)

			continue
		}

		for _, e := range entities {
			if e.PrimaryKey == nil {
				t.Errorf("embedded key %d has an entity with no primary key", i)
			}

			// A private half here would mean a signing key had been committed
			// where only the public one belongs.
			if e.PrivateKey != nil {
				t.Errorf("embedded key %d carries a PRIVATE key; only public halves belong in the binary", i)
			}
		}
	}
}

// TestTheEmbeddedKeyIsTheOneProvenanceRecords cross-checks the file against the
// build's own record of it.
//
// pkg/cmd/root/provenance.go names the key the release tooling signs with. If
// the embedded file and that record drift apart, the binary verifies against a
// key nothing signs with — which fails closed, but only at the moment somebody
// tries to update, and with no clue as to why.
func TestTheEmbeddedKeyIsTheOneProvenanceRecords(t *testing.T) {
	t.Parallel()

	recorded := recordedKeyPath(t)

	const prefix = "internal/trustkeys/"

	name, ok := strings.CutPrefix(recorded, prefix)
	if !ok {
		t.Fatalf("provenance records %q, which is not under %s, so this package cannot embed it",
			recorded, prefix)
	}

	// Anchored before it is opened. The path comes out of a source file, so
	// treating it as trusted would be the same shape as the e2e harness reading
	// artefact names straight from a feature file — and the check is one line.
	clean := filepath.Clean(recorded)
	if clean != recorded || strings.Contains(clean, "..") {
		t.Fatalf("provenance records a non-canonical path %q", recorded)
	}

	onDisk, err := os.ReadFile(filepath.Join("..", "..", clean))
	if err != nil {
		t.Fatalf("provenance records %q but it is not there: %v", recorded, err)
	}

	var found bool

	for _, key := range trustkeys.Keys() {
		if string(key) == string(onDisk) {
			found = true

			break
		}
	}

	if !found {
		t.Errorf("the key provenance records (%s) is not among the %d embedded, so the binary "+
			"trusts something other than what the release tooling signs with",
			name, len(trustkeys.Keys()))
	}
}

// recordedKeyPath reads the key path out of the build's provenance record.
func recordedKeyPath(t *testing.T) string {
	t.Helper()

	provenance, err := os.ReadFile("../../pkg/cmd/root/provenance.go")
	if err != nil {
		t.Fatalf("reading provenance: %v", err)
	}

	match := regexp.MustCompile(`public_key=(\S+)`).FindSubmatch(provenance)
	if match == nil {
		t.Fatal("provenance records no public_key, so nothing states which key this binary trusts")
	}

	recorded, err := url.QueryUnescape(string(match[1]))
	if err != nil {
		t.Fatalf("provenance's public_key is not a valid escaped path: %v", err)
	}

	return recorded
}
