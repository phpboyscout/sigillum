package publish_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keysite"
	"gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/publish"
)

const (
	project   = "rtb-cli-bin"
	validFrom = "2026-08-01"
)

// site is a keys site under test and the directory its input keys are read from.
type site struct {
	root string
	keys string
}

func newSite(t *testing.T) site {
	t.Helper()

	tmp := t.TempDir()

	return site{root: filepath.Join(tmp, "site"), keys: tmp}
}

// pubFile writes a public-key file for a fresh key, as `keys minisign --output`
// would, and returns its path and the key.
func (s site) pubFile(t *testing.T, name string) (string, minisign.PublicKey) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key, err := minisign.NewPublicKey(pub)
	require.NoError(t, err)

	body, err := key.File("minisign public key")
	require.NoError(t, err)

	return signtest.WriteFile(t, s.keys, name, string(body)), key
}

// publish runs the command for project against the site, with validFrom pinned
// unless args override it.
func (s site) publish(t *testing.T, keyPath, project string, args ...string) error {
	t.Helper()

	return s.publishWith(t, signtest.Props(), keyPath, project, args...)
}

func (s site) publishWith(t *testing.T, p *props.Props, keyPath, project string, args ...string) error {
	t.Helper()

	all := append([]string{"--output", s.root, "--project", project, "--valid-from", validFrom}, args...)

	return signtest.Execute(t, publish.NewCmdPublish(p).Command, append(all, keyPath)...)
}

func (s site) manifestBytes(t *testing.T) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(s.root, keysite.ManifestName))
	require.NoError(t, err)

	return raw
}

func (s site) entries(t *testing.T) []keysite.Entry {
	t.Helper()

	var m struct {
		Keys []keysite.Entry `json:"keys"`
	}

	require.NoError(t, json.Unmarshal(s.manifestBytes(t), &m))

	return m.Keys
}

func (s site) published(t *testing.T, project string, generation int) []byte {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(s.root, "minisign", project, fmt.Sprintf("v%d.pub", generation)))
	require.NoError(t, err)

	return body
}

func TestRunPublish_WritesKeyAndManifest(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, key := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project))

	parsed, err := minisign.ParsePublicKey(string(s.published(t, project, 1)))
	require.NoError(t, err)
	assert.Equal(t, key, parsed, "the published file must round-trip to the same key")

	assert.Equal(t, []keysite.Entry{{
		ID:         fmt.Sprintf("%X", key.KeyID),
		Project:    project,
		Generation: 1,
		Algorithm:  "minisign-ED",
		Purpose:    "artefact",
		Status:     keysite.StatusActive,
		ValidFrom:  validFrom,
		// The exact string pinned as cargo-binstall's `pubkey`, so the two can
		// be compared directly.
		PubKey: key.Encode(),
		Path:   "minisign/rtb-cli-bin/v1.pub",
	}}, s.entries(t))
}

// The comment is in the published bytes. A site published by go/signing-cli must
// re-publish as a no-op under sigillum, so the wording cannot move (go/signing#18).
func TestRunPublish_UntrustedCommentIsGoSigningClis(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, key := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project, "--generation", "3"))

	comment, _, _ := strings.Cut(string(s.published(t, project, 3)), "\n")
	assert.Equal(t,
		fmt.Sprintf("untrusted comment: phpboyscout rtb-cli-bin artefact signing v3 (minisign key %X)", key.KeyID),
		comment)
}

func TestRunPublish_IsIdempotent(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project))

	firstManifest, firstKey := s.manifestBytes(t), s.published(t, project, 1)

	require.NoError(t, s.publish(t, keyPath, project))

	assert.Equal(t, string(firstManifest), string(s.manifestBytes(t)))
	assert.Equal(t, string(firstKey), string(s.published(t, project, 1)))
	assert.Len(t, s.entries(t), 1, "re-publishing must not duplicate the entry")
}

func TestRunPublish_LogsWhetherTheKeyIsNew(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, key := s.pubFile(t, "rtb.pub")

	for _, added := range []bool{true, false} {
		log := logger.NewBuffer()

		require.NoError(t, s.publishWith(t, &props.Props{Logger: log}, keyPath, project))

		entries := log.Entries()
		require.Len(t, entries, 1)
		assert.Equal(t, "Published minisign public key", entries[0].Message)
		assert.Equal(t, []any{
			"project", project,
			"generation", int64(1), // the buffer logger widens integers
			"minisign_key_id", fmt.Sprintf("%X", key.KeyID),
			"status", keysite.StatusActive,
			"path", "minisign/rtb-cli-bin/v1.pub",
			"output", s.root,
			"new", added,
		}, entries[0].Keyvals)
	}
}

// Consumers pin a published key, so a different key for the same project and
// generation is refused. Rotation publishes a new generation.
func TestRunPublish_RefusesToReplaceAPublishedKey(t *testing.T) {
	t.Parallel()

	s := newSite(t)

	first, _ := s.pubFile(t, "first.pub")
	require.NoError(t, s.publish(t, first, project))

	publishedKey, manifest := s.published(t, project, 1), s.manifestBytes(t)

	second, _ := s.pubFile(t, "second.pub")

	err := s.publish(t, second, project)
	require.ErrorIs(t, err, publish.ErrKeyAlreadyPublished)
	assert.Equal(t, "signing-cli.key_already_published", errors.KindOf(err))
	assert.Equal(t,
		filepath.Join(s.root, "minisign", project, "v1.pub")+
			" already holds a different key — published keys are add-only; publish a new generation instead"+
			": a different key is already published at this path",
		err.Error())

	assert.Equal(t, string(publishedKey), string(s.published(t, project, 1)), "the published key must be untouched")
	assert.Equal(t, string(manifest), string(s.manifestBytes(t)), "the manifest must be untouched")
}

// The manifest is the second guard: with the key file gone, a different key for
// a recorded generation is still refused.
func TestRunPublish_RefusesAKeyTheManifestRecordsDifferently(t *testing.T) {
	t.Parallel()

	s := newSite(t)

	first, _ := s.pubFile(t, "first.pub")
	require.NoError(t, s.publish(t, first, project))
	require.NoError(t, os.Remove(filepath.Join(s.root, "minisign", project, "v1.pub")))

	second, _ := s.pubFile(t, "second.pub")

	err := s.publish(t, second, project)
	require.ErrorIs(t, err, publish.ErrKeyAlreadyPublished)
	require.ErrorContains(t, err, "records a different key for rtb-cli-bin generation 1")
}

func TestRunPublish_AllowsStatusChangeOnTheSameKey(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project))
	require.NoError(t, s.publish(t, keyPath, project, "--status", keysite.StatusRetired))

	entries := s.entries(t)
	require.Len(t, entries, 1)
	assert.Equal(t, keysite.StatusRetired, entries[0].Status)
}

// An omitted --valid-from on a same-key re-run keeps the recorded date, so the
// re-run leaves keys.json byte-identical (go/signing-cli#6).
func TestRunPublish_RerunWithoutValidFromKeepsTheRecordedDate(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project, "--valid-from", "2026-01-01"))

	before := s.manifestBytes(t)

	require.NoError(t, signtest.Execute(t, publish.NewCmdPublish(signtest.Props()).Command,
		"--output", s.root, "--project", project, keyPath))

	assert.Equal(t, string(before), string(s.manifestBytes(t)), "a re-run on unchanged input must leave keys.json untouched")
	assert.Equal(t, "2026-01-01", s.entries(t)[0].ValidFrom)
}

func TestRunPublish_RerunWithValidFromUpdatesTheRecordedDate(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	require.NoError(t, s.publish(t, keyPath, project))
	require.NoError(t, s.publish(t, keyPath, project, "--valid-from", "2026-07-15"))

	assert.Equal(t, "2026-07-15", s.entries(t)[0].ValidFrom)
}

func TestRunPublish_NewEntryWithoutValidFromRecordsToday(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	before := time.Now().UTC().Format(time.DateOnly)

	require.NoError(t, signtest.Execute(t, publish.NewCmdPublish(signtest.Props()).Command,
		"--output", s.root, "--project", project, keyPath))

	after := time.Now().UTC().Format(time.DateOnly)

	assert.Contains(t, []string{before, after}, s.entries(t)[0].ValidFrom)
}

func TestRunPublish_AccumulatesGenerationsAndProjects(t *testing.T) {
	t.Parallel()

	s := newSite(t)

	v1, _ := s.pubFile(t, "a1.pub")
	v2, _ := s.pubFile(t, "a2.pub")
	other, _ := s.pubFile(t, "b1.pub")

	require.NoError(t, s.publish(t, v1, "zeta-tool"))
	require.NoError(t, s.publish(t, v2, "zeta-tool", "--generation", "2"))
	require.NoError(t, s.publish(t, other, "alpha-tool"))

	type slot struct {
		project    string
		generation int
	}

	var got []slot
	for _, e := range s.entries(t) {
		got = append(got, slot{e.Project, e.Generation})
	}

	// Ordered, so the file does not churn and a diff shows only real changes.
	assert.Equal(t, []slot{{"alpha-tool", 1}, {"zeta-tool", 1}, {"zeta-tool", 2}}, got)

	assert.FileExists(t, filepath.Join(s.root, "minisign", "zeta-tool", "v2.pub"))
	assert.FileExists(t, filepath.Join(s.root, "minisign", "alpha-tool", "v1.pub"))
}

// The site also carries a hand-maintained index and the tree `keys wkd` writes.
func TestRunPublish_LeavesUnrelatedSiteFilesAlone(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	hu := filepath.Join(s.root, ".well-known", "openpgpkey", "hu")
	require.NoError(t, os.MkdirAll(hu, 0o755))

	index := signtest.WriteFile(t, s.root, "index.html", "<h1>hand written</h1>")
	bucket := signtest.WriteFile(t, hu, "abc", "bucket")

	require.NoError(t, s.publish(t, keyPath, project))

	got, err := os.ReadFile(index)
	require.NoError(t, err)
	assert.Equal(t, "<h1>hand written</h1>", string(got))

	got, err = os.ReadFile(bucket)
	require.NoError(t, err)
	assert.Equal(t, "bucket", string(got))
}

// The project name becomes a path segment, so traversal and separators must not
// survive into the layout.
func TestRunPublish_RejectsUnsafeProjectNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "../escape", "with/slash", "UPPER", strings.Repeat("x", 65)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newSite(t)
			keyPath, _ := s.pubFile(t, "rtb.pub")

			err := s.publish(t, keyPath, name)
			require.ErrorIs(t, err, publish.ErrInvalidProject)
			assert.Equal(t, "signing-cli.invalid_project", errors.KindOf(err))
			assert.Equal(t,
				fmt.Sprintf("got %q: project name must be lowercase alphanumeric with dots, dashes or underscores", name),
				err.Error())
			assert.NoDirExists(t, s.root, "a refused publish must write nothing")
		})
	}
}

func TestRunPublish_RejectsBadFlags(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args []string
		want string
		is   error
		kind string
	}{
		"unknown status": {
			args: []string{"--status", "probationary"},
			want: `got "probationary"; valid values are "active", "retired", "revoked": unknown status`,
			is:   publish.ErrInvalidStatus,
			kind: "signing-cli.invalid_status",
		},
		"zero generation": {
			args: []string{"--generation", "0"},
			want: "--generation must be 1 or greater, got 0",
		},
		"bad valid-from": {
			args: []string{"--valid-from", "August 2026"},
			want: `parsing --valid-from "August 2026" as YYYY-MM-DD`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newSite(t)
			keyPath, _ := s.pubFile(t, "rtb.pub")

			err := s.publish(t, keyPath, project, tc.args...)
			require.ErrorContains(t, err, tc.want)

			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
				assert.Equal(t, tc.kind, errors.KindOf(err))
			}

			assert.NoDirExists(t, s.root, "a refused publish must write nothing")
		})
	}
}

func TestRunPublish_RejectsAMalformedKeyFile(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	bad := signtest.WriteFile(t, s.keys, "bad.pub", "not a minisign key\n")

	err := s.publish(t, bad, project)
	require.ErrorIs(t, err, minisign.ErrMalformedPublicKey)
	require.ErrorContains(t, err, "parsing "+bad)
	assert.NoDirExists(t, s.root)
}

func TestRunPublish_ReportsAMissingKeyFile(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	absent := filepath.Join(s.keys, "absent.pub")

	err := s.publish(t, absent, project)
	require.ErrorContains(t, err, "reading "+absent)
}

func TestRunPublish_TakesExactlyOneKeyFile(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	a, _ := s.pubFile(t, "a.pub")
	b, _ := s.pubFile(t, "b.pub")

	cmd := publish.NewCmdPublish(signtest.Props()).Command

	require.ErrorContains(t, signtest.Execute(t, cmd, "--output", s.root, "--project", project, a, b),
		"accepts 1 arg(s), received 2")
	assert.NoDirExists(t, s.root)
}

func TestRunPublish_RequiresProject(t *testing.T) {
	t.Parallel()

	s := newSite(t)
	keyPath, _ := s.pubFile(t, "rtb.pub")

	err := signtest.Execute(t, publish.NewCmdPublish(signtest.Props()).Command, "--output", s.root, keyPath)
	require.ErrorContains(t, err, `required flag(s) "project" not set`)
}
