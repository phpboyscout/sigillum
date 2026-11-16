package wkd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"

	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/wkd"
)

const (
	domain        = "phpboyscout.uk"
	releaseEmail  = "release@phpboyscout.uk"
	securityEmail = "security@phpboyscout.uk"

	// The hashes gpg-wks-client gives the two local parts.
	releaseHash  = "y84sdmnksfqswe7fxf5mzjg53tbdz8f5"
	securityHash = "t5s8ztdbon8yzntexy6oz5y48etqsnbb"
)

func armoredKey(t *testing.T, name, email string) []byte {
	t.Helper()

	armored, err := openpgpkey.ArmoredPublicKey(signtest.RSAKey(t), name, email, signtest.FixtureKeyTime)
	require.NoError(t, err)

	return armored
}

func keyFile(t *testing.T, dir, filename, name, email string) string {
	t.Helper()

	return signtest.WriteFile(t, dir, filename, string(armoredKey(t, name, email)))
}

// ringFile writes one armored block holding a key per email.
func ringFile(t *testing.T, dir, filename string, emails ...string) string {
	t.Helper()

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)

	for _, email := range emails {
		ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredKey(t, "Ring", email)))
		require.NoError(t, err)
		require.Len(t, ring, 1)
		require.NoError(t, ring[0].Serialize(w))
	}

	require.NoError(t, w.Close())

	return signtest.WriteFile(t, dir, filename, buf.String())
}

func runWkd(t *testing.T, out string, args ...string) error {
	t.Helper()

	return runWkdWith(t, signtest.Props(), out, args...)
}

func runWkdWith(t *testing.T, p *props.Props, out string, args ...string) error {
	t.Helper()

	all := append([]string{"--domain", domain, "--output", out}, args...)

	return signtest.Execute(t, wkd.NewCmdWkd(p).Command, all...)
}

func advanced(out string, elem ...string) string {
	return filepath.Join(append([]string{out, ".well-known", "openpgpkey", domain}, elem...)...)
}

// bucket reads a hu/ file, which holds binary OpenPGP packets.
func bucket(t *testing.T, path string) openpgp.EntityList {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	ring, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
	require.NoError(t, err)

	return ring
}

func emailsOf(ring openpgp.EntityList) []string {
	var out []string

	for _, entity := range ring {
		for _, identity := range entity.Identities {
			out = append(out, identity.UserId.Email)
		}
	}

	return out
}

func TestRunWkd_GroupsKeysForOneEmailIntoOneBucket(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	a := keyFile(t, in, "a.asc", "Rotation", releaseEmail)
	b := keyFile(t, in, "b.asc", "Signing", releaseEmail)

	require.NoError(t, runWkd(t, out, "--email", releaseEmail, "--submission-address", "auto", a, b))

	assert.FileExists(t, advanced(out, "policy"))
	assert.FileExists(t, advanced(out, "submission-address"))
	assert.Len(t, bucket(t, advanced(out, "hu", releaseHash)), 2)
}

// A ring file publishes each of its keys on its own. Attaching the whole file to
// every key in it once put every key under every email.
func TestRunWkd_ARingFilePublishesEachKeyUnderItsOwnEmailOnly(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	ring := ringFile(t, in, "ring.asc", releaseEmail, securityEmail)

	require.NoError(t, runWkd(t, out, ring))

	assert.Equal(t, []string{releaseEmail}, emailsOf(bucket(t, advanced(out, "hu", releaseHash))))
	assert.Equal(t, []string{securityEmail}, emailsOf(bucket(t, advanced(out, "hu", securityHash))))
}

func TestRunWkd_SubmissionAddress(t *testing.T) {
	t.Parallel()

	named := []string{"--email", releaseEmail}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"empty omits the file":      {args: named},
		"auto uses the first email": {args: append(named, "--submission-address", "auto"), want: releaseEmail},
		"an address is used verbatim": {
			args: append(named, "--submission-address", "keys@phpboyscout.uk"),
			want: "keys@phpboyscout.uk",
		},
		"auto with no --email uses the first email found": {
			args: []string{"--submission-address", "auto"},
			want: releaseEmail,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			in, out := t.TempDir(), t.TempDir()
			key := keyFile(t, in, "k.asc", "Release", releaseEmail)

			require.NoError(t, runWkd(t, out, append(tc.args[:len(tc.args):len(tc.args)], key)...))

			path := advanced(out, "submission-address")
			if tc.want == "" {
				assert.NoFileExists(t, path)

				return
			}

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}
}

func TestRunWkd_PublishesEveryEmailFoundWhenNoneIsNamed(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	rel := keyFile(t, in, "rel.asc", "Release", releaseEmail)
	sec := keyFile(t, in, "sec.asc", "Security", securityEmail)

	require.NoError(t, runWkd(t, out, rel, sec))

	assert.Len(t, bucket(t, advanced(out, "hu", releaseHash)), 1)
	assert.Len(t, bucket(t, advanced(out, "hu", securityHash)), 1)
}

func TestRunWkd_NamedEmailsLeaveOtherKeysUnpublished(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	rel := keyFile(t, in, "rel.asc", "Release", releaseEmail)
	sec := keyFile(t, in, "sec.asc", "Security", securityEmail)

	require.NoError(t, runWkd(t, out, "--email", securityEmail, rel, sec))

	assert.FileExists(t, advanced(out, "hu", securityHash))
	assert.NoFileExists(t, advanced(out, "hu", releaseHash))
}

func TestRunWkd_DirectMethodOmitsTheDomainSegment(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	key := keyFile(t, in, "k.asc", "Release", releaseEmail)

	require.NoError(t, runWkd(t, out, "--email", releaseEmail, "--method", "direct", key))

	assert.FileExists(t, filepath.Join(out, ".well-known", "openpgpkey", "hu", releaseHash))
	assert.NoFileExists(t, advanced(out, "hu", releaseHash), "direct method must not emit the advanced layout")
}

func TestRunWkd_Refusals(t *testing.T) {
	t.Parallel()

	in := t.TempDir()
	key := keyFile(t, in, "k.asc", "Release", releaseEmail)
	garbage := signtest.WriteFile(t, in, "garbage.asc", "not an OpenPGP key")
	absent := filepath.Join(in, "absent.asc")

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"missing key file":   {args: []string{absent}, want: "reading " + absent},
		"not an OpenPGP key": {args: []string{garbage}, want: "parsing " + garbage + " as armored OpenPGP"},
		"email on no key": {
			args: []string{"--email", securityEmail, key},
			want: "no input key matched --email " + securityEmail,
		},
		"unknown method": {
			args: []string{"--method", "sideways", key},
			want: `writing WKD tree: WriteWKDTree: invalid Method "sideways"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			out := filepath.Join(t.TempDir(), "site")

			require.ErrorContains(t, runWkd(t, out, tc.args...), tc.want)
			assert.NoDirExists(t, out, "a refused run must write nothing")
		})
	}
}

func TestRunWkd_LogsEachBucketAndFile(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	key := keyFile(t, in, "k.asc", "Release", releaseEmail)
	log := logger.NewBuffer()

	require.NoError(t, runWkdWith(t, &props.Props{Logger: log}, out, key))

	type line struct {
		message string
		keyvals []any
	}

	var got []line
	for _, e := range log.Entries() {
		got = append(got, line{e.Message, e.Keyvals})
	}

	rel := filepath.Join(".well-known", "openpgpkey", domain)

	assert.Equal(t, []line{
		{"WKD bucket", []any{"email", releaseEmail, "hash", releaseHash, "keys", int64(1)}},
		{"wrote", []any{"path", filepath.Join(out, rel, "policy")}},
		{"wrote", []any{"path", filepath.Join(out, rel, "hu", releaseHash)}},
		{"WKD tree complete", []any{"output", out, "method", "advanced", "emails", int64(1), "files", int64(2)}},
	}, got)
}

func TestRunWkd_RequiresDomainAndAKey(t *testing.T) {
	t.Parallel()

	key := keyFile(t, t.TempDir(), "k.asc", "Release", releaseEmail)

	require.ErrorContains(t, signtest.Execute(t, wkd.NewCmdWkd(signtest.Props()).Command, key),
		`required flag(s) "domain" not set`)
	require.ErrorContains(t, signtest.Execute(t, wkd.NewCmdWkd(signtest.Props()).Command, "--domain", domain),
		"requires at least 1 arg(s), only received 0")
}
