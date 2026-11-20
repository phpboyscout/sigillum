package rotate_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/signing/minisign"
	"gitlab.com/phpboyscout/go/signing/verify"

	"gitlab.com/phpboyscout/sigillum/internal/rotate"
	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	rotatecmd "gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/rotate"
)

const fakeBackend = "fake"

func notAfter() string { return time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339) }

func registerAuthority(t *testing.T) string {
	t.Helper()

	priv := signtest.Ed25519Key()
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	key, err := signcmd.MinisignPublicKey(priv)
	require.NoError(t, err)

	return key.Encode()
}

func runRotate(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := rotatecmd.NewCmdRotate(signtest.Props()).Command
	all := append([]string{"--backend", fakeBackend, "--key-id", "ignored"}, args...)
	cmd.SetArgs(all)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true

	err := cmd.Execute()

	return out.String(), err
}

func writeReleaseKey(t *testing.T, dir, name string) (path, fingerprint string) {
	t.Helper()

	e, err := openpgp.NewEntity(name, "", name+"@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, e.Serialize(w))
	require.NoError(t, w.Close())

	return signtest.WriteFile(t, dir, name+".asc", buf.String()),
		strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func readManifest(t *testing.T, authority, dir string) *verify.RotationManifest {
	t.Helper()

	manifest, err := os.ReadFile(filepath.Join(dir, verify.RotationManifestFile))
	require.NoError(t, err)
	signature, err := os.ReadFile(filepath.Join(dir, verify.RotationSignatureFile))
	require.NoError(t, err)

	a, err := verify.NewRotationAuthority(authority)
	require.NoError(t, err)

	m, err := a.VerifyRotationManifest(manifest, signature)
	require.NoError(t, err)

	return m
}

func TestRunRotate_TheFireDrillWritesAManifestThatVerifies(t *testing.T) {
	authority := registerAuthority(t)
	dir := t.TempDir()

	out, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir)
	require.NoError(t, err)

	m := readManifest(t, authority, dir)
	assert.EqualValues(t, 1, m.Epoch)

	for _, name := range []string{verify.RotationManifestFile, verify.RotationSignatureFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "%s is a release asset", name)
	}
	assert.Empty(t, m.Add)
	assert.Contains(t, out, "authority  "+authority)
	assert.Contains(t, out, "epoch      1 (scheduled)")
}

func TestRunRotate_CarriesThePreviousManifestAndReportsIt(t *testing.T) {
	authority := registerAuthority(t)
	keys, first, second := t.TempDir(), t.TempDir(), t.TempDir()
	v1, v1fp := writeReleaseKey(t, keys, "v1")
	v2, v2fp := writeReleaseKey(t, keys, "v2")
	v3, v3fp := writeReleaseKey(t, keys, "v3")

	_, err := runRotate(t, "--reason", "compromise", "--not-after", notAfter(), "--output-dir", first,
		"--add", v3, "--revoke", v1fp+"@2026-11-01T00:00:00Z", "--anchor", v1, "--anchor", v2)
	require.NoError(t, err)

	out, err := runRotate(t, "--reason", "compromise", "--not-after", notAfter(), "--output-dir", second,
		"--previous", filepath.Join(first, verify.RotationManifestFile), "--revoke", v2fp)
	require.NoError(t, err)

	m := readManifest(t, authority, second)
	assert.EqualValues(t, 2, m.Epoch)
	require.Len(t, m.Add, 1)
	assert.Equal(t, v3fp, m.Add[0].Fingerprint)
	require.Len(t, m.Revoke, 2)
	assert.Equal(t, time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC), m.Revoke[0].Since)
	assert.Contains(t, out, "add        "+v3fp+"  (carried)")
	assert.Contains(t, out, "revoke     "+v1fp+" since 2026-11-01T00:00:00Z  (carried)")
	assert.Regexp(t, "revoke     "+v2fp+" since [^\n]*Z\n", out, "this run's revoke is not marked")
}

func TestRunRotate_Refusals(t *testing.T) {
	registerAuthority(t)
	keys := t.TempDir()
	_, v1fp := writeReleaseKey(t, keys, "v1")

	for name, tc := range map[string]struct {
		args []string
		want string
		is   error
	}{
		"an unknown reason":        {[]string{"--reason", "routine", "--not-after", notAfter()}, `--reason must be`, nil},
		"a not-after in no format": {[]string{"--reason", "scheduled", "--not-after", "next year"}, "not an RFC 3339 time", nil},
		"a revoke time in no format": {[]string{"--reason", "compromise", "--not-after", notAfter(), "--revoke", v1fp + "@soon"},
			"not an RFC 3339 time", nil},
		"a revoke on a scheduled manifest": {[]string{"--reason", "scheduled", "--not-after", notAfter(), "--revoke", v1fp},
			"", rotate.ErrScheduledRevoke},
		"a previous manifest with no signature beside it": {[]string{"--reason", "scheduled", "--not-after", notAfter(),
			"--previous", signtest.WriteFile(t, keys, "rotate-keys.json", "{}")}, "needs its signature beside it", nil},
		"a not-after already past": {[]string{"--reason", "scheduled", "--not-after", "2000-01-01T00:00:00Z"},
			"", verify.ErrRotationManifestMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()

			_, err := runRotate(t, append(tc.args, "--output-dir", dir)...)
			require.Error(t, err)

			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			} else {
				assert.Contains(t, err.Error(), tc.want)
			}

			entries, _ := os.ReadDir(dir)
			assert.Empty(t, entries, "a refusal writes nothing")
		})
	}
}

func TestRunRotate_RefusesAnAuthorityThatIsNotEd25519(t *testing.T) {
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.RSAKey(t)})

	_, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Ed25519")
}

func TestRunRotate_KeepsAnExistingManifestWithoutForce(t *testing.T) {
	registerAuthority(t)
	dir := t.TempDir()
	existing := signtest.WriteFile(t, dir, verify.RotationManifestFile, "published")

	_, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir)
	require.Error(t, err)

	b, _ := os.ReadFile(existing)
	assert.Equal(t, "published", string(b))
	assert.NoFileExists(t, filepath.Join(dir, verify.RotationSignatureFile))

	sigOnly := t.TempDir()
	signtest.WriteFile(t, sigOnly, verify.RotationSignatureFile, "published")
	_, err = runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", sigOnly)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	assert.NoFileExists(t, filepath.Join(sigOnly, verify.RotationManifestFile), "nothing written when the second path exists")

	_, err = runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir, "--force")
	require.NoError(t, err)
}

func TestRunRotate_RemovesTheManifestWhenTheSignatureCannotBeWritten(t *testing.T) {
	registerAuthority(t)
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, verify.RotationSignatureFile), 0o755))

	_, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir, "--force")
	require.Error(t, err)
	assert.NoFileExists(t, filepath.Join(dir, verify.RotationManifestFile))
}

func TestRunRotate_RestoresTheEarlierManifestWhenAForcedSignatureFails(t *testing.T) {
	registerAuthority(t)
	dir := t.TempDir()
	earlier := signtest.WriteFile(t, dir, verify.RotationManifestFile, "published")
	require.NoError(t, os.Mkdir(filepath.Join(dir, verify.RotationSignatureFile), 0o755))

	_, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir, "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restored to the earlier manifest")

	b, readErr := os.ReadFile(earlier)
	require.NoError(t, readErr)
	assert.Equal(t, "published", string(b))
}

func TestRunRotate_RefusesAnExplicitEpochZero(t *testing.T) {
	registerAuthority(t)

	_, err := runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", t.TempDir(), "--epoch", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--epoch must be at least 1")
}

func TestRunRotate_RefusesAPrivateKeyFileForAdd(t *testing.T) {
	registerAuthority(t)
	dir := t.TempDir()

	e, err := openpgp.NewEntity("v2", "", "v2@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, e.SerializePrivate(w, nil))
	require.NoError(t, w.Close())

	priv := signtest.WriteFile(t, dir, "v2.priv.asc", buf.String())

	_, err = runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", dir, "--add", priv)
	require.ErrorIs(t, err, rotate.ErrSecretKey)
	assert.Contains(t, err.Error(), "v2.priv.asc")
	assert.NoFileExists(t, filepath.Join(dir, verify.RotationManifestFile))
}

func TestNewCmdRotate_IsNotAnMCPTool(t *testing.T) {
	cmd := rotatecmd.NewCmdRotate(signtest.Props())

	assert.Equal(t, setup.MCPExposureExcluded, setup.MCPExposureOf(cmd.Command))
}

// The authority signs over whatever bytes it is given, so a previous manifest
// from another issuer can carry a secret even though SignRotationManifest
// would refuse to write one.
func TestRunRotate_RefusesAPreviousManifestCarryingPrivateKeyMaterial(t *testing.T) {
	registerAuthority(t)
	keys, first, second := t.TempDir(), t.TempDir(), t.TempDir()

	e, err := openpgp.NewEntity("v2", "", "v2@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)

	public, secret := armored(t, e, false), armored(t, e, true)
	add := signtest.WriteFile(t, keys, "v2.asc", public)

	_, err = runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", first, "--add", add)
	require.NoError(t, err)

	previous := filepath.Join(first, verify.RotationManifestFile)
	leakSecretInto(t, previous, secret)

	_, err = runRotate(t, "--reason", "scheduled", "--not-after", notAfter(), "--output-dir", second,
		"--previous", previous)
	require.ErrorIs(t, err, verify.ErrRotationManifestMalformed)
	assert.Contains(t, err.Error(), "the previous manifest: added key")
	assert.Contains(t, err.Error(), "the armored text must be one PGP PUBLIC KEY BLOCK")
	assert.NoFileExists(t, filepath.Join(second, verify.RotationManifestFile))
}

func armored(t *testing.T, e *openpgp.Entity, private bool) string {
	t.Helper()

	blockType, serialize := openpgp.PublicKeyType, e.Serialize
	if private {
		blockType = openpgp.PrivateKeyType
		serialize = func(w io.Writer) error { return e.SerializePrivateWithoutSigning(w, nil) }
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	require.NoError(t, err)
	require.NoError(t, serialize(w))
	require.NoError(t, w.Close())

	return buf.String()
}

// leakSecretInto swaps the manifest's one added key for secret and re-signs it
// with the authority, as a careless issuer's tool might.
func leakSecretInto(t *testing.T, path, secret string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["add"].([]any)[0].(map[string]any)["armored"] = secret

	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	sig, err := minisign.Sign(signtest.Ed25519Key(), bytes.NewReader(raw), minisign.Options{})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".minisig", sig, 0o600))
}
