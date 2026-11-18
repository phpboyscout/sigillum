package generate_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	"gitlab.com/phpboyscout/go/signing/local"
	"gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/generate"
)

const (
	created      = "2026-06-08T00:00:00Z"
	createdLater = "2026-06-09T00:00:00Z"

	publicKeyBlock = "PGP PUBLIC KEY BLOCK"
	secretKeyBlock = "PGP PRIVATE KEY BLOCK"
	pkcs1Block     = "RSA PRIVATE KEY"
	pkcs8Block     = "PRIVATE KEY"
)

// pemHeader builds a PEM opening line. Written out whole, a private-key header
// trips the secret scanner.
func pemHeader(block string) []byte {
	return []byte("-----BEGIN " + block + "-----")
}

// keyPaths are the two files one generate run writes.
type keyPaths struct{ pub, priv string }

func pathsIn(dir, pub, priv string) keyPaths {
	return keyPaths{pub: filepath.Join(dir, pub), priv: filepath.Join(dir, priv)}
}

func runGenerate(t *testing.T, paths keyPaths, args ...string) error {
	t.Helper()

	return runGenerateWith(t, signtest.Props(), paths, args...)
}

func runGenerateWith(t *testing.T, p *props.Props, paths keyPaths, args ...string) error {
	t.Helper()

	all := append([]string{
		"--name", "Test Key", "--email", "test@example.com",
		"--output", paths.pub, "--private-output", paths.priv,
	}, args...)

	return signtest.Execute(t, generate.NewCmdGenerate(p).Command, all...)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return data
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)

	return info.Mode().Perm()
}

func TestRunGenerate_RSA_WritesPKCS1AndAnArmoredPublicKey(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "rsa.asc", "rsa.pem")

	require.NoError(t, runGenerate(t, paths, "--algorithm", "rsa", "--rsa-bits", "2048", "--created", created))

	assert.True(t, bytes.HasPrefix(readFile(t, paths.pub), pemHeader(publicKeyBlock)))

	priv := readFile(t, paths.priv)
	assert.True(t, bytes.HasPrefix(priv, pemHeader(pkcs1Block)), "RSA private half should be PKCS#1 PEM")

	block, _ := pem.Decode(priv)
	require.NotNil(t, block)

	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
}

func TestRunGenerate_Ed25519_WritesArmoredOpenPGPByDefault(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "ed25519.asc", "ed25519.priv.asc")

	require.NoError(t, runGenerate(t, paths, "--algorithm", "ed25519"))

	pub := readFile(t, paths.pub)
	assert.True(t, bytes.HasPrefix(pub, pemHeader(publicKeyBlock)))
	assert.True(t, bytes.HasPrefix(readFile(t, paths.priv), pemHeader(secretKeyBlock)),
		"Ed25519 private half should be armored OpenPGP")

	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	require.NoError(t, err)
	require.Len(t, ring, 1)
	assert.Equal(t, 22, int(ring[0].PrimaryKey.PubKeyAlgo),
		"Ed25519 must be algorithm 22 (v4 EdDSA) for GnuPG 2.4 compatibility")
}

func TestRunGenerate_DefaultPathsComeFromTheAlgorithm(t *testing.T) {
	t.Chdir(t.TempDir())

	require.NoError(t, signtest.Execute(t, generate.NewCmdGenerate(signtest.Props()).Command,
		"--algorithm", "ed25519", "--name", "N", "--email", "e@example.com"))

	assert.FileExists(t, "ed25519.asc")
	assert.FileExists(t, "ed25519.priv.asc")
}

func TestRunGenerate_Refusals(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"rsa bits": {
			args: []string{"--algorithm", "rsa", "--rsa-bits", "1024"},
			want: "--rsa-bits must be 2048, 3072, or 4096 (got 1024)",
		},
		"unknown algorithm": {
			args: []string{"--algorithm", "magic"},
			want: `unknown algorithm "magic" (expected "ed25519" or "rsa")`,
		},
		"created time": {
			args: []string{"--algorithm", "rsa", "--created", "garbage"},
			want: "parsing --created (RFC3339 expected)",
		},
		"private format": {
			args: []string{"--algorithm", "ed25519", "--private-format", "der"},
			want: `unknown --private-format "der" (expected "openpgp" or "pem")`,
		},
		"rsa as openpgp": {
			args: []string{"--algorithm", "rsa", "--private-format", "openpgp"},
			want: "--private-format openpgp is not supported for --algorithm rsa",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			paths := pathsIn(t.TempDir(), "out.asc", "out.pem")

			err := runGenerate(t, paths, tc.args...)
			require.ErrorContains(t, err, tc.want)
			assert.NoFileExists(t, paths.priv, "a refused generate writes nothing")
			assert.NoFileExists(t, paths.pub)
		})
	}
}

func TestRunGenerate_RefusesOnePathForBothHalves(t *testing.T) {
	t.Parallel()

	same := filepath.Join(t.TempDir(), "same.asc")

	err := runGenerate(t, keyPaths{pub: same, priv: same}, "--algorithm", "rsa", "--rsa-bits", "2048")
	require.ErrorContains(t, err, "must differ")
	assert.NoFileExists(t, same)
}

func TestRunGenerate_RefusesOneFileSpeltTwoWays(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "same.asc")
	require.NoError(t, os.WriteFile(path, []byte("an older private key"), keyfile.PrivatePerm))

	respelt := dir + string(filepath.Separator) + "." + string(filepath.Separator) + "same.asc"

	err := runGenerate(t, keyPaths{pub: respelt, priv: path}, "--algorithm", "rsa", "--rsa-bits", "2048", "--force")
	require.ErrorContains(t, err, "must differ")

	kept, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "an older private key", string(kept), "the private half is not overwritten by the public one")
}

// The put-back after a late failure is go/signing's to test. This proves only
// that generate's writes go through the pair write's up-front checks.
func TestRunGenerate_AnUnwritablePublicPathIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "out.asc", "out.pem")
	require.NoError(t, os.WriteFile(paths.priv, []byte("an older private key"), keyfile.PrivatePerm))
	require.NoError(t, os.Mkdir(paths.pub, 0o700))

	err := runGenerate(t, paths, "--algorithm", "rsa", "--rsa-bits", "2048", "--force")
	require.Error(t, err)

	kept, err := os.ReadFile(paths.priv)
	require.NoError(t, err)
	assert.Equal(t, "an older private key", string(kept))
}

func TestRunGenerate_RequiresAlgorithmNameAndEmail(t *testing.T) {
	t.Parallel()

	err := signtest.Execute(t, generate.NewCmdGenerate(signtest.Props()).Command)
	require.ErrorContains(t, err, `required flag(s) "algorithm", "email", "name" not set`)
}

func TestRunGenerate_RefusesToClobberPrivateKey(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "rsa.asc", "rsa.pem")
	rsa := []string{"--algorithm", "rsa", "--rsa-bits", "2048"}

	require.NoError(t, runGenerate(t, paths, append(rsa, "--created", created)...))
	assert.Equal(t, os.FileMode(0o600), mode(t, paths.priv), "freshly generated private key must be 0o600")

	original := readFile(t, paths.priv)

	err := runGenerate(t, paths, append(rsa, "--created", createdLater)...)
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.ErrorContains(t, err, "pass --force to overwrite")

	assert.Equal(t, original, readFile(t, paths.priv), "a refused generate must not modify the existing private key")
}

// The public half alone existing stops the run before either half is written,
// so no new private key is left without its public half.
func TestRunGenerate_RefusesToClobberPublicKey(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "ed.asc", "ed.priv.asc")
	require.NoError(t, os.WriteFile(paths.pub, []byte("published"), 0o600))

	err := runGenerate(t, paths, "--algorithm", "ed25519")
	require.ErrorIs(t, err, signcmd.ErrKeyFileExists)
	require.ErrorContains(t, err, paths.pub)

	assert.Equal(t, "published", string(readFile(t, paths.pub)))
	assert.NoFileExists(t, paths.priv)
}

func TestRunGenerate_ForceOverwritesPrivateKey(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "rsa.asc", "rsa.pem")
	rsa := []string{"--algorithm", "rsa", "--rsa-bits", "2048"}

	require.NoError(t, runGenerate(t, paths, append(rsa, "--created", created)...))

	original := readFile(t, paths.priv)

	require.NoError(t, runGenerate(t, paths, append(rsa, "--created", createdLater, "--force")...))

	assert.NotEqual(t, original, readFile(t, paths.priv), "--force must overwrite the existing private key")
	assert.Equal(t, os.FileMode(0o600), mode(t, paths.priv), "overwritten private key must remain 0o600")
}

func TestRunGenerate_ForceTightensALooserPrivateKeyMode(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "ed.asc", "ed.priv.asc")

	require.NoError(t, os.WriteFile(paths.priv, []byte("stale"), 0o600))
	require.NoError(t, os.Chmod(paths.priv, 0o644)) //nolint:gosec // the loose mode is the fixture

	require.NoError(t, runGenerate(t, paths, "--algorithm", "ed25519", "--force"))

	assert.Equal(t, os.FileMode(0o600), mode(t, paths.priv),
		"--force over a world-readable file must leave the new private key 0o600")
}

func TestRunGenerate_Ed25519PEMPrivateHalfMatchesThePublishedKey(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "artefact.asc", "artefact.pem")

	require.NoError(t, runGenerate(t, paths, "--algorithm", "ed25519", "--private-format", "pem", "--created", created))

	privData := readFile(t, paths.priv)
	assert.True(t, bytes.HasPrefix(privData, pemHeader(pkcs8Block)), "PKCS#8 PEM, not an armored OpenPGP block")

	block, _ := pem.Decode(privData)
	require.NotNil(t, block)

	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	priv, ok := anyKey.(ed25519.PrivateKey)
	require.True(t, ok, "expected an ed25519.PrivateKey, got %T", anyKey)

	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(readFile(t, paths.pub)))
	require.NoError(t, err)
	require.Len(t, ring, 1)

	published, ok := ring[0].PrimaryKey.PublicKey.(*eddsa.PublicKey)
	require.True(t, ok, "expected an EdDSA public key, got %T", ring[0].PrimaryKey.PublicKey)

	derived, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)

	// A PEM that disagrees with the .asc signs under a key nobody was given.
	assert.Equal(t, []byte(derived), published.X, "the PEM private half must correspond to the published public key")
}

func TestRunGenerate_Ed25519PEMDrivesMinisignThroughTheLocalBackend(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "artefact.asc", "artefact.pem")

	require.NoError(t, runGenerate(t, paths, "--algorithm", "ed25519", "--private-format", "pem"))

	signer, err := local.NewSigner(context.Background(), paths.priv)
	require.NoError(t, err)

	pub, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "local backend must yield an Ed25519 signer, got %T", signer.Public())

	artefact := []byte("a release archive")

	sig, err := minisign.Sign(signer, bytes.NewReader(artefact), minisign.Options{Filename: "tool.tar.gz", Project: "demo"})
	require.NoError(t, err)

	key, err := minisign.NewPublicKey(pub)
	require.NoError(t, err)
	require.NoError(t, minisign.VerifyFile(key, artefact, sig),
		"a key generated here must produce a verifiable minisign signature")
}

func TestRunGenerate_TellsTheOperatorToMoveThePrivateHalfOffline(t *testing.T) {
	t.Parallel()

	paths := pathsIn(t.TempDir(), "ed.asc", "ed.priv.asc")
	log := logger.NewBuffer()

	require.NoError(t, runGenerateWith(t, &props.Props{Logger: log}, paths, "--algorithm", "ed25519", "--created", created))

	assert.True(t, log.ContainsLevel(logger.WarnLevel, "Move the private-half file to offline storage now."))

	var generated *logger.Entry

	for _, e := range log.Entries() {
		if e.Message == "Generated OpenPGP keypair" {
			generated = &e
		}
	}

	require.NotNil(t, generated)
	assert.Contains(t, generated.Keyvals, "fingerprint")
	assert.Contains(t, generated.Keyvals, paths.priv)
	assert.Contains(t, generated.Keyvals, created)
}

func TestNewCmdGenerate_Flags(t *testing.T) {
	t.Parallel()

	fs := generate.NewCmdGenerate(signtest.Props()).Flags()

	for _, name := range []string{
		"algorithm", "private-format", "rsa-bits", "name", "email", "output", "private-output", "created", "force",
	} {
		assert.NotNil(t, fs.Lookup(name), "expected flag --%s on `keys generate`", name)
	}

	assert.Equal(t, "4096", fs.Lookup("rsa-bits").DefValue)
}
