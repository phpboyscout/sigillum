package sign_test

import (
	"bytes"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/local"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/sign"
)

// openPGPFixture registers a backend serving a fresh RSA key and returns a
// request that signs payload.txt under it.
func openPGPFixture(t *testing.T) (signRequest, *rsa.PrivateKey) {
	t.Helper()

	tmp := t.TempDir()
	priv := signtest.RSAKey(t)

	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	return signRequest{
		publicKey: signtest.WritePublicKey(t, tmp, priv),
		input:     signtest.WriteFile(t, tmp, "payload.txt", "hello\n"),
	}, priv
}

func TestRunSign_OpenPGP_WritesArmoredSignatureBesideTheInput(t *testing.T) {
	req, _ := openPGPFixture(t)

	require.NoError(t, runSign(t, req))

	sig, err := os.ReadFile(req.input + ".sig")
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

func TestRunSign_OpenPGP_AsksTheBackendForTheNamedKeyAndLogsTheSigning(t *testing.T) {
	tmp := t.TempDir()
	priv := signtest.RSAKey(t)

	backend := signtest.RegisterAwsKms(t)
	backend.Signer = priv

	publicKey := signtest.WritePublicKey(t, tmp, priv)
	input := signtest.WriteFile(t, tmp, "payload.txt", "hello\n")
	log := logger.NewBuffer()

	require.NoError(t, signtest.Execute(t, sign.NewCmdSign(&props.Props{Logger: log}).Command,
		"--backend", "aws-kms", "--key-id", "alias/release", "--public-key", publicKey,
		"--created", "2026-06-08T00:00:00Z", input))

	assert.Equal(t, []string{"alias/release"}, backend.KeyIDs)

	armored, err := os.ReadFile(publicKey)
	require.NoError(t, err)

	fingerprint, err := signcmd.ReadFingerprint(armored)
	require.NoError(t, err)

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "Signed file", entries[0].Message)
	assert.Equal(t, []any{
		"backend", "aws-kms",
		"key_id", "alias/release",
		"public_key", publicKey,
		"input", input,
		"output", input + ".sig",
		"sig_creation_time", "2026-06-08T00:00:00Z",
		"fingerprint", fingerprint,
	}, entries[0].Keyvals)
}

// The selector's settings may hold anything the user typed, so the log names
// the backend by its canonical identity.
func TestRunSign_OpenPGP_LogsTheBackendIdentityNotTheSelector(t *testing.T) {
	tmp := t.TempDir()
	priv := signtest.RSAKey(t)

	signtest.RegisterAwsKms(t).Signer = priv

	log := logger.NewBuffer()

	require.NoError(t, signtest.Execute(t, sign.NewCmdSign(&props.Props{Logger: log}).Command,
		"--backend", "aws-kms:prod?kms-region=eu-west-1", "--key-id", "alias/release",
		"--public-key", signtest.WritePublicKey(t, tmp, priv),
		signtest.WriteFile(t, tmp, "payload.txt", "hello\n")))

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, []any{"backend", "aws-kms:prod"}, entries[0].Keyvals[:2])
}

func TestRunSign_OpenPGP_RequiresPublicKey(t *testing.T) {
	req, _ := openPGPFixture(t)
	req.publicKey = ""

	require.EqualError(t, runSign(t, req), "--public-key is required for --format openpgp")
}

func TestRunSign_OpenPGP_MissingPublicKeyFile_Errors(t *testing.T) {
	req, _ := openPGPFixture(t)
	req.publicKey = filepath.Join(t.TempDir(), "nonexistent.asc")

	err := runSign(t, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading public key")
}

func TestRunSign_OpenPGP_RefusesOutputEqualsInput(t *testing.T) {
	req, _ := openPGPFixture(t)

	spellings := map[string]string{
		"the same path": req.input,
		"a dot segment": filepath.Dir(req.input) + string(filepath.Separator) + "." +
			string(filepath.Separator) + filepath.Base(req.input),
	}

	for name, output := range spellings {
		t.Run(name, func(t *testing.T) {
			req.output = output

			err := runSign(t, req)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "equals the input path")

			body, readErr := os.ReadFile(req.input)
			require.NoError(t, readErr)
			assert.Equal(t, "hello\n", string(body))
		})
	}
}

// The public key is the identity claimed. A backend holding a different key
// must be caught before an unverifiable signature is written.
func TestRunSign_OpenPGP_SignerMismatchPublicKey_Errors(t *testing.T) {
	req, _ := openPGPFixture(t)

	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.RSAKey(t)})

	err := runSign(t, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.NoFileExists(t, req.input+".sig")
}

func TestRunSign_OpenPGP_InvalidCreatedFlag_Errors(t *testing.T) {
	req, _ := openPGPFixture(t)
	req.created = "not-an-rfc3339-instant"

	require.ErrorContains(t, runSign(t, req), `parsing --created "not-an-rfc3339-instant" as RFC3339`)
}

func TestRunSign_OpenPGP_IsReproducibleWithPinnedCreated(t *testing.T) {
	req, _ := openPGPFixture(t)
	req.created = "2026-07-29T12:00:00Z"

	req.output = req.input + ".a.sig"
	require.NoError(t, runSign(t, req))

	req.output = req.input + ".b.sig"
	require.NoError(t, runSign(t, req))

	first, err := os.ReadFile(req.input + ".a.sig")
	require.NoError(t, err)

	second, err := os.ReadFile(req.input + ".b.sig")
	require.NoError(t, err)

	assert.Equal(t, string(first), string(second))
}

// The key-rotation overlap: one armored file carries a signature from the old
// key and one from the new, so a binary trusting either accepts it.
func TestRunSign_OpenPGP_Append_DualSignServesBothTrustSets(t *testing.T) {
	tmp := t.TempDir()
	input := signtest.WriteFile(t, tmp, "checksums.txt", "deadbeef  gtb\n")
	sigPath := input + ".sig"

	publicKeys := map[string]string{}

	// --append on an output that does not exist yet must be a no-op, so a
	// pipeline can pass it on every run.
	for _, name := range []string{"old", "new"} {
		priv := signtest.RSAKey(t)
		publicKeys[name] = signtest.WritePublicKey(t, t.TempDir(), priv)

		signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})
		require.NoError(t, runSign(t, signRequest{
			publicKey: publicKeys[name], output: sigPath, input: input, appendSig: true,
		}))
	}

	publicKeys["unrelated"] = signtest.WritePublicKey(t, t.TempDir(), signtest.RSAKey(t))

	sig, err := os.ReadFile(sigPath)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(sig), "-----BEGIN PGP SIGNATURE-----"))

	verify := func(publicKeyPath string) error {
		armored, err := os.ReadFile(publicKeyPath)
		require.NoError(t, err)

		keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
		require.NoError(t, err)

		_, err = openpgp.CheckArmoredDetachedSignature(
			keyring, strings.NewReader("deadbeef  gtb\n"), bytes.NewReader(sig), nil)

		return err
	}

	require.NoError(t, verify(publicKeys["old"]), "a verifier trusting only the old key must accept")
	require.NoError(t, verify(publicKeys["new"]), "a verifier trusting only the new key must accept")
	require.Error(t, verify(publicKeys["unrelated"]), "a verifier trusting neither key must reject")
}

// An armored OpenPGP secret key is Ed25519, so the refusal names the format
// that takes it.
func TestRunSign_OpenPGP_SecretKeyRefusalHintsAtMinisign(t *testing.T) {
	req, _ := openPGPFixture(t)

	signtest.Register(t, &signtest.Backend{
		BackendName: fakeBackend,
		Err:         errors.Wrap(local.ErrOpenPGPSecretKey, "./ed.priv.asc"),
	})

	err := runSign(t, req)

	require.ErrorIs(t, err, local.ErrOpenPGPSecretKey)
	assert.Contains(t, errors.Hints(err), sign.OpenPGPSecretKeyHint)
}

func TestRunSign_NoMinisignHintWhereItWouldMislead(t *testing.T) {
	req, _ := openPGPFixture(t)

	cases := []struct {
		name   string
		format string
		err    error
	}{
		{name: "the minisign format", format: signcmd.FormatMinisign, err: local.ErrOpenPGPSecretKey},
		{name: "a different error", format: signcmd.FormatOpenPGP, err: assert.AnError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Err: tc.err})

			failing := req
			failing.format = tc.format

			if tc.format == signcmd.FormatMinisign {
				failing.publicKey = ""
			}

			err := runSign(t, failing)

			require.ErrorIs(t, err, tc.err)
			assert.NotContains(t, errors.Hints(err), sign.OpenPGPSecretKeyHint)
		})
	}
}
