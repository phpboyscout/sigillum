package sign_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/sign"
)

func TestRunSign_UnknownFormat_Errors(t *testing.T) {
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.Ed25519Key()})

	err := runSign(t, signRequest{format: "pkcs7", input: "in.txt"})

	require.EqualError(t, err, `unknown --format "pkcs7"; valid values are "openpgp" and "minisign"`)
}

// Callers written before --format existed must keep getting an OpenPGP
// signature when they omit the flag.
func TestRunSign_NoFormatIsOpenPGP(t *testing.T) {
	tmp := t.TempDir()
	priv := signtest.RSAKey(t)
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	input := signtest.WriteFile(t, tmp, "payload.txt", "hello\n")

	require.NoError(t, signtest.Execute(t, sign.NewCmdSign(signtest.Props()).Command,
		"--backend", fakeBackend, "--key-id", "ignored",
		"--public-key", signtest.WritePublicKey(t, tmp, priv), input))

	sig, err := os.ReadFile(input + ".sig")
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

// go/signing-cli refused an explicitly empty --format, and spec 0007 keeps its
// refusals.
func TestRunSign_AnEmptyFormatIsRefused(t *testing.T) {
	tmp := t.TempDir()
	priv := signtest.RSAKey(t)
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	input := signtest.WriteFile(t, tmp, "payload.txt", "hello\n")

	err := signtest.Execute(t, sign.NewCmdSign(signtest.Props()).Command,
		"--format", "", "--backend", fakeBackend, "--key-id", "ignored",
		"--public-key", signtest.WritePublicKey(t, tmp, priv), input)
	require.EqualError(t, err, `--format is required; valid values are "openpgp" and "minisign"`)
	assert.NoFileExists(t, input+".sig")
}

func TestRunSign_FlagOfTheOtherFormatIsRefused(t *testing.T) {
	cases := []struct {
		name string
		req  signRequest
		want string
	}{
		{
			name: "--public-key under minisign",
			req:  signRequest{format: signcmd.FormatMinisign, publicKey: "release.asc"},
			want: "--public-key is not accepted for --format minisign; it is a --format openpgp flag",
		},
		{
			name: "--append under minisign",
			req:  signRequest{format: signcmd.FormatMinisign, appendSig: true},
			want: "--append is not accepted for --format minisign; it is a --format openpgp flag",
		},
		{
			name: "--project under openpgp",
			req:  signRequest{format: signcmd.FormatOpenPGP, publicKey: "release.asc", project: "rtb-cli-bin"},
			want: "--project is not accepted for --format openpgp; it is a --format minisign flag",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.Ed25519Key()})

			tc.req.input = signtest.WriteFile(t, t.TempDir(), "artefact.bin", "x")

			require.EqualError(t, runSign(t, tc.req), tc.want)
			assert.NoFileExists(t, tc.req.input+".sig")
			assert.NoFileExists(t, tc.req.input+".minisig")
		})
	}
}

func TestRunSign_UnknownBackend_Errors(t *testing.T) {
	signtest.Register(t)

	tmp := t.TempDir()

	err := runSign(t, signRequest{
		backend:   "nope",
		publicKey: signtest.WritePublicKey(t, tmp, signtest.RSAKey(t)),
		input:     signtest.WriteFile(t, tmp, "payload.txt", "x"),
	})

	require.ErrorIs(t, err, signing.ErrUnknownBackend)
}

// Only the CLI knows a flag was set, so this refusal is the command's own
// (go/signing-cli#7).
func TestNewCmdSign_NamedInstanceWithTopLevelBackendFlag_IsRefused(t *testing.T) {
	signtest.RegisterAwsKms(t)

	err := signtest.Execute(t, sign.NewCmdSign(signtest.Props()).Command,
		"--backend", "aws-kms:prod", "--kms-region", "eu-west-1",
		"--key-id", "alias/release", "--public-key", "unused.asc", "unused.txt")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--kms-region")
	assert.NotContains(t, err.Error(), "eu-west-1")
}

func TestNewCmdSign_BindsTheLinkedBackendsSettings(t *testing.T) {
	signtest.RegisterAwsKms(t)

	flag := sign.NewCmdSign(signtest.Props()).Flags().Lookup("kms-region")

	require.NotNil(t, flag)
	assert.Equal(t, "eu-west-2", flag.DefValue)
}
