package generate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/openpgpkey"
)

func TestResolveOutputs(t *testing.T) {
	t.Parallel()

	const (
		ed  = openpgpkey.AlgorithmEd25519
		rsa = openpgpkey.AlgorithmRSA
	)

	for name, tc := range map[string]struct {
		algorithm, format, output, privateOutput string
		wantPub, wantPriv                        string
	}{
		"ed25519 defaults":                 {algorithm: ed, wantPub: "ed25519.asc", wantPriv: "ed25519.priv.asc"},
		"rsa defaults":                     {algorithm: rsa, wantPub: "rsa.asc", wantPriv: "rsa.pem"},
		"explicit public derives private":  {algorithm: rsa, output: "my-key.asc", wantPub: "my-key.asc", wantPriv: "my-key.pem"},
		"both explicit":                    {algorithm: ed, output: "a.asc", privateOutput: "b.key", wantPub: "a.asc", wantPriv: "b.key"},
		"a PEM private half is named .pem": {algorithm: ed, format: openpgpkey.PrivateFormatPEM, output: "artefact.asc", wantPub: "artefact.asc", wantPriv: "artefact.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pub, priv, err := resolveOutputs(tc.algorithm, tc.format, tc.output, tc.privateOutput)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPub, pub)
			assert.Equal(t, tc.wantPriv, priv)
		})
	}
}

func TestResolveOutputs_Refusals(t *testing.T) {
	t.Parallel()

	_, _, err := resolveOutputs(openpgpkey.AlgorithmRSA, "", "same.asc", "same.asc")
	require.EqualError(t, err, "--output (same.asc) must differ from --private-output (same.asc)")

	_, _, err = resolveOutputs("magic", "", "", "")
	require.EqualError(t, err, `unknown algorithm "magic" (expected "ed25519" or "rsa")`)
}

func TestValidatePrivateFormat(t *testing.T) {
	t.Parallel()

	const (
		ed  = openpgpkey.AlgorithmEd25519
		rsa = openpgpkey.AlgorithmRSA
	)

	require.NoError(t, validatePrivateFormat(ed, ""))
	require.NoError(t, validatePrivateFormat(ed, openpgpkey.PrivateFormatPEM))
	require.NoError(t, validatePrivateFormat(ed, openpgpkey.PrivateFormatOpenPGP))
	require.NoError(t, validatePrivateFormat(rsa, openpgpkey.PrivateFormatPEM))

	require.EqualError(t, validatePrivateFormat(rsa, openpgpkey.PrivateFormatOpenPGP),
		"--private-format openpgp is not supported for --algorithm rsa; RSA private halves are written as PKCS#1 PEM")
	require.EqualError(t, validatePrivateFormat(ed, "der"),
		`unknown --private-format "der" (expected "openpgp" or "pem")`)
}
