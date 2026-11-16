package sign_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
)

const pinnedCreated = "2026-07-29T12:00:00Z"

// minisignFixture registers a backend serving the fixture Ed25519 key and
// returns a request that signs an artefact under it, with the key's public
// half.
func minisignFixture(t *testing.T) (signRequest, minisign.PublicKey) {
	t.Helper()

	priv := signtest.Ed25519Key()
	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})

	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)

	key, err := minisign.NewPublicKey(pub)
	require.NoError(t, err)

	return signRequest{
		format: signcmd.FormatMinisign,
		input: signtest.WriteFile(t, t.TempDir(), "tool_1.2.3_linux_amd64.tar.gz",
			strings.Repeat("artefact", 1000)),
	}, key
}

func readSignature(t *testing.T, path string) ([]byte, minisign.Signature) {
	t.Helper()

	sig, err := os.ReadFile(path)
	require.NoError(t, err)

	parsed, err := minisign.ParseSignature(sig)
	require.NoError(t, err)

	return sig, parsed
}

func TestRunSign_Minisign_WritesVerifiableSignature(t *testing.T) {
	req, key := minisignFixture(t)
	req.created = pinnedCreated

	require.NoError(t, runSign(t, req))

	// rtb-update picks its parser by the .minisig extension.
	sig, parsed := readSignature(t, req.input+".minisig")

	artefact, err := os.ReadFile(req.input)
	require.NoError(t, err)

	require.NoError(t, minisign.VerifyFile(key, artefact, sig))
	assert.True(t, parsed.Prehashed(), `cargo-binstall requires the prehashed "ED" variant`)
}

func TestRunSign_Minisign_IsReproducibleWithPinnedCreated(t *testing.T) {
	req, _ := minisignFixture(t)
	req.created = pinnedCreated

	req.output = req.input + ".a.minisig"
	require.NoError(t, runSign(t, req))

	req.output = req.input + ".b.minisig"
	require.NoError(t, runSign(t, req))

	first, _ := readSignature(t, req.input+".a.minisig")
	second, _ := readSignature(t, req.input+".b.minisig")

	assert.Equal(t, string(first), string(second))
}

func TestRunSign_Minisign_TrustedCommentTime(t *testing.T) {
	cases := []struct {
		name    string
		epoch   string
		created string
		want    string
	}{
		{name: "SOURCE_DATE_EPOCH when --created is unset", epoch: "1785326400", want: "timestamp:1785326400"},
		{
			name:  "--created beats SOURCE_DATE_EPOCH",
			epoch: "1785326400", created: "2020-01-01T00:00:00Z", want: "timestamp:1577836800",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := minisignFixture(t)
			req.created = tc.created

			t.Setenv(minisign.SourceDateEpochEnv, tc.epoch)

			require.NoError(t, runSign(t, req))

			_, parsed := readSignature(t, req.input+".minisig")
			assert.Contains(t, parsed.TrustedComment, tc.want)
		})
	}
}

func TestRunSign_Minisign_RejectsBadSourceDateEpoch(t *testing.T) {
	req, _ := minisignFixture(t)

	t.Setenv(minisign.SourceDateEpochEnv, "not-a-number")

	err := runSign(t, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), minisign.SourceDateEpochEnv)
	assert.NoFileExists(t, req.input+".minisig")
}

func TestRunSign_Minisign_InvalidCreatedFlag_Errors(t *testing.T) {
	req, _ := minisignFixture(t)
	req.created = "yesterday"

	require.ErrorContains(t, runSign(t, req), `parsing --created "yesterday" as RFC3339`)
}

// The likeliest cause is pointing at the RSA manifest key, so the error names
// the format that key belongs to.
func TestRunSign_Minisign_RejectsRSAKey(t *testing.T) {
	req, _ := minisignFixture(t)

	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: signtest.RSAKey(t)})

	err := runSign(t, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires an Ed25519 signing key")
	assert.Contains(t, err.Error(), signcmd.FormatOpenPGP)
	assert.NoFileExists(t, req.input+".minisig")
}

func TestRunSign_Minisign_RefusesOutputEqualsInput(t *testing.T) {
	req, _ := minisignFixture(t)
	req.output = req.input

	err := runSign(t, req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to write signature")
}

func TestRunSign_Minisign_ProjectLandsInTheTrustedComment(t *testing.T) {
	req, key := minisignFixture(t)
	req.created = pinnedCreated
	req.project = "rtb-cli-bin"

	require.NoError(t, runSign(t, req))

	sig, parsed := readSignature(t, req.input+".minisig")

	// minisign's conventional fields first, ours appended.
	assert.Contains(t, parsed.TrustedComment, "\thashed\tproject:rtb-cli-bin\tkey:")
	assert.Contains(t, parsed.TrustedComment, fmt.Sprintf("key:%X", key.KeyID))

	artefact, err := os.ReadFile(req.input)
	require.NoError(t, err)
	require.NoError(t, minisign.VerifyFile(key, artefact, sig))

	// The comment is signed, so a rewritten project must not verify.
	tampered := bytes.ReplaceAll(sig, []byte("project:rtb-cli-bin"), []byte("project:evil-crate"))
	require.Error(t, minisign.VerifyFile(key, artefact, tampered))
}

func TestRunSign_Minisign_NoProjectKeepsMinisignsDefault(t *testing.T) {
	req, _ := minisignFixture(t)
	req.created = pinnedCreated

	require.NoError(t, runSign(t, req))

	_, parsed := readSignature(t, req.input+".minisig")
	assert.NotContains(t, parsed.TrustedComment, "project:")
}
