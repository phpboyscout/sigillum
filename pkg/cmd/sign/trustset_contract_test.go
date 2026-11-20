package sign_test

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/verify"

	"gitlab.com/phpboyscout/sigillum/internal/signtest"
)

// These tests hold sign to the verifier a self-update runs before it installs
// anything: go/signing's verify.TrustSet. They need no key service, so the
// half of the contract that matters most runs on every commit.

// The trust set refuses RSA below 3072 bits.
const trustSetMinBits = 3072

const releaseManifest = "deadbeef  gtb_Linux_x86_64.tar.gz\ncafebabe  checksums.txt\n"

type contractKeyPair struct {
	signer   *rsa.PrivateKey
	stranger *rsa.PrivateKey
}

// A 3072-bit key is slow to generate, so the tests share one pair.
var contractKeys = sync.OnceValues(func() (contractKeyPair, error) {
	signer, err := rsa.GenerateKey(rand.Reader, trustSetMinBits)
	if err != nil {
		return contractKeyPair{}, err
	}

	stranger, err := rsa.GenerateKey(rand.Reader, trustSetMinBits)
	if err != nil {
		return contractKeyPair{}, err
	}

	return contractKeyPair{signer: signer, stranger: stranger}, nil
})

// signManifest signs body through the sign command and returns the signature
// and the armored public key.
func signManifest(t *testing.T, priv *rsa.PrivateKey, body string) (signature, publicKey []byte) {
	t.Helper()

	tmp := t.TempDir()
	publicKeyPath := signtest.WritePublicKey(t, tmp, priv)
	manifestPath := signtest.WriteFile(t, tmp, "checksums.txt", body)

	signtest.Register(t, &signtest.Backend{BackendName: fakeBackend, Signer: priv})
	require.NoError(t, runSign(t, signRequest{publicKey: publicKeyPath, input: manifestPath, created: pinnedCreated}))

	signature, err := os.ReadFile(manifestPath + ".sig")
	require.NoError(t, err)

	publicKey, err = os.ReadFile(publicKeyPath)
	require.NoError(t, err)

	return signature, publicKey
}

func TestSignVerifyContract_SignatureIsAcceptedByTrustSet(t *testing.T) {
	keys, err := contractKeys()
	require.NoError(t, err)

	signature, publicKey := signManifest(t, keys.signer, releaseManifest)

	ts, err := verify.LoadTrustSet(publicKey)
	require.NoError(t, err)

	require.NoError(t, ts.VerifyManifestSignature([]byte(releaseManifest), signature))
}

func TestSignVerifyContract_TamperedManifestIsRejected(t *testing.T) {
	keys, err := contractKeys()
	require.NoError(t, err)

	signature, publicKey := signManifest(t, keys.signer, releaseManifest)

	ts, err := verify.LoadTrustSet(publicKey)
	require.NoError(t, err)

	tampered := []byte("00000000  gtb_Linux_x86_64.tar.gz\ncafebabe  checksums.txt\n")

	require.ErrorIs(t, ts.VerifyManifestSignature(tampered, signature), verify.ErrSignatureInvalid)
}

func TestSignVerifyContract_UntrustedKeyIsRejected(t *testing.T) {
	keys, err := contractKeys()
	require.NoError(t, err)

	signature, _ := signManifest(t, keys.signer, releaseManifest)
	_, strangerPublicKey := signManifest(t, keys.stranger, "unrelated\n")

	ts, err := verify.LoadTrustSet(strangerPublicKey)
	require.NoError(t, err)

	require.ErrorIs(t, ts.VerifyManifestSignature([]byte(releaseManifest), signature), verify.ErrSignatureInvalid)
}
