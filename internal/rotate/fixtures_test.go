package rotate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/minisign"
	"gitlab.com/phpboyscout/go/signing/verify"
)

var now = time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC)

type releaseKey struct {
	armored     []byte
	private     []byte
	fingerprint string
}

func newReleaseKey(t *testing.T, name string) releaseKey {
	t.Helper()

	e, err := openpgp.NewEntity(name, "", name+"@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, e.Serialize(w))
	require.NoError(t, w.Close())

	var priv bytes.Buffer
	pw, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, e.SerializePrivate(pw, nil))
	require.NoError(t, pw.Close())

	return releaseKey{
		armored: buf.Bytes(), private: priv.Bytes(),
		fingerprint: strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)),
	}
}

type authority struct {
	signer ed25519.PrivateKey
	public string
}

func newAuthority(t *testing.T) authority {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key, err := minisign.NewPublicKey(pub)
	require.NoError(t, err)

	return authority{signer: priv, public: key.Encode()}
}

// issue builds and signs a manifest, returning the two published files.
func issue(t *testing.T, a authority, req Request) (manifest, signature []byte) {
	t.Helper()

	m, _, err := Build(req, a.public)
	require.NoError(t, err)

	manifest, signature, err = verify.SignRotationManifest(a.signer, m)
	require.NoError(t, err)

	return manifest, signature
}

func scheduled() Request {
	return Request{Reason: verify.RotationReasonScheduled, Now: now, NotAfter: now.Add(90 * 24 * time.Hour)}
}

func compromise() Request {
	r := scheduled()
	r.Reason = verify.RotationReasonCompromise

	return r
}
