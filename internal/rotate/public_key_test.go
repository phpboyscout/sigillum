package rotate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/phpboyscout/go/signing/minisign"
	"gitlab.com/phpboyscout/go/signing/verify"
)

func newEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	e, err := openpgp.NewEntity("k", "", "k@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)

	return e
}

func armored(t *testing.T, blockType string, write func(io.Writer) error) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	require.NoError(t, err)
	require.NoError(t, write(w))
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func TestOnePublicEntity_Refuses(t *testing.T) {
	t.Parallel()

	primaryOnly := newEntity(t)
	primaryOnly.Subkeys = nil

	withSecretSubkey := newEntity(t)

	for name, tc := range map[string]struct {
		file []byte
		want error
	}{
		"a public key under another block type": {
			armored(t, "PGP SIGNATURE", newEntity(t).Serialize), ErrBadKey,
		},
		"a public header over no key": {
			armored(t, openpgp.PublicKeyType, func(w io.Writer) error { _, err := w.Write([]byte("not a key")); return err }), ErrBadKey,
		},
		"a secret primary key with no subkeys under a public header": {
			armored(t, openpgp.PublicKeyType, func(w io.Writer) error { return primaryOnly.SerializePrivateWithoutSigning(w, nil) }), ErrSecretKey,
		},
		"a public primary key with a secret subkey": {
			armored(t, openpgp.PublicKeyType, func(w io.Writer) error { return publicPrimarySecretSubkey(w, withSecretSubkey) }), ErrSecretKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := onePublicEntity(tc.file)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func publicPrimarySecretSubkey(w io.Writer, e *openpgp.Entity) error {
	if err := e.PrimaryKey.Serialize(w); err != nil {
		return err
	}

	for _, id := range e.Identities {
		if err := id.UserId.Serialize(w); err != nil {
			return err
		}

		if err := id.SelfSignature.Serialize(w); err != nil {
			return err
		}
	}

	for _, sub := range e.Subkeys {
		if err := sub.PrivateKey.Serialize(w); err != nil {
			return err
		}

		if err := sub.Sig.Serialize(w); err != nil {
			return err
		}
	}

	return nil
}

func TestBuild_RefusesACarriedAddHoldingPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v2 := newReleaseKey(t, "v2")

	first := scheduled()
	first.Add = []KeyFile{{Armored: v2.armored}}
	manifest, _ := issue(t, a, first)

	pub, err := json.Marshal(string(v2.armored))
	require.NoError(t, err)
	priv, err := json.Marshal(string(v2.private))
	require.NoError(t, err)
	trimmed := func(b []byte) string { return strings.Trim(string(b), `"`) }
	require.Contains(t, string(manifest), trimmed(pub))

	tampered := []byte(strings.Replace(string(manifest), trimmed(pub), trimmed(priv), 1))
	signature, err := minisign.Sign(a.signer, bytes.NewReader(tampered), minisign.Options{})
	require.NoError(t, err)

	second := scheduled()
	second.Previous = &Previous{Manifest: tampered, Signature: signature}

	_, _, err = Build(second, a.public)
	require.Error(t, err)
	// go/signing#26 makes verifying the previous manifest refuse this first.
	assert.True(t, errorIsAny(err, ErrSecretKey, verify.ErrRotationManifestMalformed), "got %v", err)
	assert.Contains(t, err.Error(), v2.fingerprint)
}

func errorIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}
