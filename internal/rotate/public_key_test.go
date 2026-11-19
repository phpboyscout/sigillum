package rotate

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCarry_RefusesAnAddHoldingPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	v2 := newReleaseKey(t, "v2")
	prev := &verify.RotationManifest{Add: []verify.RotationAdd{{Fingerprint: v2.fingerprint, Armored: string(v2.private)}}}

	_, err := carry(&verify.RotationManifest{}, prev)
	require.ErrorIs(t, err, ErrSecretKey)
	assert.Contains(t, err.Error(), "carried add "+v2.fingerprint)
}

func TestCarry_RepublishesOnlyTheKeyItRead(t *testing.T) {
	t.Parallel()

	v2 := newReleaseKey(t, "v2")
	prev := &verify.RotationManifest{Add: []verify.RotationAdd{{Fingerprint: v2.fingerprint, Armored: "issued by another tool\n" + string(v2.armored)}}}

	var m verify.RotationManifest
	carried, err := carry(&m, prev)
	require.NoError(t, err)
	assert.True(t, carried[v2.fingerprint])
	require.Len(t, m.Add, 1)
	assert.NotContains(t, m.Add[0].Armored, "issued by another tool")
	assert.True(t, strings.HasPrefix(m.Add[0].Armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
}
