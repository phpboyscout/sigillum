package rotate

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go/signing/verify"
)

func trustSet(t *testing.T, release []releaseKey, anchorOnly ...releaseKey) *verify.TrustSet {
	t.Helper()

	var keys [][]byte
	var fps []string

	for _, k := range release {
		keys = append(keys, k.armored)
	}

	for _, k := range anchorOnly {
		keys = append(keys, k.armored)
		fps = append(fps, k.fingerprint)
	}

	r, err := verify.BuildKeyResolver(verify.KeyResolverConfig{KeySource: "embedded", AnchorOnlyFingerprints: fps}, keys...)
	require.NoError(t, err)

	ts, err := r.Resolve(context.Background())
	require.NoError(t, err)

	return ts
}

func apply(t *testing.T, a authority, manifest, signature []byte, stored verify.RotationRecord, ts *verify.TrustSet) (verify.RotationRecord, error) {
	t.Helper()

	auth, err := verify.NewRotationAuthority(a.public)
	require.NoError(t, err)

	m, err := auth.VerifyRotationManifest(manifest, signature)
	require.NoError(t, err)

	return verify.Apply(m, stored, ts, now)
}

func TestBuild_TheFireDrillIsEpochOneAndApplies(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v1 := newReleaseKey(t, "v1")

	manifest, signature := issue(t, a, scheduled())

	rec, err := apply(t, a, manifest, signature, verify.RotationRecord{}, trustSet(t, []releaseKey{v1}))
	require.NoError(t, err)
	assert.Equal(t, verify.RotationRecord{Epoch: 1}, rec)
}

func TestBuild_AnEpochAboveOneNeedsThePreviousManifest(t *testing.T) {
	t.Parallel()

	req := scheduled()
	req.Epoch = 2

	_, _, err := Build(req, newAuthority(t).public)
	require.ErrorIs(t, err, ErrNeedsPrevious)
}

func TestBuild_CarriesThePreviousManifestForward(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v1, v2, v3 := newReleaseKey(t, "v1"), newReleaseKey(t, "v2"), newReleaseKey(t, "v3")

	first := compromise()
	first.Add = []KeyFile{{Armored: v2.armored}}
	first.Revoke = []Revocation{{Fingerprint: v1.fingerprint, Since: now.Add(-3 * time.Hour)}}
	prevManifest, prevSig := issue(t, a, first)

	second := compromise()
	second.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}
	second.Add = []KeyFile{{Armored: v3.armored}}

	m, carried, err := Build(second, a.public)
	require.NoError(t, err)
	assert.Equal(t, Carried{v1.fingerprint: true, v2.fingerprint: true}, carried, "v3 is this run's")
	assert.EqualValues(t, 2, m.Epoch)
	assert.ElementsMatch(t, []string{v2.fingerprint, v3.fingerprint}, addedFingerprints(m))
	require.Len(t, m.Revoke, 1)
	assert.Equal(t, v1.fingerprint, m.Revoke[0].Fingerprint)
	assert.Equal(t, now.Add(-3*time.Hour), m.Revoke[0].Since, "a carried revoke keeps its since")
}

func TestBuild_RevokingACarriedAddRemovesIt(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v2 := newReleaseKey(t, "v2")

	first := scheduled()
	first.Add = []KeyFile{{Armored: v2.armored}}
	prevManifest, prevSig := issue(t, a, first)

	second := compromise()
	second.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}
	second.Revoke = []Revocation{{Fingerprint: v2.fingerprint}}
	second.Anchors = [][]byte{newReleaseKey(t, "v1").armored}

	m, carried, err := Build(second, a.public)
	require.NoError(t, err)
	assert.Empty(t, carried, "revoking a carried add is this run's change")
	assert.Empty(t, m.Add)
	require.Len(t, m.Revoke, 1)
}

func TestBuild_TheEpochGuard(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	prevManifest, prevSig := issue(t, a, scheduled())

	for name, tc := range map[string]struct {
		epoch    uint64
		allowGap bool
		want     error
	}{
		"the next epoch by default":       {0, false, nil},
		"the next epoch named":            {2, false, nil},
		"a gap":                           {5, false, ErrEpochGap},
		"a gap, allowed":                  {5, true, nil},
		"the previous epoch":              {1, true, ErrEpochNotAfterPrevious},
		"beyond what an updater accepts":  {1026, true, ErrEpochTooFar},
		"the furthest an updater accepts": {1025, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := scheduled()
			req.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}
			req.Epoch = tc.epoch
			req.AllowEpochGap = tc.allowGap

			_, _, err := Build(req, a.public)
			if tc.want == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestBuild_ThePreviousManifestMustVerify(t *testing.T) {
	t.Parallel()

	a, old := newAuthority(t), newAuthority(t)
	prevManifest, prevSig := issue(t, old, scheduled())

	req := scheduled()
	req.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}

	_, _, err := Build(req, a.public)
	require.ErrorIs(t, err, verify.ErrRotationSignatureInvalid, "signed by another authority")

	req.PreviousAuthority = old.public
	_, _, err = Build(req, a.public)
	require.NoError(t, err, "succession names the old authority")

	tampered := append([]byte(nil), prevManifest...)
	tampered[len(tampered)-3] ^= 1
	req.Previous = &Previous{Manifest: tampered, Signature: prevSig}
	_, _, err = Build(req, a.public)
	require.Error(t, err)
}

func TestBuild_Refusals(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v1, v2 := newReleaseKey(t, "v1"), newReleaseKey(t, "v2")

	revoked := compromise()
	revoked.Revoke = []Revocation{{Fingerprint: v1.fingerprint}}
	revoked.Add = []KeyFile{{Armored: v2.armored}}
	prevManifest, prevSig := issue(t, a, revoked)

	for name, tc := range map[string]struct {
		req  func() Request
		want error
	}{
		"a revoke on a scheduled manifest": {func() Request {
			r := scheduled()
			r.Revoke = []Revocation{{Fingerprint: v1.fingerprint}}

			return r
		}, ErrScheduledRevoke},
		"a carried revoke on a scheduled manifest": {func() Request {
			r := scheduled()
			r.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}

			return r
		}, ErrScheduledRevoke},
		"one key added and revoked": {func() Request {
			r := compromise()
			r.Add = []KeyFile{{Armored: v2.armored}}
			r.Revoke = []Revocation{{Fingerprint: v2.fingerprint}}

			return r
		}, ErrAddedAndRevoked},
		"revoking and adding nothing, without anchors": {func() Request {
			r := compromise()
			r.Revoke = []Revocation{{Fingerprint: v1.fingerprint}}

			return r
		}, ErrNeedsAnchors},
		"carried revokes and nothing added, without anchors": {func() Request {
			r := compromise()
			r.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}
			r.Revoke = []Revocation{{Fingerprint: v2.fingerprint}}

			return r
		}, ErrNeedsAnchors},
		"revoking the last release key": {func() Request {
			r := compromise()
			r.Revoke = []Revocation{{Fingerprint: v1.fingerprint}}
			r.Anchors = [][]byte{v1.armored}

			return r
		}, verify.ErrRotationRefused},
		"adding an anchor-only key": {func() Request {
			r := scheduled()
			r.Add = []KeyFile{{Armored: v2.armored}}
			r.Anchors = [][]byte{v1.armored}
			r.AnchorOnly = [][]byte{v2.armored}

			return r
		}, verify.ErrRotationRefused},
		"an add that is not one OpenPGP key": {func() Request {
			r := scheduled()
			r.Add = []KeyFile{{Armored: []byte("not a key")}}

			return r
		}, ErrBadKey},
		"a malformed fingerprint": {func() Request {
			r := compromise()
			r.Revoke = []Revocation{{Fingerprint: "ABCD"}}

			return r
		}, ErrBadFingerprint},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := Build(tc.req(), a.public)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestBuild_AnchorsProveARevokeLeavesASigner(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v1, v2 := newReleaseKey(t, "v1"), newReleaseKey(t, "v2")

	req := compromise()
	req.Revoke = []Revocation{{Fingerprint: v1.fingerprint, Since: now.Add(-time.Hour)}}
	req.Anchors = [][]byte{v1.armored, v2.armored}

	manifest, signature := issue(t, a, req)

	rec, err := apply(t, a, manifest, signature, verify.RotationRecord{}, trustSet(t, []releaseKey{v1, v2}))
	require.NoError(t, err)
	assert.Equal(t, []string{v1.fingerprint}, rec.Revoked)
}

func addedFingerprints(m verify.RotationManifest) []string {
	out := make([]string, 0, len(m.Add))
	for _, a := range m.Add {
		out = append(out, a.Fingerprint)
	}

	return out
}

func TestBuild_NeverPublishesPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v2 := newReleaseKey(t, "v2")

	for name, file := range map[string][]byte{
		"a private key file":                     v2.private,
		"the public block, then the private one": slices.Concat(v2.armored, v2.private),
		"secret packets under a public header": bytes.Replace(v2.private,
			[]byte("PGP PRIVATE KEY BLOCK"), []byte("PGP PUBLIC KEY BLOCK"), 2),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := scheduled()
			req.Add = []KeyFile{{Armored: file}}

			_, _, err := Build(req, a.public)
			require.ErrorIs(t, err, ErrSecretKey)
		})
	}
}

func TestBuild_RefusesAFileWithTwoKeys(t *testing.T) {
	t.Parallel()

	req := scheduled()
	req.Add = []KeyFile{{Armored: slices.Concat(newReleaseKey(t, "v2").armored, newReleaseKey(t, "v3").armored)}}

	_, _, err := Build(req, newAuthority(t).public)
	require.ErrorIs(t, err, ErrBadKey)
}

func TestBuild_PublishesTheKeyItReadNotTheFile(t *testing.T) {
	t.Parallel()

	v2 := newReleaseKey(t, "v2")

	req := scheduled()
	req.Add = []KeyFile{{Armored: append([]byte("a comment before the block\n"), v2.armored...)}}

	m, _, err := Build(req, newAuthority(t).public)
	require.NoError(t, err)
	require.Len(t, m.Add, 1)
	assert.True(t, strings.HasPrefix(m.Add[0].Armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	assert.NotContains(t, m.Add[0].Armored, "PRIVATE")
}

func TestBuild_ARevokeDefaultsToTheTimeOfTheRun(t *testing.T) {
	t.Parallel()

	req := compromise()
	req.Revoke = []Revocation{{Fingerprint: newReleaseKey(t, "v1").fingerprint}}
	req.Anchors = [][]byte{newReleaseKey(t, "v2").armored}

	m, _, err := Build(req, newAuthority(t).public)
	require.NoError(t, err)
	require.Len(t, m.Revoke, 1)
	assert.Equal(t, now, m.Revoke[0].Since)
}

func TestBuild_RevokingACarriedRevokeAgainKeepsTheFirst(t *testing.T) {
	t.Parallel()

	a := newAuthority(t)
	v1 := newReleaseKey(t, "v1")
	first := now.Add(-3 * time.Hour)

	prev := compromise()
	prev.Revoke = []Revocation{{Fingerprint: v1.fingerprint, Since: first}}
	prev.Anchors = [][]byte{v1.armored, newReleaseKey(t, "v2").armored}
	prevManifest, prevSig := issue(t, a, prev)

	req := compromise()
	req.Previous = &Previous{Manifest: prevManifest, Signature: prevSig}
	req.Revoke = []Revocation{{Fingerprint: v1.fingerprint}}
	req.Anchors = prev.Anchors

	m, carried, err := Build(req, a.public)
	require.NoError(t, err)
	require.Len(t, m.Revoke, 1)
	assert.Equal(t, first, m.Revoke[0].Since)
	assert.True(t, carried[v1.fingerprint])
}
