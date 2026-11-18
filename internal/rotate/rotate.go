package rotate

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/verify"
)

// maxEpochStep matches the step an updater accepts above its stored epoch.
const maxEpochStep = 1024

// Refusals Build returns before anything is signed.
var (
	ErrNeedsPrevious         = errors.NewSentinel("sigillum.rotate_needs_previous", "an epoch above 1 needs the previous manifest")
	ErrEpochGap              = errors.NewSentinel("sigillum.rotate_epoch_gap", "epoch skips past the previous manifest's next epoch")
	ErrEpochNotAfterPrevious = errors.NewSentinel("sigillum.rotate_epoch_replayed", "epoch is not above the previous manifest's")
	ErrEpochTooFar           = errors.NewSentinel("sigillum.rotate_epoch_too_far", "epoch is further above the previous manifest's than an updater accepts")
	ErrScheduledRevoke       = errors.NewSentinel("sigillum.rotate_scheduled_revoke", "a manifest that revokes must have reason compromise")
	ErrAddedAndRevoked       = errors.NewSentinel("sigillum.rotate_added_and_revoked", "a key is both added and revoked")
	ErrNeedsAnchors          = errors.NewSentinel("sigillum.rotate_needs_anchors", "a manifest that revokes and adds nothing needs the anchors to prove a release key remains")
	ErrBadKey                = errors.NewSentinel("sigillum.rotate_bad_key", "not exactly one armored OpenPGP public key")
	ErrSecretKey             = errors.NewSentinel("sigillum.rotate_secret_key", "holds private key material, which a published manifest must never carry")
	ErrBadFingerprint        = errors.NewSentinel("sigillum.rotate_bad_fingerprint", "not a 40-character hex fingerprint")
)

// Request is everything one run of keys rotate is given.
type Request struct {
	Reason   verify.RotationReason
	Now      time.Time
	NotAfter time.Time

	// Epoch is the operator's epoch, or 0 for the default: 1 for the first
	// manifest, the previous epoch plus one after it.
	Epoch         uint64
	AllowEpochGap bool

	Add    []KeyFile
	Revoke []Revocation

	Previous *Previous
	// PreviousAuthority verifies Previous instead of the signing authority,
	// for authority succession.
	PreviousAuthority string

	// Anchors and AnchorOnly are the armored keys the binaries embed. With
	// either, the manifest is checked as an updater would check it.
	Anchors    [][]byte
	AnchorOnly [][]byte
}

// KeyFile is an armored public key and the name it was read from.
type KeyFile struct {
	Name    string
	Armored []byte
}

// Revocation is one key to revoke. A zero Since means the time of the run.
type Revocation struct {
	Fingerprint string
	Since       time.Time
}

// Previous is the latest published manifest and its detached signature.
type Previous struct {
	Manifest  []byte
	Signature []byte
}

// Carried is the set of fingerprints a manifest took from the previous one
// rather than from this run.
type Carried map[string]bool

// Build returns the manifest to sign with the authority whose minisign public
// key is authority, and which of its entries were carried, or the refusal that
// stops it.
func Build(req Request, authority string) (verify.RotationManifest, Carried, error) {
	m := verify.RotationManifest{
		Schema:   verify.RotationSchema,
		IssuedAt: req.Now,
		NotAfter: req.NotAfter,
		Reason:   req.Reason,
	}

	prev, err := readPrevious(req, authority)
	if err != nil {
		return m, nil, err
	}

	if m.Epoch, err = epoch(req, prev); err != nil {
		return m, nil, err
	}

	carried := Carried{}

	if prev != nil {
		m.Add, m.Revoke = slices.Clone(prev.Add), slices.Clone(prev.Revoke)

		for _, a := range m.Add {
			carried[a.Fingerprint] = true
		}

		for _, r := range m.Revoke {
			carried[r.Fingerprint] = true
		}
	}

	if err := applyRun(&m, req, carried); err != nil {
		return m, nil, err
	}

	if len(m.Revoke) > 0 && m.Reason != verify.RotationReasonCompromise {
		return m, nil, scheduledRevoke(req)
	}

	if err := checkAgainstAnchors(m, req); err != nil {
		return m, nil, err
	}

	return m, carried, nil
}

func readPrevious(req Request, authority string) (*verify.RotationManifest, error) {
	if req.Previous == nil {
		return nil, nil //nolint:nilnil // no previous manifest is the first rotation
	}

	if req.PreviousAuthority != "" {
		authority = req.PreviousAuthority
	}

	a, err := verify.NewRotationAuthority(authority)
	if err != nil {
		return nil, errors.Wrap(err, "loading the authority for the previous manifest")
	}

	prev, err := a.VerifyRotationManifest(req.Previous.Manifest, req.Previous.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "the previous manifest")
	}

	return prev, nil
}

func epoch(req Request, prev *verify.RotationManifest) (uint64, error) {
	if prev == nil {
		if req.Epoch > 1 {
			return 0, errors.Wrapf(ErrNeedsPrevious, "epoch %d: pass --previous with the latest published manifest", req.Epoch)
		}

		return 1, nil
	}

	next := prev.Epoch + 1

	switch {
	case req.Epoch == 0 || req.Epoch == next:
		return next, nil
	case req.Epoch <= prev.Epoch:
		return 0, errors.Wrapf(ErrEpochNotAfterPrevious, "epoch %d, previous is %d", req.Epoch, prev.Epoch)
	case req.Epoch-prev.Epoch > maxEpochStep:
		return 0, errors.Wrapf(ErrEpochTooFar, "epoch %d is more than %d above the previous %d", req.Epoch, maxEpochStep, prev.Epoch)
	case !req.AllowEpochGap:
		return 0, errors.Wrapf(ErrEpochGap,
			"epoch %d, previous is %d: a stale --previous drops later revokes; pass --allow-epoch-gap if the gap is deliberate",
			req.Epoch, prev.Epoch)
	default:
		return req.Epoch, nil
	}
}

func applyRun(m *verify.RotationManifest, req Request, carried Carried) error {
	added := map[string]struct{}{}

	for _, f := range req.Add {
		fp, public, err := publicKey(f.Armored)
		if err != nil {
			return errors.Wrapf(err, "--add %s", f.Name)
		}

		added[fp] = struct{}{}
		delete(carried, fp)

		if !slices.ContainsFunc(m.Add, func(a verify.RotationAdd) bool { return a.Fingerprint == fp }) {
			m.Add = append(m.Add, verify.RotationAdd{Fingerprint: fp, Armored: public})
		}
	}

	for _, r := range req.Revoke {
		fp, err := normalise(r.Fingerprint)
		if err != nil {
			return err
		}

		if _, ok := added[fp]; ok {
			return errors.Wrapf(ErrAddedAndRevoked, "%s", fp)
		}

		m.Add = slices.DeleteFunc(m.Add, func(a verify.RotationAdd) bool { return a.Fingerprint == fp })

		if slices.ContainsFunc(m.Revoke, func(v verify.RotationRevoke) bool { return v.Fingerprint == fp }) {
			continue
		}

		delete(carried, fp)

		since := r.Since
		if since.IsZero() {
			since = req.Now
		}

		m.Revoke = append(m.Revoke, verify.RotationRevoke{Fingerprint: fp, Since: since})
	}

	return nil
}

func scheduledRevoke(req Request) error {
	if len(req.Revoke) == 0 {
		return errors.Wrap(ErrScheduledRevoke,
			"the previous manifest revokes keys, and every later manifest must carry them, so pass --reason compromise")
	}

	return errors.Wrap(ErrScheduledRevoke, "pass --reason compromise")
}

func checkAgainstAnchors(m verify.RotationManifest, req Request) error {
	if len(req.Anchors) == 0 && len(req.AnchorOnly) == 0 {
		if len(m.Add) == 0 && len(m.Revoke) > 0 {
			return errors.Wrap(ErrNeedsAnchors, "pass --anchor with the release keys the binaries embed")
		}

		return nil
	}

	anchorOnly := make([]string, 0, len(req.AnchorOnly))

	for _, armored := range req.AnchorOnly {
		fp, _, err := publicKey(armored)
		if err != nil {
			return errors.Wrap(err, "--anchor-only")
		}

		anchorOnly = append(anchorOnly, fp)
	}

	r, err := verify.BuildKeyResolver(verify.KeyResolverConfig{KeySource: "embedded", AnchorOnlyFingerprints: anchorOnly},
		slices.Concat(req.Anchors, req.AnchorOnly)...)
	if err != nil {
		return errors.Wrap(err, "loading the anchors")
	}

	agreed, err := r.Resolve(context.Background())
	if err != nil {
		return errors.Wrap(err, "loading the anchors")
	}

	return verify.CheckRotation(m, agreed) //nolint:wrapcheck // the updater's own refusal, unchanged
}

// publicKey returns the fingerprint of the one public key in armored, and that
// key re-serialised, so nothing else in the file can reach a published manifest.
func publicKey(armored []byte) (fingerprint, public string, err error) {
	e, err := onePublicEntity(armored)
	if err != nil {
		return "", "", err
	}

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err == nil {
		err = e.Serialize(w)
	}

	if err == nil {
		err = w.Close()
	}

	if err != nil {
		return "", "", errors.Wrap(err, "re-armoring the public key")
	}

	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)), buf.String(), nil
}

func onePublicEntity(armored []byte) (*openpgp.Entity, error) {
	if bytes.Contains(armored, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
		return nil, ErrSecretKey
	}

	if bytes.Count(armored, []byte("-----BEGIN PGP ")) != 1 {
		return nil, errors.Wrap(ErrBadKey, "the file must hold one armored block")
	}

	block, err := armor.Decode(bytes.NewReader(armored))
	if err != nil || block.Type != openpgp.PublicKeyType {
		return nil, ErrBadKey
	}

	ring, err := openpgp.ReadKeyRing(block.Body)
	if err != nil || len(ring) != 1 {
		return nil, ErrBadKey
	}

	e := ring[0]
	if e.PrivateKey != nil || slices.ContainsFunc(e.Subkeys, func(k openpgp.Subkey) bool { return k.PrivateKey != nil }) {
		return nil, ErrSecretKey
	}

	return e, nil
}

func normalise(fp string) (string, error) {
	n := strings.ToUpper(strings.ReplaceAll(fp, " ", ""))

	if _, err := hex.DecodeString(n); err != nil || len(n) != 40 {
		return "", errors.Wrapf(ErrBadFingerprint, "%q", fp)
	}

	return n, nil
}
