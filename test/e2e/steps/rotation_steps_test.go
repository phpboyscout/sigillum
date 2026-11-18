package steps_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/cucumber/godog"

	"gitlab.com/phpboyscout/go/signing/verify"
)

const releaseKeyFile = "demo.asc"

func registerRotationSteps(ctx *godog.ScenarioContext, w *world) {
	ctx.When(`^I issue an empty rotation manifest with that key$`, w.issueEmptyRotationManifest)
	ctx.When(`^I issue a scheduled rotation manifest that revokes that key$`, w.issueScheduledRevoke)
	ctx.Then(`^the rotation manifest verifies against the key's minisign public key$`, w.rotationManifestVerifies)
	ctx.Then(`^applying it leaves the trust set unchanged at epoch (\d+)$`, w.applyingLeavesTrustUnchanged)
	ctx.Then(`^the file "([^"]*)" does not exist$`, w.fileDoesNotExist)
}

func notAfter() string { return time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339) }

func (w *world) rotate(args ...string) error {
	return w.run(append([]string{"keys", "rotate", "--backend", "local", "--key-id", "demo.pem", "--not-after", notAfter()}, args...)...)
}

func (w *world) issueEmptyRotationManifest() error {
	return w.rotate("--reason", "scheduled")
}

func (w *world) issueScheduledRevoke() error {
	fp, err := w.releaseKeyFingerprint()
	if err != nil {
		return err
	}

	return w.rotate("--reason", "scheduled", "--revoke", fp)
}

func (w *world) releaseKeyFingerprint() (string, error) {
	armored, err := os.ReadFile(w.path(releaseKeyFile))
	if err != nil {
		return "", err
	}

	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(ring[0].PrimaryKey.Fingerprint)), nil
}

// verifiedRotation verifies the written manifest against the key `keys
// minisign` derives, not the authority line rotate printed about itself.
func (w *world) verifiedRotation() (*verify.RotationManifest, error) {
	if err := w.run("keys", "minisign", "--backend", "local", "--key-id", "demo.pem"); err != nil {
		return nil, err
	}

	if err := w.commandSucceeds(); err != nil {
		return nil, err
	}

	authority, err := verify.NewRotationAuthority(strings.TrimSpace(w.stdout))
	if err != nil {
		return nil, err
	}

	manifest, err := os.ReadFile(w.path(verify.RotationManifestFile))
	if err != nil {
		return nil, err
	}

	signature, err := os.ReadFile(w.path(verify.RotationSignatureFile))
	if err != nil {
		return nil, err
	}

	return authority.VerifyRotationManifest(manifest, signature)
}

func (w *world) rotationManifestVerifies() error {
	_, err := w.verifiedRotation()

	return err
}

func (w *world) applyingLeavesTrustUnchanged(epoch uint64) error {
	m, err := w.verifiedRotation()
	if err != nil {
		return err
	}

	armored, err := os.ReadFile(w.path(releaseKeyFile))
	if err != nil {
		return err
	}

	r, err := verify.BuildKeyResolver(verify.KeyResolverConfig{KeySource: "embedded"}, armored)
	if err != nil {
		return err
	}

	agreed, err := r.Resolve(context.Background())
	if err != nil {
		return err
	}

	rec, err := verify.Apply(m, verify.RotationRecord{}, agreed, time.Now())
	if err != nil {
		return err
	}

	if rec.Epoch != epoch || len(rec.Added) != 0 || len(rec.Revoked) != 0 {
		return fmt.Errorf("applied record is %+v, want an empty record at epoch %d", rec, epoch)
	}

	return nil
}

func (w *world) fileDoesNotExist(name string) error {
	if _, err := os.Stat(w.path(name)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s exists, or cannot be checked: %w", name, err)
	}

	return nil
}
