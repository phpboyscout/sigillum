package steps_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
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
	ctx.Given(`^a second release key "([^"]*)"$`, w.aSecondReleaseKey)
	ctx.When(`^I issue a compromise rotation manifest that adds "([^"]*)" and revokes that key$`, w.issueCompromise)
	ctx.When(`^I issue a scheduled rotation manifest after it into "([^"]*)"$`, w.issueScheduledAfter)
	ctx.Then(`^the manifest in "([^"]*)" is scheduled at epoch (\d+) and still revokes that key$`, w.manifestStillRevokes)
	ctx.Then(`^an install that applies only the manifest in "([^"]*)" stops trusting that key$`, w.skippedInstallRefuses)
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

func (w *world) aSecondReleaseKey(name string) error {
	if err := w.run("keys", "generate", "--algorithm", "ed25519", "--private-format", "pem",
		"--name", "E2E Next", "--email", "e2e@example.com",
		"--output", name, "--private-output", name+".pem"); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *world) issueCompromise(add string) error {
	fp, err := w.releaseKeyFingerprint()
	if err != nil {
		return err
	}

	if err := w.rotate("--reason", "compromise", "--add", add, "--revoke", fp); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *world) issueScheduledAfter(dir string) error {
	if err := os.MkdirAll(w.path(dir), 0o750); err != nil {
		return err
	}

	return w.rotate("--reason", "scheduled", "--previous", verify.RotationManifestFile, "--output-dir", dir)
}

func (w *world) manifestIn(dir string) (*verify.RotationManifest, error) {
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

	manifest, err := os.ReadFile(w.path(dir + "/" + verify.RotationManifestFile))
	if err != nil {
		return nil, err
	}

	signature, err := os.ReadFile(w.path(dir + "/" + verify.RotationSignatureFile))
	if err != nil {
		return nil, err
	}

	return authority.VerifyRotationManifest(manifest, signature)
}

func (w *world) manifestStillRevokes(dir string, epoch uint64) error {
	m, err := w.manifestIn(dir)
	if err != nil {
		return err
	}

	fp, err := w.releaseKeyFingerprint()
	if err != nil {
		return err
	}

	if m.Reason != verify.RotationReasonScheduled || m.Epoch != epoch || len(m.Revoke) != 1 || m.Revoke[0].Fingerprint != fp {
		return fmt.Errorf("manifest is %s at epoch %d revoking %+v, want scheduled at epoch %d revoking %s", m.Reason, m.Epoch, m.Revoke, epoch, fp)
	}

	return nil
}

func (w *world) skippedInstallRefuses(dir string) error {
	m, err := w.manifestIn(dir)
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

	fp, err := w.releaseKeyFingerprint()
	if err != nil {
		return err
	}

	if !slices.Contains(rec.Revoked, fp) {
		return fmt.Errorf("applied record %+v does not revoke %s", rec, fp)
	}

	return nil
}
