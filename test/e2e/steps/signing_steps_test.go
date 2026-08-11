package steps_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"gitlab.com/phpboyscout/go/signing/minisign"
)

// The binary is built once for the whole suite. Building per scenario
// would dominate the runtime and prove nothing extra.
var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// pinnedTime is a fixed instant for the reproducibility scenario.
const pinnedTime = "2026-08-01T00:00:00Z"

// sigillumBinary builds cmd/sigillum and returns the path.
//
// The suite drives the built binary rather than calling the library,
// because sigillum IS the wiring: which stream a value lands on,
// whether a flag reaches the library, whether a file appears where the
// docs say. None of that is visible from a library-level test — a
// stdout/stderr mistake in particular survives a fully green unit
// suite, because a test that sets the command's output cannot tell the
// two streams apart.
func sigillumBinary() (string, error) {
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sigillum-e2e-bin-")
		if err != nil {
			buildErr = err

			return
		}

		out := filepath.Join(dir, "sigillum")

		// -buildvcs=false: the stamp is irrelevant to what these
		// scenarios assert, and resolving it fails outright in a git
		// worktree or a shallow/detached CI clone. Making the build
		// independent of git state keeps the suite runnable everywhere.
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/sigillum")
		cmd.Dir = "../../.."

		if combined, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building sigillum: %w\n%s", err, combined)

			return
		}

		binPath = out
	})

	return binPath, buildErr
}

// world carries one scenario's state.
type world struct {
	dir      string
	stdout   string
	stderr   string
	exitErr  error
	artefact string
	verified *bool

	// manifestBefore snapshots keys.json so a re-publish can be shown
	// to change nothing.
	manifestBefore string
}

// run executes sigillum with args, capturing stdout and stderr
// SEPARATELY. Merging them would defeat the point: the bug this suite
// exists to catch was a value written to the wrong stream, which looks
// identical on a terminal.
func (w *world) run(args ...string) error {
	bin, err := sigillumBinary()
	if err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer

	cmd := exec.Command(bin, args...)
	cmd.Dir = w.dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	w.exitErr = cmd.Run()
	w.stdout = stdout.String()
	w.stderr = stderr.String()

	return nil
}

func (w *world) path(name string) string { return filepath.Join(w.dir, name) }

func (w *world) read(name string) (string, error) {
	b, err := os.ReadFile(w.path(name))

	return string(b), err
}

// --- Background ---

func (w *world) aFreshlyBuiltBinary() error {
	_, err := sigillumBinary()

	return err
}

func (w *world) anEmptyWorkingDirectory() error {
	dir, err := os.MkdirTemp("", "sigillum-e2e-")
	if err != nil {
		return err
	}

	w.dir = dir

	return nil
}

// --- key generation ---

func (w *world) generateEd25519PEMKey() error {
	return w.run("keys", "generate",
		"--algorithm", "ed25519",
		"--private-format", "pem",
		"--name", "E2E Demo",
		"--email", "e2e@example.com",
		"--output", "demo.asc",
		"--private-output", "demo.pem")
}

func (w *world) haveEd25519PEMKey() error {
	if err := w.generateEd25519PEMKey(); err != nil {
		return err
	}

	return w.commandSucceeds()
}

// --- artefacts and signing ---

func (w *world) aReleaseArtefact(name string) error {
	w.artefact = name

	// Deterministic content: reproducibility is asserted elsewhere, and
	// random bytes would make a failure hard to reproduce.
	body := bytes.Repeat([]byte("release artefact payload\n"), 4096)

	return os.WriteFile(w.path(name), body, 0o600)
}

func (w *world) signAsMinisign(project string) error {
	return w.run("sign", "--format", "minisign",
		"--backend", "local", "--key-id", "./demo.pem",
		"--project", project, w.artefact)
}

func (w *world) haveSignedAsMinisign(project string) error {
	if err := w.signAsMinisign(project); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *world) signAtPinnedTime() error {
	if err := w.run("sign", "--format", "minisign",
		"--backend", "local", "--key-id", "./demo.pem",
		"--project", "demo-tool", "--created", pinnedTime,
		"--output", w.artefact+".a.minisig", w.artefact); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *world) signAtPinnedTimeAgain() error {
	if err := w.run("sign", "--format", "minisign",
		"--backend", "local", "--key-id", "./demo.pem",
		"--project", "demo-tool", "--created", pinnedTime,
		"--output", w.artefact+".b.minisig", w.artefact); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *world) bothSignaturesIdentical() error {
	a, err := w.read(w.artefact + ".a.minisig")
	if err != nil {
		return err
	}

	b, err := w.read(w.artefact + ".b.minisig")
	if err != nil {
		return err
	}

	if a != b {
		return fmt.Errorf("a pinned timestamp must yield byte-identical signatures")
	}

	return nil
}

func (w *world) signPassingAnOpenPGPPublicKey() error {
	return w.run("sign", "--format", "minisign",
		"--backend", "local", "--key-id", "./demo.pem",
		"--public-key", "demo.asc", w.artefact)
}

// --- public key ---

func (w *world) askForTheMinisignPublicKey() error {
	return w.run("keys", "minisign", "--backend", "local", "--key-id", "./demo.pem")
}

func (w *world) stdoutIsTheMinisignPublicKey() error {
	got := strings.TrimSpace(w.stdout)

	if _, err := minisign.ParsePublicKey(got); err != nil {
		return fmt.Errorf("stdout is not a minisign public key (%q): %w", got, err)
	}

	return nil
}

func (w *world) stderrContainsNoKeyMaterial() error {
	// The key must not ALSO appear on stderr — that is how the original
	// bug hid, with both streams landing together on a terminal.
	if key := strings.TrimSpace(w.stdout); key != "" && strings.Contains(w.stderr, key) {
		return fmt.Errorf("the public key also appears on stderr")
	}

	return nil
}

// --- verification ---

func (w *world) verifySignatureAgainstKey() error {
	sig, err := w.read(w.artefact + ".minisig")
	if err != nil {
		return err
	}

	pubFile, err := w.read("demo.pub")
	if err != nil {
		// Emit the public key on demand so the scenarios stay readable.
		if runErr := w.run("keys", "minisign", "--backend", "local",
			"--key-id", "./demo.pem", "--output", "demo.pub"); runErr != nil {
			return runErr
		}

		if pubFile, err = w.read("demo.pub"); err != nil {
			return err
		}
	}

	key, err := minisign.ParsePublicKey(pubFile)
	if err != nil {
		return err
	}

	artefact, err := os.ReadFile(w.path(w.artefact))
	if err != nil {
		return err
	}

	ok := minisign.VerifyFile(key, artefact, []byte(sig)) == nil
	w.verified = &ok

	return nil
}

func (w *world) signatureIsValid() error {
	if w.verified == nil || !*w.verified {
		return fmt.Errorf("signature did not verify")
	}

	return nil
}

func (w *world) signatureIsNotValid() error {
	if w.verified == nil || *w.verified {
		return fmt.Errorf("signature verified when it should not have")
	}

	return nil
}

func (w *world) tamperWithTheArtefact() error {
	body, err := os.ReadFile(w.path(w.artefact))
	if err != nil {
		return err
	}

	body[0] ^= 0xff

	return os.WriteFile(w.path(w.artefact), body, 0o600)
}

func (w *world) tamperWithTheProjectField() error {
	name := w.artefact + ".minisig"

	sig, err := w.read(name)
	if err != nil {
		return err
	}

	return os.WriteFile(w.path(name),
		[]byte(strings.Replace(sig, "project:demo-tool", "project:evil-tool", 1)), 0o600)
}

// --- publication ---

func (w *world) publishFor(project string) error {
	if err := w.run("keys", "minisign", "--backend", "local",
		"--key-id", "./demo.pem", "--output", "demo.pub", "--force"); err != nil {
		return err
	}

	return w.run("keys", "publish", "--output", "site",
		"--project", project, "--valid-from", "2026-08-01", "demo.pub")
}

// havePublishedForRecording publishes and snapshots the manifest, so
// the follow-up re-publish can be compared against it.
func (w *world) havePublishedForRecording(project string) error {
	if err := w.publishFor(project); err != nil {
		return err
	}

	if err := w.commandSucceeds(); err != nil {
		return err
	}

	before, err := w.read(filepath.Join("site", "keys.json"))
	if err != nil {
		return err
	}

	w.manifestBefore = before

	return nil
}

type manifest struct {
	Keys []struct {
		Project    string `json:"project"`
		Generation int    `json:"generation"`
		PubKey     string `json:"pubkey"`
		Path       string `json:"path"`
	} `json:"keys"`
}

func (w *world) readManifest() (manifest, error) {
	var m manifest

	raw, err := w.read(filepath.Join("site", "keys.json"))
	if err != nil {
		return m, err
	}

	return m, json.Unmarshal([]byte(raw), &m)
}

func (w *world) manifestRecords(project string, generation int) error {
	m, err := w.readManifest()
	if err != nil {
		return err
	}

	for _, k := range m.Keys {
		if k.Project == project && k.Generation == generation {
			return nil
		}
	}

	return fmt.Errorf("manifest has no entry for %s generation %d", project, generation)
}

// manifestPubKeyMatchesFile is the property the whole design rests on:
// the string in the manifest is what gets pinned in cargo-binstall
// metadata, so it must be exactly the published key.
func (w *world) manifestPubKeyMatchesFile() error {
	m, err := w.readManifest()
	if err != nil {
		return err
	}

	if len(m.Keys) == 0 {
		return fmt.Errorf("manifest is empty")
	}

	body, err := w.read(filepath.Join("site", m.Keys[0].Path))
	if err != nil {
		return err
	}

	key, err := minisign.ParsePublicKey(body)
	if err != nil {
		return err
	}

	if key.Encode() != m.Keys[0].PubKey {
		return fmt.Errorf("manifest pubkey %q does not match the published key file %q",
			m.Keys[0].PubKey, key.Encode())
	}

	return nil
}

func (w *world) manifestIsUnchanged() error {
	// The "have published" step recorded the manifest; compare it now.
	current, err := w.read(filepath.Join("site", "keys.json"))
	if err != nil {
		return err
	}

	if current != w.manifestBefore {
		return fmt.Errorf("re-publishing an identical key changed the manifest")
	}

	return nil
}

// --- generic assertions ---

func (w *world) commandSucceeds() error {
	if w.exitErr != nil {
		return fmt.Errorf("command failed: %v\nstdout: %s\nstderr: %s", w.exitErr, w.stdout, w.stderr)
	}

	return nil
}

func (w *world) commandFails() error {
	if w.exitErr == nil {
		return fmt.Errorf("command unexpectedly succeeded\nstdout: %s", w.stdout)
	}

	return nil
}

func (w *world) stderrMentions(text string) error {
	if !strings.Contains(w.stderr, text) {
		return fmt.Errorf("stderr does not mention %q\nstderr: %s", text, w.stderr)
	}

	return nil
}

func (w *world) fileExists(name string) error {
	if _, err := os.Stat(w.path(name)); err != nil {
		return fmt.Errorf("expected %s to exist: %w", name, err)
	}

	return nil
}

func (w *world) fileStartsWith(name, prefix string) error {
	body, err := w.read(name)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(body, prefix) {
		return fmt.Errorf("%s does not start with %q", name, prefix)
	}

	return nil
}

func (w *world) signatureBodyStartsWith(prefix string) error {
	sig, err := w.read(w.artefact + ".minisig")
	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimRight(sig, "\n"), "\n")
	if len(lines) < 2 {
		return fmt.Errorf("signature has %d lines, want at least 2", len(lines))
	}

	if !strings.HasPrefix(lines[1], prefix) {
		return fmt.Errorf("signature body %q does not start with %q", lines[1], prefix)
	}

	return nil
}

func (w *world) trustedCommentContains(text string) error {
	sig, err := w.read(w.artefact + ".minisig")
	if err != nil {
		return err
	}

	parsed, err := minisign.ParseSignature([]byte(sig))
	if err != nil {
		return err
	}

	if !strings.Contains(parsed.TrustedComment, text) {
		return fmt.Errorf("trusted comment %q does not contain %q", parsed.TrustedComment, text)
	}

	return nil
}

func initializeScenario(ctx *godog.ScenarioContext) {
	w := &world{}

	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*w = world{}

		return ctx, nil
	})

	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.dir != "" {
			_ = os.RemoveAll(w.dir)
		}

		return ctx, nil
	})

	registerDecryptSteps(ctx, w)

	ctx.Given(`^a freshly built sigillum binary$`, w.aFreshlyBuiltBinary)
	ctx.Given(`^an empty working directory$`, w.anEmptyWorkingDirectory)
	ctx.Given(`^an ed25519 key with a pem private half$`, w.haveEd25519PEMKey)
	ctx.Given(`^a release artefact "([^"]*)"$`, w.aReleaseArtefact)
	ctx.Given(`^I have signed that artefact as minisign for project "([^"]*)"$`, w.haveSignedAsMinisign)
	ctx.Given(`^I have published the public key for project "([^"]*)"$`, w.havePublishedForRecording)

	ctx.When(`^I generate an ed25519 key with a pem private half$`, w.generateEd25519PEMKey)
	ctx.When(`^I sign that artefact as minisign for project "([^"]*)"$`, w.signAsMinisign)
	ctx.When(`^I sign that artefact as minisign at a pinned time$`, w.signAtPinnedTime)
	ctx.When(`^I sign that artefact as minisign at a pinned time again$`, w.signAtPinnedTimeAgain)
	ctx.When(`^I sign that artefact as minisign passing an OpenPGP public key$`, w.signPassingAnOpenPGPPublicKey)
	ctx.When(`^I ask for the minisign public key$`, w.askForTheMinisignPublicKey)
	ctx.When(`^I publish the public key for project "([^"]*)"$`, w.publishFor)
	ctx.When(`^I verify the signature against the key$`, w.verifySignatureAgainstKey)
	ctx.When(`^I tamper with the artefact$`, w.tamperWithTheArtefact)
	ctx.When(`^I tamper with the project field in the signature$`, w.tamperWithTheProjectField)

	ctx.Then(`^the command succeeds$`, w.commandSucceeds)
	ctx.Then(`^the command fails$`, w.commandFails)
	ctx.Then(`^the file "([^"]*)" exists$`, w.fileExists)
	ctx.Then(`^the file "([^"]*)" starts with "([^"]*)"$`, w.fileStartsWith)
	ctx.Then(`^the signature body starts with "([^"]*)"$`, w.signatureBodyStartsWith)
	ctx.Then(`^the trusted comment contains "([^"]*)"$`, w.trustedCommentContains)
	ctx.Then(`^the signature is valid$`, w.signatureIsValid)
	ctx.Then(`^the signature is not valid$`, w.signatureIsNotValid)
	ctx.Then(`^stdout is the minisign public key$`, w.stdoutIsTheMinisignPublicKey)
	ctx.Then(`^stderr contains no key material$`, w.stderrContainsNoKeyMaterial)
	ctx.Then(`^stderr mentions "([^"]*)"$`, w.stderrMentions)
	ctx.Then(`^the manifest records project "([^"]*)" at generation (\d+)$`, w.manifestRecords)
	ctx.Then(`^the manifest pubkey matches the published key file$`, w.manifestPubKeyMatchesFile)
	ctx.Then(`^the manifest is unchanged$`, w.manifestIsUnchanged)
	ctx.Then(`^both signatures are byte-identical$`, w.bothSignaturesIdentical)
}
